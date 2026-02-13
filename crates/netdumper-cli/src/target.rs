//! ICLRDataTarget implementation for DAC interaction.
//!
//! This module provides the COM interface implementation that the DAC uses
//! to read memory from the target process.

#![allow(non_snake_case)]

use std::collections::HashMap;
use std::ffi::c_void;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use windows::Win32::Foundation::{CloseHandle, E_FAIL, E_NOINTERFACE, E_NOTIMPL, HANDLE, S_OK};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::ProcessStatus::{
    EnumProcessModulesEx, GetModuleBaseNameW, GetModuleFileNameExW, LIST_MODULES_ALL,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use windows::core::{GUID, HRESULT};

use crate::runtime::{
    EmbeddedRuntimeInfo, exe_has_clr_exports, get_embedded_clr_version_with_handle,
};
use crate::{Error, Result};

/// Type alias for CLR data addresses
pub type ClrDataAddress = u64;

// GUID for ICLRDataTarget interface
const IID_ICLR_DATA_TARGET: GUID = GUID::from_u128(0x3E11CCEE_D08B_43E5_AF01_32717A64DA03);

// =============================================================================
// ICLRDataTarget vtable and implementation struct
// =============================================================================

#[repr(C)]
struct ICLRDataTargetVtbl {
    // IUnknown
    query_interface: unsafe extern "system" fn(
        *mut ICLRDataTargetImpl,
        *const GUID,
        *mut *mut c_void,
    ) -> HRESULT,
    add_ref: unsafe extern "system" fn(*mut ICLRDataTargetImpl) -> u32,
    release: unsafe extern "system" fn(*mut ICLRDataTargetImpl) -> u32,
    // ICLRDataTarget
    get_machine_type: unsafe extern "system" fn(*mut ICLRDataTargetImpl, *mut u32) -> HRESULT,
    get_pointer_size: unsafe extern "system" fn(*mut ICLRDataTargetImpl, *mut u32) -> HRESULT,
    get_image_base: unsafe extern "system" fn(
        *mut ICLRDataTargetImpl,
        *const u16,
        *mut ClrDataAddress,
    ) -> HRESULT,
    read_virtual: unsafe extern "system" fn(
        *mut ICLRDataTargetImpl,
        ClrDataAddress,
        *mut u8,
        u32,
        *mut u32,
    ) -> HRESULT,
    write_virtual: unsafe extern "system" fn(
        *mut ICLRDataTargetImpl,
        ClrDataAddress,
        *mut u8,
        u32,
        *mut u32,
    ) -> HRESULT,
    get_tls_value: unsafe extern "system" fn(
        *mut ICLRDataTargetImpl,
        u32,
        u32,
        *mut ClrDataAddress,
    ) -> HRESULT,
    set_tls_value:
        unsafe extern "system" fn(*mut ICLRDataTargetImpl, u32, u32, ClrDataAddress) -> HRESULT,
    get_current_thread_id: unsafe extern "system" fn(*mut ICLRDataTargetImpl, *mut u32) -> HRESULT,
    get_thread_context:
        unsafe extern "system" fn(*mut ICLRDataTargetImpl, u32, u32, u32, *mut u8) -> HRESULT,
    set_thread_context:
        unsafe extern "system" fn(*mut ICLRDataTargetImpl, u32, u32, *mut u8) -> HRESULT,
    request: unsafe extern "system" fn(
        *mut ICLRDataTargetImpl,
        u32,
        u32,
        *mut u8,
        u32,
        *mut u8,
    ) -> HRESULT,
}

#[repr(C)]
pub struct ICLRDataTargetImpl {
    vtbl: *const ICLRDataTargetVtbl,
}

// =============================================================================
// Process Handle RAII Wrapper
// =============================================================================

/// RAII wrapper for Windows process handles.
/// Automatically closes the handle when dropped.
pub(crate) struct ProcessHandle(pub(crate) HANDLE);

impl ProcessHandle {
    /// Open a process with query and read permissions.
    pub fn open(pid: u32) -> Result<Self> {
        let handle =
            unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }
                .map_err(|e| Error::Other(format!("Failed to open process {}: {}", pid, e)))?;
        Ok(Self(handle))
    }

    /// Get the raw handle for Windows API calls.
    pub fn as_raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0).ok() };
    }
}

// =============================================================================
// Process Information Cache
// =============================================================================

/// Cached information about a target process.
/// Consolidates process inspection to avoid repeated handle opens and module enumeration.
pub struct ProcessInfo {
    pub(crate) handle: ProcessHandle,
    /// Map of module name (lowercase) -> base address
    pub(crate) module_bases: HashMap<String, u64>,
    /// Main executable base address
    pub(crate) exe_base_address: u64,
    /// Path to the main executable (currently unused, reserved for future use)
    #[allow(dead_code)]
    pub(crate) exe_path: Option<PathBuf>,
    /// Target process machine type (from PE header)
    pub(crate) machine_type: u16,
    /// Whether this process has an embedded CLR (single-file deployment)
    pub(crate) is_embedded_clr: bool,
    /// Cached embedded CLR info (if applicable)
    pub(crate) embedded_clr_info: Option<EmbeddedRuntimeInfo>,
}

impl ProcessInfo {
    /// Create a new ProcessInfo by inspecting the target process.
    pub fn new(pid: u32) -> Result<Self> {
        let handle = ProcessHandle::open(pid)?;

        let mut modules = [windows::Win32::Foundation::HMODULE::default(); 1024];
        let mut needed = 0u32;

        unsafe {
            EnumProcessModulesEx(
                handle.as_raw(),
                modules.as_mut_ptr(),
                std::mem::size_of_val(&modules) as u32,
                &mut needed,
                LIST_MODULES_ALL,
            )
        }
        .map_err(|e| Error::Other(format!("EnumProcessModulesEx failed: {}", e)))?;

        let count = needed as usize / std::mem::size_of::<windows::Win32::Foundation::HMODULE>();

        let mut module_bases = HashMap::new();
        for i in 0..count {
            let module = modules[i];
            let mut name_buf = [0u16; 260];
            let len = unsafe { GetModuleBaseNameW(handle.as_raw(), Some(module), &mut name_buf) };
            if len > 0 {
                let name = String::from_utf16_lossy(&name_buf[..len as usize]).to_lowercase();
                module_bases.insert(name, module.0 as u64);
            }
        }

        let exe_base_address = if count > 0 { modules[0].0 as u64 } else { 0 };

        // Read machine type from main module's PE header
        let machine_type = if exe_base_address != 0 {
            read_machine_type_from_process(handle.as_raw(), exe_base_address as usize)
                .unwrap_or(default_machine_type())
        } else {
            default_machine_type()
        };

        let exe_path = if count > 0 {
            let mut path_buf = [0u16; 512];
            let path_len = unsafe {
                GetModuleFileNameExW(Some(handle.as_raw()), Some(modules[0]), &mut path_buf)
            };
            if path_len > 0 {
                Some(PathBuf::from(String::from_utf16_lossy(
                    &path_buf[..path_len as usize],
                )))
            } else {
                None
            }
        } else {
            None
        };

        let has_coreclr_module = module_bases.contains_key("coreclr.dll");
        let has_clr_exports = exe_path.as_ref().is_some_and(exe_has_clr_exports);
        let is_embedded_clr = !has_coreclr_module && has_clr_exports;

        let embedded_clr_info = if is_embedded_clr {
            get_embedded_clr_version_with_handle(handle.as_raw())
        } else {
            None
        };

        Ok(Self {
            handle,
            module_bases,
            exe_base_address,
            exe_path,
            machine_type,
            is_embedded_clr,
            embedded_clr_info,
        })
    }
}

/// Read the machine type from a PE header in a remote process.
fn read_machine_type_from_process(handle: HANDLE, base_address: usize) -> Option<u16> {
    // Read DOS header to get e_lfanew
    let mut dos_header = [0u8; 64];
    let mut bytes_read = 0usize;

    if unsafe {
        ReadProcessMemory(
            handle,
            base_address as *const c_void,
            dos_header.as_mut_ptr() as *mut c_void,
            dos_header.len(),
            Some(&mut bytes_read),
        )
    }
    .is_err()
        || bytes_read < 64
    {
        return None;
    }

    // Check DOS signature (MZ)
    if dos_header[0] != b'M' || dos_header[1] != b'Z' {
        return None;
    }

    // Get PE header offset
    let e_lfanew = u32::from_le_bytes([
        dos_header[0x3C],
        dos_header[0x3D],
        dos_header[0x3E],
        dos_header[0x3F],
    ]) as usize;

    if !(64..=1024).contains(&e_lfanew) {
        return None;
    }

    // Read PE signature + COFF header (at least 8 bytes for PE sig + machine type)
    let mut pe_header = [0u8; 8];
    if unsafe {
        ReadProcessMemory(
            handle,
            (base_address + e_lfanew) as *const c_void,
            pe_header.as_mut_ptr() as *mut c_void,
            pe_header.len(),
            Some(&mut bytes_read),
        )
    }
    .is_err()
        || bytes_read < 8
    {
        return None;
    }

    // Check PE signature
    if pe_header[0] != b'P' || pe_header[1] != b'E' || pe_header[2] != 0 || pe_header[3] != 0 {
        return None;
    }

    // Machine type is at offset 4-5 in COFF header (after PE signature)
    let machine_type = u16::from_le_bytes([pe_header[4], pe_header[5]]);
    Some(machine_type)
}

/// Get the default machine type for the current build architecture.
#[cfg(target_arch = "x86_64")]
fn default_machine_type() -> u16 {
    0x8664 // AMD64
}

#[cfg(target_arch = "x86")]
fn default_machine_type() -> u16 {
    0x014c // I386
}

#[cfg(target_arch = "aarch64")]
fn default_machine_type() -> u16 {
    0xAA64 // ARM64
}

// =============================================================================
// CLRDataTarget - unified ICLRDataTarget using ReadProcessMemory
// =============================================================================

/// ICLRDataTarget implementation using ReadProcessMemory.
#[repr(C)]
pub struct CLRDataTarget {
    vtbl: *const ICLRDataTargetVtbl,
    ref_count: AtomicU32,
    process_handle: HANDLE,
    owns_handle: bool,
    module_bases: HashMap<String, u64>,
    exe_base_address: u64,
    machine_type: u16,
    is_embedded_clr: bool,
}

static CLR_DATA_TARGET_VTBL: ICLRDataTargetVtbl = ICLRDataTargetVtbl {
    query_interface: clr_query_interface,
    add_ref: clr_add_ref,
    release: clr_release,
    get_machine_type: clr_get_machine_type,
    get_pointer_size: clr_get_pointer_size,
    get_image_base: clr_get_image_base,
    read_virtual: clr_read_virtual,
    write_virtual: clr_write_virtual,
    get_tls_value: clr_get_tls_value,
    set_tls_value: clr_set_tls_value,
    get_current_thread_id: clr_get_current_thread_id,
    get_thread_context: clr_get_thread_context,
    set_thread_context: clr_set_thread_context,
    request: clr_request,
};

impl CLRDataTarget {
    /// Create a new CLRDataTarget for an external process (opens handle).
    pub fn new_external(pid: u32) -> Result<*mut ICLRDataTargetImpl> {
        let info = ProcessInfo::new(pid)?;
        Self::from_process_info(info)
    }

    /// Create a new CLRDataTarget from an existing ProcessInfo.
    pub fn from_process_info(info: ProcessInfo) -> Result<*mut ICLRDataTargetImpl> {
        let handle = info.handle.0;
        let module_bases = info.module_bases;
        let exe_base_address = info.exe_base_address;
        let machine_type = info.machine_type;
        let is_embedded_clr = info.is_embedded_clr;

        std::mem::forget(info.handle);

        let target = Box::new(CLRDataTarget {
            vtbl: &CLR_DATA_TARGET_VTBL,
            ref_count: AtomicU32::new(1),
            process_handle: handle,
            owns_handle: true,
            module_bases,
            exe_base_address,
            machine_type,
            is_embedded_clr,
        });

        Ok(Box::into_raw(target) as *mut ICLRDataTargetImpl)
    }
}

// IUnknown implementation
unsafe extern "system" fn clr_query_interface(
    this: *mut ICLRDataTargetImpl,
    riid: *const GUID,
    ppv_object: *mut *mut c_void,
) -> HRESULT {
    if ppv_object.is_null() {
        return E_FAIL;
    }

    let riid = unsafe { &*riid };
    if *riid == GUID::zeroed() || *riid == IID_ICLR_DATA_TARGET {
        unsafe {
            *ppv_object = this as *mut c_void;
            clr_add_ref(this);
        }
        return S_OK;
    }

    unsafe { *ppv_object = std::ptr::null_mut() };
    E_NOINTERFACE
}

unsafe extern "system" fn clr_add_ref(this: *mut ICLRDataTargetImpl) -> u32 {
    let target = unsafe { &*(this as *const CLRDataTarget) };
    target.ref_count.fetch_add(1, Ordering::SeqCst) + 1
}

unsafe extern "system" fn clr_release(this: *mut ICLRDataTargetImpl) -> u32 {
    let target = unsafe { &*(this as *const CLRDataTarget) };
    let count = target.ref_count.fetch_sub(1, Ordering::SeqCst) - 1;
    if count == 0 {
        let target = unsafe { Box::from_raw(this as *mut CLRDataTarget) };
        if target.owns_handle {
            unsafe { CloseHandle(target.process_handle).ok() };
        }
    }
    count
}

unsafe extern "system" fn clr_get_machine_type(
    this: *mut ICLRDataTargetImpl,
    machine_type: *mut u32,
) -> HRESULT {
    if machine_type.is_null() {
        return E_FAIL;
    }
    let target = unsafe { &*(this as *const CLRDataTarget) };
    unsafe { *machine_type = target.machine_type as u32 };
    S_OK
}

unsafe extern "system" fn clr_get_pointer_size(
    this: *mut ICLRDataTargetImpl,
    pointer_size: *mut u32,
) -> HRESULT {
    if pointer_size.is_null() {
        return E_FAIL;
    }
    let target = unsafe { &*(this as *const CLRDataTarget) };
    // Determine pointer size based on target machine type
    let size = match target.machine_type {
        0x8664 | 0xAA64 => 8, // AMD64 or ARM64 = 64-bit
        _ => 4,               // Everything else (I386, etc) = 32-bit
    };
    unsafe { *pointer_size = size };
    S_OK
}

unsafe extern "system" fn clr_get_image_base(
    this: *mut ICLRDataTargetImpl,
    image_path: *const u16,
    base_address: *mut ClrDataAddress,
) -> HRESULT {
    if image_path.is_null() || base_address.is_null() {
        return E_FAIL;
    }

    let target = unsafe { &*(this as *const CLRDataTarget) };

    let path_len = unsafe {
        let mut len = 0;
        while *image_path.add(len) != 0 {
            len += 1;
        }
        len
    };
    let path_slice = unsafe { std::slice::from_raw_parts(image_path, path_len) };
    let path_str = String::from_utf16_lossy(path_slice);

    let filename = std::path::Path::new(&path_str)
        .file_name()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_else(|| path_str.to_lowercase());

    if let Some(&base) = target.module_bases.get(&filename) {
        unsafe { *base_address = base };
        return S_OK;
    }

    if target.is_embedded_clr
        && target.exe_base_address != 0
        && (filename == "coreclr.dll" || filename == "clr.dll")
    {
        unsafe { *base_address = target.exe_base_address };
        return S_OK;
    }

    E_FAIL
}

unsafe extern "system" fn clr_read_virtual(
    this: *mut ICLRDataTargetImpl,
    address: ClrDataAddress,
    buffer: *mut u8,
    bytes_requested: u32,
    bytes_read: *mut u32,
) -> HRESULT {
    if buffer.is_null() {
        return E_FAIL;
    }

    let target = unsafe { &*(this as *const CLRDataTarget) };
    let mut actual_read = 0usize;

    let result = unsafe {
        ReadProcessMemory(
            target.process_handle,
            address as *const c_void,
            buffer as *mut c_void,
            bytes_requested as usize,
            Some(&mut actual_read),
        )
    };

    match result {
        Ok(()) => {
            if !bytes_read.is_null() {
                unsafe { *bytes_read = actual_read as u32 };
            }
            S_OK
        }
        Err(_) => E_FAIL,
    }
}

// Not implemented methods
unsafe extern "system" fn clr_write_virtual(
    _this: *mut ICLRDataTargetImpl,
    _address: ClrDataAddress,
    _buffer: *mut u8,
    _bytes_requested: u32,
    _bytes_written: *mut u32,
) -> HRESULT {
    E_NOTIMPL
}

unsafe extern "system" fn clr_get_tls_value(
    _this: *mut ICLRDataTargetImpl,
    _thread_id: u32,
    _index: u32,
    _value: *mut ClrDataAddress,
) -> HRESULT {
    E_NOTIMPL
}

unsafe extern "system" fn clr_set_tls_value(
    _this: *mut ICLRDataTargetImpl,
    _thread_id: u32,
    _index: u32,
    _value: ClrDataAddress,
) -> HRESULT {
    E_NOTIMPL
}

unsafe extern "system" fn clr_get_current_thread_id(
    _this: *mut ICLRDataTargetImpl,
    _thread_id: *mut u32,
) -> HRESULT {
    E_NOTIMPL
}

unsafe extern "system" fn clr_get_thread_context(
    _this: *mut ICLRDataTargetImpl,
    _thread_id: u32,
    _context_flags: u32,
    _context_size: u32,
    _context: *mut u8,
) -> HRESULT {
    E_NOTIMPL
}

unsafe extern "system" fn clr_set_thread_context(
    _this: *mut ICLRDataTargetImpl,
    _thread_id: u32,
    _context_size: u32,
    _context: *mut u8,
) -> HRESULT {
    E_NOTIMPL
}

unsafe extern "system" fn clr_request(
    _this: *mut ICLRDataTargetImpl,
    _req_code: u32,
    _in_buffer_size: u32,
    _in_buffer: *mut u8,
    _out_buffer_size: u32,
    _out_buffer: *mut u8,
) -> HRESULT {
    E_NOTIMPL
}
