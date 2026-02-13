//! DAC (Data Access Component) for .NET assembly enumeration and dumping.
//!
//! This module provides functionality to enumerate and dump .NET assemblies from
//! external processes using the DAC (Data Access Component) interfaces.

#![allow(non_snake_case)]
#![allow(unused_unsafe)]

use std::collections::HashMap;
use std::ffi::c_void;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use windows::Win32::Foundation::{CloseHandle, E_FAIL, E_NOINTERFACE, E_NOTIMPL, HANDLE, S_OK};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::System::ProcessStatus::{
    EnumProcessModulesEx, GetModuleBaseNameW, GetModuleFileNameExW, LIST_MODULES_ALL,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use windows::core::{GUID, HRESULT, Interface, PCWSTR};

use crate::{AssemblyInfo, Error, Result};

// Re-export DAC interfaces and types from mscoree
pub use mscoree::{
    CLRDATA_ADDRESS, DacpAppDomainData, DacpAppDomainStoreData, DacpAssemblyData, DacpModuleData,
    ISOSDacInterface, IXCLRDataProcess,
};

/// Type alias for compatibility
pub type ClrDataAddress = CLRDATA_ADDRESS;

// Machine type constant for current architecture
#[cfg(target_arch = "x86_64")]
const IMAGE_FILE_MACHINE_CURRENT: u16 = 0x8664; // AMD64
#[cfg(target_arch = "x86")]
const IMAGE_FILE_MACHINE_CURRENT: u16 = 0x014c; // I386
#[cfg(target_arch = "aarch64")]
const IMAGE_FILE_MACHINE_CURRENT: u16 = 0xAA64; // ARM64

// GUID for ICLRDataTarget interface
const IID_ICLR_DATA_TARGET: GUID = GUID::from_u128(0x3E11CCEE_D08B_43e5_AF01_32717A64DA03);

/// CLRDataCreateInstance function type (exported by DAC DLLs)
type CLRDataCreateInstanceFn = unsafe extern "system" fn(
    riid: *const GUID,
    data_target: *mut c_void,
    ppv_object: *mut *mut c_void,
) -> HRESULT;

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
struct ICLRDataTargetImpl {
    vtbl: *const ICLRDataTargetVtbl,
}

// =============================================================================
// CLRDataTarget - unified ICLRDataTarget using ReadProcessMemory
// =============================================================================

/// ICLRDataTarget implementation using ReadProcessMemory.
/// Works for both internal (GetCurrentProcess) and external (OpenProcess) scenarios.
#[repr(C)]
pub struct CLRDataTarget {
    vtbl: *const ICLRDataTargetVtbl,
    ref_count: AtomicU32,
    process_handle: HANDLE,
    owns_handle: bool,
    /// Map of module name (lowercase) -> base address
    module_bases: HashMap<String, u64>,
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
    fn new_external(pid: u32) -> Result<*mut ICLRDataTargetImpl> {
        let handle =
            unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }
                .map_err(|e| Error::Other(format!("Failed to open process: {}", e)))?;

        let module_bases = enumerate_module_bases(handle)?;

        let target = Box::new(CLRDataTarget {
            vtbl: &CLR_DATA_TARGET_VTBL,
            ref_count: AtomicU32::new(1),
            process_handle: handle,
            owns_handle: true,
            module_bases,
        });

        Ok(Box::into_raw(target) as *mut ICLRDataTargetImpl)
    }
}

/// Enumerate all modules in a process and return a map of name -> base address
fn enumerate_module_bases(handle: HANDLE) -> Result<HashMap<String, u64>> {
    let mut modules = [windows::Win32::Foundation::HMODULE::default(); 1024];
    let mut needed = 0u32;

    unsafe {
        EnumProcessModulesEx(
            handle,
            modules.as_mut_ptr(),
            std::mem::size_of_val(&modules) as u32,
            &mut needed,
            LIST_MODULES_ALL,
        )
    }
    .map_err(|e| Error::Other(format!("EnumProcessModulesEx failed: {}", e)))?;

    let count = needed as usize / std::mem::size_of::<windows::Win32::Foundation::HMODULE>();
    let mut map = HashMap::new();

    for i in 0..count {
        let module = modules[i];
        let mut name_buf = [0u16; 260];
        let len = unsafe { GetModuleBaseNameW(handle, Some(module), &mut name_buf) };
        if len > 0 {
            let name = String::from_utf16_lossy(&name_buf[..len as usize]).to_lowercase();
            map.insert(name, module.0 as u64);
        }
    }

    Ok(map)
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
    _this: *mut ICLRDataTargetImpl,
    machine_type: *mut u32,
) -> HRESULT {
    if machine_type.is_null() {
        return E_FAIL;
    }

    unsafe { *machine_type = IMAGE_FILE_MACHINE_CURRENT as u32 };
    S_OK
}

unsafe extern "system" fn clr_get_pointer_size(
    _this: *mut ICLRDataTargetImpl,
    pointer_size: *mut u32,
) -> HRESULT {
    if pointer_size.is_null() {
        return E_FAIL;
    }

    unsafe { *pointer_size = std::mem::size_of::<*const c_void>() as u32 };
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

    // Convert the image path to a string and extract the filename
    let path_len = unsafe {
        let mut len = 0;
        while *image_path.add(len) != 0 {
            len += 1;
        }
        len
    };
    let path_slice = unsafe { std::slice::from_raw_parts(image_path, path_len) };
    let path_str = String::from_utf16_lossy(path_slice);

    // Extract just the filename and lowercase it
    let filename = std::path::Path::new(&path_str)
        .file_name()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_else(|| path_str.to_lowercase());

    // Look up in our module map
    if let Some(&base) = target.module_bases.get(&filename) {
        unsafe { *base_address = base };
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

// =============================================================================
// Runtime directory detection
// =============================================================================

/// Type of .NET runtime detected
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeType {
    /// .NET Core / .NET 5+ (coreclr.dll, mscordaccore.dll)
    Core,
    /// .NET Framework 4.x (clr.dll, mscordacwks.dll)
    Framework,
    /// .NET Framework 2.0/3.5 (mscorwks.dll, mscordacwks.dll)
    FrameworkLegacy,
}

impl RuntimeType {
    /// Get the DAC DLL name for this runtime type
    pub fn dac_dll_name(&self) -> &'static str {
        match self {
            RuntimeType::Core => "mscordaccore.dll",
            RuntimeType::Framework | RuntimeType::FrameworkLegacy => "mscordacwks.dll",
        }
    }
}

/// Information about a detected .NET runtime
#[derive(Debug, Clone)]
pub struct RuntimeInfo {
    /// Directory containing the runtime DLLs
    pub directory: PathBuf,
    /// Type of runtime (Core, Framework, etc.)
    pub runtime_type: RuntimeType,
}

impl RuntimeInfo {
    /// Get the full path to the DAC DLL
    pub fn dac_path(&self) -> PathBuf {
        self.directory.join(self.runtime_type.dac_dll_name())
    }
}

/// Find the .NET runtime directory for a process by locating the CLR DLL.
/// Supports both .NET Core (coreclr.dll) and .NET Framework (clr.dll, mscorwks.dll).
pub fn find_runtime_directory(handle: HANDLE) -> Result<Option<RuntimeInfo>> {
    let mut modules = [windows::Win32::Foundation::HMODULE::default(); 1024];
    let mut needed = 0u32;

    let result = unsafe {
        EnumProcessModulesEx(
            handle,
            modules.as_mut_ptr(),
            std::mem::size_of_val(&modules) as u32,
            &mut needed,
            LIST_MODULES_ALL,
        )
    };

    if result.is_err() {
        return Err(Error::Other("EnumProcessModulesEx failed".into()));
    }

    let count = needed as usize / std::mem::size_of::<windows::Win32::Foundation::HMODULE>();

    // CLR DLLs to look for, in order of preference
    let clr_dlls = [
        ("coreclr.dll", RuntimeType::Core),
        ("clr.dll", RuntimeType::Framework),
        ("mscorwks.dll", RuntimeType::FrameworkLegacy),
    ];

    for i in 0..count {
        let module = modules[i];
        let mut name_buf = [0u16; 260];
        let len = unsafe { GetModuleBaseNameW(handle, Some(module), &mut name_buf) };
        if len > 0 {
            let name = String::from_utf16_lossy(&name_buf[..len as usize]);

            for (clr_dll, runtime_type) in &clr_dlls {
                if name.eq_ignore_ascii_case(clr_dll) {
                    // Get the full path using GetModuleFileNameExW
                    let mut path_buf = [0u16; 512];
                    let path_len =
                        unsafe { GetModuleFileNameExW(Some(handle), Some(module), &mut path_buf) };
                    if path_len > 0 {
                        let full_path = String::from_utf16_lossy(&path_buf[..path_len as usize]);
                        let path = PathBuf::from(&full_path);
                        if let Some(parent) = path.parent() {
                            return Ok(Some(RuntimeInfo {
                                directory: parent.to_path_buf(),
                                runtime_type: *runtime_type,
                            }));
                        }
                    }
                }
            }
        }
    }

    Ok(None)
}

/// Find runtime directory by PID (opens and closes handle internally)
pub fn find_runtime_directory_by_pid(pid: u32) -> Result<Option<RuntimeInfo>> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }
        .map_err(|e| Error::Other(format!("Failed to open process: {}", e)))?;

    let result = find_runtime_directory(handle);
    unsafe { CloseHandle(handle).ok() };
    result
}

// =============================================================================
// DAC Enumeration
// =============================================================================

/// Enumerate assemblies from an external process using DAC
pub fn enumerate_assemblies_external(pid: u32) -> Result<Vec<AssemblyInfo>> {
    // Find the runtime directory
    let runtime_info = find_runtime_directory_by_pid(pid)?
        .ok_or_else(|| Error::Other("Could not find .NET runtime in target process".into()))?;

    // Load the appropriate DAC DLL
    let dac_path = runtime_info.dac_path();
    let dac_dll_name = runtime_info.runtime_type.dac_dll_name();

    if !dac_path.exists() {
        return Err(Error::Other(format!(
            "{} not found at {}",
            dac_dll_name,
            dac_path.display()
        )));
    }

    let dac_path_wide: Vec<u16> = dac_path
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let dac_module = unsafe { LoadLibraryW(PCWSTR::from_raw(dac_path_wide.as_ptr())) }
        .map_err(|e| Error::Other(format!("Failed to load {}: {}", dac_dll_name, e)))?;

    // Get CLRDataCreateInstance
    let create_instance: CLRDataCreateInstanceFn = unsafe {
        let proc = GetProcAddress(dac_module, windows::core::s!("CLRDataCreateInstance"));
        match proc {
            Some(p) => std::mem::transmute(p),
            None => return Err(Error::Other("CLRDataCreateInstance not found".into())),
        }
    };

    // Create our external data target
    let data_target = CLRDataTarget::new_external(pid)?;

    // Create IXCLRDataProcess and enumerate
    enumerate_with_dac(create_instance, data_target)
}

/// Common enumeration logic using DAC
#[inline(never)]
fn enumerate_with_dac(
    create_instance: CLRDataCreateInstanceFn,
    data_target: *mut ICLRDataTargetImpl,
) -> Result<Vec<AssemblyInfo>> {
    // Create IXCLRDataProcess
    let mut xclr_process: *mut c_void = std::ptr::null_mut();
    let hr = unsafe {
        create_instance(
            &IXCLRDataProcess::IID,
            data_target as *mut c_void,
            &mut xclr_process,
        )
    };

    if hr.is_err() || xclr_process.is_null() {
        return Err(Error::Other(format!(
            "CLRDataCreateInstance failed: 0x{:08X}",
            hr.0
        )));
    }

    // Convert raw pointer to proper COM interface using windows crate's Interface::from_raw
    // SAFETY: We just got this from CLRDataCreateInstance which returns a valid COM object
    let xclr: IXCLRDataProcess = unsafe { Interface::from_raw(xclr_process) };

    // Query for ISOSDacInterface using windows crate's Interface::cast()
    let sos: ISOSDacInterface = match xclr.cast() {
        Ok(s) => s,
        Err(e) => {
            return Err(Error::Other(format!(
                "QueryInterface for ISOSDacInterface failed: {}",
                e
            )));
        }
    };

    // Enumerate assemblies
    let assemblies = unsafe { enumerate_via_dac(&sos) };

    // Interfaces are released automatically when dropped (windows crate handles ref counting)
    assemblies
}

/// Enumerate assemblies using ISOSDacInterface
/// With proper COM interfaces from windows crate, LLVM understands these are external calls
#[inline(never)]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn enumerate_via_dac(sos_dac: &ISOSDacInterface) -> Result<Vec<AssemblyInfo>> {
    let mut assemblies = Vec::new();

    // Get AppDomain store data
    let mut store_data = DacpAppDomainStoreData::default();
    let hr = sos_dac.GetAppDomainStoreData(&mut store_data);

    if hr.is_err() {
        return Err(Error::Other(format!(
            "GetAppDomainStoreData failed: 0x{:08X}",
            hr.0
        )));
    }

    let domain_count = store_data.DomainCount as u32;

    // Sanity check
    if domain_count > 1000 {
        return Err(Error::Other(format!(
            "Suspicious domain count: {} - likely data corruption",
            domain_count
        )));
    }

    let mut domain_addresses: Vec<ClrDataAddress> = vec![0; domain_count as usize];
    let mut actual_domain_count = 0u32;
    let hr = sos_dac.GetAppDomainList(
        domain_count,
        domain_addresses.as_mut_ptr(),
        &mut actual_domain_count,
    );

    let domains_to_use = if hr.is_err() {
        // Try system domain as fallback
        if store_data.systemDomain != 0 {
            domain_addresses = vec![store_data.systemDomain];
            1
        } else {
            return Err(Error::Other("No app domains found".into()));
        }
    } else {
        (actual_domain_count as usize).min(domain_addresses.len())
    };

    // Enumerate each app domain
    for i in 0..domains_to_use {
        let domain_addr = domain_addresses[i];

        if domain_addr == 0 {
            continue;
        }

        // Get app domain data
        let mut domain_data = DacpAppDomainData::default();
        let hr = sos_dac.GetAppDomainData(domain_addr, &mut domain_data);

        let asm_count_val = domain_data.AssemblyCount;
        if hr.is_err() || asm_count_val <= 0 {
            continue;
        }

        // Sanity check
        if asm_count_val > 10000 {
            continue;
        }

        let mut asm_addresses: Vec<ClrDataAddress> = vec![0; asm_count_val as usize];
        let mut actual_count = 0i32;
        let hr = sos_dac.GetAssemblyList(
            domain_addr,
            asm_count_val,
            asm_addresses.as_mut_ptr(),
            &mut actual_count,
        );

        if hr.is_err() {
            continue;
        }

        // Use the smaller of actual_count and our buffer size
        let count_to_use = (actual_count as usize).min(asm_addresses.len());

        // Enumerate each assembly
        for j in 0..count_to_use {
            let asm_addr = asm_addresses[j];

            if asm_addr == 0 {
                continue;
            }

            if let Some(info) = get_assembly_info(sos_dac, domain_addr, asm_addr) {
                assemblies.push(info);
            }
        }
    }

    Ok(assemblies)
}

/// Get assembly info from DAC
#[inline(never)]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn get_assembly_info(
    sos_dac: &ISOSDacInterface,
    domain_addr: ClrDataAddress,
    asm_addr: ClrDataAddress,
) -> Option<AssemblyInfo> {
    // Get assembly data
    let mut asm_data = DacpAssemblyData::default();
    let hr = sos_dac.GetAssemblyData(domain_addr, asm_addr, &mut asm_data);

    if hr.is_err() {
        return None;
    }

    // Get assembly name - use heap allocation to prevent optimizer issues
    let mut name_buf: Box<[u16; 1024]> = Box::new([0u16; 1024]);
    let mut name_len: u32 = 0;

    // Get raw pointer and pass through black_box to hide it from optimizer
    let name_ptr = std::hint::black_box(name_buf.as_mut_ptr());
    let len_ptr = std::hint::black_box(&mut name_len as *mut u32);

    let hr = sos_dac.GetAssemblyName(asm_addr, 1024, name_ptr, len_ptr);

    // Force compiler to re-read the values after the COM call
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);

    // Read name_len through volatile to prevent optimizer caching
    let actual_len = std::ptr::read_volatile(&name_len);

    let path = if hr.is_ok() && actual_len > 0 {
        let len = (actual_len as usize).saturating_sub(1).min(1024);
        // Read the string data through volatile
        let mut str_data = Vec::with_capacity(len);
        for i in 0..len {
            str_data.push(std::ptr::read_volatile(&name_buf[i]));
        }
        Some(String::from_utf16_lossy(&str_data))
    } else {
        None
    };

    // Extract filename from path
    let name = path
        .as_ref()
        .and_then(|p| std::path::Path::new(p).file_name())
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| format!("Assembly_0x{:X}", asm_addr));

    // Get module data for base address
    let mut base_address = 0u64;
    let mut size = 0u32;

    let module_count = asm_data.ModuleCount;
    if module_count > 0 && module_count < 1000 {
        let mut module_addrs: Vec<ClrDataAddress> = vec![0; module_count as usize];
        let mut actual_module_count = 0u32;
        let hr = sos_dac.GetAssemblyModuleList(
            asm_addr,
            module_count,
            module_addrs.as_mut_ptr(),
            &mut actual_module_count,
        );

        if hr.is_ok() && actual_module_count > 0 {
            let module_addr = module_addrs[0];
            let mut module_data = DacpModuleData::default();
            let hr = sos_dac.GetModuleData(module_addr, &mut module_data);
            if hr.is_ok() {
                base_address = module_data.ilBase;
                size = module_data.metadataSize as u32;
            }
        }
    }

    let mut info = AssemblyInfo::new(name, base_address as usize, size as usize);
    info.path = path;

    Some(info)
}

// =============================================================================
// Assembly Dumping
// =============================================================================

/// Result of dumping an assembly
#[derive(Debug)]
pub struct DumpResult {
    /// Assembly name
    pub name: String,
    /// Path where the assembly was saved
    pub output_path: PathBuf,
    /// Number of bytes dumped
    pub size: usize,
    /// Whether the dump was successful
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
}

/// Section header information for PE reconstruction
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct SectionInfo {
    /// Virtual address (RVA) of the section
    virtual_address: u32,
    /// Size of the section in memory
    virtual_size: u32,
    /// File offset of the section
    pointer_to_raw_data: u32,
    /// Size of the section on disk
    size_of_raw_data: u32,
}

/// PE header information needed for dumping
#[derive(Debug)]
#[allow(dead_code)]
struct PeInfo {
    /// Offset to PE signature (e_lfanew)
    e_lfanew: u32,
    /// Size of the image in memory
    size_of_image: u32,
    /// Size of headers on disk
    size_of_headers: u32,
    /// Number of sections
    number_of_sections: u16,
    /// Size of optional header
    size_of_optional_header: u16,
    /// Section information
    sections: Vec<SectionInfo>,
    /// Whether this is PE32+ (64-bit)
    is_pe32_plus: bool,
}

/// Read PE header information from a process
fn read_pe_info(process_handle: HANDLE, base_address: usize) -> Option<PeInfo> {
    // DOS Header: we need e_lfanew at offset 0x3C (4 bytes)
    let mut dos_header = [0u8; 64];
    let mut bytes_read = 0usize;

    let result = unsafe {
        ReadProcessMemory(
            process_handle,
            base_address as *const c_void,
            dos_header.as_mut_ptr() as *mut c_void,
            dos_header.len(),
            Some(&mut bytes_read),
        )
    };

    if result.is_err() || bytes_read < 64 {
        return None;
    }

    // Check DOS magic "MZ"
    if dos_header[0] != 0x4D || dos_header[1] != 0x5A {
        return None;
    }

    let e_lfanew = u32::from_le_bytes([
        dos_header[0x3C],
        dos_header[0x3D],
        dos_header[0x3E],
        dos_header[0x3F],
    ]);

    if e_lfanew < 64 || e_lfanew > 1024 {
        return None;
    }

    // Read PE header + COFF header + full optional header
    // We need enough to get section count and all optional header fields
    let pe_header_offset = base_address + e_lfanew as usize;
    let mut pe_header = [0u8; 264]; // PE sig (4) + COFF (20) + OptionalHeader (up to 240)

    let result = unsafe {
        ReadProcessMemory(
            process_handle,
            pe_header_offset as *const c_void,
            pe_header.as_mut_ptr() as *mut c_void,
            pe_header.len(),
            Some(&mut bytes_read),
        )
    };

    if result.is_err() || bytes_read < 264 {
        return None;
    }

    // Check PE signature
    if pe_header[0] != 0x50 || pe_header[1] != 0x45 || pe_header[2] != 0 || pe_header[3] != 0 {
        return None;
    }

    // COFF header starts at offset 4
    // NumberOfSections at COFF+2
    let number_of_sections = u16::from_le_bytes([pe_header[6], pe_header[7]]);
    // SizeOfOptionalHeader at COFF+16
    let size_of_optional_header = u16::from_le_bytes([pe_header[20], pe_header[21]]);

    // Optional header starts at offset 24
    let optional_magic = u16::from_le_bytes([pe_header[24], pe_header[25]]);
    let is_pe32_plus = optional_magic == 0x20b;

    // SizeOfHeaders offset: OptionalHeader + 60 (PE32) or OptionalHeader + 60 (PE32+)
    // SizeOfImage offset: OptionalHeader + 56
    let size_of_image =
        u32::from_le_bytes([pe_header[80], pe_header[81], pe_header[82], pe_header[83]]);
    let size_of_headers =
        u32::from_le_bytes([pe_header[84], pe_header[85], pe_header[86], pe_header[87]]);

    // Sanity checks
    if size_of_image < 0x1000 || size_of_image > 0x40000000 {
        return None;
    }
    if number_of_sections > 96 {
        return None;
    }

    // Read section headers
    // Section table starts immediately after optional header
    let section_table_offset = pe_header_offset + 24 + size_of_optional_header as usize;
    let section_table_size = number_of_sections as usize * 40; // Each section header is 40 bytes
    let mut section_data = vec![0u8; section_table_size];

    let result = unsafe {
        ReadProcessMemory(
            process_handle,
            section_table_offset as *const c_void,
            section_data.as_mut_ptr() as *mut c_void,
            section_table_size,
            Some(&mut bytes_read),
        )
    };

    if result.is_err() || bytes_read < section_table_size {
        return None;
    }

    let mut sections = Vec::with_capacity(number_of_sections as usize);
    for i in 0..number_of_sections as usize {
        let offset = i * 40;
        // VirtualSize at section+8
        let virtual_size = u32::from_le_bytes([
            section_data[offset + 8],
            section_data[offset + 9],
            section_data[offset + 10],
            section_data[offset + 11],
        ]);
        // VirtualAddress at section+12
        let virtual_address = u32::from_le_bytes([
            section_data[offset + 12],
            section_data[offset + 13],
            section_data[offset + 14],
            section_data[offset + 15],
        ]);
        // SizeOfRawData at section+16
        let size_of_raw_data = u32::from_le_bytes([
            section_data[offset + 16],
            section_data[offset + 17],
            section_data[offset + 18],
            section_data[offset + 19],
        ]);
        // PointerToRawData at section+20
        let pointer_to_raw_data = u32::from_le_bytes([
            section_data[offset + 20],
            section_data[offset + 21],
            section_data[offset + 22],
            section_data[offset + 23],
        ]);

        sections.push(SectionInfo {
            virtual_address,
            virtual_size,
            pointer_to_raw_data,
            size_of_raw_data,
        });
    }

    Some(PeInfo {
        e_lfanew,
        size_of_image,
        size_of_headers,
        number_of_sections,
        size_of_optional_header,
        sections,
        is_pe32_plus,
    })
}

/// Convert a PE image from memory layout (RVA-based) to file layout (file offset-based)
/// This "unrolls" sections from their virtual addresses to their file offsets
fn convert_memory_to_file_layout(memory_image: &[u8], pe_info: &PeInfo) -> Vec<u8> {
    // Calculate the file size: find the maximum (PointerToRawData + SizeOfRawData)
    let mut file_size = pe_info.size_of_headers as usize;
    for section in &pe_info.sections {
        let section_end = section.pointer_to_raw_data as usize + section.size_of_raw_data as usize;
        if section_end > file_size {
            file_size = section_end;
        }
    }

    // Create output buffer
    let mut file_image = vec![0u8; file_size];

    // Copy headers (up to SizeOfHeaders, which is already at file offsets = RVAs for headers)
    let headers_size = (pe_info.size_of_headers as usize).min(memory_image.len());
    file_image[..headers_size].copy_from_slice(&memory_image[..headers_size]);

    // Copy each section from its virtual address to its file offset
    for section in &pe_info.sections {
        let src_offset = section.virtual_address as usize;
        let dst_offset = section.pointer_to_raw_data as usize;

        // Use the smaller of virtual_size and size_of_raw_data to copy
        let copy_size = (section.size_of_raw_data as usize)
            .min(section.virtual_size as usize)
            .min(memory_image.len().saturating_sub(src_offset))
            .min(file_image.len().saturating_sub(dst_offset));

        if copy_size > 0 && src_offset < memory_image.len() && dst_offset < file_image.len() {
            file_image[dst_offset..dst_offset + copy_size]
                .copy_from_slice(&memory_image[src_offset..src_offset + copy_size]);
        }
    }

    file_image
}

/// Dump a single assembly from a process to a file
/// Converts from memory layout (RVA-based) to file layout (file offset-based)
pub fn dump_assembly(
    process_handle: HANDLE,
    assembly: &AssemblyInfo,
    output_dir: &std::path::Path,
) -> DumpResult {
    let safe_name = sanitize_filename(&assembly.name);
    let output_path = output_dir.join(format!("{}.dll", safe_name));

    // Check if we have valid base address
    if assembly.base_address == 0 {
        return DumpResult {
            name: assembly.name.clone(),
            output_path,
            size: 0,
            success: false,
            error: Some("Assembly has no base address (dynamic assembly?)".into()),
        };
    }

    // Read PE info to get section layout and image size
    let pe_info = match read_pe_info(process_handle, assembly.base_address) {
        Some(info) => info,
        None => {
            return DumpResult {
                name: assembly.name.clone(),
                output_path,
                size: 0,
                success: false,
                error: Some("Could not parse PE header".into()),
            };
        }
    };

    let image_size = pe_info.size_of_image as usize;

    // Read the assembly bytes from the target process (memory layout)
    // We read page-by-page because the image may have gaps (guard pages, PAGE_NOACCESS regions)
    // between sections that would cause a single large ReadProcessMemory to fail
    let mut buffer = vec![0u8; image_size];
    const PAGE_SIZE: usize = 0x1000;

    for offset in (0..image_size).step_by(PAGE_SIZE) {
        let chunk_size = PAGE_SIZE.min(image_size - offset);
        let mut bytes_read = 0usize;

        let _ = unsafe {
            ReadProcessMemory(
                process_handle,
                (assembly.base_address + offset) as *const c_void,
                buffer[offset..].as_mut_ptr() as *mut c_void,
                chunk_size,
                Some(&mut bytes_read),
            )
        };
        // Ignore errors - pages that fail to read will remain zeroed
        // This handles guard pages, uncommitted memory, etc.
    }

    // Convert from memory layout to file layout
    // This "unrolls" sections from their virtual addresses to their file offsets
    let file_image = convert_memory_to_file_layout(&buffer, &pe_info);

    // Write to file
    match std::fs::write(&output_path, &file_image) {
        Ok(()) => DumpResult {
            name: assembly.name.clone(),
            output_path,
            size: file_image.len(),
            success: true,
            error: None,
        },
        Err(e) => DumpResult {
            name: assembly.name.clone(),
            output_path,
            size: file_image.len(),
            success: false,
            error: Some(format!("Failed to write file: {}", e)),
        },
    }
}

/// Dump all assemblies from a process
pub fn dump_assemblies_external(pid: u32, output_dir: &std::path::Path) -> Result<Vec<DumpResult>> {
    // Create output directory if it doesn't exist
    std::fs::create_dir_all(output_dir)
        .map_err(|e| Error::Other(format!("Failed to create output directory: {}", e)))?;

    // Enumerate assemblies first
    let assemblies = enumerate_assemblies_external(pid)?;

    // Open process for reading
    let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }
        .map_err(|e| Error::Other(format!("Failed to open process: {}", e)))?;

    // Dump each assembly
    let mut results = Vec::with_capacity(assemblies.len());
    for assembly in &assemblies {
        let result = dump_assembly(handle, assembly, output_dir);
        results.push(result);
    }

    // Close handle
    unsafe { CloseHandle(handle).ok() };

    Ok(results)
}

/// Sanitize a filename by removing invalid characters
fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enumerate_own_process() {
        // Get our own PID
        let pid = std::process::id();
        println!("Testing external DAC on our own process (PID {})", pid);

        // This should work - enumerate our own process externally
        let result = enumerate_assemblies_external(pid);

        // We're not a .NET process, so this should fail gracefully
        match result {
            Ok(assemblies) => {
                println!(
                    "Found {} assemblies (unexpected for non-.NET process)",
                    assemblies.len()
                );
                for asm in &assemblies {
                    println!("  - {}", asm.name);
                }
            }
            Err(e) => {
                println!("Expected error for non-.NET process: {}", e);
                // This is expected - we're not a .NET process
            }
        }
    }

    #[test]
    fn test_enumerate_module_bases() {
        use windows::Win32::System::Threading::GetCurrentProcess;

        let handle = unsafe { GetCurrentProcess() };
        println!("Testing enumerate_module_bases with GetCurrentProcess()");

        let result = enumerate_module_bases(handle);
        match result {
            Ok(bases) => {
                println!("Found {} modules:", bases.len());
                for (name, addr) in &bases {
                    println!("  {} @ 0x{:X}", name, addr);
                }
                assert!(!bases.is_empty(), "Should find at least one module");
            }
            Err(e) => {
                panic!("enumerate_module_bases failed: {}", e);
            }
        }
    }
}
