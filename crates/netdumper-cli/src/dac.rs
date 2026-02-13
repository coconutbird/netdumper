//! DAC (Data Access Component) for .NET assembly enumeration and dumping.
//!
//! This module provides functionality to enumerate and dump .NET assemblies from
//! external processes using the DAC (Data Access Component) interfaces.

#![allow(non_snake_case)]
#![allow(unused_unsafe)]

use std::collections::HashMap;
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use windows::Win32::Foundation::{CloseHandle, E_FAIL, E_NOINTERFACE, E_NOTIMPL, HANDLE, S_OK};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, VirtualQueryEx,
};
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
const IID_ICLR_DATA_TARGET: GUID = GUID::from_u128(0x3E11CCEE_D08B_43E5_AF01_32717A64DA03);

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
// Process Handle RAII Wrapper
// =============================================================================

/// RAII wrapper for Windows process handles.
/// Automatically closes the handle when dropped.
struct ProcessHandle(HANDLE);

impl ProcessHandle {
    /// Open a process with query and read permissions.
    fn open(pid: u32) -> Result<Self> {
        let handle =
            unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }
                .map_err(|e| Error::Other(format!("Failed to open process {}: {}", pid, e)))?;
        Ok(Self(handle))
    }

    /// Get the raw handle for Windows API calls.
    fn as_raw(&self) -> HANDLE {
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
    handle: ProcessHandle,
    /// Map of module name (lowercase) -> base address
    module_bases: HashMap<String, u64>,
    /// Main executable base address
    exe_base_address: u64,
    /// Path to the main executable (currently unused, reserved for future use)
    #[allow(dead_code)]
    exe_path: Option<PathBuf>,
    /// Whether this process has an embedded CLR (single-file deployment)
    is_embedded_clr: bool,
    /// Cached embedded CLR info (if applicable)
    embedded_clr_info: Option<EmbeddedRuntimeInfo>,
}

impl ProcessInfo {
    /// Create a new ProcessInfo by inspecting the target process.
    pub fn new(pid: u32) -> Result<Self> {
        let handle = ProcessHandle::open(pid)?;

        // Enumerate all modules
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

        // Build module map
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

        // Get main EXE base address and path
        let exe_base_address = if count > 0 { modules[0].0 as u64 } else { 0 };

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

        // Check if this is an embedded CLR process
        let has_coreclr_module = module_bases.contains_key("coreclr.dll");
        let has_clr_exports = exe_path.as_ref().is_some_and(exe_has_clr_exports);
        let is_embedded_clr = !has_coreclr_module && has_clr_exports;

        // Get embedded CLR info if applicable
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
            is_embedded_clr,
            embedded_clr_info,
        })
    }
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
    /// Main executable base address (for single-file apps with embedded CLR)
    exe_base_address: u64,
    /// Whether this is an embedded CLR process (single-file deployment)
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
    fn new_external(pid: u32) -> Result<*mut ICLRDataTargetImpl> {
        let info = ProcessInfo::new(pid)?;
        Self::from_process_info(info)
    }

    /// Create a new CLRDataTarget from an existing ProcessInfo.
    /// Note: This takes ownership of the ProcessInfo's handle.
    fn from_process_info(info: ProcessInfo) -> Result<*mut ICLRDataTargetImpl> {
        // Extract the raw handle before ProcessInfo is consumed
        // We need to prevent ProcessInfo from closing the handle
        let handle = info.handle.0;
        let module_bases = info.module_bases;
        let exe_base_address = info.exe_base_address;
        let is_embedded_clr = info.is_embedded_clr;

        // Prevent ProcessInfo's Drop from closing the handle
        std::mem::forget(info.handle);

        let target = Box::new(CLRDataTarget {
            vtbl: &CLR_DATA_TARGET_VTBL,
            ref_count: AtomicU32::new(1),
            process_handle: handle,
            owns_handle: true,
            module_bases,
            exe_base_address,
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

    // For embedded CLR (single-file deployment), the CLR is embedded in the EXE
    // When DAC asks for coreclr.dll but it's not a separate module, return the EXE base
    if target.is_embedded_clr && target.exe_base_address != 0 {
        if filename == "coreclr.dll" || filename == "clr.dll" {
            unsafe { *base_address = target.exe_base_address };
            return S_OK;
        }
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
/// Also handles single-file deployments where runtime is embedded in the executable.
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

    let mut main_exe_path: Option<PathBuf> = None;

    // First pass: look for CLR DLLs by name
    for i in 0..count {
        let module = modules[i];
        let mut name_buf = [0u16; 260];
        let len = unsafe { GetModuleBaseNameW(handle, Some(module), &mut name_buf) };
        if len > 0 {
            let name = String::from_utf16_lossy(&name_buf[..len as usize]);

            // Capture main executable path (first module)
            if i == 0 {
                let mut path_buf = [0u16; 512];
                let path_len =
                    unsafe { GetModuleFileNameExW(Some(handle), Some(module), &mut path_buf) };
                if path_len > 0 {
                    let full_path = String::from_utf16_lossy(&path_buf[..path_len as usize]);
                    main_exe_path = Some(PathBuf::from(full_path));
                }
            }

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

    // Second pass: look for modules loaded from .NET temp extraction paths
    // Single-file apps extract to %TEMP%\.net\<appname>\<hash>\
    for i in 0..count {
        let module = modules[i];
        let mut path_buf = [0u16; 512];
        let path_len = unsafe { GetModuleFileNameExW(Some(handle), Some(module), &mut path_buf) };
        if path_len > 0 {
            let full_path = String::from_utf16_lossy(&path_buf[..path_len as usize]);
            let path_lower = full_path.to_lowercase();

            // Check for single-file extraction path pattern
            if path_lower.contains("\\.net\\") || path_lower.contains("/.net/") {
                let path = PathBuf::from(&full_path);
                // Look for coreclr.dll in this directory
                if let Some(parent) = path.parent() {
                    let coreclr_path = parent.join("coreclr.dll");
                    if coreclr_path.exists() {
                        return Ok(Some(RuntimeInfo {
                            directory: parent.to_path_buf(),
                            runtime_type: RuntimeType::Core,
                        }));
                    }
                }
            }
        }
    }

    // Third pass: check if main executable has embedded CLR (single-file with native AOT host)
    // These apps export CLR symbols like g_dacTable, DotNetRuntimeInfo, etc.
    if let Some(exe_path) = main_exe_path {
        if exe_has_clr_exports(&exe_path) {
            // Try to read the embedded CLR version and find a matching DAC
            if let Some(embedded_info) = get_embedded_clr_version_with_handle(handle) {
                // Find a matching DAC based on the embedded version
                if let Some(dac_path) = find_best_matching_dac(
                    embedded_info.major(),
                    embedded_info.minor(),
                    embedded_info.build(),
                ) {
                    if let Some(runtime_dir) = dac_path.parent() {
                        return Ok(Some(RuntimeInfo {
                            directory: runtime_dir.to_path_buf(),
                            runtime_type: RuntimeType::Core,
                        }));
                    }
                }
            }

            // Fallback: Find any compatible .NET runtime from system installation
            if let Some(runtime_dir) = find_system_dotnet_runtime() {
                return Ok(Some(RuntimeInfo {
                    directory: runtime_dir,
                    runtime_type: RuntimeType::Core,
                }));
            }
        }
    }

    Ok(None)
}

/// Check if an executable has CLR exports (indicating embedded CoreCLR)
fn exe_has_clr_exports(path: &PathBuf) -> bool {
    let Ok(data) = std::fs::read(path) else {
        return false;
    };

    // Quick check for CLR export names in the binary
    // These are exported by CoreCLR and would be present in a single-file app with embedded runtime
    let clr_export_signatures: &[&[u8]] = &[
        b"g_dacTable",
        b"DotNetRuntimeInfo",
        b"MetaDataGetDispenser",
        b"g_CLREngineMetrics",
    ];

    for sig in clr_export_signatures {
        if data.windows(sig.len()).any(|w| w == *sig) {
            return true;
        }
    }

    false
}

/// Find a .NET Core runtime installation on the system
fn find_system_dotnet_runtime() -> Option<PathBuf> {
    // Return the first (highest) version found
    let versions = find_all_system_dotnet_runtimes();
    versions.into_iter().next()
}

/// Find all .NET Core runtime installations on the system, sorted by version (highest first)
fn find_all_system_dotnet_runtimes() -> Vec<PathBuf> {
    // Common .NET installation paths
    let dotnet_paths = [
        r"C:\Program Files\dotnet\shared\Microsoft.NETCore.App",
        r"C:\Program Files (x86)\dotnet\shared\Microsoft.NETCore.App",
    ];

    let mut all_versions: Vec<PathBuf> = Vec::new();

    for base_path in &dotnet_paths {
        let base = PathBuf::from(base_path);
        if !base.exists() {
            continue;
        }

        let Ok(entries) = std::fs::read_dir(&base) else {
            continue;
        };

        let versions: Vec<PathBuf> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_dir() && p.join("mscordaccore.dll").exists())
            .collect();

        all_versions.extend(versions);
    }

    // Sort by version (highest first)
    all_versions.sort_by(|a, b| {
        let va = a.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let vb = b.file_name().and_then(|s| s.to_str()).unwrap_or("");
        // Reverse order for highest first
        compare_versions(vb, va)
    });

    all_versions
}

/// Compare version strings (e.g., "8.0.23" vs "9.0.12")
fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let parse_parts =
        |s: &str| -> Vec<u32> { s.split('.').filter_map(|p| p.parse::<u32>().ok()).collect() };

    let pa = parse_parts(a);
    let pb = parse_parts(b);

    for (a, b) in pa.iter().zip(pb.iter()) {
        match a.cmp(b) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }

    pa.len().cmp(&pb.len())
}

/// Find runtime directory by PID (opens and closes handle internally)
pub fn find_runtime_directory_by_pid(pid: u32) -> Result<Option<RuntimeInfo>> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }
        .map_err(|e| Error::Other(format!("Failed to open process: {}", e)))?;

    let result = find_runtime_directory(handle);
    unsafe { CloseHandle(handle).ok() };
    result
}

/// Diagnostic information about why .NET detection might have failed
#[derive(Debug)]
pub struct DiagnosticInfo {
    /// All loaded module names
    pub modules: Vec<String>,
    /// Modules that look like they might be .NET related
    pub potential_dotnet_modules: Vec<String>,
    /// Whether the main executable appears to be a .NET assembly (has CLR header)
    pub exe_has_clr_header: bool,
    /// Whether the main executable has embedded CLR exports (single-file app)
    pub has_embedded_clr: bool,
    /// Embedded CLR version if detected (major, minor, build, revision)
    pub embedded_clr_version: Option<(i32, i32, i32, i32)>,
    /// Suggested reason for detection failure
    pub failure_reason: String,
}

/// Get diagnostic information about a process to help debug .NET detection failures
pub fn diagnose_process(pid: u32) -> Result<DiagnosticInfo> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }
        .map_err(|e| Error::Other(format!("Failed to open process: {}", e)))?;

    let mut modules_arr = [windows::Win32::Foundation::HMODULE::default(); 1024];
    let mut needed = 0u32;

    let result = unsafe {
        EnumProcessModulesEx(
            handle,
            modules_arr.as_mut_ptr(),
            std::mem::size_of_val(&modules_arr) as u32,
            &mut needed,
            LIST_MODULES_ALL,
        )
    };

    if result.is_err() {
        unsafe { CloseHandle(handle).ok() };
        return Err(Error::Other("EnumProcessModulesEx failed".into()));
    }

    let count = needed as usize / std::mem::size_of::<windows::Win32::Foundation::HMODULE>();
    let mut modules = Vec::new();
    let mut potential_dotnet_modules = Vec::new();
    let mut exe_path: Option<PathBuf> = None;

    // .NET related patterns to look for
    let dotnet_patterns = [
        "coreclr",
        "clr.dll",
        "mscor",
        "clrjit",
        "hostfxr",
        "hostpolicy",
        "system.private",
        "microsoft.netcore",
        ".net\\",
        "/.net/",
    ];

    for i in 0..count {
        let module = modules_arr[i];
        let mut path_buf = [0u16; 512];
        let path_len = unsafe { GetModuleFileNameExW(Some(handle), Some(module), &mut path_buf) };

        if path_len > 0 {
            let full_path = String::from_utf16_lossy(&path_buf[..path_len as usize]);
            let path_lower = full_path.to_lowercase();

            // First module is typically the main executable
            if i == 0 {
                exe_path = Some(PathBuf::from(&full_path));
            }

            // Check if this looks like a .NET module
            for pattern in &dotnet_patterns {
                if path_lower.contains(pattern) {
                    potential_dotnet_modules.push(full_path.clone());
                    break;
                }
            }

            modules.push(full_path);
        }
    }

    unsafe { CloseHandle(handle).ok() };

    // Check if the main executable has a CLR header
    let exe_has_clr_header = exe_path
        .as_ref()
        .map(|p| check_pe_has_clr_header(p))
        .unwrap_or(false);

    // Check for embedded CLR (single-file deployment)
    let has_embedded_clr = exe_path
        .as_ref()
        .map(|p| exe_has_clr_exports(p))
        .unwrap_or(false);

    // Try to read embedded CLR version
    let embedded_clr_version = get_embedded_clr_version(pid)
        .map(|info| (info.major(), info.minor(), info.build(), info.revision()));

    // Determine failure reason
    let failure_reason = if !potential_dotnet_modules.is_empty() {
        "Found potential .NET modules but no CLR DLL. The runtime may not be fully initialized yet."
            .to_string()
    } else if has_embedded_clr {
        let version_str = embedded_clr_version
            .map(|(maj, min, build, rev)| format!("{}.{}.{}.{}", maj, min, build, rev))
            .unwrap_or_else(|| "unknown".to_string());
        format!(
            "This is a single-file .NET app with embedded CLR (version: {}).\n\
             Use a system-installed DAC with matching version to enumerate assemblies.\n\
             Try: netdumper enum --pid {}",
            version_str, pid
        )
    } else if exe_has_clr_header {
        "Executable has CLR header but no .NET runtime loaded. This could be:\n\
         - A NativeAOT compiled app (no CLR needed)\n\
         - The app hasn't started the CLR yet\n\
         - A single-file app that failed to extract"
            .to_string()
    } else {
        "No .NET indicators found. This may not be a .NET application.".to_string()
    };

    Ok(DiagnosticInfo {
        modules,
        potential_dotnet_modules,
        exe_has_clr_header,
        has_embedded_clr,
        embedded_clr_version,
        failure_reason,
    })
}

/// Check if a PE file has a CLR header (indicating it's a .NET assembly)
fn check_pe_has_clr_header(path: &PathBuf) -> bool {
    let Ok(data) = std::fs::read(path) else {
        return false;
    };

    if data.len() < 64 {
        return false;
    }

    // Check DOS signature
    if data[0] != 0x4D || data[1] != 0x5A {
        return false;
    }

    // Get e_lfanew
    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if e_lfanew + 4 > data.len() {
        return false;
    }

    // Check PE signature
    if data[e_lfanew] != 0x50 || data[e_lfanew + 1] != 0x45 {
        return false;
    }

    // Get optional header offset and check magic
    let opt_header_offset = e_lfanew + 24;
    if opt_header_offset + 2 > data.len() {
        return false;
    }

    let magic = u16::from_le_bytes([data[opt_header_offset], data[opt_header_offset + 1]]);

    // PE32 = 0x10B, PE32+ = 0x20B
    let clr_dir_offset = match magic {
        0x10B => opt_header_offset + 208, // PE32: offset to CLR directory entry
        0x20B => opt_header_offset + 224, // PE32+: offset to CLR directory entry
        _ => return false,
    };

    if clr_dir_offset + 8 > data.len() {
        return false;
    }

    // CLR directory RVA and size
    let clr_rva = u32::from_le_bytes([
        data[clr_dir_offset],
        data[clr_dir_offset + 1],
        data[clr_dir_offset + 2],
        data[clr_dir_offset + 3],
    ]);
    let clr_size = u32::from_le_bytes([
        data[clr_dir_offset + 4],
        data[clr_dir_offset + 5],
        data[clr_dir_offset + 6],
        data[clr_dir_offset + 7],
    ]);

    // If CLR directory has non-zero RVA and size, it's a .NET assembly
    clr_rva != 0 && clr_size != 0
}

// =============================================================================
// DAC Enumeration
// =============================================================================

/// Enumerate assemblies from an external process using DAC
pub fn enumerate_assemblies_external(pid: u32) -> Result<Vec<AssemblyInfo>> {
    // Create ProcessInfo once - this caches all process information
    let process_info = ProcessInfo::new(pid)?;

    // Check if this is an embedded CLR (single-file app)
    // In that case, we may need to try multiple DAC versions
    if process_info.is_embedded_clr {
        // Try multiple DAC versions, starting from highest
        return enumerate_with_multiple_dacs(process_info);
    }

    // Find the runtime directory for standard CLR
    let runtime_info = find_runtime_directory_by_pid(pid)?
        .ok_or_else(|| Error::Other("Could not find .NET runtime in target process".into()))?;

    // Standard case: use the DAC from the same directory as the CLR
    try_enumerate_with_dac_path(process_info, &runtime_info.dac_path())
}

/// RuntimeInfo structure from embedded CLR (matches dotnet/runtime runtimeinfo.h)
/// Layout:
///   Signature[18]: "DotNetRuntimeInfo\0"
///   Version: i32
///   RuntimeModuleIndex[24]: u8
///   DacModuleIndex[24]: u8
///   DbiModuleIndex[24]: u8
///   RuntimeVersion[4]: i32 (major, minor, build, revision)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct EmbeddedRuntimeInfo {
    signature: [u8; 18],
    version: i32,
    runtime_module_index: [u8; 24],
    dac_module_index: [u8; 24],
    dbi_module_index: [u8; 24],
    runtime_version: [i32; 4], // major, minor, build, revision
}

/// DAC module index information extracted from EmbeddedRuntimeInfo
/// Contains TimeDateStamp and SizeOfImage needed for symbol server lookup
#[derive(Debug, Clone, Copy)]
pub struct DacModuleIndex {
    pub timestamp: u32,
    pub size_of_image: u32,
}

impl DacModuleIndex {
    /// Generate the symbol server key for this DAC
    /// Format: <TIMESTAMP_8_HEX_UPPER><SIZEOFIMAGE_HEX_LOWER>
    pub fn symbol_server_key(&self) -> String {
        format!("{:08X}{:x}", self.timestamp, self.size_of_image)
    }

    /// Generate the full symbol server URL for mscordaccore.dll
    pub fn symbol_server_url(&self) -> String {
        format!(
            "https://msdl.microsoft.com/download/symbols/mscordaccore.dll/{}/mscordaccore.dll",
            self.symbol_server_key()
        )
    }
}

impl EmbeddedRuntimeInfo {
    fn is_valid(&self) -> bool {
        self.signature.starts_with(b"DotNetRuntimeInfo")
    }

    fn major(&self) -> i32 {
        self.runtime_version[0]
    }
    fn minor(&self) -> i32 {
        self.runtime_version[1]
    }
    fn build(&self) -> i32 {
        self.runtime_version[2]
    }
    fn revision(&self) -> i32 {
        self.runtime_version[3]
    }

    /// Extract DAC module index information
    /// Format (from genmoduleindex.cmd):
    /// - Byte 0: Length (0x08 = 8 bytes follow)
    /// - Bytes 1-4: TimeDateStamp (little-endian)
    /// - Bytes 5-8: SizeOfImage (little-endian)
    fn dac_index(&self) -> Option<DacModuleIndex> {
        // Check that the length byte indicates 8 bytes of data
        if self.dac_module_index[0] != 0x08 {
            return None;
        }

        // Extract timestamp (bytes 1-4, little-endian)
        let timestamp = u32::from_le_bytes([
            self.dac_module_index[1],
            self.dac_module_index[2],
            self.dac_module_index[3],
            self.dac_module_index[4],
        ]);

        // Extract size of image (bytes 5-8, little-endian)
        let size_of_image = u32::from_le_bytes([
            self.dac_module_index[5],
            self.dac_module_index[6],
            self.dac_module_index[7],
            self.dac_module_index[8],
        ]);

        Some(DacModuleIndex {
            timestamp,
            size_of_image,
        })
    }
}

/// Get the DAC cache directory
fn get_dac_cache_dir() -> Option<PathBuf> {
    std::env::var("LOCALAPPDATA")
        .ok()
        .map(|appdata| PathBuf::from(appdata).join("netdumper").join("dac-cache"))
}

/// Download mscordaccore.dll from Microsoft Symbol Server
/// Returns the path to the downloaded (and cached) DAC
fn download_dac_from_symbol_server(dac_index: &DacModuleIndex) -> Result<PathBuf> {
    let cache_dir = get_dac_cache_dir()
        .ok_or_else(|| Error::Other("Could not determine cache directory".into()))?;

    // Create subdirectory based on the symbol server key
    let key = dac_index.symbol_server_key();
    let dac_cache_subdir = cache_dir.join(&key);

    // Check if already cached
    let dac_path = dac_cache_subdir.join("mscordaccore.dll");
    if dac_path.exists() {
        eprintln!("Using cached DAC: {}", dac_path.display());
        return Ok(dac_path);
    }

    // Create cache directory
    std::fs::create_dir_all(&dac_cache_subdir).map_err(|e| {
        Error::Other(format!(
            "Failed to create cache directory {}: {}",
            dac_cache_subdir.display(),
            e
        ))
    })?;

    // Download from symbol server
    let url = dac_index.symbol_server_url();
    eprintln!("Downloading DAC from: {}", url);

    let response = ureq::get(&url)
        .call()
        .map_err(|e| Error::Other(format!("Failed to download DAC from symbol server: {}", e)))?;

    if response.status() != 200 {
        return Err(Error::Other(format!(
            "Symbol server returned status {}: {}",
            response.status(),
            url
        )));
    }

    // Read the response body
    let body = response
        .into_body()
        .read_to_vec()
        .map_err(|e| Error::Other(format!("Failed to read DAC response: {}", e)))?;

    // Write to cache
    std::fs::write(&dac_path, &body).map_err(|e| {
        Error::Other(format!(
            "Failed to write DAC to cache {}: {}",
            dac_path.display(),
            e
        ))
    })?;

    eprintln!(
        "Downloaded DAC ({} bytes) to: {}",
        body.len(),
        dac_path.display()
    );

    Ok(dac_path)
}

/// Get the embedded CLR version from a process
fn get_embedded_clr_version(pid: u32) -> Option<EmbeddedRuntimeInfo> {
    let handle =
        unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }.ok()?;

    let result = get_embedded_clr_version_with_handle(handle);

    unsafe { CloseHandle(handle).ok() };
    result
}

/// Get the embedded CLR version from a process using an existing handle
fn get_embedded_clr_version_with_handle(handle: HANDLE) -> Option<EmbeddedRuntimeInfo> {
    // Get main module
    let mut modules = [windows::Win32::Foundation::HMODULE::default(); 1];
    let mut needed = 0u32;

    if unsafe {
        EnumProcessModulesEx(
            handle,
            modules.as_mut_ptr(),
            std::mem::size_of_val(&modules) as u32,
            &mut needed,
            LIST_MODULES_ALL,
        )
    }
    .is_err()
    {
        return None;
    }

    let main_module = modules[0];
    let base_address = main_module.0 as usize;

    // Read DOS header to get PE header offset
    let mut dos_header = [0u8; 64];
    let mut bytes_read = 0;
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
    {
        return None;
    }

    // Check DOS signature (MZ)
    if dos_header[0] != b'M' || dos_header[1] != b'Z' {
        return None;
    }

    // Get PE header offset (at offset 0x3C)
    let pe_offset = u32::from_le_bytes([
        dos_header[0x3C],
        dos_header[0x3D],
        dos_header[0x3E],
        dos_header[0x3F],
    ]) as usize;

    // Read PE header (enough for Optional Header pointer to export directory)
    let mut pe_header = [0u8; 256];
    if unsafe {
        ReadProcessMemory(
            handle,
            (base_address + pe_offset) as *const c_void,
            pe_header.as_mut_ptr() as *mut c_void,
            pe_header.len(),
            Some(&mut bytes_read),
        )
    }
    .is_err()
    {
        return None;
    }

    // Check PE signature
    if pe_header[0] != b'P' || pe_header[1] != b'E' || pe_header[2] != 0 || pe_header[3] != 0 {
        return None;
    }

    // Parse COFF header (after 4-byte PE signature)
    // Number of sections at offset 6 in COFF
    let _num_sections = u16::from_le_bytes([pe_header[6], pe_header[7]]) as usize;
    let _optional_header_size = u16::from_le_bytes([pe_header[20], pe_header[21]]) as usize;

    // Optional header starts at offset 24 (after 4-byte PE sig + 20-byte COFF header)
    let opt_header_offset = 24usize;

    // Check magic to determine PE32 or PE32+
    let magic = u16::from_le_bytes([
        pe_header[opt_header_offset],
        pe_header[opt_header_offset + 1],
    ]);
    let is_pe32_plus = magic == 0x20B;

    // Export directory RVA is in DataDirectory[0] of optional header
    // For PE32+: DataDirectory starts at offset 112 from optional header
    // For PE32: DataDirectory starts at offset 96 from optional header
    let data_dir_offset = if is_pe32_plus {
        opt_header_offset + 112
    } else {
        opt_header_offset + 96
    };
    let export_dir_rva = u32::from_le_bytes([
        pe_header[data_dir_offset],
        pe_header[data_dir_offset + 1],
        pe_header[data_dir_offset + 2],
        pe_header[data_dir_offset + 3],
    ]) as usize;

    if export_dir_rva == 0 {
        return None; // No exports
    }

    // Read export directory
    let mut export_dir = [0u8; 40];
    if unsafe {
        ReadProcessMemory(
            handle,
            (base_address + export_dir_rva) as *const c_void,
            export_dir.as_mut_ptr() as *mut c_void,
            export_dir.len(),
            Some(&mut bytes_read),
        )
    }
    .is_err()
    {
        return None;
    }

    // Parse export directory
    let number_of_names = u32::from_le_bytes([
        export_dir[24],
        export_dir[25],
        export_dir[26],
        export_dir[27],
    ]) as usize;
    let address_table_rva = u32::from_le_bytes([
        export_dir[28],
        export_dir[29],
        export_dir[30],
        export_dir[31],
    ]) as usize;
    let name_pointer_rva = u32::from_le_bytes([
        export_dir[32],
        export_dir[33],
        export_dir[34],
        export_dir[35],
    ]) as usize;
    let ordinal_table_rva = u32::from_le_bytes([
        export_dir[36],
        export_dir[37],
        export_dir[38],
        export_dir[39],
    ]) as usize;

    // Read name pointer table
    let name_table_size = number_of_names * 4;
    let mut name_pointers = vec![0u8; name_table_size];
    if unsafe {
        ReadProcessMemory(
            handle,
            (base_address + name_pointer_rva) as *const c_void,
            name_pointers.as_mut_ptr() as *mut c_void,
            name_table_size,
            Some(&mut bytes_read),
        )
    }
    .is_err()
    {
        return None;
    }

    // Read ordinal table
    let ordinal_table_size = number_of_names * 2;
    let mut ordinals = vec![0u8; ordinal_table_size];
    if unsafe {
        ReadProcessMemory(
            handle,
            (base_address + ordinal_table_rva) as *const c_void,
            ordinals.as_mut_ptr() as *mut c_void,
            ordinal_table_size,
            Some(&mut bytes_read),
        )
    }
    .is_err()
    {
        return None;
    }

    // Search for "DotNetRuntimeInfo" export
    for i in 0..number_of_names {
        let name_rva = u32::from_le_bytes([
            name_pointers[i * 4],
            name_pointers[i * 4 + 1],
            name_pointers[i * 4 + 2],
            name_pointers[i * 4 + 3],
        ]) as usize;

        // Read export name
        let mut name_buf = [0u8; 32];
        if unsafe {
            ReadProcessMemory(
                handle,
                (base_address + name_rva) as *const c_void,
                name_buf.as_mut_ptr() as *mut c_void,
                name_buf.len(),
                Some(&mut bytes_read),
            )
        }
        .is_err()
        {
            continue;
        }

        // Check if this is DotNetRuntimeInfo
        if name_buf.starts_with(b"DotNetRuntimeInfo\0") {
            // Get ordinal for this name
            let ordinal = u16::from_le_bytes([ordinals[i * 2], ordinals[i * 2 + 1]]) as usize;

            // Read address table entry
            let mut addr_entry = [0u8; 4];
            if unsafe {
                ReadProcessMemory(
                    handle,
                    (base_address + address_table_rva + ordinal * 4) as *const c_void,
                    addr_entry.as_mut_ptr() as *mut c_void,
                    4,
                    Some(&mut bytes_read),
                )
            }
            .is_err()
            {
                return None;
            }

            let export_rva = u32::from_le_bytes(addr_entry) as usize;

            // Read RuntimeInfo structure
            let mut runtime_info_bytes = [0u8; std::mem::size_of::<EmbeddedRuntimeInfo>()];
            if unsafe {
                ReadProcessMemory(
                    handle,
                    (base_address + export_rva) as *const c_void,
                    runtime_info_bytes.as_mut_ptr() as *mut c_void,
                    runtime_info_bytes.len(),
                    Some(&mut bytes_read),
                )
            }
            .is_err()
            {
                return None;
            }

            // Parse the structure
            let runtime_info: EmbeddedRuntimeInfo = unsafe {
                std::ptr::read(runtime_info_bytes.as_ptr() as *const EmbeddedRuntimeInfo)
            };

            if runtime_info.is_valid() {
                return Some(runtime_info);
            }
        }
    }

    None
}

/// Find the best matching DAC for a given version
fn find_best_matching_dac(major: i32, minor: i32, build: i32) -> Option<PathBuf> {
    let all_runtimes = find_all_system_dotnet_runtimes();

    // First, try to find an exact match
    let target_version = format!("{}.{}.{}", major, minor, build);
    for runtime_dir in &all_runtimes {
        if let Some(version) = runtime_dir.file_name().and_then(|s| s.to_str()) {
            if version == target_version {
                let dac_path = runtime_dir.join("mscordaccore.dll");
                if dac_path.exists() {
                    return Some(dac_path);
                }
            }
        }
    }

    // If no exact match, find the closest matching major.minor version
    for runtime_dir in &all_runtimes {
        if let Some(version) = runtime_dir.file_name().and_then(|s| s.to_str()) {
            let parts: Vec<i32> = version.split('.').filter_map(|p| p.parse().ok()).collect();
            if parts.len() >= 2 && parts[0] == major && parts[1] == minor {
                let dac_path = runtime_dir.join("mscordaccore.dll");
                if dac_path.exists() {
                    return Some(dac_path);
                }
            }
        }
    }

    // If still no match, return the highest available version
    for runtime_dir in &all_runtimes {
        let dac_path = runtime_dir.join("mscordaccore.dll");
        if dac_path.exists() {
            return Some(dac_path);
        }
    }

    None
}

/// Try to enumerate assemblies using multiple DAC versions
/// Takes a ProcessInfo to avoid re-opening handles for embedded CLR detection.
fn enumerate_with_multiple_dacs(process_info: ProcessInfo) -> Result<Vec<AssemblyInfo>> {
    // Use the cached embedded CLR info from ProcessInfo
    let embedded_info = process_info.embedded_clr_info;

    // We need to consume the ProcessInfo for the first DAC attempt
    // But we might need to try multiple DACs, so we need to track the pid
    // and create new ProcessInfo for each subsequent attempt
    let pid = {
        // Get pid from handle - we need to extract it before consuming process_info
        // Unfortunately Windows doesn't have a clean way to get PID from handle without QueryFullProcessImageName
        // So we'll capture the pid before the first attempt by using GetProcessId
        unsafe {
            windows::Win32::System::Threading::GetProcessId(process_info.handle.as_raw())
        }
    };

    if let Some(ref info) = embedded_info {
        eprintln!(
            "Detected embedded CLR version: {}.{}.{}.{}",
            info.major(),
            info.minor(),
            info.build(),
            info.revision()
        );

        // Try to find a matching local DAC
        if let Some(matching_dac) = find_best_matching_dac(info.major(), info.minor(), info.build())
        {
            eprintln!("Using matching DAC: {}", matching_dac.display());

            // Use the provided ProcessInfo for the first attempt
            match try_enumerate_with_dac_path_and_info(process_info, &matching_dac) {
                Ok(assemblies) => return Ok(assemblies),
                Err(e) => {
                    eprintln!("Matching DAC failed: {}. Trying other versions...", e);
                }
            }

            // After first attempt, process_info is consumed. Create new ones for subsequent attempts.
        } else {
            // No matching DAC found, drop process_info and continue with pid-based attempts
            drop(process_info);
        }
    } else {
        // No embedded info, drop process_info and continue with pid-based attempts
        drop(process_info);
    }

    // Fall back to trying all available local DAC versions
    let dac_paths = find_all_system_dotnet_runtimes();

    let mut last_error = String::new();

    for runtime_dir in &dac_paths {
        let dac_path = runtime_dir.join("mscordaccore.dll");
        if !dac_path.exists() {
            continue;
        }

        let version = runtime_dir
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown");

        eprintln!("Trying DAC version {}...", version);

        match try_enumerate_with_dac_path_by_pid(pid, &dac_path) {
            Ok(assemblies) => {
                eprintln!("Success with DAC version {}", version);
                return Ok(assemblies);
            }
            Err(e) => {
                last_error = format!("{}", e);
                // Continue trying other versions
            }
        }
    }

    // If we have embedded CLR info, try downloading the exact matching DAC from symbol server
    if let Some(ref info) = embedded_info {
        if let Some(dac_index) = info.dac_index() {
            eprintln!("No local DAC matched. Attempting download from Microsoft Symbol Server...");
            eprintln!(
                "  DAC TimeDateStamp: 0x{:08X}, SizeOfImage: 0x{:08X}",
                dac_index.timestamp, dac_index.size_of_image
            );

            match download_dac_from_symbol_server(&dac_index) {
                Ok(dac_path) => {
                    eprintln!("Downloaded DAC, attempting to use: {}", dac_path.display());
                    match try_enumerate_with_dac_path_by_pid(pid, &dac_path) {
                        Ok(assemblies) => {
                            eprintln!("Success with downloaded DAC!");
                            return Ok(assemblies);
                        }
                        Err(e) => {
                            last_error = format!("Downloaded DAC failed: {}", e);
                            eprintln!("{}", last_error);
                        }
                    }
                }
                Err(e) => {
                    last_error = format!("DAC download failed: {}", e);
                    eprintln!("{}", last_error);
                }
            }
        } else {
            eprintln!("Could not extract DAC module index from embedded CLR info");
        }
    }

    if dac_paths.is_empty() && embedded_info.is_none() {
        return Err(Error::Other("No .NET Core runtimes found on system".into()));
    }

    Err(Error::Other(format!(
        "Failed to enumerate with any DAC version. Last error: {}",
        last_error
    )))
}

/// Try to enumerate assemblies using a specific DAC path and an existing ProcessInfo.
/// This consumes the ProcessInfo.
fn try_enumerate_with_dac_path_and_info(
    process_info: ProcessInfo,
    dac_path: &Path,
) -> Result<Vec<AssemblyInfo>> {
    let create_instance = load_dac_create_instance(dac_path)?;
    let data_target = CLRDataTarget::from_process_info(process_info)?;
    enumerate_with_dac(create_instance, data_target)
}

/// Try to enumerate assemblies using a specific DAC path by opening a new process handle.
fn try_enumerate_with_dac_path_by_pid(pid: u32, dac_path: &Path) -> Result<Vec<AssemblyInfo>> {
    let create_instance = load_dac_create_instance(dac_path)?;
    let data_target = CLRDataTarget::new_external(pid)?;
    enumerate_with_dac(create_instance, data_target)
}

/// Try to enumerate assemblies using a specific DAC path.
/// Convenience wrapper that creates ProcessInfo internally.
fn try_enumerate_with_dac_path(process_info: ProcessInfo, dac_path: &Path) -> Result<Vec<AssemblyInfo>> {
    try_enumerate_with_dac_path_and_info(process_info, dac_path)
}

/// Load the DAC DLL and get the CLRDataCreateInstance function pointer.
fn load_dac_create_instance(dac_path: &Path) -> Result<CLRDataCreateInstanceFn> {
    if !dac_path.exists() {
        return Err(Error::Other(format!(
            "DAC not found at {}",
            dac_path.display()
        )));
    }

    let dac_path_wide: Vec<u16> = dac_path
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let dac_module = unsafe { LoadLibraryW(PCWSTR::from_raw(dac_path_wide.as_ptr())) }
        .map_err(|e| Error::Other(format!("Failed to load DAC: {}", e)))?;

    // Get CLRDataCreateInstance
    let create_instance: CLRDataCreateInstanceFn = unsafe {
        let proc = GetProcAddress(dac_module, windows::core::s!("CLRDataCreateInstance"));
        match proc {
            Some(p) => std::mem::transmute::<_, CLRDataCreateInstanceFn>(p),
            None => return Err(Error::Other("CLRDataCreateInstance not found".into())),
        }
    };

    Ok(create_instance)
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

// =============================================================================
// PE Header Reconstruction (Anti-Anti-Dump)
// =============================================================================

/// Memory region information from VirtualQuery
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct MemoryRegion {
    /// Base address of the region
    base_address: usize,
    /// Size of the region
    size: usize,
    /// Memory protection flags
    protect: u32,
    /// Whether the region is committed
    is_committed: bool,
}

/// Scan memory regions using VirtualQueryEx to find section boundaries
fn scan_memory_regions(
    process_handle: HANDLE,
    base_address: usize,
    max_size: usize,
) -> Vec<MemoryRegion> {
    let mut regions = Vec::new();
    let mut current_address = base_address;
    let end_address = base_address + max_size;

    while current_address < end_address {
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let result = unsafe {
            VirtualQueryEx(
                process_handle,
                Some(current_address as *const c_void),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };

        if result == 0 {
            break;
        }

        let region_base = mbi.BaseAddress as usize;
        let region_size = mbi.RegionSize;

        // Only include regions that are part of our image
        if region_base >= base_address && region_base < end_address {
            regions.push(MemoryRegion {
                base_address: region_base,
                size: region_size.min(end_address - region_base),
                protect: mbi.Protect.0,
                is_committed: mbi.State == MEM_COMMIT,
            });
        }

        current_address = region_base + region_size;
    }

    regions
}

/// Convert memory protection flags to PE section characteristics
#[allow(dead_code)]
fn protection_to_characteristics(protect: u32) -> u32 {
    let mut characteristics: u32 = 0;

    // IMAGE_SCN_MEM_READ
    if protect == PAGE_READONLY.0
        || protect == PAGE_READWRITE.0
        || protect == PAGE_WRITECOPY.0
        || protect == PAGE_EXECUTE_READ.0
        || protect == PAGE_EXECUTE_READWRITE.0
        || protect == PAGE_EXECUTE_WRITECOPY.0
    {
        characteristics |= 0x40000000; // IMAGE_SCN_MEM_READ
    }

    // IMAGE_SCN_MEM_WRITE
    if protect == PAGE_READWRITE.0
        || protect == PAGE_WRITECOPY.0
        || protect == PAGE_EXECUTE_READWRITE.0
        || protect == PAGE_EXECUTE_WRITECOPY.0
    {
        characteristics |= 0x80000000; // IMAGE_SCN_MEM_WRITE
    }

    // IMAGE_SCN_MEM_EXECUTE
    if protect == PAGE_EXECUTE.0
        || protect == PAGE_EXECUTE_READ.0
        || protect == PAGE_EXECUTE_READWRITE.0
        || protect == PAGE_EXECUTE_WRITECOPY.0
    {
        characteristics |= 0x20000000; // IMAGE_SCN_MEM_EXECUTE
    }

    // IMAGE_SCN_CNT_CODE for executable sections
    if characteristics & 0x20000000 != 0 {
        characteristics |= 0x00000020; // IMAGE_SCN_CNT_CODE
    }

    // IMAGE_SCN_CNT_INITIALIZED_DATA for readable non-executable sections
    if characteristics & 0x40000000 != 0 && characteristics & 0x20000000 == 0 {
        characteristics |= 0x00000040; // IMAGE_SCN_CNT_INITIALIZED_DATA
    }

    characteristics
}

/// Reconstruct PE headers from memory regions when original headers are corrupted
fn reconstruct_pe_info(process_handle: HANDLE, base_address: usize) -> Option<PeInfo> {
    // First, try to estimate image size by scanning memory
    // Start with a reasonable max (256MB) and scan to find actual extent
    let regions = scan_memory_regions(process_handle, base_address, 0x10000000);

    if regions.is_empty() {
        return None;
    }

    // Find the total image size from regions
    let mut size_of_image: u32 = 0;
    for region in &regions {
        let region_end = (region.base_address - base_address + region.size) as u32;
        if region_end > size_of_image {
            size_of_image = region_end;
        }
    }

    // Merge adjacent regions with same protection into sections
    let mut sections = Vec::new();
    let mut current_file_offset: u32 = 0x1000; // Start after headers

    // Group committed regions into sections
    let committed_regions: Vec<_> = regions
        .iter()
        .filter(|r| r.is_committed && r.base_address > base_address)
        .collect();

    for region in committed_regions {
        let virtual_address = (region.base_address - base_address) as u32;
        let virtual_size = region.size as u32;

        // Align file offset to 0x200 (file alignment)
        let aligned_offset = (current_file_offset + 0x1FF) & !0x1FF;
        let size_of_raw_data = (virtual_size + 0x1FF) & !0x1FF;

        sections.push(SectionInfo {
            virtual_address,
            virtual_size,
            pointer_to_raw_data: aligned_offset,
            size_of_raw_data,
        });

        current_file_offset = aligned_offset + size_of_raw_data;
    }

    // If no sections found, create one big section
    if sections.is_empty() && size_of_image > 0x1000 {
        sections.push(SectionInfo {
            virtual_address: 0x1000,
            virtual_size: size_of_image - 0x1000,
            pointer_to_raw_data: 0x1000,
            size_of_raw_data: size_of_image - 0x1000,
        });
    }

    Some(PeInfo {
        e_lfanew: 0x80, // Standard offset
        size_of_image,
        size_of_headers: 0x1000, // Standard page-aligned headers
        number_of_sections: sections.len() as u16,
        size_of_optional_header: if cfg!(target_arch = "x86_64") {
            0xF0
        } else {
            0xE0
        },
        sections,
        is_pe32_plus: cfg!(target_arch = "x86_64"),
    })
}

/// Build a complete PE file with reconstructed headers
fn build_pe_with_reconstructed_headers(memory_image: &[u8], pe_info: &PeInfo) -> Vec<u8> {
    // Calculate file size
    let mut file_size = pe_info.size_of_headers as usize;
    for section in &pe_info.sections {
        let section_end = section.pointer_to_raw_data as usize + section.size_of_raw_data as usize;
        if section_end > file_size {
            file_size = section_end;
        }
    }

    let mut file_image = vec![0u8; file_size];

    // Build DOS header
    let dos_header: [u8; 64] = [
        0x4D, 0x5A, // MZ signature
        0x90, 0x00, // Bytes on last page
        0x03, 0x00, // Pages in file
        0x00, 0x00, // Relocations
        0x04, 0x00, // Size of header in paragraphs
        0x00, 0x00, // Minimum extra paragraphs
        0xFF, 0xFF, // Maximum extra paragraphs
        0x00, 0x00, // Initial SS
        0xB8, 0x00, // Initial SP
        0x00, 0x00, // Checksum
        0x00, 0x00, // Initial IP
        0x00, 0x00, // Initial CS
        0x40, 0x00, // Offset to relocation table
        0x00, 0x00, // Overlay number
        0x00, 0x00, 0x00, 0x00, // Reserved
        0x00, 0x00, 0x00, 0x00, // Reserved
        0x00, 0x00, // OEM identifier
        0x00, 0x00, // OEM info
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reserved
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reserved
        0x00, 0x00, 0x00, 0x00, // Reserved
        0x80, 0x00, 0x00, 0x00, // e_lfanew (offset to PE header = 0x80)
    ];
    file_image[..64].copy_from_slice(&dos_header);

    // DOS stub (minimal)
    let dos_stub: [u8; 64] = [
        0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54,
        0x68, 0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E,
        0x6E, 0x6F, 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x44,
        0x4F, 0x53, 0x20, 0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A, 0x24, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];
    file_image[64..128].copy_from_slice(&dos_stub);

    // PE signature at 0x80
    file_image[0x80..0x84].copy_from_slice(&[0x50, 0x45, 0x00, 0x00]); // "PE\0\0"

    // COFF header (20 bytes) at 0x84
    let coff_offset = 0x84;
    // Machine
    file_image[coff_offset..coff_offset + 2]
        .copy_from_slice(&IMAGE_FILE_MACHINE_CURRENT.to_le_bytes());
    // NumberOfSections
    file_image[coff_offset + 2..coff_offset + 4]
        .copy_from_slice(&pe_info.number_of_sections.to_le_bytes());
    // TimeDateStamp (0)
    file_image[coff_offset + 4..coff_offset + 8].copy_from_slice(&0u32.to_le_bytes());
    // PointerToSymbolTable (0)
    file_image[coff_offset + 8..coff_offset + 12].copy_from_slice(&0u32.to_le_bytes());
    // NumberOfSymbols (0)
    file_image[coff_offset + 12..coff_offset + 16].copy_from_slice(&0u32.to_le_bytes());
    // SizeOfOptionalHeader
    file_image[coff_offset + 16..coff_offset + 18]
        .copy_from_slice(&pe_info.size_of_optional_header.to_le_bytes());
    // Characteristics: EXECUTABLE_IMAGE | DLL
    let characteristics: u16 = 0x2000 | 0x0002; // DLL | EXECUTABLE_IMAGE
    file_image[coff_offset + 18..coff_offset + 20].copy_from_slice(&characteristics.to_le_bytes());

    // Optional header at 0x98
    let opt_offset = 0x98;
    if pe_info.is_pe32_plus {
        // PE32+ magic
        file_image[opt_offset..opt_offset + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        // Linker version
        file_image[opt_offset + 2] = 14;
        file_image[opt_offset + 3] = 0;
        // SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData (estimate)
        // AddressOfEntryPoint at offset 16
        // BaseOfCode at offset 20
        // ImageBase at offset 24 (8 bytes for PE32+)
        file_image[opt_offset + 24..opt_offset + 32].copy_from_slice(&0x180000000u64.to_le_bytes());
        // SectionAlignment at offset 32
        file_image[opt_offset + 32..opt_offset + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        // FileAlignment at offset 36
        file_image[opt_offset + 36..opt_offset + 40].copy_from_slice(&0x200u32.to_le_bytes());
        // OS version at offset 40
        file_image[opt_offset + 40..opt_offset + 42].copy_from_slice(&6u16.to_le_bytes());
        // SizeOfImage at offset 56
        file_image[opt_offset + 56..opt_offset + 60]
            .copy_from_slice(&pe_info.size_of_image.to_le_bytes());
        // SizeOfHeaders at offset 60
        file_image[opt_offset + 60..opt_offset + 64]
            .copy_from_slice(&pe_info.size_of_headers.to_le_bytes());
        // Subsystem at offset 68: IMAGE_SUBSYSTEM_WINDOWS_CUI = 3
        file_image[opt_offset + 68..opt_offset + 70].copy_from_slice(&3u16.to_le_bytes());
        // DllCharacteristics at offset 70: DYNAMIC_BASE | NX_COMPAT | NO_SEH
        file_image[opt_offset + 70..opt_offset + 72].copy_from_slice(&0x8160u16.to_le_bytes());
        // NumberOfRvaAndSizes at offset 108
        file_image[opt_offset + 108..opt_offset + 112].copy_from_slice(&16u32.to_le_bytes());
    } else {
        // PE32 magic
        file_image[opt_offset..opt_offset + 2].copy_from_slice(&0x10Bu16.to_le_bytes());
        // Similar fields but with 32-bit ImageBase at offset 28
        file_image[opt_offset + 28..opt_offset + 32].copy_from_slice(&0x10000000u32.to_le_bytes());
        // SectionAlignment at offset 32
        file_image[opt_offset + 32..opt_offset + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        // FileAlignment at offset 36
        file_image[opt_offset + 36..opt_offset + 40].copy_from_slice(&0x200u32.to_le_bytes());
        // SizeOfImage at offset 56
        file_image[opt_offset + 56..opt_offset + 60]
            .copy_from_slice(&pe_info.size_of_image.to_le_bytes());
        // SizeOfHeaders at offset 60
        file_image[opt_offset + 60..opt_offset + 64]
            .copy_from_slice(&pe_info.size_of_headers.to_le_bytes());
        // NumberOfRvaAndSizes at offset 92
        file_image[opt_offset + 92..opt_offset + 96].copy_from_slice(&16u32.to_le_bytes());
    }

    // Section headers start after optional header
    let section_table_offset = opt_offset + pe_info.size_of_optional_header as usize;
    for (i, section) in pe_info.sections.iter().enumerate() {
        let section_offset = section_table_offset + i * 40;

        // Section name (8 bytes) - generate .text, .data, .rsrc, etc.
        let name = match i {
            0 => b".text\0\0\0",
            1 => b".rdata\0\0",
            2 => b".data\0\0\0",
            3 => b".rsrc\0\0\0",
            _ => b".sect\0\0\0",
        };
        file_image[section_offset..section_offset + 8].copy_from_slice(name);

        // VirtualSize
        file_image[section_offset + 8..section_offset + 12]
            .copy_from_slice(&section.virtual_size.to_le_bytes());
        // VirtualAddress
        file_image[section_offset + 12..section_offset + 16]
            .copy_from_slice(&section.virtual_address.to_le_bytes());
        // SizeOfRawData
        file_image[section_offset + 16..section_offset + 20]
            .copy_from_slice(&section.size_of_raw_data.to_le_bytes());
        // PointerToRawData
        file_image[section_offset + 20..section_offset + 24]
            .copy_from_slice(&section.pointer_to_raw_data.to_le_bytes());
        // PointerToRelocations, PointerToLinenumbers, NumberOfRelocations, NumberOfLinenumbers (0)
        // Characteristics at offset 36
        let characteristics: u32 = 0x60000020; // CODE | EXECUTE | READ
        file_image[section_offset + 36..section_offset + 40]
            .copy_from_slice(&characteristics.to_le_bytes());
    }

    // Copy section data from memory image
    for section in &pe_info.sections {
        let src_offset = section.virtual_address as usize;
        let dst_offset = section.pointer_to_raw_data as usize;

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

/// Check if PE headers appear to be corrupted/zeroed (anti-dump protection)
fn is_pe_header_corrupted(buffer: &[u8]) -> bool {
    if buffer.len() < 64 {
        return true;
    }

    // Check DOS signature
    if buffer[0] != 0x4D || buffer[1] != 0x5A {
        return true;
    }

    // Check e_lfanew
    let e_lfanew =
        u32::from_le_bytes([buffer[0x3C], buffer[0x3D], buffer[0x3E], buffer[0x3F]]) as usize;
    if e_lfanew < 64 || e_lfanew > 1024 || e_lfanew + 4 > buffer.len() {
        return true;
    }

    // Check PE signature
    if buffer[e_lfanew] != 0x50
        || buffer[e_lfanew + 1] != 0x45
        || buffer[e_lfanew + 2] != 0x00
        || buffer[e_lfanew + 3] != 0x00
    {
        return true;
    }

    // Check if NumberOfSections is zeroed (common anti-dump technique)
    if e_lfanew + 6 < buffer.len() {
        let num_sections = u16::from_le_bytes([buffer[e_lfanew + 6], buffer[e_lfanew + 7]]);
        if num_sections == 0 || num_sections > 96 {
            return true;
        }
    }

    false
}

/// Dump a single assembly from a process to a file
/// Converts from memory layout (RVA-based) to file layout (file offset-based)
/// Handles anti-dump protection by reconstructing headers if needed
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

    // Try to read PE info from headers first
    let pe_info_result = read_pe_info(process_handle, assembly.base_address);

    // Determine image size - either from PE headers or by scanning memory
    let (pe_info, needs_reconstruction) = match pe_info_result {
        Some(info) => (info, false),
        None => {
            // Headers might be corrupted (anti-dump protection)
            // Try to reconstruct from memory layout
            match reconstruct_pe_info(process_handle, assembly.base_address) {
                Some(info) => (info, true),
                None => {
                    return DumpResult {
                        name: assembly.name.clone(),
                        output_path,
                        size: 0,
                        success: false,
                        error: Some("Could not parse or reconstruct PE header".into()),
                    };
                }
            }
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

    // Check if headers are corrupted even if we parsed them initially
    // (anti-dump might have zeroed specific fields)
    let use_reconstruction = needs_reconstruction || is_pe_header_corrupted(&buffer);

    // Convert from memory layout to file layout
    let file_image = if use_reconstruction {
        // Reconstruct headers and build PE from scratch
        let reconstructed_info = if needs_reconstruction {
            pe_info
        } else {
            // Re-reconstruct with fresh memory scan since original headers are bad
            reconstruct_pe_info(process_handle, assembly.base_address).unwrap_or(pe_info)
        };
        build_pe_with_reconstructed_headers(&buffer, &reconstructed_info)
    } else {
        // Use original headers - just unroll sections
        convert_memory_to_file_layout(&buffer, &pe_info)
    };

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
