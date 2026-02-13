//! Unified DAC enumeration - works for both internal (GetCurrentProcess) and external (OpenProcess) scenarios.
//!
//! Uses ReadProcessMemory which works with any HANDLE, including GetCurrentProcess().
//!
//! Uses the windows crate's #[interface] macro for proper COM interface definitions that
//! LLVM understands as true external calls.

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
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};
use windows::core::{GUID, HRESULT, Interface, PCWSTR};

use crate::{
    AssemblyInfo, Error, Result,
    dac::{
        CLRDataCreateInstanceFn, ClrDataAddress, DacpAppDomainData, DacpAppDomainStoreData,
        DacpAssemblyData, DacpModuleData, ICLRDataTargetImpl, ICLRDataTargetVtbl, IID_ICLR_DATA_TARGET,
        ISOSDacInterface, IXCLRDataProcess,
    },
};

#[cfg(target_arch = "x86_64")]
use crate::dac::IMAGE_FILE_MACHINE_AMD64;
#[cfg(target_arch = "aarch64")]
use crate::dac::IMAGE_FILE_MACHINE_ARM64;
#[cfg(target_arch = "x86")]
use crate::dac::IMAGE_FILE_MACHINE_I386;

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
    pub fn new_external(pid: u32) -> Result<*mut ICLRDataTargetImpl> {
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

    /// Create a new CLRDataTarget for the current process (uses GetCurrentProcess).
    pub fn new_internal() -> Result<*mut ICLRDataTargetImpl> {
        let handle = unsafe { GetCurrentProcess() };
        let module_bases = enumerate_module_bases(handle)?;

        let target = Box::new(CLRDataTarget {
            vtbl: &CLR_DATA_TARGET_VTBL,
            ref_count: AtomicU32::new(1),
            process_handle: handle,
            owns_handle: false, // GetCurrentProcess returns a pseudo-handle, don't close it
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

    #[cfg(target_arch = "x86_64")]
    {
        unsafe { *machine_type = IMAGE_FILE_MACHINE_AMD64 as u32 };
    }
    #[cfg(target_arch = "x86")]
    {
        unsafe { *machine_type = IMAGE_FILE_MACHINE_I386 as u32 };
    }
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { *machine_type = IMAGE_FILE_MACHINE_ARM64 as u32 };
    }

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

/// Find the .NET Core runtime directory for a process by locating coreclr.dll
pub fn find_runtime_directory(handle: HANDLE) -> Result<Option<PathBuf>> {
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

    for i in 0..count {
        let module = modules[i];
        let mut name_buf = [0u16; 260];
        let len = unsafe { GetModuleBaseNameW(handle, Some(module), &mut name_buf) };
        if len > 0 {
            let name = String::from_utf16_lossy(&name_buf[..len as usize]);
            if name.eq_ignore_ascii_case("coreclr.dll") {
                // Get the full path using GetModuleFileNameExW
                let mut path_buf = [0u16; 512];
                let path_len =
                    unsafe { GetModuleFileNameExW(Some(handle), Some(module), &mut path_buf) };
                if path_len > 0 {
                    let full_path = String::from_utf16_lossy(&path_buf[..path_len as usize]);
                    let path = PathBuf::from(&full_path);
                    if let Some(parent) = path.parent() {
                        return Ok(Some(parent.to_path_buf()));
                    }
                }
            }
        }
    }

    Ok(None)
}

/// Find runtime directory by PID (opens and closes handle internally)
pub fn find_runtime_directory_by_pid(pid: u32) -> Result<Option<PathBuf>> {
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
    let runtime_dir = find_runtime_directory_by_pid(pid)?
        .ok_or_else(|| Error::Other("Could not find .NET Core runtime in target process".into()))?;

    // Load mscordaccore.dll
    let dac_path = runtime_dir.join("mscordaccore.dll");
    if !dac_path.exists() {
        return Err(Error::Other(format!(
            "mscordaccore.dll not found at {}",
            dac_path.display()
        )));
    }

    let dac_path_wide: Vec<u16> = dac_path
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let dac_module = unsafe { LoadLibraryW(PCWSTR::from_raw(dac_path_wide.as_ptr())) }
        .map_err(|e| Error::Other(format!("Failed to load mscordaccore.dll: {}", e)))?;

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

/// Enumerate assemblies from the current process using DAC (for injected payload)
pub fn enumerate_assemblies_internal(runtime_dir: &str) -> Result<Vec<AssemblyInfo>> {
    // Load mscordaccore.dll
    let dac_path = format!("{}\\mscordaccore.dll", runtime_dir);
    let dac_path_wide: Vec<u16> = dac_path.encode_utf16().chain(std::iter::once(0)).collect();

    let dac_module = unsafe { LoadLibraryW(PCWSTR::from_raw(dac_path_wide.as_ptr())) }
        .map_err(|e| Error::Other(format!("Failed to load mscordaccore.dll: {}", e)))?;

    // Get CLRDataCreateInstance
    let create_instance: CLRDataCreateInstanceFn = unsafe {
        let proc = GetProcAddress(dac_module, windows::core::s!("CLRDataCreateInstance"));
        match proc {
            Some(p) => std::mem::transmute(p),
            None => return Err(Error::Other("CLRDataCreateInstance not found".into())),
        }
    };

    // Create our internal data target (uses GetCurrentProcess)
    let data_target = CLRDataTarget::new_internal()?;

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
