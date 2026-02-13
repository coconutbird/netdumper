//! Process inspection and DAC-based assembly enumeration.
//!
//! This module handles connecting to target processes via DAC,
//! including symbol server downloads for matching DAC versions.

use std::ffi::c_void;
use std::path::{Path, PathBuf};

use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::core::{GUID, HRESULT, Interface, PCWSTR};

pub use mscoree::{
    CLRDATA_ADDRESS, DacpAppDomainData, DacpAppDomainStoreData, DacpAssemblyData, DacpModuleData,
    ISOSDacInterface, IXCLRDataProcess,
};

use crate::runtime::{
    DacModuleIndex, find_all_system_dotnet_runtimes, find_best_matching_dac,
    find_runtime_directory_by_pid,
};
use crate::target::{CLRDataTarget, ICLRDataTargetImpl, ProcessInfo};
use crate::{AssemblyInfo, Error, Result};

/// CLRDataCreateInstance function type (exported by DAC DLLs)
type CLRDataCreateInstanceFn = unsafe extern "system" fn(
    riid: *const GUID,
    data_target: *mut c_void,
    ppv_object: *mut *mut c_void,
) -> HRESULT;

// =============================================================================
// Public API
// =============================================================================

/// Enumerate assemblies from an external process using DAC
pub fn enumerate_assemblies_external(pid: u32) -> Result<Vec<AssemblyInfo>> {
    let process_info = ProcessInfo::new(pid)?;

    if process_info.is_embedded_clr {
        return enumerate_with_multiple_dacs(process_info);
    }

    let runtime_info = find_runtime_directory_by_pid(pid)?
        .ok_or_else(|| Error::Other("Could not find .NET runtime in target process".into()))?;

    try_enumerate_with_dac_path(process_info, &runtime_info.dac_path())
}

// =============================================================================
// DAC Loading
// =============================================================================

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

    let create_instance: CLRDataCreateInstanceFn = unsafe {
        let proc = GetProcAddress(dac_module, windows::core::s!("CLRDataCreateInstance"));
        match proc {
            Some(p) => std::mem::transmute::<
                unsafe extern "system" fn() -> isize,
                CLRDataCreateInstanceFn,
            >(p),
            None => return Err(Error::Other("CLRDataCreateInstance not found".into())),
        }
    };

    Ok(create_instance)
}

/// Try to enumerate assemblies using a specific DAC path.
fn try_enumerate_with_dac_path(
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

/// Common enumeration logic using DAC
#[inline(never)]
fn enumerate_with_dac(
    create_instance: CLRDataCreateInstanceFn,
    data_target: *mut ICLRDataTargetImpl,
) -> Result<Vec<AssemblyInfo>> {
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

    let xclr: IXCLRDataProcess = unsafe { Interface::from_raw(xclr_process) };

    let sos: ISOSDacInterface = match xclr.cast() {
        Ok(s) => s,
        Err(e) => {
            return Err(Error::Other(format!(
                "QueryInterface for ISOSDacInterface failed: {}",
                e
            )));
        }
    };

    unsafe { enumerate_via_dac(&sos) }
}

// =============================================================================
// Symbol Server
// =============================================================================

/// Get the DAC cache directory
fn get_dac_cache_dir() -> Option<PathBuf> {
    std::env::var("LOCALAPPDATA")
        .ok()
        .map(|appdata| PathBuf::from(appdata).join("netdumper").join("dac-cache"))
}

/// Download mscordaccore.dll from Microsoft Symbol Server
fn download_dac_from_symbol_server(dac_index: &DacModuleIndex) -> Result<PathBuf> {
    let cache_dir = get_dac_cache_dir()
        .ok_or_else(|| Error::Other("Could not determine cache directory".into()))?;

    let key = dac_index.symbol_server_key();
    let dac_cache_subdir = cache_dir.join(&key);
    let dac_path = dac_cache_subdir.join("mscordaccore.dll");

    if dac_path.exists() {
        eprintln!("Using cached DAC: {}", dac_path.display());
        return Ok(dac_path);
    }

    std::fs::create_dir_all(&dac_cache_subdir).map_err(|e| {
        Error::Other(format!(
            "Failed to create cache directory {}: {}",
            dac_cache_subdir.display(),
            e
        ))
    })?;

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

    let body = response
        .into_body()
        .read_to_vec()
        .map_err(|e| Error::Other(format!("Failed to read DAC response: {}", e)))?;

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

// =============================================================================
// Multiple DAC Version Handling
// =============================================================================

/// Try to enumerate assemblies using multiple DAC versions
fn enumerate_with_multiple_dacs(process_info: ProcessInfo) -> Result<Vec<AssemblyInfo>> {
    let embedded_info = process_info.embedded_clr_info;

    let pid =
        unsafe { windows::Win32::System::Threading::GetProcessId(process_info.handle.as_raw()) };

    if let Some(ref info) = embedded_info {
        eprintln!(
            "Detected embedded CLR version: {}.{}.{}.{}",
            info.major(),
            info.minor(),
            info.build(),
            info.revision()
        );

        if let Some(matching_dac) = find_best_matching_dac(info.major(), info.minor(), info.build())
        {
            eprintln!("Using matching DAC: {}", matching_dac.display());

            match try_enumerate_with_dac_path(process_info, &matching_dac) {
                Ok(assemblies) => return Ok(assemblies),
                Err(e) => {
                    eprintln!("Matching DAC failed: {}. Trying other versions...", e);
                }
            }
        } else {
            drop(process_info);
        }
    } else {
        drop(process_info);
    }

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
            }
        }
    }

    // Try downloading from symbol server
    if let Some(ref info) = embedded_info
        && let Some(dac_index) = info.dac_index()
    {
        eprintln!("No local DAC matched. Attempting download from Microsoft Symbol Server...");

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
    }

    if dac_paths.is_empty() && embedded_info.is_none() {
        return Err(Error::Other("No .NET Core runtimes found on system".into()));
    }

    Err(Error::Other(format!(
        "Failed to enumerate with any DAC version. Last error: {}",
        last_error
    )))
}

// =============================================================================
// DAC Enumeration
// =============================================================================

/// Enumerate assemblies using ISOSDacInterface
#[inline(never)]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn enumerate_via_dac(sos_dac: &ISOSDacInterface) -> Result<Vec<AssemblyInfo>> {
    let mut assemblies = Vec::new();

    let mut store_data = DacpAppDomainStoreData::default();
    let hr = sos_dac.GetAppDomainStoreData(&mut store_data);

    if hr.is_err() {
        return Err(Error::Other(format!(
            "GetAppDomainStoreData failed: 0x{:08X}",
            hr.0
        )));
    }

    let domain_count = store_data.DomainCount as u32;

    if domain_count > 1000 {
        return Err(Error::Other(format!(
            "Suspicious domain count: {} - likely data corruption",
            domain_count
        )));
    }

    let mut domain_addresses: Vec<CLRDATA_ADDRESS> = vec![0; domain_count as usize];
    let mut actual_domain_count = 0u32;
    let hr = sos_dac.GetAppDomainList(
        domain_count,
        domain_addresses.as_mut_ptr(),
        &mut actual_domain_count,
    );

    let domains_to_use = if hr.is_err() {
        if store_data.systemDomain != 0 {
            domain_addresses = vec![store_data.systemDomain];
            1
        } else {
            return Err(Error::Other("No app domains found".into()));
        }
    } else {
        (actual_domain_count as usize).min(domain_addresses.len())
    };

    for &domain_addr in domain_addresses.iter().take(domains_to_use) {
        if domain_addr == 0 {
            continue;
        }

        let mut domain_data = DacpAppDomainData::default();
        let hr = sos_dac.GetAppDomainData(domain_addr, &mut domain_data);

        let asm_count_val = domain_data.AssemblyCount;
        if hr.is_err() || asm_count_val <= 0 {
            continue;
        }

        if asm_count_val > 10000 {
            continue;
        }

        let mut asm_addresses: Vec<CLRDATA_ADDRESS> = vec![0; asm_count_val as usize];
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

        let count_to_use = (actual_count as usize).min(asm_addresses.len());

        for &asm_addr in asm_addresses.iter().take(count_to_use) {
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
    domain_addr: CLRDATA_ADDRESS,
    asm_addr: CLRDATA_ADDRESS,
) -> Option<AssemblyInfo> {
    let mut asm_data = DacpAssemblyData::default();
    let hr = sos_dac.GetAssemblyData(domain_addr, asm_addr, &mut asm_data);

    if hr.is_err() {
        return None;
    }

    let mut name_buf: Box<[u16; 1024]> = Box::new([0u16; 1024]);
    let mut name_len: u32 = 0;

    let name_ptr = std::hint::black_box(name_buf.as_mut_ptr());
    let len_ptr = std::hint::black_box(&mut name_len as *mut u32);

    let hr = sos_dac.GetAssemblyName(asm_addr, 1024, name_ptr, len_ptr);

    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);

    let actual_len = std::ptr::read_volatile(&name_len);

    let path = if hr.is_ok() && actual_len > 0 {
        let len = (actual_len as usize).saturating_sub(1).min(1024);
        let mut str_data = Vec::with_capacity(len);
        for i in 0..len {
            str_data.push(std::ptr::read_volatile(&name_buf[i]));
        }
        Some(String::from_utf16_lossy(&str_data))
    } else {
        None
    };

    let name = path
        .as_ref()
        .and_then(|p| std::path::Path::new(p).file_name())
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| format!("Assembly_0x{:X}", asm_addr));

    let mut base_address = 0u64;
    let mut size = 0u32;

    let module_count = asm_data.ModuleCount;
    if module_count > 0 && module_count < 1000 {
        let mut module_addrs: Vec<CLRDATA_ADDRESS> = vec![0; module_count as usize];
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

                let mut info = AssemblyInfo::new(name, base_address as usize, size as usize);
                info.path = path;
                info.is_reflection = module_data.bIsReflection != 0;
                info.is_pe_file = module_data.bIsPEFile != 0;
                info.metadata_address = module_data.metadataStart as usize;
                info.metadata_size = module_data.metadataSize as usize;
                info.module_address = module_addr as usize;
                return Some(info);
            }
        }
    }

    let mut info = AssemblyInfo::new(name, base_address as usize, size as usize);
    info.path = path;

    Some(info)
}

// =============================================================================
// IL Method Body Reading
// =============================================================================

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

/// Read IL bodies for a specific module in a process.
/// This re-establishes DAC connection to call GetILForModule.
///
/// # Arguments
/// * `pid` - Process ID
/// * `module_address` - DAC module address (from AssemblyInfo.module_address)
/// * `method_rvas` - List of method RVAs from metadata (only those with rva != 0)
///
/// # Returns
/// Vector of IL bodies with their RVAs
pub fn read_il_bodies_for_module(
    pid: u32,
    module_address: u64,
    method_rvas: &[u32],
) -> Vec<ILMethodBody> {
    // Try to get DAC interface
    let process_info = match ProcessInfo::new(pid) {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };

    let process_handle = process_info.handle.as_raw();

    // Find runtime and load DAC
    let dac_path = if process_info.is_embedded_clr {
        // For embedded CLR, try to find matching DAC
        if let Some(ref info) = process_info.embedded_clr_info {
            find_best_matching_dac(info.major(), info.minor(), info.build())
        } else {
            // Fall back to finding any system runtime
            find_all_system_dotnet_runtimes()
                .into_iter()
                .map(|dir| dir.join("mscordaccore.dll"))
                .find(|p| p.exists())
        }
    } else {
        find_runtime_directory_by_pid(pid)
            .ok()
            .flatten()
            .map(|info| info.dac_path())
    };

    let dac_path = match dac_path {
        Some(p) => p,
        None => return Vec::new(),
    };

    let create_instance = match load_dac_create_instance(&dac_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    // Create data target - need to clone handle since CLRDataTarget might need it
    let data_target = match CLRDataTarget::new_external(pid) {
        Ok(dt) => dt,
        Err(_) => return Vec::new(),
    };

    // Get DAC interfaces
    let mut xclr_process: *mut c_void = std::ptr::null_mut();
    let hr = unsafe {
        create_instance(
            &IXCLRDataProcess::IID,
            data_target as *mut c_void,
            &mut xclr_process,
        )
    };

    if hr.is_err() || xclr_process.is_null() {
        return Vec::new();
    }

    let xclr: IXCLRDataProcess = unsafe { Interface::from_raw(xclr_process) };
    let sos: ISOSDacInterface = match xclr.cast() {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    read_il_bodies(&sos, process_handle, module_address, method_rvas)
}

/// IL method body with its RVA.
#[derive(Debug, Clone)]
pub struct ILMethodBody {
    /// RVA where this IL should be placed in the PE.
    pub rva: u32,
    /// Raw IL method body bytes (including header).
    pub data: Vec<u8>,
}

/// Read IL method bodies from a process using DAC.
///
/// This function:
/// 1. Takes method RVAs from metadata
/// 2. Calls GetILForModule to get IL addresses in process memory
/// 3. Reads IL bodies (determining size from IL header format)
/// 4. Returns (rva, bytes) pairs for PE reconstruction
fn read_il_bodies(
    sos: &ISOSDacInterface,
    process_handle: HANDLE,
    module_addr: u64,
    method_rvas: &[u32],
) -> Vec<ILMethodBody> {
    let mut bodies = Vec::new();

    for &rva in method_rvas {
        if rva == 0 {
            continue;
        }

        // Get IL address from DAC
        let mut il_addr: CLRDATA_ADDRESS = 0;
        let hr = unsafe { sos.GetILForModule(module_addr, rva, &mut il_addr) };

        if hr.is_err() || il_addr == 0 {
            continue;
        }

        // Read IL method body
        if let Some(data) = read_il_method_body(process_handle, il_addr as usize) {
            bodies.push(ILMethodBody { rva, data });
        }
    }

    bodies
}

/// Read an IL method body from process memory.
/// Determines size from the IL header format (tiny or fat).
fn read_il_method_body(process_handle: HANDLE, il_addr: usize) -> Option<Vec<u8>> {
    // First read the header byte to determine format
    let mut header_byte = [0u8; 1];
    let mut bytes_read = 0usize;

    let result = unsafe {
        ReadProcessMemory(
            process_handle,
            il_addr as *const c_void,
            header_byte.as_mut_ptr() as *mut c_void,
            1,
            Some(&mut bytes_read),
        )
    };

    if result.is_err() || bytes_read == 0 {
        return None;
    }

    // IL Method Header Format (ECMA-335 II.25.4):
    // Tiny format: (CodeSize << 2) | 0x02 - single byte header
    // Fat format: Flags[0] & 0x03 == 0x03 - 12 byte header

    let is_tiny = (header_byte[0] & 0x03) == 0x02;

    if is_tiny {
        // Tiny format: code size is in upper 6 bits
        let code_size = (header_byte[0] >> 2) as usize;
        let total_size = 1 + code_size;

        let mut data = vec![0u8; total_size];
        let result = unsafe {
            ReadProcessMemory(
                process_handle,
                il_addr as *const c_void,
                data.as_mut_ptr() as *mut c_void,
                total_size,
                Some(&mut bytes_read),
            )
        };

        if result.is_ok() && bytes_read == total_size {
            Some(data)
        } else {
            None
        }
    } else if (header_byte[0] & 0x03) == 0x03 {
        // Fat format: need to read 12-byte header first
        let mut fat_header = [0u8; 12];
        let result = unsafe {
            ReadProcessMemory(
                process_handle,
                il_addr as *const c_void,
                fat_header.as_mut_ptr() as *mut c_void,
                12,
                Some(&mut bytes_read),
            )
        };

        if result.is_err() || bytes_read != 12 {
            return None;
        }

        // Fat header layout:
        // Flags: u16 (includes header size in upper 4 bits of high byte)
        // MaxStack: u16
        // CodeSize: u32
        // LocalVarSigTok: u32
        let flags = u16::from_le_bytes([fat_header[0], fat_header[1]]);
        let header_size = ((flags >> 12) & 0x0F) as usize * 4; // Size in dwords
        let code_size =
            u32::from_le_bytes([fat_header[4], fat_header[5], fat_header[6], fat_header[7]])
                as usize;

        // Check for exception handlers (CorILMethod_MoreSects = 0x08)
        let has_more_sects = (flags & 0x08) != 0;

        let mut total_size = header_size + code_size;

        // If there are more sections (exception handlers), we need to read them too
        // For now, just read the code - exception handlers are complex
        if has_more_sects {
            // Align to 4-byte boundary after code
            let aligned_end = (header_size + code_size + 3) & !3;
            // Read a bit extra for exception handlers (estimate)
            total_size = aligned_end + 256; // Conservative estimate
        }

        // Sanity check
        if total_size > 1024 * 1024 {
            return None; // Method too large, probably corrupt
        }

        let mut data = vec![0u8; total_size];
        let result = unsafe {
            ReadProcessMemory(
                process_handle,
                il_addr as *const c_void,
                data.as_mut_ptr() as *mut c_void,
                total_size,
                Some(&mut bytes_read),
            )
        };

        if result.is_ok() && bytes_read > 0 {
            // Trim to actual size read
            data.truncate(bytes_read);

            // If we have more sections, try to determine actual size
            if has_more_sects && bytes_read >= header_size + code_size {
                if let Some(actual_size) =
                    calculate_method_size_with_eh(&data, header_size, code_size)
                {
                    data.truncate(actual_size);
                }
            } else {
                // No extra sections, just header + code
                data.truncate(header_size + code_size);
            }

            Some(data)
        } else {
            None
        }
    } else {
        // Unknown format
        None
    }
}

/// Calculate the total method size including exception handlers.
fn calculate_method_size_with_eh(
    data: &[u8],
    header_size: usize,
    code_size: usize,
) -> Option<usize> {
    // Exception handler section starts at 4-byte aligned offset after code
    let eh_offset = (header_size + code_size + 3) & !3;

    if eh_offset >= data.len() {
        return Some(header_size + code_size);
    }

    let eh_header = data[eh_offset];
    let is_fat_eh = (eh_header & 0x40) != 0;

    if is_fat_eh {
        // Fat exception header: 4 bytes header + n * 24 bytes per clause
        if eh_offset + 4 > data.len() {
            return None;
        }
        let size = u32::from_le_bytes([
            data[eh_offset] & 0x3F, // Lower 6 bits of first byte
            data[eh_offset + 1],
            data[eh_offset + 2],
            0,
        ]) as usize;
        // Size includes the header
        Some(eh_offset + ((size + 3) & !3))
    } else {
        // Small exception header: 4 bytes header + n * 12 bytes per clause
        if eh_offset + 4 > data.len() {
            return None;
        }
        let size = data[eh_offset + 1] as usize;
        Some(eh_offset + size)
    }
}
