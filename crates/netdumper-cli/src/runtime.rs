//! Runtime detection and diagnostics.
//!
//! This module handles detecting .NET runtimes in target processes,
//! including embedded CLR in single-file deployments.

use std::ffi::c_void;
use std::path::PathBuf;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::ProcessStatus::{
    EnumProcessModulesEx, GetModuleBaseNameW, GetModuleFileNameExW, LIST_MODULES_ALL,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

use crate::{Error, Result};

// =============================================================================
// Runtime Types
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

// =============================================================================
// Embedded CLR Info
// =============================================================================

/// RuntimeInfo structure from embedded CLR (matches dotnet/runtime runtimeinfo.h)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EmbeddedRuntimeInfo {
    pub(crate) signature: [u8; 18],
    pub(crate) version: i32,
    pub(crate) runtime_module_index: [u8; 24],
    pub(crate) dac_module_index: [u8; 24],
    pub(crate) dbi_module_index: [u8; 24],
    pub(crate) runtime_version: [i32; 4], // major, minor, build, revision
}

impl EmbeddedRuntimeInfo {
    pub fn is_valid(&self) -> bool {
        self.signature.starts_with(b"DotNetRuntimeInfo")
    }

    pub fn major(&self) -> i32 {
        self.runtime_version[0]
    }
    pub fn minor(&self) -> i32 {
        self.runtime_version[1]
    }
    pub fn build(&self) -> i32 {
        self.runtime_version[2]
    }
    pub fn revision(&self) -> i32 {
        self.runtime_version[3]
    }

    /// Extract DAC module index information
    pub fn dac_index(&self) -> Option<DacModuleIndex> {
        if self.dac_module_index[0] != 0x08 {
            return None;
        }

        let timestamp = u32::from_le_bytes([
            self.dac_module_index[1],
            self.dac_module_index[2],
            self.dac_module_index[3],
            self.dac_module_index[4],
        ]);

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

/// DAC module index information for symbol server lookup
#[derive(Debug, Clone, Copy)]
pub struct DacModuleIndex {
    pub timestamp: u32,
    pub size_of_image: u32,
}

impl DacModuleIndex {
    /// Generate the symbol server key for this DAC
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

// =============================================================================
// Diagnostics
// =============================================================================

/// Diagnostic information about why .NET detection might have failed
#[derive(Debug)]
pub struct DiagnosticInfo {
    pub modules: Vec<String>,
    pub potential_dotnet_modules: Vec<String>,
    pub exe_has_clr_header: bool,
    pub has_embedded_clr: bool,
    pub embedded_clr_version: Option<(i32, i32, i32, i32)>,
    pub failure_reason: String,
}

// =============================================================================
// Runtime Detection
// =============================================================================

/// Find the .NET runtime directory for a process by locating the CLR DLL.
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

    let clr_dlls = [
        ("coreclr.dll", RuntimeType::Core),
        ("clr.dll", RuntimeType::Framework),
        ("mscorwks.dll", RuntimeType::FrameworkLegacy),
    ];

    let mut main_exe_path: Option<PathBuf> = None;

    for i in 0..count {
        let module = modules[i];
        let mut name_buf = [0u16; 260];
        let len = unsafe { GetModuleBaseNameW(handle, Some(module), &mut name_buf) };
        if len > 0 {
            let name = String::from_utf16_lossy(&name_buf[..len as usize]);

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

    // Check for single-file extraction path
    for i in 0..count {
        let module = modules[i];
        let mut path_buf = [0u16; 512];
        let path_len = unsafe { GetModuleFileNameExW(Some(handle), Some(module), &mut path_buf) };
        if path_len > 0 {
            let full_path = String::from_utf16_lossy(&path_buf[..path_len as usize]);
            let path_lower = full_path.to_lowercase();

            if path_lower.contains("\\.net\\") || path_lower.contains("/.net/") {
                let path = PathBuf::from(&full_path);
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

    // Check for embedded CLR
    if let Some(exe_path) = main_exe_path
        && exe_has_clr_exports(&exe_path)
    {
        if let Some(embedded_info) = get_embedded_clr_version_with_handle(handle)
            && let Some(dac_path) = find_best_matching_dac(
                embedded_info.major(),
                embedded_info.minor(),
                embedded_info.build(),
            )
            && let Some(runtime_dir) = dac_path.parent()
        {
            return Ok(Some(RuntimeInfo {
                directory: runtime_dir.to_path_buf(),
                runtime_type: RuntimeType::Core,
            }));
        }

        if let Some(runtime_dir) = find_system_dotnet_runtime() {
            return Ok(Some(RuntimeInfo {
                directory: runtime_dir,
                runtime_type: RuntimeType::Core,
            }));
        }
    }

    Ok(None)
}

/// Check if an executable has CLR exports (indicating embedded CoreCLR)
pub fn exe_has_clr_exports(path: &PathBuf) -> bool {
    let Ok(data) = std::fs::read(path) else {
        return false;
    };

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
    let versions = find_all_system_dotnet_runtimes();
    versions.into_iter().next()
}

/// Find all .NET Core runtime installations on the system, sorted by version (highest first)
pub fn find_all_system_dotnet_runtimes() -> Vec<PathBuf> {
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

    all_versions.sort_by(|a, b| {
        let va = a.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let vb = b.file_name().and_then(|s| s.to_str()).unwrap_or("");
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

/// Find the best matching DAC for a given version
pub fn find_best_matching_dac(major: i32, minor: i32, build: i32) -> Option<PathBuf> {
    let all_runtimes = find_all_system_dotnet_runtimes();

    let target_version = format!("{}.{}.{}", major, minor, build);
    for runtime_dir in &all_runtimes {
        if let Some(version) = runtime_dir.file_name().and_then(|s| s.to_str())
            && version == target_version
        {
            let dac_path = runtime_dir.join("mscordaccore.dll");
            if dac_path.exists() {
                return Some(dac_path);
            }
        }
    }

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

    for runtime_dir in &all_runtimes {
        let dac_path = runtime_dir.join("mscordaccore.dll");
        if dac_path.exists() {
            return Some(dac_path);
        }
    }

    None
}

/// Get diagnostic information about a process
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

            if i == 0 {
                exe_path = Some(PathBuf::from(&full_path));
            }

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

    let exe_has_clr_header = exe_path
        .as_ref()
        .map(check_pe_has_clr_header)
        .unwrap_or(false);

    let has_embedded_clr = exe_path.as_ref().is_some_and(exe_has_clr_exports);

    let embedded_clr_version = get_embedded_clr_version(pid)
        .map(|info| (info.major(), info.minor(), info.build(), info.revision()));

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
        "Executable has CLR header but no .NET runtime loaded.".to_string()
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

/// Check if a PE file has a CLR header
fn check_pe_has_clr_header(path: &PathBuf) -> bool {
    let Ok(data) = std::fs::read(path) else {
        return false;
    };

    if data.len() < 64 || data[0] != 0x4D || data[1] != 0x5A {
        return false;
    }

    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if e_lfanew + 4 > data.len() || data[e_lfanew] != 0x50 || data[e_lfanew + 1] != 0x45 {
        return false;
    }

    let opt_header_offset = e_lfanew + 24;
    if opt_header_offset + 2 > data.len() {
        return false;
    }

    let magic = u16::from_le_bytes([data[opt_header_offset], data[opt_header_offset + 1]]);
    let clr_dir_offset = match magic {
        0x10B => opt_header_offset + 208,
        0x20B => opt_header_offset + 224,
        _ => return false,
    };

    if clr_dir_offset + 8 > data.len() {
        return false;
    }

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

    clr_rva != 0 && clr_size != 0
}

/// Get the embedded CLR version from a process
pub fn get_embedded_clr_version(pid: u32) -> Option<EmbeddedRuntimeInfo> {
    let handle =
        unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }.ok()?;

    let result = get_embedded_clr_version_with_handle(handle);
    unsafe { CloseHandle(handle).ok() };
    result
}

/// Get the embedded CLR version from a process using an existing handle
pub fn get_embedded_clr_version_with_handle(handle: HANDLE) -> Option<EmbeddedRuntimeInfo> {
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
