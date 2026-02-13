//! Assembly dumping functionality.
//!
//! This module handles reading assembly data from process memory
//! and writing it to disk with proper PE layout conversion.

use std::ffi::c_void;
use std::path::PathBuf;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

use crate::pe::{
    build_pe_with_reconstructed_headers, convert_memory_to_file_layout, is_pe_header_corrupted,
    read_pe_info, reconstruct_pe_info,
};
use crate::process::enumerate_assemblies_external;
use crate::{AssemblyInfo, Error, Result};

// =============================================================================
// Types
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

// =============================================================================
// Public API
// =============================================================================

/// Dump all assemblies from a process
pub fn dump_assemblies_external(pid: u32, output_dir: &std::path::Path) -> Result<Vec<DumpResult>> {
    std::fs::create_dir_all(output_dir)
        .map_err(|e| Error::Other(format!("Failed to create output directory: {}", e)))?;

    let assemblies = enumerate_assemblies_external(pid)?;

    let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }
        .map_err(|e| Error::Other(format!("Failed to open process: {}", e)))?;

    let mut results = Vec::with_capacity(assemblies.len());
    for assembly in &assemblies {
        let result = dump_assembly(handle, assembly, output_dir);
        results.push(result);
    }

    unsafe { CloseHandle(handle).ok() };

    Ok(results)
}

/// Dump a single assembly from a process to a file
pub fn dump_assembly(
    process_handle: HANDLE,
    assembly: &AssemblyInfo,
    output_dir: &std::path::Path,
) -> DumpResult {
    let safe_name = sanitize_filename(&assembly.name);
    let output_path = output_dir.join(format!("{}.dll", safe_name));

    if assembly.base_address == 0 {
        return DumpResult {
            name: assembly.name.clone(),
            output_path,
            size: 0,
            success: false,
            error: Some("Assembly has no base address (dynamic assembly?)".into()),
        };
    }

    let pe_info_result = read_pe_info(process_handle, assembly.base_address);

    let (pe_info, needs_reconstruction) = match pe_info_result {
        Some(info) => (info, false),
        None => match reconstruct_pe_info(process_handle, assembly.base_address) {
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
        },
    };

    let image_size = pe_info.size_of_image as usize;

    // Read the assembly bytes page-by-page
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
    }

    let use_reconstruction = needs_reconstruction || is_pe_header_corrupted(&buffer);

    let file_image = if use_reconstruction {
        let reconstructed_info = if needs_reconstruction {
            pe_info
        } else {
            reconstruct_pe_info(process_handle, assembly.base_address).unwrap_or(pe_info)
        };
        build_pe_with_reconstructed_headers(&buffer, &reconstructed_info)
    } else {
        convert_memory_to_file_layout(&buffer, &pe_info)
    };

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

