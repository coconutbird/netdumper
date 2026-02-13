//! Assembly dumping functionality.
//!
//! This module handles reading assembly data from process memory
//! and writing it to disk with proper PE layout conversion.

use std::ffi::c_void;
use std::path::PathBuf;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

use crate::pe::{
    build_pe_from_metadata_with_il, build_pe_with_reconstructed_headers,
    convert_memory_to_file_layout, extract_assembly_name_from_metadata_debug,
    extract_entry_point_from_pe, extract_metadata_info, extract_method_rvas,
    is_pe_header_corrupted, read_pe_info, reconstruct_pe_info, validate_cli_header_in_memory,
};
use crate::process::{enumerate_assemblies_external, read_il_bodies_for_module};
use crate::target::ProcessInfo;
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

    // Get process info to read machine type
    let process_info = ProcessInfo::new(pid)?;
    let handle = process_info.handle.as_raw();
    let machine_type = process_info.machine_type;

    let mut results = Vec::with_capacity(assemblies.len());
    for assembly in &assemblies {
        let result = dump_assembly(handle, assembly, output_dir, machine_type, pid);
        results.push(result);
    }

    // Handle is automatically closed when process_info is dropped

    Ok(results)
}

/// Dump a single assembly from a process to a file
pub fn dump_assembly(
    process_handle: HANDLE,
    assembly: &AssemblyInfo,
    output_dir: &std::path::Path,
    machine_type: u16,
    pid: u32,
) -> DumpResult {
    // We'll determine the final name after reading the assembly
    let fallback_name = assembly.name.clone();

    // Check if this is a reflection/dynamic assembly that can't be dumped as PE
    if assembly.is_reflection && !assembly.is_pe_file {
        let safe_name = sanitize_filename(&fallback_name);
        let output_path = output_dir.join(format!("{}.dll", safe_name));
        return DumpResult {
            name: fallback_name,
            output_path,
            size: 0,
            success: false,
            error: Some("Dynamic/Reflection assembly (no PE file)".into()),
        };
    }

    if assembly.base_address == 0 {
        let safe_name = sanitize_filename(&fallback_name);
        let output_path = output_dir.join(format!("{}.dll", safe_name));
        return DumpResult {
            name: fallback_name,
            output_path,
            size: 0,
            success: false,
            error: Some("Assembly has no base address (dynamic assembly?)".into()),
        };
    }

    let pe_info_result = read_pe_info(process_handle, assembly.base_address);

    let (pe_info, needs_reconstruction) = match pe_info_result {
        Some(info) => (info, false),
        None => match reconstruct_pe_info(process_handle, assembly.base_address, machine_type) {
            Some(info) => (info, true),
            None => {
                let safe_name = sanitize_filename(&fallback_name);
                let output_path = output_dir.join(format!("{}.dll", safe_name));
                return DumpResult {
                    name: fallback_name,
                    output_path,
                    size: 0,
                    success: false,
                    error: Some("Could not parse or reconstruct PE header".into()),
                };
            }
        },
    };

    // Validate that the CLI header is valid in memory
    // This catches cases where ilBase doesn't point to a real PE image
    let cli_valid = validate_cli_header_in_memory(process_handle, assembly.base_address, &pe_info);

    // Track if assembly has entry point (EXE vs DLL)
    let (file_image, has_entry_point) = if !cli_valid {
        // CLI header is invalid - try to build PE from raw metadata
        if assembly.metadata_address == 0 || assembly.metadata_size == 0 {
            let safe_name = sanitize_filename(&fallback_name);
            let output_path = output_dir.join(format!("{}.dll", safe_name));
            return DumpResult {
                name: fallback_name,
                output_path,
                size: 0,
                success: false,
                error: Some("Invalid CLI header and no metadata address available".into()),
            };
        }

        // Read metadata directly from metadataStart
        let mut metadata = vec![0u8; assembly.metadata_size];
        let mut bytes_read = 0usize;

        let result = unsafe {
            ReadProcessMemory(
                process_handle,
                assembly.metadata_address as *const c_void,
                metadata.as_mut_ptr() as *mut c_void,
                assembly.metadata_size,
                Some(&mut bytes_read),
            )
        };

        if result.is_err() || bytes_read < 4 {
            let safe_name = sanitize_filename(&fallback_name);
            let output_path = output_dir.join(format!("{}.dll", safe_name));
            return DumpResult {
                name: fallback_name,
                output_path,
                size: 0,
                success: false,
                error: Some("Failed to read metadata from process memory".into()),
            };
        }

        // Verify BSJB signature
        if metadata.len() < 4 || &metadata[0..4] != b"BSJB" {
            let safe_name = sanitize_filename(&fallback_name);
            let output_path = output_dir.join(format!("{}.dll", safe_name));
            return DumpResult {
                name: fallback_name,
                output_path,
                size: 0,
                success: false,
                error: Some("Metadata does not have BSJB signature".into()),
            };
        }

        // Extract metadata info for logging
        let (meta_entry_point, _flags) = extract_metadata_info(&metadata);
        let method_rvas = extract_method_rvas(&metadata);
        let rvas_only: Vec<u32> = method_rvas
            .iter()
            .filter(|m| m.rva != 0)
            .map(|m| m.rva)
            .collect();
        let methods_with_il = rvas_only.len();

        // Read IL bodies using DAC's GetILForModule
        let il_bodies = if assembly.module_address != 0 && !rvas_only.is_empty() {
            eprintln!(
                "  [INFO] {} - Reading {} IL method bodies from process memory...",
                fallback_name, methods_with_il
            );
            read_il_bodies_for_module(pid, assembly.module_address as u64, &rvas_only)
        } else {
            Vec::new()
        };

        if meta_entry_point != 0 {
            eprintln!(
                "  [INFO] {} - Reconstructing PE: entry point 0x{:08X}, {} methods with IL, {} IL bodies recovered",
                fallback_name,
                meta_entry_point,
                methods_with_il,
                il_bodies.len()
            );
        } else {
            eprintln!(
                "  [INFO] {} - Reconstructing PE: no entry point, {} methods with IL, {} IL bodies recovered",
                fallback_name,
                methods_with_il,
                il_bodies.len()
            );
        }

        // Build PE from raw metadata with IL bodies
        let is_64bit = machine_type == 0x8664; // AMD64
        (
            build_pe_from_metadata_with_il(&metadata, &il_bodies, is_64bit),
            meta_entry_point != 0,
        )
    } else {
        // Normal path - read full PE image
        let image_size = pe_info.size_of_image as usize;

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

        let pe_data = if use_reconstruction {
            let reconstructed_info = if needs_reconstruction {
                pe_info
            } else {
                reconstruct_pe_info(process_handle, assembly.base_address, machine_type)
                    .unwrap_or(pe_info)
            };
            build_pe_with_reconstructed_headers(&buffer, &reconstructed_info)
        } else {
            convert_memory_to_file_layout(&buffer, &pe_info)
        };

        // Check if the PE has an entry point by reading COR20 header
        // Entry point token is at offset 20 in COR20 header (after Flags at 16)
        let entry_point = extract_entry_point_from_pe(&pe_data);
        (pe_data, entry_point != 0)
    };

    // Try to extract the real assembly name from .NET metadata
    let final_name = match extract_assembly_name_from_metadata_debug(&file_image) {
        Ok(name) => name,
        Err(e) => {
            eprintln!(
                "  [DEBUG] {} metadata error: {:?} (cli_valid={})",
                fallback_name, e, cli_valid
            );
            fallback_name
        }
    };
    let safe_name = sanitize_filename(&final_name);
    // Use .exe extension if assembly has entry point, .dll otherwise
    let extension = if has_entry_point { "exe" } else { "dll" };
    let output_path = output_dir.join(format!("{}.{}", safe_name, extension));

    match std::fs::write(&output_path, &file_image) {
        Ok(()) => DumpResult {
            name: final_name,
            output_path,
            size: file_image.len(),
            success: true,
            error: None,
        },
        Err(e) => DumpResult {
            name: final_name,
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
