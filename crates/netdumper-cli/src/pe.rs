//! PE header parsing and reconstruction.
//!
//! This module handles reading PE headers from process memory,
//! converting between memory and file layouts, and reconstructing
//! corrupted headers (anti-anti-dump).

use std::ffi::c_void;

use crate::assembly::AssemblyMetadata;
use crate::reader::ProcessMemoryReader;
use portex::coff::{CoffHeader, characteristics as coff_chars};
use portex::data_dir::{DataDirectory, DataDirectoryType};
use portex::dos::DosHeader;
use portex::optional::{OptionalHeader, OptionalHeader32, OptionalHeader64, dll_characteristics};
use portex::section::{Section, characteristics as sec_chars};
use portex::{PE, PEHeaders};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Memory::{MEM_COMMIT, MEMORY_BASIC_INFORMATION, VirtualQueryEx};

// =============================================================================
// Types
// =============================================================================

/// Section header information for PE reconstruction
#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub pointer_to_raw_data: u32,
    pub size_of_raw_data: u32,
}

/// PE header information needed for dumping
#[derive(Debug)]
#[allow(dead_code)]
pub struct PeInfo {
    pub machine_type: u16,
    pub e_lfanew: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub number_of_sections: u16,
    pub size_of_optional_header: u16,
    pub sections: Vec<SectionInfo>,
    pub is_pe32_plus: bool,
}

/// Memory region information from VirtualQuery
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct MemoryRegion {
    pub base_address: usize,
    pub size: usize,
    pub protect: u32,
    pub is_committed: bool,
}

// =============================================================================
// Helper Functions for PE Parsing with Portex
// =============================================================================

/// CLI header information extracted from PE
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CliHeaderInfo {
    /// RVA of the CLI header
    pub cli_rva: u32,
    /// Size of the CLI header
    pub cli_size: u32,
    /// File offset of the CLI header (if conversion succeeded)
    pub cli_file_offset: Option<u32>,
    /// Whether this is PE32+ (64-bit)
    pub is_pe32_plus: bool,
}

/// Parse CLI data directory information from a PE byte slice using portex.
/// Returns the CLI RVA, size, and optional file offset.
pub fn get_cli_directory_from_slice(pe_data: &[u8]) -> Option<CliHeaderInfo> {
    let headers = PEHeaders::from_slice(pe_data).ok()?;

    // Get CLI Runtime data directory (index 14)
    let cli_dir = headers
        .optional_header
        .data_directories()
        .get(DataDirectoryType::ClrRuntime.as_index())?;

    if cli_dir.virtual_address == 0 {
        return None;
    }

    // Try to convert RVA to file offset
    let cli_file_offset = headers.rva_to_offset(cli_dir.virtual_address);

    Some(CliHeaderInfo {
        cli_rva: cli_dir.virtual_address,
        cli_size: cli_dir.size,
        cli_file_offset,
        is_pe32_plus: headers.is_64bit(),
    })
}

// =============================================================================
// PE Header Reading
// =============================================================================

/// Read PE header information from a process using portex.
pub fn read_pe_info(process_handle: HANDLE, base_address: usize) -> Option<PeInfo> {
    // Use ProcessMemoryReader with portex
    let reader = ProcessMemoryReader::new(process_handle, base_address, None);

    // Parse headers using portex
    let headers = PEHeaders::read_from(&reader, 0).ok()?;

    // Validate size_of_image
    let size_of_image = headers.optional_header.size_of_image();
    if !(0x1000..=0x40000000).contains(&size_of_image) {
        return None;
    }

    // Validate section count
    let number_of_sections = headers.coff_header.number_of_sections;
    if number_of_sections > 96 {
        return None;
    }

    // Convert portex section headers to our SectionInfo format
    let sections: Vec<SectionInfo> = headers
        .section_headers
        .iter()
        .map(|s| SectionInfo {
            virtual_address: s.virtual_address,
            virtual_size: s.virtual_size,
            pointer_to_raw_data: s.pointer_to_raw_data,
            size_of_raw_data: s.size_of_raw_data,
        })
        .collect();

    Some(PeInfo {
        machine_type: headers.coff_header.machine,
        e_lfanew: headers.dos_header.e_lfanew as u32,
        size_of_image,
        size_of_headers: headers.optional_header.size_of_headers(),
        number_of_sections,
        size_of_optional_header: headers.coff_header.size_of_optional_header,
        sections,
        is_pe32_plus: headers.is_64bit(),
    })
}

/// Validate that the PE has a valid CLI header in memory.
/// Returns true if the CLI header at the given RVA contains valid .NET metadata.
pub fn validate_cli_header_in_memory(
    process_handle: HANDLE,
    base_address: usize,
    pe_info: &PeInfo,
) -> bool {
    // Use ProcessMemoryReader with portex to get CLI data directory
    let reader = ProcessMemoryReader::new(process_handle, base_address, None);
    let headers = match PEHeaders::read_from(&reader, 0) {
        Ok(h) => h,
        Err(_) => return false,
    };

    // Get CLI Runtime data directory (index 14)
    let cli_dir = match headers
        .optional_header
        .data_directories()
        .get(DataDirectoryType::ClrRuntime.as_index())
    {
        Some(dir) if dir.virtual_address != 0 && dir.size >= 72 => dir,
        _ => return false,
    };

    let cli_rva = cli_dir.virtual_address;

    // Read the CLI header from memory (still need direct read for content validation)
    let cli_header_addr = base_address + cli_rva as usize;
    let mut cli_header = [0u8; 16];
    let mut bytes_read = 0usize;

    let result = unsafe {
        ReadProcessMemory(
            process_handle,
            cli_header_addr as *const c_void,
            cli_header.as_mut_ptr() as *mut c_void,
            16,
            Some(&mut bytes_read),
        )
    };

    if result.is_err() || bytes_read < 16 {
        return false;
    }

    // Validate CLI header structure:
    // - cb (size) should be 0x48 (72 bytes)
    // - MajorRuntimeVersion should be 2
    // - MinorRuntimeVersion should be 0 or 5
    let cb = u32::from_le_bytes([cli_header[0], cli_header[1], cli_header[2], cli_header[3]]);
    let major_version = u16::from_le_bytes([cli_header[4], cli_header[5]]);
    let minor_version = u16::from_le_bytes([cli_header[6], cli_header[7]]);

    // cb should be 0x48, major should be 2, minor should be 0 or 5
    if cb != 0x48 {
        return false;
    }
    if major_version != 2 {
        return false;
    }
    if minor_version != 0 && minor_version != 5 {
        return false;
    }

    // Also validate metadata RVA is reasonable
    let meta_rva =
        u32::from_le_bytes([cli_header[8], cli_header[9], cli_header[10], cli_header[11]]);
    let meta_size = u32::from_le_bytes([
        cli_header[12],
        cli_header[13],
        cli_header[14],
        cli_header[15],
    ]);

    // Metadata RVA should be less than image size
    if meta_rva == 0 || meta_size == 0 || meta_rva > pe_info.size_of_image {
        return false;
    }

    true
}

/// Extract entry point token from a PE file by reading the COR20 header.
/// Returns the entry point token, or 0 if not found.
pub fn extract_entry_point_from_pe(pe_data: &[u8]) -> u32 {
    // Use portex helper to get CLI directory info
    let cli_info = match get_cli_directory_from_slice(pe_data) {
        Some(info) => info,
        None => return 0,
    };

    // Get CLI file offset (using portex's RVA-to-offset conversion)
    let clr_file_offset = match cli_info.cli_file_offset {
        Some(offset) => offset as usize,
        None => return 0,
    };

    if pe_data.len() < clr_file_offset + 24 {
        return 0;
    }

    // Entry point token is at offset 20 in COR20 header
    u32::from_le_bytes([
        pe_data[clr_file_offset + 20],
        pe_data[clr_file_offset + 21],
        pe_data[clr_file_offset + 22],
        pe_data[clr_file_offset + 23],
    ])
}

/// Extract entry point token and flags from raw metadata.
/// Returns (entry_point_token, flags) where:
/// - entry_point_token is the MethodDef token for Main() if found, or 0
/// - flags are the COR20 flags to use
pub fn extract_metadata_info(metadata: &[u8]) -> (u32, u32) {
    // Default: IL-only, no entry point
    let flags: u32 = 0x00000001; // COMIMAGE_FLAGS_ILONLY
    let mut entry_point: u32 = 0;

    // Parse metadata to find entry point
    // We look for a method named "Main" in the MethodDef table
    if let Some(ep) = find_entry_point_in_metadata(metadata) {
        entry_point = ep;
    }

    // Check if this is a 32-bit preferred assembly by looking at Assembly flags
    // For now, we just use IL-only
    (entry_point, flags)
}

/// Find the entry point method token in metadata.
/// Looks for a static method named "Main" or "<Main>$" (top-level statements).
fn find_entry_point_in_metadata(metadata: &[u8]) -> Option<u32> {
    // Check BSJB signature
    if metadata.len() < 16 || &metadata[0..4] != b"BSJB" {
        return None;
    }

    // Parse metadata header
    let version_length =
        u32::from_le_bytes([metadata[12], metadata[13], metadata[14], metadata[15]]) as usize;
    let version_padded = (version_length + 3) & !3;
    let streams_offset = 16 + version_padded;

    if streams_offset + 4 > metadata.len() {
        return None;
    }

    let num_streams =
        u16::from_le_bytes([metadata[streams_offset + 2], metadata[streams_offset + 3]]) as usize;

    // Find #Strings and #~ streams
    let mut strings_offset = 0usize;
    let mut strings_size = 0usize;
    let mut tilde_offset = 0usize;
    let mut tilde_size = 0usize;

    let mut pos = streams_offset + 4;
    for _ in 0..num_streams {
        if pos + 8 > metadata.len() {
            break;
        }

        let stream_offset = u32::from_le_bytes([
            metadata[pos],
            metadata[pos + 1],
            metadata[pos + 2],
            metadata[pos + 3],
        ]) as usize;
        let stream_size = u32::from_le_bytes([
            metadata[pos + 4],
            metadata[pos + 5],
            metadata[pos + 6],
            metadata[pos + 7],
        ]) as usize;

        pos += 8;

        let name_start = pos;
        while pos < metadata.len() && metadata[pos] != 0 {
            pos += 1;
        }
        let name = std::str::from_utf8(&metadata[name_start..pos]).unwrap_or("");
        pos += 1;
        pos = (pos + 3) & !3;

        match name {
            "#Strings" => {
                strings_offset = stream_offset;
                strings_size = stream_size;
            }
            "#~" | "#-" => {
                tilde_offset = stream_offset;
                tilde_size = stream_size;
            }
            _ => {}
        }
    }

    if strings_offset == 0 || tilde_offset == 0 {
        return None;
    }

    let tilde = metadata.get(tilde_offset..tilde_offset + tilde_size)?;
    let strings = metadata.get(strings_offset..strings_offset + strings_size)?;

    find_main_method_token(tilde, strings)
}

/// Find the MethodDef token for Main method.
fn find_main_method_token(tilde: &[u8], strings: &[u8]) -> Option<u32> {
    if tilde.len() < 24 {
        return None;
    }

    let heap_sizes = tilde[6];
    let string_idx_size = if heap_sizes & 0x01 != 0 { 4 } else { 2 };
    let guid_idx_size = if heap_sizes & 0x02 != 0 { 4 } else { 2 };
    let blob_idx_size = if heap_sizes & 0x04 != 0 { 4 } else { 2 };

    let valid = u64::from_le_bytes([
        tilde[8], tilde[9], tilde[10], tilde[11], tilde[12], tilde[13], tilde[14], tilde[15],
    ]);

    // MethodDef table is table 0x06
    let methoddef_bit = 1u64 << 0x06;
    if valid & methoddef_bit == 0 {
        return None;
    }

    // Read row counts
    let mut pos = 24usize;
    let mut row_counts: Vec<u32> = Vec::new();

    for i in 0..64 {
        if valid & (1u64 << i) != 0 {
            if pos + 4 > tilde.len() {
                return None;
            }
            let count =
                u32::from_le_bytes([tilde[pos], tilde[pos + 1], tilde[pos + 2], tilde[pos + 3]]);
            row_counts.push(count);
            pos += 4;
        }
    }

    // Calculate offset to MethodDef table
    let tables_start = pos;
    let mut methoddef_offset = 0usize;
    let mut current_offset = tables_start;

    for i in 0..64 {
        if valid & (1u64 << i) != 0 {
            if i == 0x06 {
                methoddef_offset = current_offset;
                break;
            }
            let row_size = get_table_row_size(
                i,
                &row_counts,
                valid,
                string_idx_size,
                guid_idx_size,
                blob_idx_size,
            );
            let table_index = count_bits_before(valid, i);
            let row_count = *row_counts.get(table_index)? as usize;
            current_offset += row_size * row_count;
        }
    }

    if methoddef_offset == 0 {
        return None;
    }

    // Get MethodDef row count
    let methoddef_table_index = count_bits_before(valid, 0x06);
    let methoddef_count = *row_counts.get(methoddef_table_index)? as usize;

    // MethodDef row format (ECMA-335 II.22.26):
    // RVA: u32
    // ImplFlags: u16
    // Flags: u16
    // Name: String index
    // Signature: Blob index
    // ParamList: Param index

    // Calculate ParamList index size
    let param_idx_size = simple_idx_size(&row_counts, valid, 0x08); // Param table

    let methoddef_row_size = 4 + 2 + 2 + string_idx_size + blob_idx_size + param_idx_size;
    let name_offset_in_row = 4 + 2 + 2; // After RVA, ImplFlags, Flags

    // Search for "Main" or "<Main>$" method
    for row in 0..methoddef_count {
        let row_offset = methoddef_offset + row * methoddef_row_size;
        let name_pos = row_offset + name_offset_in_row;

        if name_pos + string_idx_size > tilde.len() {
            continue;
        }

        let name_index = if string_idx_size == 4 {
            u32::from_le_bytes([
                tilde[name_pos],
                tilde[name_pos + 1],
                tilde[name_pos + 2],
                tilde[name_pos + 3],
            ]) as usize
        } else {
            u16::from_le_bytes([tilde[name_pos], tilde[name_pos + 1]]) as usize
        };

        if name_index >= strings.len() {
            continue;
        }

        // Read null-terminated string
        let mut end = name_index;
        while end < strings.len() && strings[end] != 0 {
            end += 1;
        }
        let name = std::str::from_utf8(&strings[name_index..end]).unwrap_or("");

        // Check for Main or <Main>$ (top-level statements)
        if name == "Main" || name == "<Main>$" {
            // MethodDef token = 0x06000000 | (row + 1)
            return Some(0x06000000 | ((row + 1) as u32));
        }
    }

    None
}

/// Information about a method's IL from metadata.
#[derive(Debug, Clone)]
pub struct MethodRvaInfo {
    /// MethodDef token (0x06xxxxxx).
    #[allow(dead_code)]
    pub token: u32,
    /// RVA of the method body.
    pub rva: u32,
    /// Method name (if extracted).
    #[allow(dead_code)]
    pub name: Option<String>,
}

/// Extract all method RVAs from metadata.
/// Returns a list of (token, rva) for methods with RVA != 0.
/// These RVAs can be used with GetILForModule to retrieve IL code addresses.
pub fn extract_method_rvas(metadata: &[u8]) -> Vec<MethodRvaInfo> {
    let mut methods = Vec::new();

    // Check BSJB signature
    if metadata.len() < 16 || &metadata[0..4] != b"BSJB" {
        return methods;
    }

    // Parse metadata header
    let version_length =
        u32::from_le_bytes([metadata[12], metadata[13], metadata[14], metadata[15]]) as usize;
    let version_padded = (version_length + 3) & !3;
    let streams_offset = 16 + version_padded;

    if streams_offset + 4 > metadata.len() {
        return methods;
    }

    let num_streams =
        u16::from_le_bytes([metadata[streams_offset + 2], metadata[streams_offset + 3]]) as usize;

    // Find #Strings and #~ streams
    let mut strings_offset = 0usize;
    let mut strings_size = 0usize;
    let mut tilde_offset = 0usize;
    let mut tilde_size = 0usize;

    let mut pos = streams_offset + 4;
    for _ in 0..num_streams {
        if pos + 8 > metadata.len() {
            break;
        }

        let stream_offset = u32::from_le_bytes([
            metadata[pos],
            metadata[pos + 1],
            metadata[pos + 2],
            metadata[pos + 3],
        ]) as usize;
        let stream_size = u32::from_le_bytes([
            metadata[pos + 4],
            metadata[pos + 5],
            metadata[pos + 6],
            metadata[pos + 7],
        ]) as usize;

        pos += 8;

        let name_start = pos;
        while pos < metadata.len() && metadata[pos] != 0 {
            pos += 1;
        }
        let name = std::str::from_utf8(&metadata[name_start..pos]).unwrap_or("");
        pos += 1;
        pos = (pos + 3) & !3;

        match name {
            "#Strings" => {
                strings_offset = stream_offset;
                strings_size = stream_size;
            }
            "#~" | "#-" => {
                tilde_offset = stream_offset;
                tilde_size = stream_size;
            }
            _ => {}
        }
    }

    if tilde_offset == 0 {
        return methods;
    }

    let Some(tilde) = metadata.get(tilde_offset..tilde_offset + tilde_size) else {
        return methods;
    };
    let strings = metadata.get(strings_offset..strings_offset + strings_size);

    if tilde.len() < 24 {
        return methods;
    }

    let heap_sizes = tilde[6];
    let string_idx_size = if heap_sizes & 0x01 != 0 { 4 } else { 2 };
    let guid_idx_size = if heap_sizes & 0x02 != 0 { 4 } else { 2 };
    let blob_idx_size = if heap_sizes & 0x04 != 0 { 4 } else { 2 };

    let valid = u64::from_le_bytes([
        tilde[8], tilde[9], tilde[10], tilde[11], tilde[12], tilde[13], tilde[14], tilde[15],
    ]);

    // MethodDef table is table 0x06
    let methoddef_bit = 1u64 << 0x06;
    if valid & methoddef_bit == 0 {
        return methods;
    }

    // Read row counts
    let mut pos = 24usize;
    let mut row_counts: Vec<u32> = Vec::new();

    for i in 0..64 {
        if valid & (1u64 << i) != 0 {
            if pos + 4 > tilde.len() {
                return methods;
            }
            let count =
                u32::from_le_bytes([tilde[pos], tilde[pos + 1], tilde[pos + 2], tilde[pos + 3]]);
            row_counts.push(count);
            pos += 4;
        }
    }

    // Calculate offset to MethodDef table
    let tables_start = pos;
    let mut methoddef_offset = 0usize;
    let mut current_offset = tables_start;

    for i in 0..64 {
        if valid & (1u64 << i) != 0 {
            if i == 0x06 {
                methoddef_offset = current_offset;
                break;
            }
            let row_size = get_table_row_size(
                i,
                &row_counts,
                valid,
                string_idx_size,
                guid_idx_size,
                blob_idx_size,
            );
            let table_index = count_bits_before(valid, i);
            let Some(&row_count) = row_counts.get(table_index) else {
                return methods;
            };
            current_offset += row_size * row_count as usize;
        }
    }

    if methoddef_offset == 0 {
        return methods;
    }

    // Get MethodDef row count
    let methoddef_table_index = count_bits_before(valid, 0x06);
    let Some(&methoddef_count) = row_counts.get(methoddef_table_index) else {
        return methods;
    };

    // MethodDef row format (ECMA-335 II.22.26):
    // RVA: u32
    // ImplFlags: u16
    // Flags: u16
    // Name: String index
    // Signature: Blob index
    // ParamList: Param index
    let param_idx_size = simple_idx_size(&row_counts, valid, 0x08);
    let methoddef_row_size = 4 + 2 + 2 + string_idx_size + blob_idx_size + param_idx_size;

    for row in 0..methoddef_count as usize {
        let row_offset = methoddef_offset + row * methoddef_row_size;

        if row_offset + 4 > tilde.len() {
            break;
        }

        // Read RVA (first 4 bytes)
        let rva = u32::from_le_bytes([
            tilde[row_offset],
            tilde[row_offset + 1],
            tilde[row_offset + 2],
            tilde[row_offset + 3],
        ]);

        // Skip methods with RVA 0 (abstract/extern methods)
        if rva == 0 {
            continue;
        }

        let token = 0x06000000 | ((row + 1) as u32);

        // Optionally read method name
        let name = if let Some(strings) = strings {
            let name_pos = row_offset + 4 + 2 + 2; // After RVA, ImplFlags, Flags
            if name_pos + string_idx_size <= tilde.len() {
                let name_index = if string_idx_size == 4 {
                    u32::from_le_bytes([
                        tilde[name_pos],
                        tilde[name_pos + 1],
                        tilde[name_pos + 2],
                        tilde[name_pos + 3],
                    ]) as usize
                } else {
                    u16::from_le_bytes([tilde[name_pos], tilde[name_pos + 1]]) as usize
                };

                if name_index < strings.len() {
                    let mut end = name_index;
                    while end < strings.len() && strings[end] != 0 {
                        end += 1;
                    }
                    std::str::from_utf8(&strings[name_index..end])
                        .ok()
                        .map(|s| s.to_string())
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        methods.push(MethodRvaInfo { token, rva, name });
    }

    methods
}

/// Build a minimal PE from raw metadata bytes.
/// This is used when ilBase doesn't point to a valid PE but we have metadata from DAC.
///
/// PE Layout:
/// 0x000: DOS Header (64 bytes)
/// 0x040: DOS Stub (64 bytes)
/// 0x080: PE Signature (4 bytes)
/// 0x084: COFF Header (20 bytes)
/// 0x098: Optional Header PE32+ (112 bytes + 16*8 data dirs = 240 bytes)
/// 0x188: Section Header .text (40 bytes)
/// 0x1B0: Padding to 0x200
/// 0x200: .text section start
/// 0x200: COR20 Header (72 bytes)
/// 0x248: Metadata
pub fn build_pe_from_metadata(metadata: &[u8], is_64bit: bool) -> Vec<u8> {
    // Extract entry point and flags from metadata
    let (entry_point_token, cor_flags) = extract_metadata_info(metadata);

    const COR20_SIZE: u32 = 72;
    const TEXT_RVA: u32 = 0x1000;
    const METADATA_RVA: u32 = TEXT_RVA + COR20_SIZE;

    let metadata_size = metadata.len() as u32;

    // Build COR20 header + metadata as section data
    let section_data = build_cor20_and_metadata(
        METADATA_RVA,
        metadata_size,
        cor_flags,
        entry_point_token,
        metadata,
    );

    // Build PE using portex
    let pe = build_dotnet_pe(
        is_64bit,
        entry_point_token == 0,
        &section_data,
        TEXT_RVA,
        COR20_SIZE,
    );
    pe.build()
}

/// Build a minimal .NET PE structure using portex.
fn build_dotnet_pe(
    is_64bit: bool,
    is_dll: bool,
    text_section_data: &[u8],
    cli_rva: u32,
    cli_size: u32,
) -> PE {
    const FILE_ALIGNMENT: u32 = 0x200;
    const SECTION_ALIGNMENT: u32 = 0x1000;

    // Create DOS header
    let dos_header = DosHeader {
        e_magic: 0x5A4D, // "MZ"
        e_cblp: 0,
        e_cp: 0,
        e_crlc: 0,
        e_cparhdr: 0,
        e_minalloc: 0,
        e_maxalloc: 0,
        e_ss: 0,
        e_sp: 0,
        e_csum: 0,
        e_ip: 0,
        e_cs: 0,
        e_lfarlc: 0,
        e_ovno: 0,
        e_res: [0; 4],
        e_oemid: 0,
        e_oeminfo: 0,
        e_res2: [0; 10],
        e_lfanew: 0x80,
    };

    // Machine type
    let machine = if is_64bit { 0x8664 } else { 0x014C };

    // COFF characteristics
    let mut characteristics = coff_chars::EXECUTABLE_IMAGE | coff_chars::LARGE_ADDRESS_AWARE;
    if is_dll {
        characteristics |= coff_chars::DLL;
    }

    // Create COFF header (will be updated by portex)
    let coff_header = CoffHeader {
        machine,
        number_of_sections: 1,
        time_date_stamp: 0,
        pointer_to_symbol_table: 0,
        number_of_symbols: 0,
        size_of_optional_header: 0, // Will be set by portex
        characteristics,
    };

    // DLL characteristics
    let dll_chars = dll_characteristics::DYNAMIC_BASE
        | dll_characteristics::NX_COMPAT
        | dll_characteristics::NO_SEH
        | dll_characteristics::TERMINAL_SERVER_AWARE;

    // Create 16 data directories (all zeroed initially)
    let mut data_directories = vec![DataDirectory::default(); 16];
    // Set CLR Runtime directory (index 14)
    data_directories[DataDirectoryType::ClrRuntime.as_index()] = DataDirectory {
        virtual_address: cli_rva,
        size: cli_size,
    };

    // Create optional header
    let optional_header = if is_64bit {
        OptionalHeader::Pe32Plus(OptionalHeader64 {
            magic: 0x20B,
            major_linker_version: 14,
            minor_linker_version: 0,
            size_of_code: 0, // Will be updated
            size_of_initialized_data: 0,
            size_of_uninitialized_data: 0,
            address_of_entry_point: 0, // Pure IL
            base_of_code: SECTION_ALIGNMENT,
            image_base: 0x180000000,
            section_alignment: SECTION_ALIGNMENT,
            file_alignment: FILE_ALIGNMENT,
            major_operating_system_version: 6,
            minor_operating_system_version: 0,
            major_image_version: 0,
            minor_image_version: 0,
            major_subsystem_version: 6,
            minor_subsystem_version: 0,
            win32_version_value: 0,
            size_of_image: 0,   // Will be updated
            size_of_headers: 0, // Will be updated
            check_sum: 0,
            subsystem: 3, // WINDOWS_CUI
            dll_characteristics: dll_chars,
            size_of_stack_reserve: 0x100000,
            size_of_stack_commit: 0x1000,
            size_of_heap_reserve: 0x100000,
            size_of_heap_commit: 0x1000,
            loader_flags: 0,
            number_of_rva_and_sizes: 16,
            data_directories,
        })
    } else {
        OptionalHeader::Pe32(OptionalHeader32 {
            magic: 0x10B,
            major_linker_version: 14,
            minor_linker_version: 0,
            size_of_code: 0,
            size_of_initialized_data: 0,
            size_of_uninitialized_data: 0,
            address_of_entry_point: 0,
            base_of_code: SECTION_ALIGNMENT,
            base_of_data: SECTION_ALIGNMENT,
            image_base: 0x10000000,
            section_alignment: SECTION_ALIGNMENT,
            file_alignment: FILE_ALIGNMENT,
            major_operating_system_version: 6,
            minor_operating_system_version: 0,
            major_image_version: 0,
            minor_image_version: 0,
            major_subsystem_version: 6,
            minor_subsystem_version: 0,
            win32_version_value: 0,
            size_of_image: 0,
            size_of_headers: 0,
            check_sum: 0,
            subsystem: 3,
            dll_characteristics: dll_chars,
            size_of_stack_reserve: 0x100000,
            size_of_stack_commit: 0x1000,
            size_of_heap_reserve: 0x100000,
            size_of_heap_commit: 0x1000,
            loader_flags: 0,
            number_of_rva_and_sizes: 16,
            data_directories,
        })
    };

    // Create .text section
    let mut text_section = Section::new(
        ".text",
        sec_chars::CODE | sec_chars::EXECUTE | sec_chars::READ,
    );
    text_section.set_data(text_section_data.to_vec());

    // Assemble PE
    PE {
        dos_header,
        dos_stub: vec![0u8; 64], // Minimal stub
        coff_header,
        optional_header,
        sections: vec![text_section],
    }
}

/// Build COR20 header + metadata as a contiguous byte buffer.
fn build_cor20_and_metadata(
    metadata_rva: u32,
    metadata_size: u32,
    cor_flags: u32,
    entry_point_token: u32,
    metadata: &[u8],
) -> Vec<u8> {
    const COR20_SIZE: usize = 72;

    let mut data = vec![0u8; COR20_SIZE + metadata.len()];

    // COR20 Header (IMAGE_COR20_HEADER)
    // cb = 72
    data[0..4].copy_from_slice(&(COR20_SIZE as u32).to_le_bytes());
    // MajorRuntimeVersion = 2
    data[4..6].copy_from_slice(&2u16.to_le_bytes());
    // MinorRuntimeVersion = 5
    data[6..8].copy_from_slice(&5u16.to_le_bytes());
    // MetaData RVA
    data[8..12].copy_from_slice(&metadata_rva.to_le_bytes());
    // MetaData Size
    data[12..16].copy_from_slice(&metadata_size.to_le_bytes());
    // Flags
    data[16..20].copy_from_slice(&cor_flags.to_le_bytes());
    // EntryPointToken
    data[20..24].copy_from_slice(&entry_point_token.to_le_bytes());
    // Rest of COR20 header fields are 0

    // Copy metadata after COR20 header
    data[COR20_SIZE..].copy_from_slice(metadata);

    data
}

use crate::process::ILMethodBody;

/// Build a PE from raw metadata bytes with IL method bodies at their original RVAs.
/// This reconstructs a more complete assembly by placing IL code where the metadata expects it.
///
/// The key insight: MethodDef RVAs in metadata already point to specific addresses.
/// We just need to ensure our PE has space at those RVAs and write the IL there.
pub fn build_pe_from_metadata_with_il(
    metadata: &[u8],
    il_bodies: &[ILMethodBody],
    is_64bit: bool,
) -> Vec<u8> {
    // If no IL bodies, fall back to basic PE
    if il_bodies.is_empty() {
        return build_pe_from_metadata(metadata, is_64bit);
    }

    let (entry_point_token, cor_flags) = extract_metadata_info(metadata);

    const TEXT_RVA: u32 = 0x1000;
    const COR20_SIZE: u32 = 72;
    const METADATA_RVA: u32 = TEXT_RVA + COR20_SIZE;

    let metadata_size = metadata.len() as u32;

    // Find the range of IL RVAs to determine section size
    let max_il_end = il_bodies
        .iter()
        .map(|b| b.rva + b.data.len() as u32)
        .max()
        .unwrap_or(0);

    // The .text section needs to span from TEXT_RVA to max(metadata_end, max_il_end)
    let metadata_end_rva = METADATA_RVA + metadata_size;
    let text_virtual_end = metadata_end_rva.max(max_il_end);
    let section_size = (text_virtual_end - TEXT_RVA) as usize;

    // Build section data with space for COR20 + metadata + IL bodies
    let section_data = build_cor20_metadata_and_il(
        METADATA_RVA,
        metadata_size,
        cor_flags,
        entry_point_token,
        metadata,
        section_size,
        TEXT_RVA,
        il_bodies,
    );

    // Build PE using portex
    let pe = build_dotnet_pe(
        is_64bit,
        entry_point_token == 0,
        &section_data,
        TEXT_RVA,
        COR20_SIZE,
    );
    pe.build()
}

/// Build COR20 header + metadata + IL bodies as a contiguous byte buffer.
#[allow(clippy::too_many_arguments)]
fn build_cor20_metadata_and_il(
    metadata_rva: u32,
    metadata_size: u32,
    cor_flags: u32,
    entry_point_token: u32,
    metadata: &[u8],
    section_size: usize,
    text_rva: u32,
    il_bodies: &[ILMethodBody],
) -> Vec<u8> {
    const COR20_SIZE: usize = 72;

    let mut data = vec![0u8; section_size];

    // COR20 Header at offset 0 (RVA = text_rva)
    data[0..4].copy_from_slice(&(COR20_SIZE as u32).to_le_bytes());
    data[4..6].copy_from_slice(&2u16.to_le_bytes()); // MajorRuntimeVersion
    data[6..8].copy_from_slice(&5u16.to_le_bytes()); // MinorRuntimeVersion
    data[8..12].copy_from_slice(&metadata_rva.to_le_bytes());
    data[12..16].copy_from_slice(&metadata_size.to_le_bytes());
    data[16..20].copy_from_slice(&cor_flags.to_le_bytes());
    data[20..24].copy_from_slice(&entry_point_token.to_le_bytes());

    // Metadata after COR20 header
    let metadata_offset = COR20_SIZE;
    if metadata_offset + metadata.len() <= data.len() {
        data[metadata_offset..metadata_offset + metadata.len()].copy_from_slice(metadata);
    }

    // Copy IL bodies at their original RVAs (relative to section start)
    for body in il_bodies {
        if body.rva >= text_rva {
            let offset = (body.rva - text_rva) as usize;
            if offset + body.data.len() <= data.len() {
                data[offset..offset + body.data.len()].copy_from_slice(&body.data);
            }
        }
    }

    data
}

// =============================================================================
// Layout Conversion
// =============================================================================

/// Convert a PE image from memory layout to file layout
pub fn convert_memory_to_file_layout(memory_image: &[u8], pe_info: &PeInfo) -> Vec<u8> {
    let mut file_size = pe_info.size_of_headers as usize;
    for section in &pe_info.sections {
        let section_end = section.pointer_to_raw_data as usize + section.size_of_raw_data as usize;
        if section_end > file_size {
            file_size = section_end;
        }
    }

    let mut file_image = vec![0u8; file_size];

    let headers_size = (pe_info.size_of_headers as usize).min(memory_image.len());
    file_image[..headers_size].copy_from_slice(&memory_image[..headers_size]);

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

// =============================================================================
// Memory Scanning
// =============================================================================

/// Scan memory regions using VirtualQueryEx
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

// =============================================================================
// PE Reconstruction (Anti-Anti-Dump)
// =============================================================================

/// Reconstruct PE headers from memory regions when original headers are corrupted.
/// `machine_type` must be provided since we can't read it from corrupted headers.
pub fn reconstruct_pe_info(
    process_handle: HANDLE,
    base_address: usize,
    machine_type: u16,
) -> Option<PeInfo> {
    let regions = scan_memory_regions(process_handle, base_address, 0x10000000);

    if regions.is_empty() {
        return None;
    }

    let mut size_of_image: u32 = 0;
    for region in &regions {
        let region_end = (region.base_address - base_address + region.size) as u32;
        if region_end > size_of_image {
            size_of_image = region_end;
        }
    }

    let mut sections = Vec::new();
    let mut current_file_offset: u32 = 0x1000;

    let committed_regions: Vec<_> = regions
        .iter()
        .filter(|r| r.is_committed && r.base_address > base_address)
        .collect();

    for region in committed_regions {
        let virtual_address = (region.base_address - base_address) as u32;
        let virtual_size = region.size as u32;

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

    if sections.is_empty() && size_of_image > 0x1000 {
        sections.push(SectionInfo {
            virtual_address: 0x1000,
            virtual_size: size_of_image - 0x1000,
            pointer_to_raw_data: 0x1000,
            size_of_raw_data: size_of_image - 0x1000,
        });
    }

    // Determine PE32+ based on machine type
    let is_pe32_plus = machine_type == 0x8664 || machine_type == 0xAA64; // AMD64 or ARM64

    Some(PeInfo {
        machine_type,
        e_lfanew: 0x80,
        size_of_image,
        size_of_headers: 0x1000,
        number_of_sections: sections.len() as u16,
        size_of_optional_header: if is_pe32_plus { 0xF0 } else { 0xE0 },
        sections,
        is_pe32_plus,
    })
}

/// Check if PE headers appear to be corrupted
pub fn is_pe_header_corrupted(buffer: &[u8]) -> bool {
    if buffer.len() < 64 {
        return true;
    }

    if buffer[0] != 0x4D || buffer[1] != 0x5A {
        return true;
    }

    let e_lfanew =
        u32::from_le_bytes([buffer[0x3C], buffer[0x3D], buffer[0x3E], buffer[0x3F]]) as usize;
    if !(64..=1024).contains(&e_lfanew) || e_lfanew + 4 > buffer.len() {
        return true;
    }

    if buffer[e_lfanew] != 0x50
        || buffer[e_lfanew + 1] != 0x45
        || buffer[e_lfanew + 2] != 0x00
        || buffer[e_lfanew + 3] != 0x00
    {
        return true;
    }

    if e_lfanew + 6 < buffer.len() {
        let num_sections = u16::from_le_bytes([buffer[e_lfanew + 6], buffer[e_lfanew + 7]]);
        if num_sections == 0 || num_sections > 96 {
            return true;
        }
    }

    false
}

/// Build a complete PE file with reconstructed headers
pub fn build_pe_with_reconstructed_headers(memory_image: &[u8], pe_info: &PeInfo) -> Vec<u8> {
    const FILE_ALIGNMENT: u32 = 0x200;
    const SECTION_ALIGNMENT: u32 = 0x1000;

    // Create DOS header
    let dos_header = DosHeader {
        e_magic: 0x5A4D,
        e_cblp: 0x90,
        e_cp: 0x03,
        e_crlc: 0,
        e_cparhdr: 0x04,
        e_minalloc: 0,
        e_maxalloc: 0xFFFF,
        e_ss: 0,
        e_sp: 0xB8,
        e_csum: 0,
        e_ip: 0,
        e_cs: 0,
        e_lfarlc: 0x40,
        e_ovno: 0,
        e_res: [0; 4],
        e_oemid: 0,
        e_oeminfo: 0,
        e_res2: [0; 10],
        e_lfanew: 0x80,
    };

    // DOS stub (minimal "This program cannot be run in DOS mode")
    let dos_stub: Vec<u8> = vec![
        0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54,
        0x68, 0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E,
        0x6E, 0x6F, 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x44,
        0x4F, 0x53, 0x20, 0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A, 0x24, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];

    // COFF characteristics: EXECUTABLE_IMAGE | DLL
    let characteristics = coff_chars::EXECUTABLE_IMAGE | coff_chars::DLL;

    let coff_header = CoffHeader {
        machine: pe_info.machine_type,
        number_of_sections: pe_info.number_of_sections,
        time_date_stamp: 0,
        pointer_to_symbol_table: 0,
        number_of_symbols: 0,
        size_of_optional_header: 0, // Will be set by portex
        characteristics,
    };

    // DLL characteristics
    let dll_chars = dll_characteristics::DYNAMIC_BASE
        | dll_characteristics::NX_COMPAT
        | dll_characteristics::NO_SEH
        | dll_characteristics::TERMINAL_SERVER_AWARE;

    // Create data directories (16 entries, all zeroed for reconstruction)
    let data_directories = vec![DataDirectory::default(); 16];

    // Create optional header
    let optional_header = if pe_info.is_pe32_plus {
        OptionalHeader::Pe32Plus(OptionalHeader64 {
            magic: 0x20B,
            major_linker_version: 14,
            minor_linker_version: 0,
            size_of_code: 0,
            size_of_initialized_data: 0,
            size_of_uninitialized_data: 0,
            address_of_entry_point: 0,
            base_of_code: SECTION_ALIGNMENT,
            image_base: 0x180000000,
            section_alignment: SECTION_ALIGNMENT,
            file_alignment: FILE_ALIGNMENT,
            major_operating_system_version: 6,
            minor_operating_system_version: 0,
            major_image_version: 0,
            minor_image_version: 0,
            major_subsystem_version: 6,
            minor_subsystem_version: 0,
            win32_version_value: 0,
            size_of_image: pe_info.size_of_image,
            size_of_headers: 0, // Will be updated
            check_sum: 0,
            subsystem: 3, // WINDOWS_CUI
            dll_characteristics: dll_chars,
            size_of_stack_reserve: 0x100000,
            size_of_stack_commit: 0x1000,
            size_of_heap_reserve: 0x100000,
            size_of_heap_commit: 0x1000,
            loader_flags: 0,
            number_of_rva_and_sizes: 16,
            data_directories,
        })
    } else {
        OptionalHeader::Pe32(OptionalHeader32 {
            magic: 0x10B,
            major_linker_version: 14,
            minor_linker_version: 0,
            size_of_code: 0,
            size_of_initialized_data: 0,
            size_of_uninitialized_data: 0,
            address_of_entry_point: 0,
            base_of_code: SECTION_ALIGNMENT,
            base_of_data: SECTION_ALIGNMENT,
            image_base: 0x10000000,
            section_alignment: SECTION_ALIGNMENT,
            file_alignment: FILE_ALIGNMENT,
            major_operating_system_version: 6,
            minor_operating_system_version: 0,
            major_image_version: 0,
            minor_image_version: 0,
            major_subsystem_version: 6,
            minor_subsystem_version: 0,
            win32_version_value: 0,
            size_of_image: pe_info.size_of_image,
            size_of_headers: 0,
            check_sum: 0,
            subsystem: 3,
            dll_characteristics: dll_chars,
            size_of_stack_reserve: 0x100000,
            size_of_stack_commit: 0x1000,
            size_of_heap_reserve: 0x100000,
            size_of_heap_commit: 0x1000,
            loader_flags: 0,
            number_of_rva_and_sizes: 16,
            data_directories,
        })
    };

    // Build sections from pe_info
    let section_names = [".text", ".rdata", ".data", ".rsrc", ".sect"];
    let mut sections = Vec::new();
    for (i, section_info) in pe_info.sections.iter().enumerate() {
        let name = section_names.get(i).unwrap_or(&".sect");
        let characteristics = sec_chars::CODE | sec_chars::EXECUTE | sec_chars::READ;

        let mut section = Section::new(name, characteristics);

        // Extract section data from memory image
        let src_offset = section_info.virtual_address as usize;
        let copy_size = (section_info.size_of_raw_data as usize)
            .min(section_info.virtual_size as usize)
            .min(memory_image.len().saturating_sub(src_offset));

        if copy_size > 0 && src_offset < memory_image.len() {
            let data = memory_image[src_offset..src_offset + copy_size].to_vec();
            section.set_data(data);
        }

        sections.push(section);
    }

    // Assemble PE
    let pe = PE {
        dos_header,
        dos_stub,
        coff_header,
        optional_header,
        sections,
    };

    pe.build()
}

// =============================================================================
// Metadata Reconstruction (Anti-Anti-Dump)
// =============================================================================

/// Information about located metadata streams for reconstruction.
#[derive(Debug, Clone, Default)]
pub struct MetadataStreamLocations {
    /// Offset of #~ or #- stream (table stream) relative to metadata start
    pub tilde_offset: usize,
    /// Size of #~ or #- stream
    pub tilde_size: usize,
    /// Whether this is compressed (#~) or uncompressed (#-)
    pub is_compressed: bool,
    /// Offset of #Strings heap
    pub strings_offset: usize,
    /// Size of #Strings heap
    pub strings_size: usize,
    /// Offset of #US (user strings) heap
    pub us_offset: usize,
    /// Size of #US heap
    pub us_size: usize,
    /// Offset of #GUID heap
    pub guid_offset: usize,
    /// Size of #GUID heap
    pub guid_size: usize,
    /// Offset of #Blob heap
    pub blob_offset: usize,
    /// Size of #Blob heap
    pub blob_size: usize,
}

/// Try to locate the #~ stream by scanning for its characteristic pattern.
/// The #~ stream starts with:
/// - Reserved: u32 (usually 0)
/// - MajorVersion: u8 (usually 2)
/// - MinorVersion: u8 (usually 0)
/// - HeapSizes: u8 (flags for heap index sizes)
/// - Reserved: u8 (usually 1)
/// - Valid: u64 (bitmask of present tables)
/// - Sorted: u64 (bitmask of sorted tables)
///
/// We look for patterns where:
/// - Valid mask has reasonable bits set (Module table 0x01 is always present)
/// - Row counts following are reasonable (< 0x1000000)
pub fn scan_for_tilde_stream(metadata: &[u8]) -> Option<(usize, usize)> {
    // Minimum #~ header is 24 bytes + at least one row count
    if metadata.len() < 28 {
        return None;
    }

    // Scan through metadata looking for #~ stream pattern
    for offset in 0..metadata.len().saturating_sub(28) {
        if let Some(size) = check_tilde_stream_at(metadata, offset) {
            return Some((offset, size));
        }
    }

    None
}

/// Check if there's a valid #~ stream at the given offset.
/// Returns the stream size if valid.
fn check_tilde_stream_at(metadata: &[u8], offset: usize) -> Option<usize> {
    if offset + 24 > metadata.len() {
        return None;
    }

    let data = &metadata[offset..];

    // Reserved should be 0
    let reserved = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if reserved != 0 {
        return None;
    }

    // Major version should be 1 or 2
    let major = data[4];
    if major != 1 && major != 2 {
        return None;
    }

    // Minor version should be 0
    let minor = data[5];
    if minor != 0 {
        return None;
    }

    // HeapSizes is a flags byte (0-7 are valid values)
    let heap_sizes = data[6];
    if heap_sizes > 7 {
        return None;
    }

    // Reserved2 should be 1
    let reserved2 = data[7];
    if reserved2 != 1 {
        return None;
    }

    // Valid mask - Module table (bit 0) should always be present
    let valid = u64::from_le_bytes([
        data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
    ]);

    // Module table (0x00) must be present
    if valid & 1 == 0 {
        return None;
    }

    // Count set bits to determine number of row counts
    let table_count = valid.count_ones() as usize;
    if table_count == 0 || table_count > 64 {
        return None;
    }

    // Check that we have enough space for row counts
    let row_counts_start = 24;
    let row_counts_size = table_count * 4;
    if offset + row_counts_start + row_counts_size > metadata.len() {
        return None;
    }

    // Validate row counts are reasonable
    for i in 0..table_count {
        let row_offset = row_counts_start + i * 4;
        let row_count = u32::from_le_bytes([
            data[row_offset],
            data[row_offset + 1],
            data[row_offset + 2],
            data[row_offset + 3],
        ]);

        // Row counts should be reasonable (< 16 million)
        if row_count > 0x1000000 {
            return None;
        }
    }

    // Calculate approximate stream size based on table data
    // This is a rough estimate - actual size depends on table row sizes
    let header_size = row_counts_start + row_counts_size;

    // For now, estimate remaining size as the rest of metadata or a reasonable max
    let remaining = metadata.len() - offset;
    let estimated_size = remaining.min(0x100000); // Cap at 1MB

    Some(estimated_size.max(header_size))
}

/// Scan for #Strings heap by looking for null-terminated ASCII strings.
/// The #Strings heap starts with a null byte and contains null-terminated strings.
pub fn scan_for_strings_heap(metadata: &[u8], start_after: usize) -> Option<(usize, usize)> {
    if start_after >= metadata.len() {
        return None;
    }

    // Look for a region that starts with 0x00 and contains printable ASCII
    for offset in start_after..metadata.len().saturating_sub(16) {
        // #Strings heap starts with a null byte (empty string at index 0)
        if metadata[offset] != 0 {
            continue;
        }

        // Check if following bytes look like null-terminated strings
        let mut valid_strings = 0;
        let mut pos = offset + 1;
        let mut last_null = offset;

        while pos < metadata.len() && pos < offset + 0x10000 {
            let b = metadata[pos];

            if b == 0 {
                // End of a string
                let str_len = pos - last_null - 1;
                if str_len > 0 && str_len < 256 {
                    valid_strings += 1;
                }
                last_null = pos;

                if valid_strings >= 5 {
                    // Found enough valid strings, estimate size
                    let size = find_heap_end(metadata, offset);
                    return Some((offset, size));
                }
            } else if !b.is_ascii() || (b < 0x20 && b != 0x09 && b != 0x0A && b != 0x0D) {
                // Non-printable, non-whitespace character - probably not #Strings
                break;
            }

            pos += 1;
        }
    }

    None
}

/// Find the end of a heap by looking for padding or next structure.
fn find_heap_end(metadata: &[u8], start: usize) -> usize {
    // Look for a run of zeros that might indicate padding
    let mut pos = start;
    let mut zero_run = 0;

    while pos < metadata.len() {
        if metadata[pos] == 0 {
            zero_run += 1;
            if zero_run >= 4 {
                // Found padding, heap ends here
                return pos - zero_run + 1 - start;
            }
        } else {
            zero_run = 0;
        }
        pos += 1;
    }

    metadata.len() - start
}

/// Reconstruct corrupted metadata by rebuilding the BSJB header and stream headers.
/// This is used when the metadata signature or stream headers have been zeroed/corrupted.
///
/// # Arguments
/// * `metadata` - Raw metadata bytes (may have corrupted header)
/// * `streams` - Located stream information (from scanning or DAC)
///
/// # Returns
/// Reconstructed metadata with valid BSJB header and stream headers
pub fn reconstruct_metadata_header(metadata: &[u8], streams: &MetadataStreamLocations) -> Vec<u8> {
    // Calculate sizes
    let version_string = b"v4.0.30319\0\0"; // 12 bytes, padded to 4-byte boundary
    let version_length = 12u32;

    // Count active streams
    let mut stream_count = 0u16;
    if streams.tilde_size > 0 {
        stream_count += 1;
    }
    if streams.strings_size > 0 {
        stream_count += 1;
    }
    if streams.us_size > 0 {
        stream_count += 1;
    }
    if streams.guid_size > 0 {
        stream_count += 1;
    }
    if streams.blob_size > 0 {
        stream_count += 1;
    }

    // Calculate header size
    // STORAGESIGNATURE: 16 + version_length bytes
    // STORAGEHEADER: 4 bytes
    // Stream headers: variable (8 bytes + name aligned to 4)
    let storage_sig_size = 16 + version_length as usize;
    let storage_header_size = 4;

    // Stream header sizes (offset:4 + size:4 + name aligned to 4)
    let tilde_header_size = if streams.tilde_size > 0 { 12 } else { 0 }; // "#~\0\0" or "#-\0\0"
    let strings_header_size = if streams.strings_size > 0 { 8 + 12 } else { 0 }; // "#Strings\0" padded
    let us_header_size = if streams.us_size > 0 { 8 + 4 } else { 0 }; // "#US\0"
    let guid_header_size = if streams.guid_size > 0 { 8 + 8 } else { 0 }; // "#GUID\0" padded
    let blob_header_size = if streams.blob_size > 0 { 8 + 8 } else { 0 }; // "#Blob\0" padded

    let total_header_size = storage_sig_size
        + storage_header_size
        + tilde_header_size
        + strings_header_size
        + us_header_size
        + guid_header_size
        + blob_header_size;

    // Calculate new stream offsets (relative to metadata start)
    let new_tilde_offset = total_header_size;
    let new_strings_offset = new_tilde_offset + streams.tilde_size;
    let new_us_offset = new_strings_offset + streams.strings_size;
    let new_guid_offset = new_us_offset + streams.us_size;
    let new_blob_offset = new_guid_offset + streams.guid_size;
    let total_size = new_blob_offset + streams.blob_size;

    let mut result = vec![0u8; total_size];

    // Write STORAGESIGNATURE
    result[0..4].copy_from_slice(b"BSJB"); // lSignature
    result[4..6].copy_from_slice(&1u16.to_le_bytes()); // iMajorVer
    result[6..8].copy_from_slice(&1u16.to_le_bytes()); // iMinorVer
    result[8..12].copy_from_slice(&0u32.to_le_bytes()); // iExtraData
    result[12..16].copy_from_slice(&version_length.to_le_bytes()); // iVersionString
    result[16..16 + version_string.len()].copy_from_slice(version_string);

    // Write STORAGEHEADER
    let storage_header_offset = storage_sig_size;
    result[storage_header_offset] = 0; // fFlags
    result[storage_header_offset + 1] = 0; // pad
    result[storage_header_offset + 2..storage_header_offset + 4]
        .copy_from_slice(&stream_count.to_le_bytes()); // iStreams

    // Write stream headers
    let mut header_pos = storage_header_offset + storage_header_size;

    // #~ or #- stream
    if streams.tilde_size > 0 {
        result[header_pos..header_pos + 4]
            .copy_from_slice(&(new_tilde_offset as u32).to_le_bytes());
        result[header_pos + 4..header_pos + 8]
            .copy_from_slice(&(streams.tilde_size as u32).to_le_bytes());
        if streams.is_compressed {
            result[header_pos + 8..header_pos + 12].copy_from_slice(b"#~\0\0");
        } else {
            result[header_pos + 8..header_pos + 12].copy_from_slice(b"#-\0\0");
        }
        header_pos += tilde_header_size;
    }

    // #Strings stream
    if streams.strings_size > 0 {
        result[header_pos..header_pos + 4]
            .copy_from_slice(&(new_strings_offset as u32).to_le_bytes());
        result[header_pos + 4..header_pos + 8]
            .copy_from_slice(&(streams.strings_size as u32).to_le_bytes());
        result[header_pos + 8..header_pos + 17].copy_from_slice(b"#Strings\0");
        // Pad to 4 bytes (name is 9 bytes, pad to 12)
        header_pos += strings_header_size;
    }

    // #US stream
    if streams.us_size > 0 {
        result[header_pos..header_pos + 4].copy_from_slice(&(new_us_offset as u32).to_le_bytes());
        result[header_pos + 4..header_pos + 8]
            .copy_from_slice(&(streams.us_size as u32).to_le_bytes());
        result[header_pos + 8..header_pos + 12].copy_from_slice(b"#US\0");
        header_pos += us_header_size;
    }

    // #GUID stream
    if streams.guid_size > 0 {
        result[header_pos..header_pos + 4].copy_from_slice(&(new_guid_offset as u32).to_le_bytes());
        result[header_pos + 4..header_pos + 8]
            .copy_from_slice(&(streams.guid_size as u32).to_le_bytes());
        result[header_pos + 8..header_pos + 14].copy_from_slice(b"#GUID\0");
        // Pad to 8 bytes
        header_pos += guid_header_size;
    }

    // #Blob stream
    if streams.blob_size > 0 {
        result[header_pos..header_pos + 4].copy_from_slice(&(new_blob_offset as u32).to_le_bytes());
        result[header_pos + 4..header_pos + 8]
            .copy_from_slice(&(streams.blob_size as u32).to_le_bytes());
        result[header_pos + 8..header_pos + 14].copy_from_slice(b"#Blob\0");
        // Pad to 8 bytes
    }

    // Copy stream data
    if streams.tilde_size > 0 && streams.tilde_offset + streams.tilde_size <= metadata.len() {
        let src = &metadata[streams.tilde_offset..streams.tilde_offset + streams.tilde_size];
        let dst_end = (new_tilde_offset + streams.tilde_size).min(result.len());
        let copy_len = (dst_end - new_tilde_offset).min(src.len());
        result[new_tilde_offset..new_tilde_offset + copy_len].copy_from_slice(&src[..copy_len]);
    }

    if streams.strings_size > 0 && streams.strings_offset + streams.strings_size <= metadata.len() {
        let src = &metadata[streams.strings_offset..streams.strings_offset + streams.strings_size];
        let dst_end = (new_strings_offset + streams.strings_size).min(result.len());
        let copy_len = (dst_end - new_strings_offset).min(src.len());
        result[new_strings_offset..new_strings_offset + copy_len].copy_from_slice(&src[..copy_len]);
    }

    if streams.us_size > 0 && streams.us_offset + streams.us_size <= metadata.len() {
        let src = &metadata[streams.us_offset..streams.us_offset + streams.us_size];
        let dst_end = (new_us_offset + streams.us_size).min(result.len());
        let copy_len = (dst_end - new_us_offset).min(src.len());
        result[new_us_offset..new_us_offset + copy_len].copy_from_slice(&src[..copy_len]);
    }

    if streams.guid_size > 0 && streams.guid_offset + streams.guid_size <= metadata.len() {
        let src = &metadata[streams.guid_offset..streams.guid_offset + streams.guid_size];
        let dst_end = (new_guid_offset + streams.guid_size).min(result.len());
        let copy_len = (dst_end - new_guid_offset).min(src.len());
        result[new_guid_offset..new_guid_offset + copy_len].copy_from_slice(&src[..copy_len]);
    }

    if streams.blob_size > 0 && streams.blob_offset + streams.blob_size <= metadata.len() {
        let src = &metadata[streams.blob_offset..streams.blob_offset + streams.blob_size];
        let dst_end = (new_blob_offset + streams.blob_size).min(result.len());
        let copy_len = (dst_end - new_blob_offset).min(src.len());
        result[new_blob_offset..new_blob_offset + copy_len].copy_from_slice(&src[..copy_len]);
    }

    result
}

/// Try to repair corrupted metadata by scanning for streams and rebuilding headers.
/// Returns the repaired metadata if successful, or None if repair failed.
pub fn try_repair_metadata(metadata: &[u8]) -> Option<Vec<u8>> {
    // First, check if metadata is actually corrupted
    if metadata.len() >= 4 && &metadata[0..4] == b"BSJB" {
        // BSJB signature is intact, try to parse normally
        if parse_metadata_streams(metadata).is_some() {
            // Metadata is fine, no repair needed
            return None;
        }
    }

    // Scan for #~ stream
    let (tilde_offset, tilde_size) = scan_for_tilde_stream(metadata)?;

    // Scan for #Strings heap (should be after #~ stream typically)
    let (strings_offset, strings_size) =
        scan_for_strings_heap(metadata, tilde_offset + tilde_size).unwrap_or((0, 0));

    // Build stream locations
    let streams = MetadataStreamLocations {
        tilde_offset,
        tilde_size,
        is_compressed: true, // Assume compressed for now
        strings_offset,
        strings_size,
        us_offset: 0,
        us_size: 0,
        guid_offset: 0,
        guid_size: 0,
        blob_offset: 0,
        blob_size: 0,
    };

    // Reconstruct metadata
    Some(reconstruct_metadata_header(metadata, &streams))
}

/// Parse metadata streams from valid metadata.
/// Returns stream locations if parsing succeeds.
fn parse_metadata_streams(metadata: &[u8]) -> Option<MetadataStreamLocations> {
    if metadata.len() < 16 || &metadata[0..4] != b"BSJB" {
        return None;
    }

    let version_length =
        u32::from_le_bytes([metadata[12], metadata[13], metadata[14], metadata[15]]) as usize;
    let version_padded = (version_length + 3) & !3;
    let streams_offset = 16 + version_padded;

    if streams_offset + 4 > metadata.len() {
        return None;
    }

    let num_streams =
        u16::from_le_bytes([metadata[streams_offset + 2], metadata[streams_offset + 3]]) as usize;

    let mut locations = MetadataStreamLocations::default();
    let mut pos = streams_offset + 4;

    for _ in 0..num_streams {
        if pos + 8 > metadata.len() {
            break;
        }

        let stream_offset = u32::from_le_bytes([
            metadata[pos],
            metadata[pos + 1],
            metadata[pos + 2],
            metadata[pos + 3],
        ]) as usize;
        let stream_size = u32::from_le_bytes([
            metadata[pos + 4],
            metadata[pos + 5],
            metadata[pos + 6],
            metadata[pos + 7],
        ]) as usize;

        pos += 8;

        // Read stream name
        let name_start = pos;
        while pos < metadata.len() && metadata[pos] != 0 {
            pos += 1;
        }
        let name = std::str::from_utf8(&metadata[name_start..pos]).unwrap_or("");
        pos += 1;
        pos = (pos + 3) & !3;

        match name {
            "#~" => {
                locations.tilde_offset = stream_offset;
                locations.tilde_size = stream_size;
                locations.is_compressed = true;
            }
            "#-" => {
                locations.tilde_offset = stream_offset;
                locations.tilde_size = stream_size;
                locations.is_compressed = false;
            }
            "#Strings" => {
                locations.strings_offset = stream_offset;
                locations.strings_size = stream_size;
            }
            "#US" => {
                locations.us_offset = stream_offset;
                locations.us_size = stream_size;
            }
            "#GUID" => {
                locations.guid_offset = stream_offset;
                locations.guid_size = stream_size;
            }
            "#Blob" => {
                locations.blob_offset = stream_offset;
                locations.blob_size = stream_size;
            }
            _ => {}
        }
    }

    if locations.tilde_size > 0 {
        Some(locations)
    } else {
        None
    }
}

/// Repair metadata within a PE file by replacing corrupted metadata with good metadata.
/// This is used when PE headers are valid but metadata is corrupted.
///
/// # Arguments
/// * `pe_data` - The PE file data (may have corrupted metadata)
/// * `good_metadata` - Valid metadata to replace the corrupted metadata with
///
/// # Returns
/// Repaired PE data with valid metadata, or None if repair failed
pub fn repair_pe_metadata(pe_data: &[u8], good_metadata: &[u8]) -> Option<Vec<u8>> {
    // Parse DOS header
    if pe_data.len() < 64 || pe_data[0] != b'M' || pe_data[1] != b'Z' {
        return None;
    }

    let e_lfanew =
        u32::from_le_bytes([pe_data[0x3C], pe_data[0x3D], pe_data[0x3E], pe_data[0x3F]]) as usize;

    if e_lfanew + 24 > pe_data.len() {
        return None;
    }

    // Check PE signature
    if pe_data.get(e_lfanew..e_lfanew + 4) != Some(b"PE\0\0".as_slice()) {
        return None;
    }

    // Parse COFF header
    let coff_offset = e_lfanew + 4;
    let size_of_optional_header =
        u16::from_le_bytes([pe_data[coff_offset + 16], pe_data[coff_offset + 17]]) as usize;

    if size_of_optional_header == 0 {
        return None;
    }

    // Parse optional header to find CLI header data directory
    let opt_offset = coff_offset + 20;
    let magic = u16::from_le_bytes([pe_data[opt_offset], pe_data[opt_offset + 1]]);

    let is_pe32_plus = magic == 0x20b;
    let data_dir_offset = if is_pe32_plus {
        opt_offset + 112
    } else {
        opt_offset + 96
    };

    // CLI header is data directory entry 14
    let cli_dir_offset = data_dir_offset + 14 * 8;
    if cli_dir_offset + 8 > pe_data.len() {
        return None;
    }

    let cli_rva = u32::from_le_bytes([
        pe_data[cli_dir_offset],
        pe_data[cli_dir_offset + 1],
        pe_data[cli_dir_offset + 2],
        pe_data[cli_dir_offset + 3],
    ]);

    if cli_rva == 0 {
        return None;
    }

    // Convert RVA to file offset
    let cli_offset = rva_to_file_offset(pe_data, e_lfanew, cli_rva as usize)?;

    if cli_offset + 16 > pe_data.len() {
        return None;
    }

    let metadata_rva = u32::from_le_bytes([
        pe_data[cli_offset + 8],
        pe_data[cli_offset + 9],
        pe_data[cli_offset + 10],
        pe_data[cli_offset + 11],
    ]) as usize;

    let old_metadata_size = u32::from_le_bytes([
        pe_data[cli_offset + 12],
        pe_data[cli_offset + 13],
        pe_data[cli_offset + 14],
        pe_data[cli_offset + 15],
    ]) as usize;

    if metadata_rva == 0 {
        return None;
    }

    let metadata_offset = rva_to_file_offset(pe_data, e_lfanew, metadata_rva)?;

    // Create repaired PE
    let mut result = pe_data.to_vec();

    // If the new metadata fits in the old space, just replace it
    if good_metadata.len() <= old_metadata_size
        && metadata_offset + good_metadata.len() <= result.len()
    {
        // Replace metadata in place
        result[metadata_offset..metadata_offset + good_metadata.len()]
            .copy_from_slice(good_metadata);

        // Zero out remaining space if new metadata is smaller
        if good_metadata.len() < old_metadata_size {
            let _remaining = old_metadata_size - good_metadata.len();
            let end = (metadata_offset + old_metadata_size).min(result.len());
            let start = metadata_offset + good_metadata.len();
            if start < end {
                result[start..end].fill(0);
            }
        }

        // Update metadata size in CLI header
        let new_size_bytes = (good_metadata.len() as u32).to_le_bytes();
        result[cli_offset + 12..cli_offset + 16].copy_from_slice(&new_size_bytes);

        Some(result)
    } else {
        // New metadata is larger - need to append it
        // This is more complex as we need to update RVAs
        // For now, return None and fall back to full reconstruction
        None
    }
}

// =============================================================================
// .NET Metadata Parsing - Assembly Name Extraction
// =============================================================================

/// Debug info for metadata extraction failures
#[derive(Debug)]
#[allow(dead_code)]
pub enum MetadataError {
    TooSmall,
    NoDosSignature,
    InvalidPeOffset,
    NoPeSignature,
    NoOptionalHeader,
    NoCliHeader,
    CliOffsetInvalid,
    NoMetadata,
    MetadataOffsetInvalid,
    NoBsjbSignature,
    StreamParseError,
    NoTildeStream,
    NoStringsStream,
    NoAssemblyTable,
    NameIndexOutOfBounds,
}

/// Extract the assembly name with detailed error info for debugging
pub fn extract_assembly_name_from_metadata_debug(pe_data: &[u8]) -> Result<String, MetadataError> {
    // Parse DOS header
    if pe_data.len() < 64 {
        return Err(MetadataError::TooSmall);
    }
    if pe_data[0] != b'M' || pe_data[1] != b'Z' {
        return Err(MetadataError::NoDosSignature);
    }

    let e_lfanew =
        u32::from_le_bytes([pe_data[0x3C], pe_data[0x3D], pe_data[0x3E], pe_data[0x3F]]) as usize;

    if e_lfanew + 24 > pe_data.len() {
        return Err(MetadataError::InvalidPeOffset);
    }

    // Check PE signature
    if pe_data.get(e_lfanew..e_lfanew + 4) != Some(b"PE\0\0".as_slice()) {
        return Err(MetadataError::NoPeSignature);
    }

    // Parse COFF header
    let coff_offset = e_lfanew + 4;
    let size_of_optional_header =
        u16::from_le_bytes([pe_data[coff_offset + 16], pe_data[coff_offset + 17]]) as usize;

    if size_of_optional_header == 0 {
        return Err(MetadataError::NoOptionalHeader);
    }

    // Parse optional header to find CLI header data directory
    let opt_offset = coff_offset + 20;
    let magic = u16::from_le_bytes([pe_data[opt_offset], pe_data[opt_offset + 1]]);

    // PE32 = 0x10b, PE32+ = 0x20b
    let is_pe32_plus = magic == 0x20b;
    let data_dir_offset = if is_pe32_plus {
        opt_offset + 112
    } else {
        opt_offset + 96
    };

    // CLI header is data directory entry 14 (COM Descriptor)
    let cli_dir_offset = data_dir_offset + 14 * 8;
    if cli_dir_offset + 8 > pe_data.len() {
        return Err(MetadataError::NoCliHeader);
    }

    let cli_rva = u32::from_le_bytes([
        pe_data[cli_dir_offset],
        pe_data[cli_dir_offset + 1],
        pe_data[cli_dir_offset + 2],
        pe_data[cli_dir_offset + 3],
    ]);

    if cli_rva == 0 {
        return Err(MetadataError::NoCliHeader);
    }

    // Convert RVA to file offset using section headers
    let cli_offset = rva_to_file_offset(pe_data, e_lfanew, cli_rva as usize)
        .ok_or(MetadataError::CliOffsetInvalid)?;

    // Parse CLI header - we need metadata RVA at offset 8
    if cli_offset + 16 > pe_data.len() {
        return Err(MetadataError::CliOffsetInvalid);
    }

    let metadata_rva = u32::from_le_bytes([
        pe_data[cli_offset + 8],
        pe_data[cli_offset + 9],
        pe_data[cli_offset + 10],
        pe_data[cli_offset + 11],
    ]) as usize;

    let metadata_size = u32::from_le_bytes([
        pe_data[cli_offset + 12],
        pe_data[cli_offset + 13],
        pe_data[cli_offset + 14],
        pe_data[cli_offset + 15],
    ]) as usize;

    if metadata_rva == 0 || metadata_size == 0 {
        return Err(MetadataError::NoMetadata);
    }

    let metadata_offset = rva_to_file_offset(pe_data, e_lfanew, metadata_rva)
        .ok_or(MetadataError::MetadataOffsetInvalid)?;

    if metadata_offset + metadata_size > pe_data.len() {
        return Err(MetadataError::MetadataOffsetInvalid);
    }

    let metadata = &pe_data[metadata_offset..metadata_offset + metadata_size];

    // Parse metadata root - check BSJB signature
    if metadata.len() < 16 || metadata[0..4] != [0x42, 0x53, 0x4A, 0x42] {
        return Err(MetadataError::NoBsjbSignature);
    }

    // Continue with the rest of parsing (simplified - just check we can find streams)
    let version_length =
        u32::from_le_bytes([metadata[12], metadata[13], metadata[14], metadata[15]]) as usize;
    let version_padded = (version_length + 3) & !3;
    let streams_offset = 16 + version_padded;

    if streams_offset + 4 > metadata.len() {
        return Err(MetadataError::StreamParseError);
    }

    // Use the full extraction logic
    extract_assembly_name_from_metadata(pe_data).ok_or(MetadataError::NoAssemblyTable)
}

/// Extract the assembly name from .NET metadata in a PE file.
/// This reads the Assembly table from the #~ stream and looks up the name in #Strings.
/// Returns None if the file is not a .NET assembly or metadata is corrupted.
pub fn extract_assembly_name_from_metadata(pe_data: &[u8]) -> Option<String> {
    // Parse DOS header
    if pe_data.len() < 64 || pe_data[0] != b'M' || pe_data[1] != b'Z' {
        return None;
    }

    let e_lfanew =
        u32::from_le_bytes([pe_data[0x3C], pe_data[0x3D], pe_data[0x3E], pe_data[0x3F]]) as usize;

    if e_lfanew + 24 > pe_data.len() {
        return None;
    }

    // Check PE signature
    if pe_data.get(e_lfanew..e_lfanew + 4)? != b"PE\0\0" {
        return None;
    }

    // Parse COFF header
    let coff_offset = e_lfanew + 4;
    let size_of_optional_header =
        u16::from_le_bytes([pe_data[coff_offset + 16], pe_data[coff_offset + 17]]) as usize;

    if size_of_optional_header == 0 {
        return None;
    }

    // Parse optional header to find CLI header data directory
    let opt_offset = coff_offset + 20;
    let magic = u16::from_le_bytes([pe_data[opt_offset], pe_data[opt_offset + 1]]);

    // PE32 = 0x10b, PE32+ = 0x20b
    let is_pe32_plus = magic == 0x20b;
    let data_dir_offset = if is_pe32_plus {
        opt_offset + 112 // PE32+: 112 bytes to data directories
    } else {
        opt_offset + 96 // PE32: 96 bytes to data directories
    };

    // CLI header is data directory entry 14 (COM Descriptor)
    let cli_dir_offset = data_dir_offset + 14 * 8;
    if cli_dir_offset + 8 > pe_data.len() {
        return None;
    }

    let cli_rva = u32::from_le_bytes([
        pe_data[cli_dir_offset],
        pe_data[cli_dir_offset + 1],
        pe_data[cli_dir_offset + 2],
        pe_data[cli_dir_offset + 3],
    ]);

    if cli_rva == 0 {
        return None; // Not a .NET assembly
    }

    // Convert RVA to file offset using section headers
    let cli_offset = rva_to_file_offset(pe_data, e_lfanew, cli_rva as usize)?;

    // Parse CLI header (Cor20Header) - we need metadata RVA at offset 8
    if cli_offset + 16 > pe_data.len() {
        return None;
    }

    let metadata_rva = u32::from_le_bytes([
        pe_data[cli_offset + 8],
        pe_data[cli_offset + 9],
        pe_data[cli_offset + 10],
        pe_data[cli_offset + 11],
    ]) as usize;

    let metadata_size = u32::from_le_bytes([
        pe_data[cli_offset + 12],
        pe_data[cli_offset + 13],
        pe_data[cli_offset + 14],
        pe_data[cli_offset + 15],
    ]) as usize;

    if metadata_rva == 0 || metadata_size == 0 {
        return None;
    }

    let metadata_offset = rva_to_file_offset(pe_data, e_lfanew, metadata_rva)?;

    if metadata_offset + metadata_size > pe_data.len() {
        return None;
    }

    let metadata = &pe_data[metadata_offset..metadata_offset + metadata_size];

    // Parse metadata root - check BSJB signature
    if metadata.len() < 16 || metadata[0..4] != [0x42, 0x53, 0x4A, 0x42] {
        return None;
    }

    // Skip: signature(4) + major(2) + minor(2) + reserved(4) + version_length(4)
    let version_length =
        u32::from_le_bytes([metadata[12], metadata[13], metadata[14], metadata[15]]) as usize;

    // Version string is padded to 4-byte boundary
    let version_padded = (version_length + 3) & !3;
    let streams_offset = 16 + version_padded;

    if streams_offset + 4 > metadata.len() {
        return None;
    }

    // Skip flags(2), read number of streams(2)
    let num_streams =
        u16::from_le_bytes([metadata[streams_offset + 2], metadata[streams_offset + 3]]) as usize;

    // Parse stream headers to find #Strings and #~
    let mut strings_offset = 0usize;
    let mut strings_size = 0usize;
    let mut tilde_offset = 0usize;
    let mut tilde_size = 0usize;

    let mut pos = streams_offset + 4;
    for _ in 0..num_streams {
        if pos + 8 > metadata.len() {
            break;
        }

        let stream_offset = u32::from_le_bytes([
            metadata[pos],
            metadata[pos + 1],
            metadata[pos + 2],
            metadata[pos + 3],
        ]) as usize;
        let stream_size = u32::from_le_bytes([
            metadata[pos + 4],
            metadata[pos + 5],
            metadata[pos + 6],
            metadata[pos + 7],
        ]) as usize;

        pos += 8;

        // Read stream name (null-terminated, padded to 4 bytes)
        let name_start = pos;
        while pos < metadata.len() && metadata[pos] != 0 {
            pos += 1;
        }
        let name = std::str::from_utf8(&metadata[name_start..pos]).unwrap_or("");
        pos += 1; // Skip null terminator
        pos = (pos + 3) & !3; // Align to 4 bytes

        match name {
            "#Strings" => {
                strings_offset = stream_offset;
                strings_size = stream_size;
            }
            "#~" | "#-" => {
                tilde_offset = stream_offset;
                tilde_size = stream_size;
            }
            _ => {}
        }
    }

    if strings_offset == 0 || tilde_offset == 0 {
        return None;
    }

    // Parse #~ stream to find Assembly table
    let tilde_data = metadata.get(tilde_offset..tilde_offset + tilde_size)?;
    let strings_data = metadata.get(strings_offset..strings_offset + strings_size)?;

    extract_assembly_name_from_tilde_stream(tilde_data, strings_data)
}

/// Parse the #~ stream and extract the assembly name from the Assembly table.
/// Falls back to Module table name if Assembly table is not present.
fn extract_assembly_name_from_tilde_stream(tilde: &[u8], strings: &[u8]) -> Option<String> {
    // #~ stream header:
    // Reserved: u32 (0)
    // MajorVersion: u8
    // MinorVersion: u8
    // HeapSizes: u8 (bit 0 = #Strings uses 4 bytes, bit 1 = #GUID uses 4 bytes, bit 2 = #Blob uses 4 bytes)
    // Reserved: u8
    // Valid: u64 (bitmask of present tables)
    // Sorted: u64
    // Rows: u32[] (row count for each present table)

    if tilde.len() < 24 {
        return None;
    }

    let heap_sizes = tilde[6];
    let string_idx_size = if heap_sizes & 0x01 != 0 { 4 } else { 2 };
    let guid_idx_size = if heap_sizes & 0x02 != 0 { 4 } else { 2 };
    let blob_idx_size = if heap_sizes & 0x04 != 0 { 4 } else { 2 };

    let valid = u64::from_le_bytes([
        tilde[8], tilde[9], tilde[10], tilde[11], tilde[12], tilde[13], tilde[14], tilde[15],
    ]);

    // Read row counts for all present tables
    let mut pos = 24usize; // After header
    let mut row_counts: Vec<u32> = Vec::new();

    for i in 0..64 {
        if valid & (1u64 << i) != 0 {
            if pos + 4 > tilde.len() {
                return None;
            }
            let count =
                u32::from_le_bytes([tilde[pos], tilde[pos + 1], tilde[pos + 2], tilde[pos + 3]]);
            row_counts.push(count);
            pos += 4;
        }
    }

    let tables_start = pos;

    // Check if Assembly table (0x20) exists
    let assembly_table_bit = 1u64 << 0x20;
    let has_assembly_table = valid & assembly_table_bit != 0;

    // Check if Module table (0x00) exists - it should always exist
    let module_table_bit = 1u64 << 0x00;
    let has_module_table = valid & module_table_bit != 0;

    // Try Assembly table first, then fall back to Module table
    if has_assembly_table
        && let Some(name) = extract_name_from_assembly_table(
            tilde,
            strings,
            &row_counts,
            valid,
            tables_start,
            string_idx_size,
            guid_idx_size,
            blob_idx_size,
        )
    {
        return Some(name);
    }

    // Fall back to Module table
    if has_module_table
        && let Some(name) =
            extract_name_from_module_table(tilde, strings, tables_start, string_idx_size)
    {
        return Some(name);
    }

    None
}

/// Extract full assembly metadata from PE data.
/// Returns detailed information including version, culture, and public key token.
pub fn extract_assembly_metadata(pe_data: &[u8]) -> Option<AssemblyMetadata> {
    // Parse DOS header
    if pe_data.len() < 64 || pe_data[0] != b'M' || pe_data[1] != b'Z' {
        return None;
    }

    let e_lfanew =
        u32::from_le_bytes([pe_data[0x3C], pe_data[0x3D], pe_data[0x3E], pe_data[0x3F]]) as usize;

    if e_lfanew + 24 > pe_data.len() {
        return None;
    }

    // Check PE signature
    if pe_data.get(e_lfanew..e_lfanew + 4)? != b"PE\0\0" {
        return None;
    }

    // Parse COFF header
    let coff_offset = e_lfanew + 4;
    let size_of_optional_header =
        u16::from_le_bytes([pe_data[coff_offset + 16], pe_data[coff_offset + 17]]) as usize;

    if size_of_optional_header == 0 {
        return None;
    }

    // Parse optional header to find CLI header data directory
    let opt_offset = coff_offset + 20;
    let magic = u16::from_le_bytes([pe_data[opt_offset], pe_data[opt_offset + 1]]);

    let is_pe32_plus = magic == 0x20b;
    let data_dir_offset = if is_pe32_plus {
        opt_offset + 112
    } else {
        opt_offset + 96
    };

    // CLI header is data directory entry 14
    let cli_dir_offset = data_dir_offset + 14 * 8;
    if cli_dir_offset + 8 > pe_data.len() {
        return None;
    }

    let cli_rva = u32::from_le_bytes([
        pe_data[cli_dir_offset],
        pe_data[cli_dir_offset + 1],
        pe_data[cli_dir_offset + 2],
        pe_data[cli_dir_offset + 3],
    ]);

    if cli_rva == 0 {
        return None;
    }

    let cli_offset = rva_to_file_offset(pe_data, e_lfanew, cli_rva as usize)?;

    if cli_offset + 16 > pe_data.len() {
        return None;
    }

    let metadata_rva = u32::from_le_bytes([
        pe_data[cli_offset + 8],
        pe_data[cli_offset + 9],
        pe_data[cli_offset + 10],
        pe_data[cli_offset + 11],
    ]) as usize;

    let metadata_size = u32::from_le_bytes([
        pe_data[cli_offset + 12],
        pe_data[cli_offset + 13],
        pe_data[cli_offset + 14],
        pe_data[cli_offset + 15],
    ]) as usize;

    if metadata_rva == 0 || metadata_size == 0 {
        return None;
    }

    let metadata_offset = rva_to_file_offset(pe_data, e_lfanew, metadata_rva)?;

    if metadata_offset + metadata_size > pe_data.len() {
        return None;
    }

    let metadata = &pe_data[metadata_offset..metadata_offset + metadata_size];

    // Check BSJB signature
    if metadata.len() < 16 || &metadata[0..4] != b"BSJB" {
        return None;
    }

    // Parse streams
    let version_length =
        u32::from_le_bytes([metadata[12], metadata[13], metadata[14], metadata[15]]) as usize;
    let version_padded = (version_length + 3) & !3;
    let streams_offset = 16 + version_padded;

    if streams_offset + 4 > metadata.len() {
        return None;
    }

    let num_streams =
        u16::from_le_bytes([metadata[streams_offset + 2], metadata[streams_offset + 3]]) as usize;

    let mut tilde_offset = 0usize;
    let mut tilde_size = 0usize;
    let mut strings_offset = 0usize;
    let mut strings_size = 0usize;
    let mut blob_offset = 0usize;
    let mut blob_size = 0usize;

    let mut pos = streams_offset + 4;
    for _ in 0..num_streams {
        if pos + 8 > metadata.len() {
            break;
        }

        let stream_offset = u32::from_le_bytes([
            metadata[pos],
            metadata[pos + 1],
            metadata[pos + 2],
            metadata[pos + 3],
        ]) as usize;
        let stream_size = u32::from_le_bytes([
            metadata[pos + 4],
            metadata[pos + 5],
            metadata[pos + 6],
            metadata[pos + 7],
        ]) as usize;

        pos += 8;

        let name_start = pos;
        while pos < metadata.len() && metadata[pos] != 0 {
            pos += 1;
        }
        let name = std::str::from_utf8(&metadata[name_start..pos]).unwrap_or("");
        pos += 1;
        pos = (pos + 3) & !3;

        match name {
            "#~" | "#-" => {
                tilde_offset = stream_offset;
                tilde_size = stream_size;
            }
            "#Strings" => {
                strings_offset = stream_offset;
                strings_size = stream_size;
            }
            "#Blob" => {
                blob_offset = stream_offset;
                blob_size = stream_size;
            }
            _ => {}
        }
    }

    if tilde_size == 0 || strings_size == 0 {
        return None;
    }

    let tilde_data = metadata.get(tilde_offset..tilde_offset + tilde_size)?;
    let strings_data = metadata.get(strings_offset..strings_offset + strings_size)?;
    let blob_data = if blob_size > 0 {
        metadata.get(blob_offset..blob_offset + blob_size)
    } else {
        None
    };

    extract_full_assembly_metadata(tilde_data, strings_data, blob_data)
}

/// Extract full assembly metadata from the #~ stream.
fn extract_full_assembly_metadata(
    tilde: &[u8],
    strings: &[u8],
    blob: Option<&[u8]>,
) -> Option<AssemblyMetadata> {
    if tilde.len() < 24 {
        return None;
    }

    let heap_sizes = tilde[6];
    let string_idx_size = if heap_sizes & 0x01 != 0 { 4 } else { 2 };
    let _guid_idx_size = if heap_sizes & 0x02 != 0 { 4 } else { 2 };
    let blob_idx_size = if heap_sizes & 0x04 != 0 { 4 } else { 2 };

    let valid = u64::from_le_bytes([
        tilde[8], tilde[9], tilde[10], tilde[11], tilde[12], tilde[13], tilde[14], tilde[15],
    ]);

    // Read row counts
    let mut pos = 24usize;
    let mut row_counts: Vec<u32> = Vec::new();

    for i in 0..64 {
        if valid & (1u64 << i) != 0 {
            if pos + 4 > tilde.len() {
                return None;
            }
            let count =
                u32::from_le_bytes([tilde[pos], tilde[pos + 1], tilde[pos + 2], tilde[pos + 3]]);
            row_counts.push(count);
            pos += 4;
        }
    }

    let tables_start = pos;

    // Check if Assembly table exists
    let assembly_table_bit = 1u64 << 0x20;
    if valid & assembly_table_bit == 0 {
        return None;
    }

    // Calculate offset to Assembly table
    let mut current_offset = tables_start;

    for i in 0..0x20 {
        if valid & (1u64 << i) != 0 {
            let row_size = get_table_row_size(
                i,
                &row_counts,
                valid,
                string_idx_size,
                _guid_idx_size,
                blob_idx_size,
            );
            let table_index = count_bits_before(valid, i);
            let row_count = *row_counts.get(table_index)? as usize;
            current_offset += row_size * row_count;
        }
    }

    // Now at Assembly table
    // Assembly table row format (ECMA-335 II.22.2):
    // HashAlgId: u32 (4)
    // MajorVersion: u16 (2)
    // MinorVersion: u16 (2)
    // BuildNumber: u16 (2)
    // RevisionNumber: u16 (2)
    // Flags: u32 (4)
    // PublicKey: Blob index
    // Name: String index
    // Culture: String index

    if current_offset + 16 + blob_idx_size + string_idx_size * 2 > tilde.len() {
        return None;
    }

    let row = &tilde[current_offset..];

    let _hash_alg_id = u32::from_le_bytes([row[0], row[1], row[2], row[3]]);
    let major_version = u16::from_le_bytes([row[4], row[5]]);
    let minor_version = u16::from_le_bytes([row[6], row[7]]);
    let build_number = u16::from_le_bytes([row[8], row[9]]);
    let revision_number = u16::from_le_bytes([row[10], row[11]]);
    let flags = u32::from_le_bytes([row[12], row[13], row[14], row[15]]);

    let mut offset = 16;

    // Read PublicKey blob index
    let public_key_index = if blob_idx_size == 4 {
        let idx = u32::from_le_bytes([
            row[offset],
            row[offset + 1],
            row[offset + 2],
            row[offset + 3],
        ]);
        offset += 4;
        idx as usize
    } else {
        let idx = u16::from_le_bytes([row[offset], row[offset + 1]]);
        offset += 2;
        idx as usize
    };

    // Read Name string index
    let name_index = if string_idx_size == 4 {
        let idx = u32::from_le_bytes([
            row[offset],
            row[offset + 1],
            row[offset + 2],
            row[offset + 3],
        ]);
        offset += 4;
        idx as usize
    } else {
        let idx = u16::from_le_bytes([row[offset], row[offset + 1]]);
        offset += 2;
        idx as usize
    };

    // Read Culture string index
    let culture_index = if string_idx_size == 4 {
        u32::from_le_bytes([
            row[offset],
            row[offset + 1],
            row[offset + 2],
            row[offset + 3],
        ]) as usize
    } else {
        u16::from_le_bytes([row[offset], row[offset + 1]]) as usize
    };

    // Read name from #Strings
    let name = read_string_at_index(strings, name_index)?;

    // Read culture from #Strings
    let culture = read_string_at_index(strings, culture_index).unwrap_or_default();

    // Read public key from #Blob and compute token
    let (public_key, public_key_token) = if let Some(blob_data) = blob {
        read_public_key_and_token(blob_data, public_key_index)
    } else {
        (None, None)
    };

    Some(AssemblyMetadata {
        name,
        major_version,
        minor_version,
        build_number,
        revision_number,
        culture,
        public_key_token,
        public_key,
        flags,
    })
}

/// Read a string from #Strings heap at the given index.
fn read_string_at_index(strings: &[u8], index: usize) -> Option<String> {
    if index >= strings.len() {
        return None;
    }

    let name_bytes = &strings[index..];
    let end = name_bytes
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(name_bytes.len());
    let name = std::str::from_utf8(&name_bytes[..end]).ok()?;

    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// Read public key from #Blob and compute public key token (SHA1 hash, last 8 bytes reversed).
fn read_public_key_and_token(blob: &[u8], index: usize) -> (Option<String>, Option<String>) {
    if index == 0 || index >= blob.len() {
        return (None, None);
    }

    // Blob format: length prefix (compressed) followed by data
    let (length, header_size) = read_compressed_uint(&blob[index..]);
    if length == 0 {
        return (None, None);
    }

    let data_start = index + header_size;
    if data_start + length > blob.len() {
        return (None, None);
    }

    let public_key_bytes = &blob[data_start..data_start + length];
    let public_key_hex = bytes_to_hex(public_key_bytes);

    // Compute public key token: SHA1 hash of public key, last 8 bytes reversed
    let token = compute_public_key_token(public_key_bytes);

    (Some(public_key_hex), token)
}

/// Read a compressed unsigned integer from blob data.
/// Returns (value, bytes_consumed).
fn read_compressed_uint(data: &[u8]) -> (usize, usize) {
    if data.is_empty() {
        return (0, 0);
    }

    let first = data[0];
    if first & 0x80 == 0 {
        // 1 byte: 0xxxxxxx
        (first as usize, 1)
    } else if first & 0xC0 == 0x80 {
        // 2 bytes: 10xxxxxx xxxxxxxx
        if data.len() < 2 {
            return (0, 0);
        }
        let value = ((first & 0x3F) as usize) << 8 | data[1] as usize;
        (value, 2)
    } else if first & 0xE0 == 0xC0 {
        // 4 bytes: 110xxxxx xxxxxxxx xxxxxxxx xxxxxxxx
        if data.len() < 4 {
            return (0, 0);
        }
        let value = ((first & 0x1F) as usize) << 24
            | (data[1] as usize) << 16
            | (data[2] as usize) << 8
            | data[3] as usize;
        (value, 4)
    } else {
        (0, 0)
    }
}

/// Convert bytes to hex string.
fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Compute public key token from public key using SHA1.
/// Token is last 8 bytes of SHA1 hash, reversed.
fn compute_public_key_token(public_key: &[u8]) -> Option<String> {
    use sha1::{Digest, Sha1};

    if public_key.is_empty() {
        return None;
    }

    // Compute SHA1 hash of the public key
    let mut hasher = Sha1::new();
    hasher.update(public_key);
    let hash = hasher.finalize();

    // Token is last 8 bytes of SHA1 hash, reversed
    let token: Vec<u8> = hash[12..20].iter().rev().cloned().collect();
    Some(bytes_to_hex(&token))
}

/// Extract name from the Assembly table (0x20).
#[allow(clippy::too_many_arguments)]
fn extract_name_from_assembly_table(
    tilde: &[u8],
    strings: &[u8],
    row_counts: &[u32],
    valid: u64,
    tables_start: usize,
    string_idx_size: usize,
    guid_idx_size: usize,
    blob_idx_size: usize,
) -> Option<String> {
    // Calculate offset to Assembly table by summing sizes of preceding tables
    let mut current_offset = tables_start;

    for i in 0..64 {
        if valid & (1u64 << i) != 0 {
            if i == 0x20 {
                // Found Assembly table
                // Assembly table row format (ECMA-335 II.22.2):
                // HashAlgId: u32
                // MajorVersion: u16
                // MinorVersion: u16
                // BuildNumber: u16
                // RevisionNumber: u16
                // Flags: u32
                // PublicKey: Blob index
                // Name: String index
                // Culture: String index

                let name_offset_in_row = 4 + 2 + 2 + 2 + 2 + 4 + blob_idx_size;
                let name_pos = current_offset + name_offset_in_row;

                return read_string_from_heap(tilde, strings, name_pos, string_idx_size);
            }
            // Calculate row size for this table
            let row_size = get_table_row_size(
                i,
                row_counts,
                valid,
                string_idx_size,
                guid_idx_size,
                blob_idx_size,
            );
            let table_index = count_bits_before(valid, i);
            let row_count = *row_counts.get(table_index)? as usize;
            current_offset += row_size * row_count;
        }
    }

    None
}

/// Extract name from the Module table (0x00).
/// Module table row format (ECMA-335 II.22.30):
/// - Generation: u16 (2 bytes)
/// - Name: String index
/// - Mvid: GUID index
/// - EncId: GUID index
/// - EncBaseId: GUID index
fn extract_name_from_module_table(
    tilde: &[u8],
    strings: &[u8],
    tables_start: usize,
    string_idx_size: usize,
) -> Option<String> {
    // Module table is always table 0, so it starts right at tables_start
    // Name is at offset 2 (after Generation: u16)
    let name_offset_in_row = 2;
    let name_pos = tables_start + name_offset_in_row;

    read_string_from_heap(tilde, strings, name_pos, string_idx_size)
}

/// Read a string from the #Strings heap given a position in the tilde stream.
fn read_string_from_heap(
    tilde: &[u8],
    strings: &[u8],
    name_pos: usize,
    string_idx_size: usize,
) -> Option<String> {
    if name_pos + string_idx_size > tilde.len() {
        return None;
    }

    let name_index = if string_idx_size == 4 {
        u32::from_le_bytes([
            tilde[name_pos],
            tilde[name_pos + 1],
            tilde[name_pos + 2],
            tilde[name_pos + 3],
        ]) as usize
    } else {
        u16::from_le_bytes([tilde[name_pos], tilde[name_pos + 1]]) as usize
    };

    // Look up name in #Strings heap
    if name_index >= strings.len() {
        return None;
    }

    let name_bytes = &strings[name_index..];
    let end = name_bytes
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(name_bytes.len());
    let name = std::str::from_utf8(&name_bytes[..end]).ok()?;

    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// Count how many bits are set before position `bit` in the bitmask.
fn count_bits_before(valid: u64, bit: usize) -> usize {
    let mask = (1u64 << bit) - 1;
    (valid & mask).count_ones() as usize
}

/// Get the row size for a metadata table.
/// Reference: ECMA-335 II.22
fn get_table_row_size(
    table: usize,
    row_counts: &[u32],
    valid: u64,
    string_idx_size: usize,
    guid_idx_size: usize,
    blob_idx_size: usize,
) -> usize {
    // Helper to get coded index size based on tag bits and referenced tables
    let coded_idx_size = |tag_bits: usize, tables: &[usize]| -> usize {
        let max_rows = tables
            .iter()
            .filter_map(|&t| {
                if valid & (1u64 << t) != 0 {
                    let idx = count_bits_before(valid, t);
                    row_counts.get(idx).copied()
                } else {
                    Some(0)
                }
            })
            .max()
            .unwrap_or(0);
        if max_rows < (1 << (16 - tag_bits)) {
            2
        } else {
            4
        }
    };

    // Coded index definitions from ECMA-335 II.24.2.6
    let type_def_or_ref = || coded_idx_size(2, &[0x02, 0x01, 0x1B]); // TypeDef, TypeRef, TypeSpec
    let has_constant = || coded_idx_size(2, &[0x04, 0x08, 0x17]); // Field, Param, Property
    let has_custom_attribute = || {
        coded_idx_size(
            5,
            &[
                0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00, 0x0E, 0x17, 0x14, 0x11, 0x1A, 0x1B,
                0x20, 0x23, 0x26, 0x27, 0x28, 0x2A, 0x2C,
            ],
        )
    };
    let has_field_marshal = || coded_idx_size(1, &[0x04, 0x08]); // Field, Param
    let has_decl_security = || coded_idx_size(2, &[0x02, 0x06, 0x20]); // TypeDef, MethodDef, Assembly
    let member_ref_parent = || coded_idx_size(3, &[0x02, 0x01, 0x1A, 0x06, 0x1B]); // TypeDef, TypeRef, ModuleRef, MethodDef, TypeSpec
    let has_semantics = || coded_idx_size(1, &[0x14, 0x17]); // Event, Property
    let method_def_or_ref = || coded_idx_size(1, &[0x06, 0x0A]); // MethodDef, MemberRef
    let member_forwarded = || coded_idx_size(1, &[0x04, 0x06]); // Field, MethodDef
    let _implementation = || coded_idx_size(2, &[0x26, 0x23, 0x27]); // File, AssemblyRef, ExportedType
    let custom_attribute_type = || coded_idx_size(3, &[0x06, 0x0A]); // MethodDef, MemberRef (only 2 used, but 3 bits)
    let resolution_scope = || coded_idx_size(2, &[0x00, 0x1A, 0x23, 0x01]); // Module, ModuleRef, AssemblyRef, TypeRef

    match table {
        // 0x00: Module - Generation(2) + Name(S) + Mvid(G) + EncId(G) + EncBaseId(G)
        0x00 => 2 + string_idx_size + guid_idx_size * 3,
        // 0x01: TypeRef - ResolutionScope(coded) + TypeName(S) + TypeNamespace(S)
        0x01 => resolution_scope() + string_idx_size * 2,
        // 0x02: TypeDef - Flags(4) + TypeName(S) + TypeNamespace(S) + Extends(coded) + FieldList(idx) + MethodList(idx)
        0x02 => {
            4 + string_idx_size * 2
                + type_def_or_ref()
                + simple_idx_size(row_counts, valid, 0x04)
                + simple_idx_size(row_counts, valid, 0x06)
        }
        // 0x04: Field - Flags(2) + Name(S) + Signature(B)
        0x04 => 2 + string_idx_size + blob_idx_size,
        // 0x06: MethodDef - RVA(4) + ImplFlags(2) + Flags(2) + Name(S) + Signature(B) + ParamList(idx)
        0x06 => {
            4 + 2 + 2 + string_idx_size + blob_idx_size + simple_idx_size(row_counts, valid, 0x08)
        }
        // 0x08: Param - Flags(2) + Sequence(2) + Name(S)
        0x08 => 2 + 2 + string_idx_size,
        // 0x09: InterfaceImpl - Class(idx to TypeDef) + Interface(coded)
        0x09 => simple_idx_size(row_counts, valid, 0x02) + type_def_or_ref(),
        // 0x0A: MemberRef - Class(coded) + Name(S) + Signature(B)
        0x0A => member_ref_parent() + string_idx_size + blob_idx_size,
        // 0x0B: Constant - Type(2) + Parent(coded) + Value(B)
        0x0B => 2 + has_constant() + blob_idx_size,
        // 0x0C: CustomAttribute - Parent(coded) + Type(coded) + Value(B)
        0x0C => has_custom_attribute() + custom_attribute_type() + blob_idx_size,
        // 0x0D: FieldMarshal - Parent(coded) + NativeType(B)
        0x0D => has_field_marshal() + blob_idx_size,
        // 0x0E: DeclSecurity - Action(2) + Parent(coded) + PermissionSet(B)
        0x0E => 2 + has_decl_security() + blob_idx_size,
        // 0x0F: ClassLayout - PackingSize(2) + ClassSize(4) + Parent(idx to TypeDef)
        0x0F => 2 + 4 + simple_idx_size(row_counts, valid, 0x02),
        // 0x10: FieldLayout - Offset(4) + Field(idx)
        0x10 => 4 + simple_idx_size(row_counts, valid, 0x04),
        // 0x11: StandAloneSig - Signature(B)
        0x11 => blob_idx_size,
        // 0x12: EventMap - Parent(idx to TypeDef) + EventList(idx to Event)
        0x12 => simple_idx_size(row_counts, valid, 0x02) + simple_idx_size(row_counts, valid, 0x14),
        // 0x14: Event - EventFlags(2) + Name(S) + EventType(coded)
        0x14 => 2 + string_idx_size + type_def_or_ref(),
        // 0x15: PropertyMap - Parent(idx to TypeDef) + PropertyList(idx to Property)
        0x15 => simple_idx_size(row_counts, valid, 0x02) + simple_idx_size(row_counts, valid, 0x17),
        // 0x17: Property - Flags(2) + Name(S) + Type(B)
        0x17 => 2 + string_idx_size + blob_idx_size,
        // 0x18: MethodSemantics - Semantics(2) + Method(idx to MethodDef) + Association(coded)
        0x18 => 2 + simple_idx_size(row_counts, valid, 0x06) + has_semantics(),
        // 0x19: MethodImpl - Class(idx to TypeDef) + MethodBody(coded) + MethodDeclaration(coded)
        0x19 => {
            simple_idx_size(row_counts, valid, 0x02) + method_def_or_ref() + method_def_or_ref()
        }
        // 0x1A: ModuleRef - Name(S)
        0x1A => string_idx_size,
        // 0x1B: TypeSpec - Signature(B)
        0x1B => blob_idx_size,
        // 0x1C: ImplMap - MappingFlags(2) + MemberForwarded(coded) + ImportName(S) + ImportScope(idx to ModuleRef)
        0x1C => 2 + member_forwarded() + string_idx_size + simple_idx_size(row_counts, valid, 0x1A),
        // 0x1D: FieldRVA - RVA(4) + Field(idx)
        0x1D => 4 + simple_idx_size(row_counts, valid, 0x04),
        // 0x1E: EncLog - Token(4) + FuncCode(4)
        0x1E => 4 + 4,
        // 0x1F: EncMap - Token(4)
        0x1F => 4,
        // 0x20: Assembly - HashAlgId(4) + Major(2) + Minor(2) + Build(2) + Rev(2) + Flags(4) + PublicKey(B) + Name(S) + Culture(S)
        0x20 => 4 + 2 + 2 + 2 + 2 + 4 + blob_idx_size + string_idx_size * 2,
        _ => 0,
    }
}

/// Get simple table index size (2 or 4 bytes based on row count).
fn simple_idx_size(row_counts: &[u32], valid: u64, table: usize) -> usize {
    if valid & (1u64 << table) == 0 {
        return 2;
    }
    let idx = count_bits_before(valid, table);
    let count = row_counts.get(idx).copied().unwrap_or(0);
    if count < 0x10000 { 2 } else { 4 }
}

/// Convert an RVA to a file offset using section headers.
fn rva_to_file_offset(pe_data: &[u8], e_lfanew: usize, rva: usize) -> Option<usize> {
    let coff_offset = e_lfanew + 4;
    let number_of_sections =
        u16::from_le_bytes([pe_data[coff_offset + 2], pe_data[coff_offset + 3]]) as usize;
    let size_of_optional_header =
        u16::from_le_bytes([pe_data[coff_offset + 16], pe_data[coff_offset + 17]]) as usize;

    let section_table_offset = coff_offset + 20 + size_of_optional_header;

    for i in 0..number_of_sections {
        let section_offset = section_table_offset + i * 40;
        if section_offset + 40 > pe_data.len() {
            break;
        }

        let virtual_size = u32::from_le_bytes([
            pe_data[section_offset + 8],
            pe_data[section_offset + 9],
            pe_data[section_offset + 10],
            pe_data[section_offset + 11],
        ]) as usize;

        let virtual_address = u32::from_le_bytes([
            pe_data[section_offset + 12],
            pe_data[section_offset + 13],
            pe_data[section_offset + 14],
            pe_data[section_offset + 15],
        ]) as usize;

        let pointer_to_raw_data = u32::from_le_bytes([
            pe_data[section_offset + 20],
            pe_data[section_offset + 21],
            pe_data[section_offset + 22],
            pe_data[section_offset + 23],
        ]) as usize;

        if rva >= virtual_address && rva < virtual_address + virtual_size {
            return Some(pointer_to_raw_data + (rva - virtual_address));
        }
    }

    // If not in any section, assume it's in the header (RVA == file offset)
    if rva < 0x1000 { Some(rva) } else { None }
}
