//! PE header parsing and reconstruction.
//!
//! This module handles reading PE headers from process memory,
//! converting between memory and file layouts, and reconstructing
//! corrupted headers (anti-anti-dump).

use std::ffi::c_void;

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
// PE Header Reading
// =============================================================================

/// Read PE header information from a process
pub fn read_pe_info(process_handle: HANDLE, base_address: usize) -> Option<PeInfo> {
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

    if dos_header[0] != 0x4D || dos_header[1] != 0x5A {
        return None;
    }

    let e_lfanew = u32::from_le_bytes([
        dos_header[0x3C],
        dos_header[0x3D],
        dos_header[0x3E],
        dos_header[0x3F],
    ]);

    if !(64..=1024).contains(&e_lfanew) {
        return None;
    }

    let pe_header_offset = base_address + e_lfanew as usize;
    let mut pe_header = [0u8; 264];

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

    if pe_header[0] != 0x50 || pe_header[1] != 0x45 || pe_header[2] != 0 || pe_header[3] != 0 {
        return None;
    }

    // Machine type is at offset 4-5 in COFF header (after PE signature)
    let machine_type = u16::from_le_bytes([pe_header[4], pe_header[5]]);
    let number_of_sections = u16::from_le_bytes([pe_header[6], pe_header[7]]);
    let size_of_optional_header = u16::from_le_bytes([pe_header[20], pe_header[21]]);

    let optional_magic = u16::from_le_bytes([pe_header[24], pe_header[25]]);
    let is_pe32_plus = optional_magic == 0x20b;

    let size_of_image =
        u32::from_le_bytes([pe_header[80], pe_header[81], pe_header[82], pe_header[83]]);
    let size_of_headers =
        u32::from_le_bytes([pe_header[84], pe_header[85], pe_header[86], pe_header[87]]);

    if !(0x1000..=0x40000000).contains(&size_of_image) {
        return None;
    }
    if number_of_sections > 96 {
        return None;
    }

    // Read section headers
    let section_table_offset = pe_header_offset + 24 + size_of_optional_header as usize;
    let section_table_size = number_of_sections as usize * 40;
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
        sections.push(SectionInfo {
            virtual_size: u32::from_le_bytes([
                section_data[offset + 8],
                section_data[offset + 9],
                section_data[offset + 10],
                section_data[offset + 11],
            ]),
            virtual_address: u32::from_le_bytes([
                section_data[offset + 12],
                section_data[offset + 13],
                section_data[offset + 14],
                section_data[offset + 15],
            ]),
            size_of_raw_data: u32::from_le_bytes([
                section_data[offset + 16],
                section_data[offset + 17],
                section_data[offset + 18],
                section_data[offset + 19],
            ]),
            pointer_to_raw_data: u32::from_le_bytes([
                section_data[offset + 20],
                section_data[offset + 21],
                section_data[offset + 22],
                section_data[offset + 23],
            ]),
        });
    }

    Some(PeInfo {
        machine_type,
        e_lfanew,
        size_of_image,
        size_of_headers,
        number_of_sections,
        size_of_optional_header,
        sections,
        is_pe32_plus,
    })
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
    // Machine (from pe_info, detected from target process)
    file_image[coff_offset..coff_offset + 2].copy_from_slice(&pe_info.machine_type.to_le_bytes());
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

// =============================================================================
// .NET Metadata Parsing - Assembly Name Extraction
// =============================================================================

/// Extract the assembly name from .NET metadata in a PE file.
/// This reads the Assembly table from the #~ stream and looks up the name in #Strings.
/// Returns None if the file is not a .NET assembly or metadata is corrupted.
pub fn extract_assembly_name_from_metadata(pe_data: &[u8]) -> Option<String> {
    // Parse DOS header
    if pe_data.len() < 64 || pe_data[0] != b'M' || pe_data[1] != b'Z' {
        return None;
    }

    let e_lfanew = u32::from_le_bytes([
        pe_data[0x3C],
        pe_data[0x3D],
        pe_data[0x3E],
        pe_data[0x3F],
    ]) as usize;

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

        let stream_offset =
            u32::from_le_bytes([metadata[pos], metadata[pos + 1], metadata[pos + 2], metadata[pos + 3]])
                as usize;
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
    let string_index_size = if heap_sizes & 0x01 != 0 { 4 } else { 2 };
    let blob_index_size = if heap_sizes & 0x04 != 0 { 4 } else { 2 };

    let valid = u64::from_le_bytes([
        tilde[8], tilde[9], tilde[10], tilde[11], tilde[12], tilde[13], tilde[14], tilde[15],
    ]);

    // Count present tables and find Assembly table (0x20 = bit 32)
    let assembly_table_bit = 1u64 << 0x20;
    if valid & assembly_table_bit == 0 {
        return None; // No Assembly table
    }

    // Read row counts for all present tables
    let mut pos = 24usize; // After header
    let mut assembly_table_offset = 0usize;
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

    // Calculate offset to Assembly table by summing sizes of preceding tables
    let tables_start = pos;
    let mut current_offset = tables_start;

    for i in 0..64 {
        if valid & (1u64 << i) != 0 {
            if i == 0x20 {
                assembly_table_offset = current_offset;
                break;
            }
            // Calculate row size for this table
            let row_size = get_table_row_size(i, &row_counts, valid, string_index_size, blob_index_size);
            let table_index = count_bits_before(valid, i);
            let row_count = *row_counts.get(table_index)? as usize;
            current_offset += row_size * row_count;
        }
    }

    if assembly_table_offset == 0 {
        return None;
    }

    // Assembly table row format:
    // HashAlgId: u32
    // MajorVersion: u16
    // MinorVersion: u16
    // BuildNumber: u16
    // RevisionNumber: u16
    // Flags: u32
    // PublicKey: Blob index
    // Name: String index
    // Culture: String index

    let name_offset_in_row = 4 + 2 + 2 + 2 + 2 + 4 + blob_index_size;
    let name_pos = assembly_table_offset + name_offset_in_row;

    if name_pos + string_index_size > tilde.len() {
        return None;
    }

    let name_index = if string_index_size == 4 {
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
    let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
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
/// This is a simplified version - we only need accurate sizes for tables before Assembly (0x20).
fn get_table_row_size(
    table: usize,
    row_counts: &[u32],
    valid: u64,
    string_idx_size: usize,
    blob_idx_size: usize,
) -> usize {
    // Simplified table row sizes - we only need tables 0x00 to 0x1F
    // For a complete implementation, each table has specific column definitions
    // Reference: ECMA-335 II.22

    let guid_idx_size = 2usize; // Simplified - could be 4 if #GUID is large

    // Helper to get coded index size
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

    match table {
        0x00 => 4 + string_idx_size * 2 + guid_idx_size * 3, // Module
        0x01 => coded_idx_size(2, &[0x00, 0x1A, 0x23, 0x01]) + string_idx_size * 2, // TypeRef
        0x02 => {
            // TypeDef
            4 + string_idx_size * 2
                + coded_idx_size(3, &[0x01, 0x02, 0x1B])
                + simple_idx_size(row_counts, valid, 0x04)
                + simple_idx_size(row_counts, valid, 0x06)
        }
        0x04 => 2 + string_idx_size + blob_idx_size, // Field
        0x06 => {
            // MethodDef
            4 + 2 + 2 + string_idx_size + blob_idx_size + simple_idx_size(row_counts, valid, 0x08)
        }
        0x08 => 2 + string_idx_size + blob_idx_size, // Param
        0x09 => {
            // InterfaceImpl
            simple_idx_size(row_counts, valid, 0x02) + coded_idx_size(3, &[0x01, 0x02, 0x1B])
        }
        0x0A => coded_idx_size(3, &[0x01, 0x02, 0x1B]) + string_idx_size + blob_idx_size, // MemberRef
        0x0B => coded_idx_size(5, &[0x00, 0x01, 0x02, 0x04, 0x06, 0x08, 0x09, 0x0A, 0x0E, 0x11, 0x14, 0x17, 0x20, 0x23, 0x26, 0x27, 0x28]) + coded_idx_size(2, &[0x04, 0x06, 0x00, 0x00]) + blob_idx_size, // Constant
        0x0C => coded_idx_size(5, &[0x00, 0x01, 0x02, 0x04, 0x06, 0x08, 0x09, 0x0A, 0x0E, 0x11, 0x14, 0x17, 0x20, 0x23, 0x26, 0x27, 0x28]) + coded_idx_size(3, &[0x00, 0x00, 0x0A, 0x00]) + blob_idx_size, // CustomAttribute
        0x0D => coded_idx_size(1, &[0x04, 0x08]) + blob_idx_size, // FieldMarshal
        0x0E => 2 + blob_idx_size,                   // DeclSecurity
        0x0F => 2 + 4 + 4 + simple_idx_size(row_counts, valid, 0x02), // ClassLayout
        0x10 => 4 + simple_idx_size(row_counts, valid, 0x04), // FieldLayout
        0x11 => blob_idx_size,                       // StandAloneSig
        0x12 => simple_idx_size(row_counts, valid, 0x02) + simple_idx_size(row_counts, valid, 0x04), // EventMap
        0x14 => 2 + string_idx_size + coded_idx_size(3, &[0x01, 0x02, 0x1B]), // Event
        0x15 => simple_idx_size(row_counts, valid, 0x02) + simple_idx_size(row_counts, valid, 0x17), // PropertyMap
        0x17 => 2 + string_idx_size + blob_idx_size, // Property
        0x18 => 2 + coded_idx_size(1, &[0x06, 0x0A]) + coded_idx_size(5, &[0x00, 0x01, 0x02, 0x04, 0x06, 0x08, 0x09, 0x0A, 0x0E, 0x11, 0x14, 0x17, 0x20, 0x23, 0x26, 0x27, 0x28]), // MethodSemantics
        0x19 => simple_idx_size(row_counts, valid, 0x02) + coded_idx_size(2, &[0x02, 0x1B]) + simple_idx_size(row_counts, valid, 0x06), // MethodImpl
        0x1A => string_idx_size,                     // ModuleRef
        0x1B => blob_idx_size,                       // TypeSpec
        0x1C => 2 + coded_idx_size(3, &[0x01, 0x02, 0x1B]) + string_idx_size + string_idx_size, // ImplMap
        0x1D => 4 + simple_idx_size(row_counts, valid, 0x04), // FieldRVA
        0x20 => 4 + 2 + 2 + 2 + 2 + 4 + blob_idx_size + string_idx_size * 2, // Assembly
        _ => 0, // We don't need tables after Assembly
    }
}

/// Get simple table index size (2 or 4 bytes based on row count).
fn simple_idx_size(row_counts: &[u32], valid: u64, table: usize) -> usize {
    if valid & (1u64 << table) == 0 {
        return 2;
    }
    let idx = count_bits_before(valid, table);
    let count = row_counts.get(idx).copied().unwrap_or(0);
    if count < 0x10000 {
        2
    } else {
        4
    }
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
    if rva < 0x1000 {
        Some(rva)
    } else {
        None
    }
}
