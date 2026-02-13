//! PE header parsing and reconstruction.
//!
//! This module handles reading PE headers from process memory,
//! converting between memory and file layouts, and reconstructing
//! corrupted headers (anti-anti-dump).

use std::ffi::c_void;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Memory::{MEM_COMMIT, MEMORY_BASIC_INFORMATION, VirtualQueryEx};

// Machine type constant for current architecture
#[cfg(target_arch = "x86_64")]
const IMAGE_FILE_MACHINE_CURRENT: u16 = 0x8664;
#[cfg(target_arch = "x86")]
const IMAGE_FILE_MACHINE_CURRENT: u16 = 0x014c;
#[cfg(target_arch = "aarch64")]
const IMAGE_FILE_MACHINE_CURRENT: u16 = 0xAA64;

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

/// Reconstruct PE headers from memory regions when original headers are corrupted
pub fn reconstruct_pe_info(process_handle: HANDLE, base_address: usize) -> Option<PeInfo> {
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

    Some(PeInfo {
        e_lfanew: 0x80,
        size_of_image,
        size_of_headers: 0x1000,
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
