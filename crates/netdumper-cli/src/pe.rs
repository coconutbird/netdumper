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

/// Validate that the PE has a valid CLI header in memory.
/// Returns true if the CLI header at the given RVA contains valid .NET metadata.
pub fn validate_cli_header_in_memory(
    process_handle: HANDLE,
    base_address: usize,
    pe_info: &PeInfo,
) -> bool {
    // Find the CLI header data directory
    // In PE32, data directories start at optional header offset 96
    // In PE32+, data directories start at optional header offset 112
    // CLI header is data directory index 14

    let pe_header_offset = base_address + pe_info.e_lfanew as usize;
    let data_dir_base_offset = if pe_info.is_pe32_plus { 112 } else { 96 };
    let cli_dir_offset = pe_header_offset + 24 + data_dir_base_offset + 14 * 8;

    let mut cli_dir = [0u8; 8];
    let mut bytes_read = 0usize;

    let result = unsafe {
        ReadProcessMemory(
            process_handle,
            cli_dir_offset as *const c_void,
            cli_dir.as_mut_ptr() as *mut c_void,
            8,
            Some(&mut bytes_read),
        )
    };

    if result.is_err() || bytes_read < 8 {
        return false;
    }

    let cli_rva = u32::from_le_bytes([cli_dir[0], cli_dir[1], cli_dir[2], cli_dir[3]]);
    let cli_size = u32::from_le_bytes([cli_dir[4], cli_dir[5], cli_dir[6], cli_dir[7]]);

    if cli_rva == 0 || cli_size < 72 {
        return false;
    }

    // Read the CLI header from memory
    let cli_header_addr = base_address + cli_rva as usize;
    let mut cli_header = [0u8; 16];

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
    const FILE_ALIGNMENT: u32 = 0x200;
    const SECTION_ALIGNMENT: u32 = 0x1000;
    const SIZE_OF_HEADERS: u32 = 0x200;
    const TEXT_RVA: u32 = 0x1000;
    const COR20_SIZE: u32 = 72;
    const METADATA_RVA: u32 = TEXT_RVA + COR20_SIZE; // 0x1048

    let metadata_size = metadata.len() as u32;
    let text_raw_size = COR20_SIZE + metadata_size;
    let text_raw_size_aligned = (text_raw_size + FILE_ALIGNMENT - 1) & !(FILE_ALIGNMENT - 1);
    let text_virtual_size = COR20_SIZE + metadata_size;
    let size_of_image = TEXT_RVA + ((text_virtual_size + SECTION_ALIGNMENT - 1) & !(SECTION_ALIGNMENT - 1));

    let total_file_size = SIZE_OF_HEADERS as usize + text_raw_size_aligned as usize;
    let mut pe = vec![0u8; total_file_size];

    // DOS Header (64 bytes)
    pe[0] = 0x4D; // 'M'
    pe[1] = 0x5A; // 'Z'
    // e_lfanew at offset 0x3C = 0x80
    pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());

    // DOS Stub (0x40-0x7F) - minimal "This program cannot be run in DOS mode"
    // We'll leave it as zeros for simplicity

    // PE Signature at 0x80
    pe[0x80] = 0x50; // 'P'
    pe[0x81] = 0x45; // 'E'
    pe[0x82] = 0x00;
    pe[0x83] = 0x00;

    // COFF Header (20 bytes at 0x84)
    let machine = if is_64bit { 0x8664u16 } else { 0x014Cu16 }; // AMD64 or i386
    pe[0x84..0x86].copy_from_slice(&machine.to_le_bytes());
    pe[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); // NumberOfSections = 1
    // TimeDateStamp, PointerToSymbolTable, NumberOfSymbols = 0
    let size_of_optional_header: u16 = if is_64bit { 240 } else { 224 };
    pe[0x94..0x96].copy_from_slice(&size_of_optional_header.to_le_bytes());
    // Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE | DLL
    let characteristics: u16 = 0x0002 | 0x0020 | 0x2000;
    pe[0x96..0x98].copy_from_slice(&characteristics.to_le_bytes());

    // Optional Header starts at 0x98
    let opt_base = 0x98usize;

    if is_64bit {
        // PE32+ Magic
        pe[opt_base..opt_base + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        // MajorLinkerVersion, MinorLinkerVersion
        pe[opt_base + 2] = 14;
        pe[opt_base + 3] = 0;
        // SizeOfCode
        pe[opt_base + 4..opt_base + 8].copy_from_slice(&text_raw_size_aligned.to_le_bytes());
        // SizeOfInitializedData = 0
        // SizeOfUninitializedData = 0
        // AddressOfEntryPoint = 0 (pure IL assembly)
        // BaseOfCode = TEXT_RVA
        pe[opt_base + 20..opt_base + 24].copy_from_slice(&TEXT_RVA.to_le_bytes());
        // ImageBase (8 bytes for PE32+) = 0x180000000
        pe[opt_base + 24..opt_base + 32].copy_from_slice(&0x180000000u64.to_le_bytes());
        // SectionAlignment
        pe[opt_base + 32..opt_base + 36].copy_from_slice(&SECTION_ALIGNMENT.to_le_bytes());
        // FileAlignment
        pe[opt_base + 36..opt_base + 40].copy_from_slice(&FILE_ALIGNMENT.to_le_bytes());
        // OS Version (6.0)
        pe[opt_base + 40..opt_base + 42].copy_from_slice(&6u16.to_le_bytes());
        pe[opt_base + 42..opt_base + 44].copy_from_slice(&0u16.to_le_bytes());
        // Image Version = 0
        // Subsystem Version (6.0)
        pe[opt_base + 48..opt_base + 50].copy_from_slice(&6u16.to_le_bytes());
        pe[opt_base + 50..opt_base + 52].copy_from_slice(&0u16.to_le_bytes());
        // Win32VersionValue = 0
        // SizeOfImage
        pe[opt_base + 56..opt_base + 60].copy_from_slice(&size_of_image.to_le_bytes());
        // SizeOfHeaders
        pe[opt_base + 60..opt_base + 64].copy_from_slice(&SIZE_OF_HEADERS.to_le_bytes());
        // CheckSum = 0
        // Subsystem = WINDOWS_CUI (3)
        pe[opt_base + 68..opt_base + 70].copy_from_slice(&3u16.to_le_bytes());
        // DllCharacteristics: DYNAMIC_BASE | NX_COMPAT | NO_SEH | TERMINAL_SERVER_AWARE
        let dll_chars: u16 = 0x0040 | 0x0100 | 0x0400 | 0x8000;
        pe[opt_base + 70..opt_base + 72].copy_from_slice(&dll_chars.to_le_bytes());
        // Stack/Heap sizes (8 bytes each for PE32+)
        pe[opt_base + 72..opt_base + 80].copy_from_slice(&0x100000u64.to_le_bytes()); // SizeOfStackReserve
        pe[opt_base + 80..opt_base + 88].copy_from_slice(&0x1000u64.to_le_bytes()); // SizeOfStackCommit
        pe[opt_base + 88..opt_base + 96].copy_from_slice(&0x100000u64.to_le_bytes()); // SizeOfHeapReserve
        pe[opt_base + 96..opt_base + 104].copy_from_slice(&0x1000u64.to_le_bytes()); // SizeOfHeapCommit
        // LoaderFlags = 0
        // NumberOfRvaAndSizes = 16
        pe[opt_base + 108..opt_base + 112].copy_from_slice(&16u32.to_le_bytes());

        // Data Directories start at opt_base + 112
        // We only need CLI header (index 14)
        let cli_dir_offset = opt_base + 112 + 14 * 8;
        pe[cli_dir_offset..cli_dir_offset + 4].copy_from_slice(&TEXT_RVA.to_le_bytes()); // CLI RVA
        pe[cli_dir_offset + 4..cli_dir_offset + 8].copy_from_slice(&COR20_SIZE.to_le_bytes()); // CLI Size
    } else {
        // PE32 Magic
        pe[opt_base..opt_base + 2].copy_from_slice(&0x10Bu16.to_le_bytes());
        pe[opt_base + 2] = 14;
        pe[opt_base + 3] = 0;
        pe[opt_base + 4..opt_base + 8].copy_from_slice(&text_raw_size_aligned.to_le_bytes());
        pe[opt_base + 20..opt_base + 24].copy_from_slice(&TEXT_RVA.to_le_bytes());
        // BaseOfData (PE32 only)
        pe[opt_base + 24..opt_base + 28].copy_from_slice(&TEXT_RVA.to_le_bytes());
        // ImageBase (4 bytes for PE32) = 0x10000000
        pe[opt_base + 28..opt_base + 32].copy_from_slice(&0x10000000u32.to_le_bytes());
        pe[opt_base + 32..opt_base + 36].copy_from_slice(&SECTION_ALIGNMENT.to_le_bytes());
        pe[opt_base + 36..opt_base + 40].copy_from_slice(&FILE_ALIGNMENT.to_le_bytes());
        pe[opt_base + 40..opt_base + 42].copy_from_slice(&6u16.to_le_bytes());
        pe[opt_base + 42..opt_base + 44].copy_from_slice(&0u16.to_le_bytes());
        pe[opt_base + 48..opt_base + 50].copy_from_slice(&6u16.to_le_bytes());
        pe[opt_base + 50..opt_base + 52].copy_from_slice(&0u16.to_le_bytes());
        pe[opt_base + 56..opt_base + 60].copy_from_slice(&size_of_image.to_le_bytes());
        pe[opt_base + 60..opt_base + 64].copy_from_slice(&SIZE_OF_HEADERS.to_le_bytes());
        pe[opt_base + 68..opt_base + 70].copy_from_slice(&3u16.to_le_bytes());
        let dll_chars: u16 = 0x0040 | 0x0100 | 0x0400 | 0x8000;
        pe[opt_base + 70..opt_base + 72].copy_from_slice(&dll_chars.to_le_bytes());
        // Stack/Heap sizes (4 bytes each for PE32)
        pe[opt_base + 72..opt_base + 76].copy_from_slice(&0x100000u32.to_le_bytes());
        pe[opt_base + 76..opt_base + 80].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[opt_base + 80..opt_base + 84].copy_from_slice(&0x100000u32.to_le_bytes());
        pe[opt_base + 84..opt_base + 88].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[opt_base + 92..opt_base + 96].copy_from_slice(&16u32.to_le_bytes());

        let cli_dir_offset = opt_base + 96 + 14 * 8;
        pe[cli_dir_offset..cli_dir_offset + 4].copy_from_slice(&TEXT_RVA.to_le_bytes());
        pe[cli_dir_offset + 4..cli_dir_offset + 8].copy_from_slice(&COR20_SIZE.to_le_bytes());
    }

    // Section Header for .text
    let section_header_offset = opt_base + size_of_optional_header as usize;
    // Name: ".text\0\0\0"
    pe[section_header_offset..section_header_offset + 5].copy_from_slice(b".text");
    // VirtualSize
    pe[section_header_offset + 8..section_header_offset + 12].copy_from_slice(&text_virtual_size.to_le_bytes());
    // VirtualAddress
    pe[section_header_offset + 12..section_header_offset + 16].copy_from_slice(&TEXT_RVA.to_le_bytes());
    // SizeOfRawData
    pe[section_header_offset + 16..section_header_offset + 20].copy_from_slice(&text_raw_size_aligned.to_le_bytes());
    // PointerToRawData
    pe[section_header_offset + 20..section_header_offset + 24].copy_from_slice(&SIZE_OF_HEADERS.to_le_bytes());
    // Characteristics: CNT_CODE | MEM_EXECUTE | MEM_READ
    let section_chars: u32 = 0x00000020 | 0x20000000 | 0x40000000;
    pe[section_header_offset + 36..section_header_offset + 40].copy_from_slice(&section_chars.to_le_bytes());

    // COR20 Header at file offset 0x200 (SIZE_OF_HEADERS)
    let cor20_offset = SIZE_OF_HEADERS as usize;
    // cb = 72
    pe[cor20_offset..cor20_offset + 4].copy_from_slice(&COR20_SIZE.to_le_bytes());
    // MajorRuntimeVersion = 2
    pe[cor20_offset + 4..cor20_offset + 6].copy_from_slice(&2u16.to_le_bytes());
    // MinorRuntimeVersion = 5
    pe[cor20_offset + 6..cor20_offset + 8].copy_from_slice(&5u16.to_le_bytes());
    // MetaData RVA
    pe[cor20_offset + 8..cor20_offset + 12].copy_from_slice(&METADATA_RVA.to_le_bytes());
    // MetaData Size
    pe[cor20_offset + 12..cor20_offset + 16].copy_from_slice(&metadata_size.to_le_bytes());
    // Flags = COMIMAGE_FLAGS_ILONLY
    pe[cor20_offset + 16..cor20_offset + 20].copy_from_slice(&1u32.to_le_bytes());
    // EntryPointToken = 0 (no entry point for class library)
    // Rest of COR20 header fields are 0 (no resources, strong name, etc.)

    // Copy metadata after COR20 header
    let metadata_offset = cor20_offset + COR20_SIZE as usize;
    pe[metadata_offset..metadata_offset + metadata.len()].copy_from_slice(metadata);

    pe
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

/// Debug info for metadata extraction failures
#[derive(Debug)]
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

    if assembly_table_offset == 0 {
        return None;
    }

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
    let name_pos = assembly_table_offset + name_offset_in_row;

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
