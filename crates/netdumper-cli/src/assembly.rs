//! Assembly information structures.

/// Information about a loaded .NET assembly.
#[derive(Debug, Clone)]
pub struct AssemblyInfo {
    /// The name of the assembly.
    pub name: String,
    /// The base address of the assembly in memory (ilBase).
    pub base_address: usize,
    /// The size of the assembly in memory.
    pub size: usize,
    /// The file path of the assembly (if available).
    pub path: Option<String>,
    /// The assembly version (if available).
    pub version: Option<String>,
    /// Whether this is a native image (NGEN/R2R).
    pub is_native_image: bool,
    /// Whether this is a reflection-emitted (dynamic) assembly.
    pub is_reflection: bool,
    /// Whether this is a PE file (vs. in-memory only).
    pub is_pe_file: bool,
    /// Direct pointer to metadata (metadataStart).
    pub metadata_address: usize,
    /// Size of metadata.
    pub metadata_size: usize,
}

impl AssemblyInfo {
    pub fn new(name: String, base_address: usize, size: usize) -> Self {
        Self {
            name,
            base_address,
            size,
            path: None,
            version: None,
            is_native_image: false,
            is_reflection: false,
            is_pe_file: true,
            metadata_address: 0,
            metadata_size: 0,
        }
    }
}
