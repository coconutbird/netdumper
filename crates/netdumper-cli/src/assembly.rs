//! Assembly information structures.

/// Detailed metadata extracted from the Assembly table.
#[derive(Debug, Clone, Default)]
pub struct AssemblyMetadata {
    /// Assembly name from metadata.
    pub name: String,
    /// Major version number.
    pub major_version: u16,
    /// Minor version number.
    pub minor_version: u16,
    /// Build number.
    pub build_number: u16,
    /// Revision number.
    pub revision_number: u16,
    /// Culture string (empty for neutral culture).
    pub culture: String,
    /// Public key token (8 bytes, hex encoded).
    pub public_key_token: Option<String>,
    /// Full public key (hex encoded).
    pub public_key: Option<String>,
    /// Assembly flags.
    pub flags: u32,
}

impl AssemblyMetadata {
    /// Format version as "Major.Minor.Build.Revision".
    pub fn version_string(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.major_version, self.minor_version, self.build_number, self.revision_number
        )
    }

    /// Format full assembly name like "MyAssembly, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null".
    pub fn full_name(&self) -> String {
        let culture = if self.culture.is_empty() {
            "neutral"
        } else {
            &self.culture
        };
        let pkt = self.public_key_token.as_deref().unwrap_or("null");
        format!(
            "{}, Version={}, Culture={}, PublicKeyToken={}",
            self.name,
            self.version_string(),
            culture,
            pkt
        )
    }
}

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
    /// DAC module address (for GetILForModule calls).
    pub module_address: usize,
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
            module_address: 0,
        }
    }
}

/// Information about a method's IL body.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct MethodILInfo {
    /// MethodDef token (0x06xxxxxx).
    pub token: u32,
    /// RVA of the method body in metadata.
    pub rva: u32,
    /// Address of IL code in process memory (from GetILForModule).
    pub il_address: usize,
    /// Size of the IL method body (including header).
    pub il_size: usize,
}
