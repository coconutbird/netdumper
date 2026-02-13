//! Message protocol for IPC communication
//!
//! Packet format:
//! ```text
//! ┌──────────────┐
//! │ magic: u32   │  <- 0x4E455444 "NETD"
//! │ id: u32      │  <- packet type
//! │ size: u32    │  <- payload size in bytes
//! │ payload...   │  <- variable length, format depends on packet type
//! └──────────────┘
//! ```

use crate::MAGIC;

/// Packet header size in bytes
pub const HEADER_SIZE: usize = 12; // magic + id + size

/// Maximum payload size (16KB for assembly data)
pub const MAX_PAYLOAD_SIZE: usize = 16384;

/// Packet types (id field)
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketId {
    /// No packet / invalid
    None = 0,
    /// Log message (payload: LogLevel + UTF-8 string)
    Log = 1,
    /// DLL is ready and waiting (payload: none)
    Ready = 2,
    /// Assembly info (payload: serialized AssemblyInfo)
    Assembly = 3,
    /// Enumeration complete (payload: count as u32)
    EnumerationComplete = 4,
    /// Fatal error (payload: UTF-8 string)
    Fatal = 5,
    /// Runtime detected (payload: RuntimeType as u8 + version string)
    RuntimeDetected = 6,
}

impl From<u32> for PacketId {
    fn from(v: u32) -> Self {
        match v {
            1 => PacketId::Log,
            2 => PacketId::Ready,
            3 => PacketId::Assembly,
            4 => PacketId::EnumerationComplete,
            5 => PacketId::Fatal,
            6 => PacketId::RuntimeDetected,
            _ => PacketId::None,
        }
    }
}

/// Log levels for Log packets
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    /// Debug message
    Debug = 0,
    /// Informational message
    Info = 1,
    /// Warning message
    Warning = 2,
    /// Error message
    Error = 3,
}

impl From<u8> for LogLevel {
    fn from(v: u8) -> Self {
        match v {
            0 => LogLevel::Debug,
            1 => LogLevel::Info,
            2 => LogLevel::Warning,
            3 => LogLevel::Error,
            _ => LogLevel::Info,
        }
    }
}

/// Packet header (12 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PacketHeader {
    /// Magic value for validation
    pub magic: u32,
    /// Packet type identifier
    pub id: u32,
    /// Payload size in bytes
    pub size: u32,
}

impl PacketHeader {
    /// Create a new packet header
    pub fn new(id: PacketId, payload_size: usize) -> Self {
        Self {
            magic: MAGIC,
            id: id as u32,
            size: payload_size as u32,
        }
    }

    /// Check if header has valid magic and reasonable size
    pub fn is_valid(&self) -> bool {
        self.magic == MAGIC && self.size as usize <= MAX_PAYLOAD_SIZE
    }

    /// Get the packet type
    pub fn packet_id(&self) -> PacketId {
        PacketId::from(self.id)
    }

    /// Serialize header to bytes (little-endian)
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut bytes = [0u8; HEADER_SIZE];
        bytes[0..4].copy_from_slice(&self.magic.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.id.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.size.to_le_bytes());
        bytes
    }

    /// Deserialize header from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < HEADER_SIZE {
            return None;
        }
        Some(Self {
            magic: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            id: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            size: u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        })
    }
}

/// A complete packet with header and payload
#[derive(Debug, Clone)]
pub struct Packet {
    /// Packet header containing type and size
    pub header: PacketHeader,
    /// Variable-length payload data
    pub payload: Vec<u8>,
}

impl Packet {
    /// Create a log message packet
    pub fn log(level: LogLevel, message: &str) -> Self {
        let mut payload = Vec::with_capacity(1 + message.len());
        payload.push(level as u8);
        payload.extend_from_slice(message.as_bytes());
        Self {
            header: PacketHeader::new(PacketId::Log, payload.len()),
            payload,
        }
    }

    /// Create a ready packet (no payload)
    pub fn ready() -> Self {
        Self {
            header: PacketHeader::new(PacketId::Ready, 0),
            payload: Vec::new(),
        }
    }

    /// Create an assembly info packet
    /// Format: name_len(u16) + name + path_len(u16) + path + base_addr(u64) + size(u64)
    pub fn assembly(name: &str, path: Option<&str>, base_address: usize, size: usize) -> Self {
        let path_str = path.unwrap_or("");
        let payload_size = 2 + name.len() + 2 + path_str.len() + 8 + 8;
        let mut payload = Vec::with_capacity(payload_size);

        // Name (length-prefixed)
        payload.extend_from_slice(&(name.len() as u16).to_le_bytes());
        payload.extend_from_slice(name.as_bytes());

        // Path (length-prefixed)
        payload.extend_from_slice(&(path_str.len() as u16).to_le_bytes());
        payload.extend_from_slice(path_str.as_bytes());

        // Base address and size
        payload.extend_from_slice(&(base_address as u64).to_le_bytes());
        payload.extend_from_slice(&(size as u64).to_le_bytes());

        Self {
            header: PacketHeader::new(PacketId::Assembly, payload.len()),
            payload,
        }
    }

    /// Create an enumeration complete packet
    pub fn enumeration_complete(count: u32) -> Self {
        Self {
            header: PacketHeader::new(PacketId::EnumerationComplete, 4),
            payload: count.to_le_bytes().to_vec(),
        }
    }

    /// Create a fatal error packet
    pub fn fatal(message: &str) -> Self {
        Self {
            header: PacketHeader::new(PacketId::Fatal, message.len()),
            payload: message.as_bytes().to_vec(),
        }
    }

    /// Create a runtime detected packet
    pub fn runtime_detected(runtime_type: u8, version: &str) -> Self {
        let mut payload = Vec::with_capacity(1 + version.len());
        payload.push(runtime_type);
        payload.extend_from_slice(version.as_bytes());
        Self {
            header: PacketHeader::new(PacketId::RuntimeDetected, payload.len()),
            payload,
        }
    }

    /// Get packet ID
    pub fn id(&self) -> PacketId {
        self.header.packet_id()
    }

    /// Get log level (for Log packets)
    pub fn log_level(&self) -> Option<LogLevel> {
        if self.id() == PacketId::Log && !self.payload.is_empty() {
            Some(LogLevel::from(self.payload[0]))
        } else {
            None
        }
    }

    /// Get message text (for Log/Fatal packets)
    pub fn message(&self) -> &str {
        match self.id() {
            PacketId::Log if !self.payload.is_empty() => {
                std::str::from_utf8(&self.payload[1..]).unwrap_or("")
            }
            PacketId::Fatal => std::str::from_utf8(&self.payload).unwrap_or(""),
            _ => "",
        }
    }

    /// Parse assembly data from Assembly packet
    /// Returns (name, path, base_address, size)
    pub fn assembly_data(&self) -> Option<(String, Option<String>, usize, usize)> {
        if self.id() != PacketId::Assembly || self.payload.len() < 4 {
            return None;
        }

        let mut offset = 0;

        // Read name
        let name_len =
            u16::from_le_bytes([self.payload[offset], self.payload[offset + 1]]) as usize;
        offset += 2;
        if offset + name_len > self.payload.len() {
            return None;
        }
        let name = String::from_utf8_lossy(&self.payload[offset..offset + name_len]).to_string();
        offset += name_len;

        // Read path
        if offset + 2 > self.payload.len() {
            return None;
        }
        let path_len =
            u16::from_le_bytes([self.payload[offset], self.payload[offset + 1]]) as usize;
        offset += 2;
        if offset + path_len > self.payload.len() {
            return None;
        }
        let path = if path_len > 0 {
            Some(String::from_utf8_lossy(&self.payload[offset..offset + path_len]).to_string())
        } else {
            None
        };
        offset += path_len;

        // Read base address and size
        if offset + 16 > self.payload.len() {
            return None;
        }
        let base_address =
            u64::from_le_bytes(self.payload[offset..offset + 8].try_into().ok()?) as usize;
        offset += 8;
        let size = u64::from_le_bytes(self.payload[offset..offset + 8].try_into().ok()?) as usize;

        Some((name, path, base_address, size))
    }

    /// Get enumeration count from EnumerationComplete packet
    pub fn enumeration_count(&self) -> Option<u32> {
        if self.id() == PacketId::EnumerationComplete && self.payload.len() >= 4 {
            Some(u32::from_le_bytes(self.payload[0..4].try_into().ok()?))
        } else {
            None
        }
    }

    /// Total size in bytes (header + payload)
    pub fn total_size(&self) -> usize {
        HEADER_SIZE + self.payload.len()
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.total_size());
        bytes.extend_from_slice(&self.header.to_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let header = PacketHeader::from_bytes(bytes)?;
        if !header.is_valid() {
            return None;
        }
        let payload_end = HEADER_SIZE + header.size as usize;
        if bytes.len() < payload_end {
            return None;
        }
        Some(Self {
            header,
            payload: bytes[HEADER_SIZE..payload_end].to_vec(),
        })
    }
}
