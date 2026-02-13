//! Shared memory IPC implementation
//!
//! Uses a byte-based ring buffer with packet protocol:
//! - Header contains control flags and ring buffer indices
//! - Data region is a circular buffer for variable-size packets

use crate::messages::{HEADER_SIZE, LogLevel, MAX_PAYLOAD_SIZE, Packet, PacketHeader};
use crate::{MAGIC, SHARED_MEMORY_NAME_PREFIX, SHARED_MEMORY_SIZE};
use std::sync::atomic::{AtomicU32, Ordering};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Memory::{
    CreateFileMappingW, FILE_MAP_ALL_ACCESS, FILE_MAP_READ, FILE_MAP_WRITE,
    MEMORY_MAPPED_VIEW_ADDRESS, MapViewOfFile, OpenFileMappingW, PAGE_READWRITE, UnmapViewOfFile,
};
use windows::core::{Error, PCWSTR, Result};

/// Size of the shared header (64 bytes core + reserved padding = 256)
pub const SHARED_HEADER_SIZE: usize = 256;

/// Size of the ring buffer data region
pub const RING_BUFFER_SIZE: usize = SHARED_MEMORY_SIZE - SHARED_HEADER_SIZE;

/// Header at the start of shared memory
#[repr(C)]
pub struct SharedHeader {
    /// Magic value to verify valid shared memory
    pub magic: u32,
    /// Process ID of the target process
    pub target_pid: u32,
    /// Write offset in ring buffer (DLL writes here)
    pub write_offset: AtomicU32,
    /// Read offset in ring buffer (CLI reads from here)
    pub read_offset: AtomicU32,
    /// Flag: DLL should start enumeration
    pub start_enumeration: AtomicU32,
    /// Flag: DLL has finished enumeration
    pub finished: AtomicU32,
    /// Number of assemblies found
    pub assembly_count: AtomicU32,
    /// Runtime type detected (0 = unknown, 1 = Framework, 2 = Core)
    pub runtime_type: AtomicU32,
    /// Reserved for future use / padding
    pub reserved: [u8; 216],
}

/// Handle to shared memory (CLI side - creates the mapping)
pub struct IpcHost {
    handle: HANDLE,
    view: MEMORY_MAPPED_VIEW_ADDRESS,
}

impl IpcHost {
    /// Create shared memory for a target process
    pub fn create(target_pid: u32) -> Result<Self> {
        let name = format!("{}{}\0", SHARED_MEMORY_NAME_PREFIX, target_pid);
        let name_wide: Vec<u16> = name.encode_utf16().collect();

        unsafe {
            let handle = CreateFileMappingW(
                HANDLE::default(),
                None,
                PAGE_READWRITE,
                0,
                SHARED_MEMORY_SIZE as u32,
                PCWSTR(name_wide.as_ptr()),
            )?;

            let view = MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, SHARED_MEMORY_SIZE);
            if view.Value.is_null() {
                CloseHandle(handle)?;
                return Err(Error::from_win32());
            }

            // Initialize header
            let header = &mut *(view.Value as *mut SharedHeader);
            header.magic = MAGIC;
            header.target_pid = target_pid;
            header.write_offset = AtomicU32::new(0);
            header.read_offset = AtomicU32::new(0);
            header.start_enumeration = AtomicU32::new(0);
            header.finished = AtomicU32::new(0);
            header.assembly_count = AtomicU32::new(0);
            header.runtime_type = AtomicU32::new(0);
            header.reserved = [0u8; 216];

            Ok(Self { handle, view })
        }
    }

    /// Get pointer to header
    fn header(&self) -> &SharedHeader {
        unsafe { &*(self.view.Value as *const SharedHeader) }
    }

    fn header_mut(&mut self) -> &mut SharedHeader {
        unsafe { &mut *(self.view.Value as *mut SharedHeader) }
    }

    /// Get pointer to ring buffer data region
    fn ring_buffer(&self) -> &[u8] {
        unsafe {
            let ptr = (self.view.Value as *const u8).add(SHARED_HEADER_SIZE);
            std::slice::from_raw_parts(ptr, RING_BUFFER_SIZE)
        }
    }

    /// Signal DLL to start enumeration
    pub fn start_enumeration(&mut self) {
        self.header_mut()
            .start_enumeration
            .store(1, Ordering::SeqCst);
    }

    /// Check if DLL has finished enumeration
    pub fn is_finished(&self) -> bool {
        self.header().finished.load(Ordering::SeqCst) != 0
    }

    /// Get number of assemblies found
    pub fn get_assembly_count(&self) -> u32 {
        self.header().assembly_count.load(Ordering::Relaxed)
    }

    /// Get detected runtime type (0 = unknown, 1 = Framework, 2 = Core)
    pub fn get_runtime_type(&self) -> u32 {
        self.header().runtime_type.load(Ordering::Relaxed)
    }

    /// Try to read a packet (non-blocking)
    pub fn try_read(&mut self) -> Option<Packet> {
        let header = self.header();
        let read_off = header.read_offset.load(Ordering::Acquire);
        let write_off = header.write_offset.load(Ordering::Acquire);

        if read_off == write_off {
            return None; // No data
        }

        let ring = self.ring_buffer();

        // Read packet header (may wrap around)
        let mut hdr_bytes = [0u8; HEADER_SIZE];
        for i in 0..HEADER_SIZE {
            hdr_bytes[i] = ring[(read_off as usize + i) % RING_BUFFER_SIZE];
        }

        let pkt_header = PacketHeader::from_bytes(&hdr_bytes)?;
        if !pkt_header.is_valid() {
            return None;
        }

        let payload_size = pkt_header.size as usize;
        if payload_size > MAX_PAYLOAD_SIZE {
            return None;
        }

        // Read payload (may wrap around)
        let mut payload = vec![0u8; payload_size];
        let payload_start = (read_off as usize + HEADER_SIZE) % RING_BUFFER_SIZE;
        for i in 0..payload_size {
            payload[i] = ring[(payload_start + i) % RING_BUFFER_SIZE];
        }

        let total_size = HEADER_SIZE + payload_size;
        let new_read_off = (read_off as usize + total_size) % RING_BUFFER_SIZE;

        // Advance read offset
        self.header_mut()
            .read_offset
            .store(new_read_off as u32, Ordering::Release);

        Some(Packet {
            header: pkt_header,
            payload,
        })
    }
}

impl Drop for IpcHost {
    fn drop(&mut self) {
        unsafe {
            let _ = UnmapViewOfFile(self.view);
            let _ = CloseHandle(self.handle);
        }
    }
}

/// Handle to shared memory (DLL side - opens existing mapping)
pub struct IpcClient {
    #[allow(dead_code)]
    handle: HANDLE,
    view: MEMORY_MAPPED_VIEW_ADDRESS,
}

// SAFETY: IpcClient can be sent between threads
unsafe impl Send for IpcClient {}
unsafe impl Sync for IpcClient {}

impl IpcClient {
    /// Open existing shared memory for this process
    pub fn open(target_pid: u32) -> Result<Self> {
        let name = format!("{}{}\0", SHARED_MEMORY_NAME_PREFIX, target_pid);
        let name_wide: Vec<u16> = name.encode_utf16().collect();

        unsafe {
            let handle = OpenFileMappingW(
                (FILE_MAP_READ | FILE_MAP_WRITE).0,
                false,
                PCWSTR(name_wide.as_ptr()),
            )?;

            let view = MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, SHARED_MEMORY_SIZE);
            if view.Value.is_null() {
                CloseHandle(handle)?;
                return Err(Error::from_win32());
            }

            // Verify magic
            let header = &*(view.Value as *const SharedHeader);
            if header.magic != MAGIC {
                UnmapViewOfFile(view)?;
                CloseHandle(handle)?;
                return Err(Error::from_win32());
            }

            Ok(Self { handle, view })
        }
    }

    /// Get pointer to header
    fn header(&self) -> &SharedHeader {
        unsafe { &*(self.view.Value as *const SharedHeader) }
    }

    fn header_mut(&mut self) -> &mut SharedHeader {
        unsafe { &mut *(self.view.Value as *mut SharedHeader) }
    }

    /// Get mutable pointer to ring buffer data region
    fn ring_buffer_mut(&mut self) -> &mut [u8] {
        unsafe {
            let ptr = (self.view.Value as *mut u8).add(SHARED_HEADER_SIZE);
            std::slice::from_raw_parts_mut(ptr, RING_BUFFER_SIZE)
        }
    }

    /// Check if we should start enumeration
    pub fn should_start(&self) -> bool {
        self.header().start_enumeration.load(Ordering::SeqCst) != 0
    }

    /// Signal that we're finished
    pub fn set_finished(&mut self) {
        self.header_mut().finished.store(1, Ordering::SeqCst);
    }

    /// Set the number of assemblies found
    pub fn set_assembly_count(&self, count: u32) {
        self.header().assembly_count.store(count, Ordering::Relaxed);
    }

    /// Set the detected runtime type (1 = Framework, 2 = Core)
    pub fn set_runtime_type(&self, runtime_type: u32) {
        self.header()
            .runtime_type
            .store(runtime_type, Ordering::Relaxed);
    }

    /// Push a packet to the ring buffer
    pub fn push_packet(&mut self, packet: Packet) {
        let bytes = packet.to_bytes();
        let total_size = bytes.len();

        let write_off = self.header().write_offset.load(Ordering::Acquire) as usize;
        let ring = self.ring_buffer_mut();

        // Write bytes with wrap-around
        for (i, &byte) in bytes.iter().enumerate() {
            ring[(write_off + i) % RING_BUFFER_SIZE] = byte;
        }

        let new_write_off = (write_off + total_size) % RING_BUFFER_SIZE;
        self.header_mut()
            .write_offset
            .store(new_write_off as u32, Ordering::Release);
    }

    /// Helper to send a debug log message
    pub fn debug(&mut self, text: &str) {
        self.push_packet(Packet::log(LogLevel::Debug, text));
    }

    /// Helper to send an info log message
    pub fn info(&mut self, text: &str) {
        self.push_packet(Packet::log(LogLevel::Info, text));
    }

    /// Helper to send a warning log message
    pub fn warn(&mut self, text: &str) {
        self.push_packet(Packet::log(LogLevel::Warning, text));
    }

    /// Helper to send an error log message
    pub fn error(&mut self, text: &str) {
        self.push_packet(Packet::log(LogLevel::Error, text));
    }

    /// Send assembly info
    pub fn send_assembly(
        &mut self,
        name: &str,
        path: Option<&str>,
        base_address: usize,
        size: usize,
    ) {
        self.push_packet(Packet::assembly(name, path, base_address, size));
    }

    /// Send enumeration complete
    pub fn send_enumeration_complete(&mut self, count: u32) {
        self.set_assembly_count(count);
        self.push_packet(Packet::enumeration_complete(count));
    }

    /// Send fatal error
    pub fn send_fatal(&mut self, message: &str) {
        self.push_packet(Packet::fatal(message));
    }
}

impl Drop for IpcClient {
    fn drop(&mut self) {
        unsafe {
            let _ = UnmapViewOfFile(self.view);
            let _ = CloseHandle(self.handle);
        }
    }
}
