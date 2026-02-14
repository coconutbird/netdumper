//! Process memory reader implementing portex::Reader trait.
//!
//! This module provides a `ProcessMemoryReader` that allows portex to read
//! PE structures directly from a remote process's memory via ReadProcessMemory.

use std::ffi::c_void;

use portex::Result as PortexResult;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

/// A reader that reads from a remote process's memory.
///
/// This implements `portex::Reader` to allow PE parsing directly from
/// process memory without having to copy the entire image first.
#[derive(Debug, Clone, Copy)]
pub struct ProcessMemoryReader {
    /// Handle to the process (must have PROCESS_VM_READ access)
    handle: HANDLE,
    /// Base address in the process to read from
    base_address: usize,
    /// Optional size limit (if known)
    size: Option<usize>,
}

impl ProcessMemoryReader {
    /// Create a new reader for the given process and base address.
    ///
    /// # Arguments
    /// * `handle` - Process handle with PROCESS_VM_READ access
    /// * `base_address` - Base address of the PE image in process memory
    /// * `size` - Optional size limit (e.g., SizeOfImage)
    pub fn new(handle: HANDLE, base_address: usize, size: Option<usize>) -> Self {
        Self {
            handle,
            base_address,
            size,
        }
    }
}

impl portex::Reader for ProcessMemoryReader {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> PortexResult<usize> {
        let offset = offset as usize;
        let address = match self.base_address.checked_add(offset) {
            Some(addr) => addr,
            None => return Ok(0), // Address overflow - return 0 bytes read
        };

        // If we have a size limit, respect it
        if let Some(size) = self.size {
            if offset >= size {
                return Ok(0);
            }
            // Limit read to remaining size
            let available = size - offset;
            if buf.len() > available {
                // Read what we can
                let mut limited_buf = vec![0u8; available];
                let mut bytes_read = 0usize;
                let result = unsafe {
                    ReadProcessMemory(
                        self.handle,
                        address as *const c_void,
                        limited_buf.as_mut_ptr() as *mut c_void,
                        available,
                        Some(&mut bytes_read),
                    )
                };
                if result.is_err() {
                    return Ok(0);
                }
                buf[..bytes_read].copy_from_slice(&limited_buf[..bytes_read]);
                return Ok(bytes_read);
            }
        }

        let mut bytes_read = 0usize;
        let result = unsafe {
            ReadProcessMemory(
                self.handle,
                address as *const c_void,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                Some(&mut bytes_read),
            )
        };

        if result.is_err() {
            // ReadProcessMemory failed - could be unmapped page, access denied, etc.
            // Return 0 bytes read rather than error, portex will handle it
            return Ok(0);
        }

        Ok(bytes_read)
    }

    fn size(&self) -> Option<u64> {
        self.size.map(|s| s as u64)
    }
}
