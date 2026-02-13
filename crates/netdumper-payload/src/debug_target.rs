//! ICorDebugDataTarget implementation for in-process memory reading.
//!
//! This implements the COM interface needed by ICLRDebugging::OpenVirtualProcess
//! to read memory from the current process.

use crate::clr_host::*;
use std::ffi::c_void;
use std::sync::atomic::{AtomicU32, Ordering};
use windows::Win32::Foundation::{E_FAIL, E_NOINTERFACE, S_OK};
use windows::core::{GUID, HRESULT};

/// Our implementation of ICorDebugDataTarget
#[repr(C)]
pub struct MyCorDebugDataTarget {
    vtbl: *const ICorDebugDataTargetVtbl,
    ref_count: AtomicU32,
}

// Static vtable for our implementation
static MYCORDEBUGDATATARGET_VTBL: ICorDebugDataTargetVtbl = ICorDebugDataTargetVtbl {
    query_interface: my_query_interface,
    add_ref: my_add_ref,
    release: my_release,
    get_platform: my_get_platform,
    read_virtual: my_read_virtual,
    get_thread_context: my_get_thread_context,
};

impl MyCorDebugDataTarget {
    /// Create a new ICorDebugDataTarget instance.
    /// Returns a raw pointer that must be released via Release().
    pub fn new() -> *mut ICorDebugDataTarget {
        let target = Box::new(MyCorDebugDataTarget {
            vtbl: &MYCORDEBUGDATATARGET_VTBL,
            ref_count: AtomicU32::new(1),
        });
        Box::into_raw(target) as *mut ICorDebugDataTarget
    }
}

// IUnknown implementation
unsafe extern "system" fn my_query_interface(
    this: *mut ICorDebugDataTarget,
    riid: *const GUID,
    ppv_object: *mut *mut c_void,
) -> HRESULT {
    if ppv_object.is_null() {
        return E_FAIL;
    }

    let riid = unsafe { &*riid };

    // Check for IUnknown or ICorDebugDataTarget
    if *riid == windows::core::GUID::zeroed() // IUnknown
        || *riid == IID_ICOR_DEBUG_DATA_TARGET
    {
        unsafe {
            *ppv_object = this as *mut c_void;
            my_add_ref(this);
        }
        return S_OK;
    }

    unsafe { *ppv_object = std::ptr::null_mut() };
    E_NOINTERFACE
}

unsafe extern "system" fn my_add_ref(this: *mut ICorDebugDataTarget) -> u32 {
    let target = unsafe { &*(this as *const MyCorDebugDataTarget) };
    target.ref_count.fetch_add(1, Ordering::SeqCst) + 1
}

unsafe extern "system" fn my_release(this: *mut ICorDebugDataTarget) -> u32 {
    let target = unsafe { &*(this as *const MyCorDebugDataTarget) };
    let count = target.ref_count.fetch_sub(1, Ordering::SeqCst) - 1;
    if count == 0 {
        // Drop the box
        drop(unsafe { Box::from_raw(this as *mut MyCorDebugDataTarget) });
    }
    count
}

// ICorDebugDataTarget implementation
unsafe extern "system" fn my_get_platform(
    _this: *mut ICorDebugDataTarget,
    p_target_platform: *mut u32,
) -> HRESULT {
    if p_target_platform.is_null() {
        return E_FAIL;
    }

    // Return the appropriate platform based on architecture
    #[cfg(target_arch = "x86_64")]
    {
        unsafe { *p_target_platform = CorDebugPlatform::CORDB_PLATFORM_WINDOWS_AMD64 as u32 };
    }
    #[cfg(target_arch = "x86")]
    {
        unsafe { *p_target_platform = CorDebugPlatform::CORDB_PLATFORM_WINDOWS_X86 as u32 };
    }
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { *p_target_platform = CorDebugPlatform::CORDB_PLATFORM_WINDOWS_ARM64 as u32 };
    }

    S_OK
}

unsafe extern "system" fn my_read_virtual(
    _this: *mut ICorDebugDataTarget,
    address: u64,
    p_buffer: *mut u8,
    cb_request_size: u32,
    pcb_read: *mut u32,
) -> HRESULT {
    if p_buffer.is_null() {
        return E_FAIL;
    }

    // For in-process reading, we can just memcpy
    // This is safe because we're reading our own process memory
    unsafe {
        std::ptr::copy_nonoverlapping(address as *const u8, p_buffer, cb_request_size as usize);
        if !pcb_read.is_null() {
            *pcb_read = cb_request_size;
        }
    }

    S_OK
}

unsafe extern "system" fn my_get_thread_context(
    _this: *mut ICorDebugDataTarget,
    _dw_thread_id: u32,
    _context_flags: u32,
    _context_size: u32,
    _p_context: *mut u8,
) -> HRESULT {
    // We don't need thread context for enumeration
    E_FAIL
}
