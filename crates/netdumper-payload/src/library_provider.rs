//! ICLRDebuggingLibraryProvider implementation for locating DAC DLLs.
//!
//! This implements the COM interface needed by ICLRDebugging::OpenVirtualProcess
//! to locate and load version-specific debugging libraries (mscordaccore.dll).

use crate::clr_host::*;
use std::ffi::c_void;
use std::sync::atomic::{AtomicU32, Ordering};
use windows::Win32::Foundation::{E_FAIL, E_NOINTERFACE, S_OK};
use windows::Win32::System::LibraryLoader::LoadLibraryW;
use windows::core::{GUID, HRESULT, PCWSTR};

/// Our implementation of ICLRDebuggingLibraryProvider
#[repr(C)]
pub struct MyLibraryProvider {
    vtbl: *const ICLRDebuggingLibraryProviderVtbl,
    ref_count: AtomicU32,
    runtime_dir: String, // Directory containing coreclr.dll
}

// Static vtable for our implementation
static MYLIBRARYPROVIDER_VTBL: ICLRDebuggingLibraryProviderVtbl =
    ICLRDebuggingLibraryProviderVtbl {
        query_interface: provider_query_interface,
        add_ref: provider_add_ref,
        release: provider_release,
        provide_library: provider_provide_library,
    };

// IID for ICLRDebuggingLibraryProvider
// {3151C08D-4D09-4f9b-8838-2880BF18FE51}
pub static IID_ICLR_DEBUGGING_LIBRARY_PROVIDER: GUID = GUID::from_values(
    0x3151C08D,
    0x4D09,
    0x4F9B,
    [0x88, 0x38, 0x28, 0x80, 0xBF, 0x18, 0xFE, 0x51],
);

impl MyLibraryProvider {
    /// Create a new ICLRDebuggingLibraryProvider instance.
    /// `runtime_dir` should be the directory containing coreclr.dll (e.g., the .NET runtime folder).
    /// Returns a raw pointer that must be released via Release().
    pub fn new(runtime_dir: String) -> *mut ICLRDebuggingLibraryProvider {
        let provider = Box::new(MyLibraryProvider {
            vtbl: &MYLIBRARYPROVIDER_VTBL,
            ref_count: AtomicU32::new(1),
            runtime_dir,
        });
        Box::into_raw(provider) as *mut ICLRDebuggingLibraryProvider
    }
}

// IUnknown implementation
unsafe extern "system" fn provider_query_interface(
    this: *mut ICLRDebuggingLibraryProvider,
    riid: *const GUID,
    ppv_object: *mut *mut c_void,
) -> HRESULT {
    if ppv_object.is_null() {
        return E_FAIL;
    }

    let riid = unsafe { &*riid };

    // Check for IUnknown or ICLRDebuggingLibraryProvider
    if *riid == windows::core::GUID::zeroed() // IUnknown
        || *riid == IID_ICLR_DEBUGGING_LIBRARY_PROVIDER
    {
        unsafe {
            *ppv_object = this as *mut c_void;
            provider_add_ref(this);
        }
        return S_OK;
    }

    unsafe { *ppv_object = std::ptr::null_mut() };
    E_NOINTERFACE
}

unsafe extern "system" fn provider_add_ref(this: *mut ICLRDebuggingLibraryProvider) -> u32 {
    let provider = unsafe { &*(this as *const MyLibraryProvider) };
    provider.ref_count.fetch_add(1, Ordering::SeqCst) + 1
}

unsafe extern "system" fn provider_release(this: *mut ICLRDebuggingLibraryProvider) -> u32 {
    let provider = unsafe { &*(this as *const MyLibraryProvider) };
    let count = provider.ref_count.fetch_sub(1, Ordering::SeqCst) - 1;
    if count == 0 {
        // Drop the box
        drop(unsafe { Box::from_raw(this as *mut MyLibraryProvider) });
    }
    count
}

// ICLRDebuggingLibraryProvider implementation
unsafe extern "system" fn provider_provide_library(
    this: *mut ICLRDebuggingLibraryProvider,
    pwsz_file_name: PCWSTR,
    _dw_timestamp: u32,
    _dw_size_of_image: u32,
    ph_module: *mut *mut c_void,
) -> HRESULT {
    if ph_module.is_null() || pwsz_file_name.is_null() {
        return E_FAIL;
    }

    let provider = unsafe { &*(this as *const MyLibraryProvider) };

    // Convert the requested filename from wide string
    let file_name = unsafe {
        let len = (0..).take_while(|&i| *pwsz_file_name.0.add(i) != 0).count();
        String::from_utf16_lossy(std::slice::from_raw_parts(pwsz_file_name.0, len))
    };

    // Build full path: runtime_dir + filename
    let full_path = format!("{}\\{}", provider.runtime_dir, file_name);

    // Convert to wide string for LoadLibraryW
    let wide_path: Vec<u16> = full_path.encode_utf16().chain(std::iter::once(0)).collect();

    // Load the library
    let module = unsafe { LoadLibraryW(PCWSTR(wide_path.as_ptr())) };

    match module {
        Ok(handle) => {
            unsafe { *ph_module = handle.0 as *mut c_void };
            S_OK
        }
        Err(_) => E_FAIL,
    }
}
