//! DAC (Data Access Component) interface definitions for .NET Core enumeration.
//!
//! Re-exports DAC interfaces from the mscoree crate, plus local types needed
//! for implementing ICLRDataTarget.

#![allow(non_snake_case)]

use std::ffi::c_void;
use windows_core::{GUID, HRESULT};

// Re-export DAC interfaces and types from mscoree
pub use mscoree::{
    // Interfaces
    ICLRDataTarget, ISOSDacInterface, IXCLRDataProcess,
    // Data structures
    CLRDATA_ADDRESS, DacpAppDomainData, DacpAppDomainStoreData, DacpAssemblyData, DacpModuleData,
};

/// Type alias for compatibility with existing code
pub type ClrDataAddress = CLRDATA_ADDRESS;

// Machine type constants
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
pub const IMAGE_FILE_MACHINE_ARM64: u16 = 0xAA64;

// GUIDs for DAC interfaces
pub const IID_ICLR_DATA_TARGET: GUID = GUID::from_u128(0x3E11CCEE_D08B_43e5_AF01_32717A64DA03);

/// CLRDataCreateInstance function type (exported by mscordaccore.dll)
pub type CLRDataCreateInstanceFn = unsafe extern "system" fn(
    riid: *const GUID,
    data_target: *mut c_void, // ICLRDataTarget*
    ppv_object: *mut *mut c_void,
) -> HRESULT;

// =============================================================================
// ICLRDataTargetVtbl - manual vtable for implementing ICLRDataTarget
// We need this because we implement ICLRDataTarget ourselves (not just call it)
// =============================================================================

#[repr(C)]
pub struct ICLRDataTargetVtbl {
    // IUnknown
    pub query_interface:
        unsafe extern "system" fn(*mut ICLRDataTargetImpl, *const GUID, *mut *mut c_void) -> HRESULT,
    pub add_ref: unsafe extern "system" fn(*mut ICLRDataTargetImpl) -> u32,
    pub release: unsafe extern "system" fn(*mut ICLRDataTargetImpl) -> u32,
    // ICLRDataTarget
    pub get_machine_type: unsafe extern "system" fn(*mut ICLRDataTargetImpl, *mut u32) -> HRESULT,
    pub get_pointer_size: unsafe extern "system" fn(*mut ICLRDataTargetImpl, *mut u32) -> HRESULT,
    pub get_image_base:
        unsafe extern "system" fn(*mut ICLRDataTargetImpl, *const u16, *mut ClrDataAddress) -> HRESULT,
    pub read_virtual: unsafe extern "system" fn(
        *mut ICLRDataTargetImpl,
        ClrDataAddress,
        *mut u8,
        u32,
        *mut u32,
    ) -> HRESULT,
    pub write_virtual: unsafe extern "system" fn(
        *mut ICLRDataTargetImpl,
        ClrDataAddress,
        *mut u8,
        u32,
        *mut u32,
    ) -> HRESULT,
    pub get_tls_value:
        unsafe extern "system" fn(*mut ICLRDataTargetImpl, u32, u32, *mut ClrDataAddress) -> HRESULT,
    pub set_tls_value:
        unsafe extern "system" fn(*mut ICLRDataTargetImpl, u32, u32, ClrDataAddress) -> HRESULT,
    pub get_current_thread_id: unsafe extern "system" fn(*mut ICLRDataTargetImpl, *mut u32) -> HRESULT,
    pub get_thread_context:
        unsafe extern "system" fn(*mut ICLRDataTargetImpl, u32, u32, u32, *mut u8) -> HRESULT,
    pub set_thread_context:
        unsafe extern "system" fn(*mut ICLRDataTargetImpl, u32, u32, *mut u8) -> HRESULT,
    pub request:
        unsafe extern "system" fn(*mut ICLRDataTargetImpl, u32, u32, *mut u8, u32, *mut u8) -> HRESULT,
}

/// Our implementation struct for ICLRDataTarget (used by CLRDataTarget in dac_enum)
#[repr(C)]
pub struct ICLRDataTargetImpl {
    pub vtbl: *const ICLRDataTargetVtbl,
}
