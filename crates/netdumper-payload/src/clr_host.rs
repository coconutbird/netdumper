//! CLR Hosting interfaces for .NET Framework and .NET Core.
//!
//! These interfaces are not included in the windows crate, so we define them manually.

use std::ffi::c_void;
use windows::Win32::System::Com::SAFEARRAY;
use windows::Win32::System::Variant::VARIANT;
use windows::core::{BSTR, GUID, HRESULT, IUnknown, PCWSTR};

// GUIDs for CLR hosting
pub const CLSID_CLR_META_HOST: GUID = GUID::from_u128(0x9280188d_0e8e_4867_b30c_7fa83884e8de);
pub const IID_ICLR_META_HOST: GUID = GUID::from_u128(0xD332DB9E_B9B3_4125_8207_A14884F53216);
pub const IID_ICLR_RUNTIME_INFO: GUID = GUID::from_u128(0xBD39D1D2_BA2F_486a_89B0_B4B0CB466891);
pub const CLSID_COR_RUNTIME_HOST: GUID = GUID::from_u128(0xcb2f6723_ab3a_11d2_9c40_00c04fa30a3e);
pub const IID_ICOR_RUNTIME_HOST: GUID = GUID::from_u128(0xcb2f6722_ab3a_11d2_9c40_00c04fa30a3e);
pub const IID_APP_DOMAIN: GUID = GUID::from_u128(0x05F696DC_2B29_3663_AD8B_C4389CF2A713);

// GUIDs for ICorDebug interfaces (used by Cheat Engine approach)
pub const CLSID_CLR_DEBUGGING: GUID = GUID::from_u128(0xBacc578d_fbdd_48a4_969f_02d932b74634);
pub const IID_ICLR_DEBUGGING: GUID = GUID::from_u128(0xd28f3c5a_9634_4206_a509_477552eefb10);
pub const IID_ICOR_DEBUG_DATA_TARGET: GUID =
    GUID::from_u128(0xFE06DC28_49FB_4636_A4A3_E80DB4AE116C);
pub const IID_ICOR_DEBUG_PROCESS: GUID = GUID::from_u128(0x3d6f5f64_7538_11d3_8d5b_00104b35e7ef);
#[allow(dead_code)]
pub const IID_ICOR_DEBUG_PROCESS5: GUID = GUID::from_u128(0x21e9d9c0_fcb8_11df_8cff_0800200c9a66);
#[allow(dead_code)]
pub const IID_ICOR_DEBUG_APP_DOMAIN: GUID = GUID::from_u128(0x3d6f5f63_7538_11d3_8d5b_00104b35e7ef);
#[allow(dead_code)]
pub const IID_ICOR_DEBUG_ASSEMBLY: GUID = GUID::from_u128(0xdf59507c_d47a_459e_bce2_6427eac8fd06);
#[allow(dead_code)]
pub const IID_ICOR_DEBUG_MODULE: GUID = GUID::from_u128(0xdba2d8c1_e5c5_4069_8c13_10a7c6abf43d);
#[allow(dead_code)]
pub const IID_ICLR_DEBUGGING_LIBRARY_PROVIDER: GUID =
    GUID::from_u128(0x3151c08d_4d09_4f9b_8838_2880bf18fe51);

// Function pointer types for mscoree.dll exports
pub type CLRCreateInstanceFn = unsafe extern "system" fn(
    clsid: *const GUID,
    riid: *const GUID,
    ppinterface: *mut *mut c_void,
) -> HRESULT;

pub type CorBindToRuntimeExFn = unsafe extern "system" fn(
    pwszversion: PCWSTR,
    pwszbuildflavor: PCWSTR,
    startupflags: u32,
    rclsid: *const GUID,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> HRESULT;

// ICLRMetaHost interface
#[repr(C)]
pub struct ICLRMetaHostVtbl {
    // IUnknown
    pub query_interface:
        unsafe extern "system" fn(*mut ICLRMetaHost, *const GUID, *mut *mut c_void) -> HRESULT,
    pub add_ref: unsafe extern "system" fn(*mut ICLRMetaHost) -> u32,
    pub release: unsafe extern "system" fn(*mut ICLRMetaHost) -> u32,
    // ICLRMetaHost
    pub get_runtime: unsafe extern "system" fn(
        *mut ICLRMetaHost,
        PCWSTR,
        *const GUID,
        *mut *mut c_void,
    ) -> HRESULT,
    pub get_version_from_file:
        unsafe extern "system" fn(*mut ICLRMetaHost, PCWSTR, *mut u16, *mut u32) -> HRESULT,
    pub enumerate_installed_runtimes:
        unsafe extern "system" fn(*mut ICLRMetaHost, *mut *mut c_void) -> HRESULT,
    pub enumerate_loaded_runtimes:
        unsafe extern "system" fn(*mut ICLRMetaHost, *mut c_void, *mut *mut c_void) -> HRESULT,
    pub request_runtime_loaded_notification:
        unsafe extern "system" fn(*mut ICLRMetaHost, *mut c_void) -> HRESULT,
    pub query_legacy_v2_runtime_binding:
        unsafe extern "system" fn(*mut ICLRMetaHost, *const GUID, *mut *mut c_void) -> HRESULT,
    pub exit_process: unsafe extern "system" fn(*mut ICLRMetaHost, i32) -> HRESULT,
}

#[repr(C)]
pub struct ICLRMetaHost {
    pub vtbl: *const ICLRMetaHostVtbl,
}

// ICLRRuntimeInfo interface
#[repr(C)]
pub struct ICLRRuntimeInfoVtbl {
    // IUnknown
    pub query_interface:
        unsafe extern "system" fn(*mut ICLRRuntimeInfo, *const GUID, *mut *mut c_void) -> HRESULT,
    pub add_ref: unsafe extern "system" fn(*mut ICLRRuntimeInfo) -> u32,
    pub release: unsafe extern "system" fn(*mut ICLRRuntimeInfo) -> u32,
    // ICLRRuntimeInfo
    pub get_version_string:
        unsafe extern "system" fn(*mut ICLRRuntimeInfo, *mut u16, *mut u32) -> HRESULT,
    pub get_runtime_directory:
        unsafe extern "system" fn(*mut ICLRRuntimeInfo, *mut u16, *mut u32) -> HRESULT,
    pub is_loaded:
        unsafe extern "system" fn(*mut ICLRRuntimeInfo, *mut c_void, *mut i32) -> HRESULT,
    pub load_error_string:
        unsafe extern "system" fn(*mut ICLRRuntimeInfo, u32, *mut u16, *mut u32, i32) -> HRESULT,
    pub load_library:
        unsafe extern "system" fn(*mut ICLRRuntimeInfo, PCWSTR, *mut *mut c_void) -> HRESULT,
    pub get_proc_address:
        unsafe extern "system" fn(*mut ICLRRuntimeInfo, *const i8, *mut *mut c_void) -> HRESULT,
    pub get_interface: unsafe extern "system" fn(
        *mut ICLRRuntimeInfo,
        *const GUID,
        *const GUID,
        *mut *mut c_void,
    ) -> HRESULT,
    pub is_loadable: unsafe extern "system" fn(*mut ICLRRuntimeInfo, *mut i32) -> HRESULT,
    pub set_default_startup_flags:
        unsafe extern "system" fn(*mut ICLRRuntimeInfo, u32, PCWSTR) -> HRESULT,
    pub get_default_startup_flags:
        unsafe extern "system" fn(*mut ICLRRuntimeInfo, *mut u32, *mut u16, *mut u32) -> HRESULT,
    pub bind_as_legacy_v2_runtime: unsafe extern "system" fn(*mut ICLRRuntimeInfo) -> HRESULT,
    pub is_started: unsafe extern "system" fn(*mut ICLRRuntimeInfo, *mut i32, *mut u32) -> HRESULT,
}

#[repr(C)]
pub struct ICLRRuntimeInfo {
    pub vtbl: *const ICLRRuntimeInfoVtbl,
}

// ICorRuntimeHost interface
#[repr(C)]
pub struct ICorRuntimeHostVtbl {
    // IUnknown
    pub query_interface:
        unsafe extern "system" fn(*mut ICorRuntimeHost, *const GUID, *mut *mut c_void) -> HRESULT,
    pub add_ref: unsafe extern "system" fn(*mut ICorRuntimeHost) -> u32,
    pub release: unsafe extern "system" fn(*mut ICorRuntimeHost) -> u32,
    // ICorRuntimeHost
    pub create_logic_thread_state: unsafe extern "system" fn(*mut ICorRuntimeHost) -> HRESULT,
    pub delete_logic_thread_state: unsafe extern "system" fn(*mut ICorRuntimeHost) -> HRESULT,
    pub switch_in_logic_thread_state:
        unsafe extern "system" fn(*mut ICorRuntimeHost, *mut u32) -> HRESULT,
    pub switch_out_logic_thread_state:
        unsafe extern "system" fn(*mut ICorRuntimeHost, *mut *mut u32) -> HRESULT,
    pub locked_in_os_thread: unsafe extern "system" fn(*mut ICorRuntimeHost) -> HRESULT,
    pub get_configuration:
        unsafe extern "system" fn(*mut ICorRuntimeHost, *mut *mut c_void) -> HRESULT,
    pub start: unsafe extern "system" fn(*mut ICorRuntimeHost) -> HRESULT,
    pub stop: unsafe extern "system" fn(*mut ICorRuntimeHost) -> HRESULT,
    pub create_domain: unsafe extern "system" fn(
        *mut ICorRuntimeHost,
        PCWSTR,
        *mut c_void,
        *mut *mut IUnknown,
    ) -> HRESULT,
    pub get_default_domain:
        unsafe extern "system" fn(*mut ICorRuntimeHost, *mut *mut IUnknown) -> HRESULT,
    pub enum_domains: unsafe extern "system" fn(*mut ICorRuntimeHost, *mut *mut c_void) -> HRESULT,
    pub next_domain:
        unsafe extern "system" fn(*mut ICorRuntimeHost, *mut c_void, *mut *mut IUnknown) -> HRESULT,
    pub close_enum: unsafe extern "system" fn(*mut ICorRuntimeHost, *mut c_void) -> HRESULT,
    pub create_domain_ex: unsafe extern "system" fn(
        *mut ICorRuntimeHost,
        PCWSTR,
        *mut c_void,
        *mut c_void,
        *mut *mut IUnknown,
    ) -> HRESULT,
    pub create_domain_setup:
        unsafe extern "system" fn(*mut ICorRuntimeHost, *mut *mut IUnknown) -> HRESULT,
    pub create_evidence:
        unsafe extern "system" fn(*mut ICorRuntimeHost, *mut *mut IUnknown) -> HRESULT,
    pub unload_domain: unsafe extern "system" fn(*mut ICorRuntimeHost, *mut IUnknown) -> HRESULT,
    pub current_domain:
        unsafe extern "system" fn(*mut ICorRuntimeHost, *mut *mut IUnknown) -> HRESULT,
}

#[repr(C)]
pub struct ICorRuntimeHost {
    pub vtbl: *const ICorRuntimeHostVtbl,
}

// _AppDomain interface (mscorlib)
#[repr(C)]
pub struct AppDomainVtbl {
    // IUnknown
    pub query_interface:
        unsafe extern "system" fn(*mut AppDomain, *const GUID, *mut *mut c_void) -> HRESULT,
    pub add_ref: unsafe extern "system" fn(*mut AppDomain) -> u32,
    pub release: unsafe extern "system" fn(*mut AppDomain) -> u32,
    // IDispatch
    pub get_type_info_count: unsafe extern "system" fn(*mut AppDomain, *mut u32) -> HRESULT,
    pub get_type_info:
        unsafe extern "system" fn(*mut AppDomain, u32, u32, *mut *mut c_void) -> HRESULT,
    pub get_ids_of_names: unsafe extern "system" fn(
        *mut AppDomain,
        *const GUID,
        *mut *mut u16,
        u32,
        u32,
        *mut i32,
    ) -> HRESULT,
    pub invoke: unsafe extern "system" fn(
        *mut AppDomain,
        i32,
        *const GUID,
        u32,
        u16,
        *mut c_void,
        *mut VARIANT,
        *mut c_void,
        *mut u32,
    ) -> HRESULT,
    // _AppDomain
    pub get_to_string: unsafe extern "system" fn(*mut AppDomain, *mut BSTR) -> HRESULT,
    pub equals: unsafe extern "system" fn(*mut AppDomain, VARIANT, *mut i16) -> HRESULT,
    pub get_hash_code: unsafe extern "system" fn(*mut AppDomain, *mut i32) -> HRESULT,
    pub get_type: unsafe extern "system" fn(*mut AppDomain, *mut *mut c_void) -> HRESULT,
    pub init_domain: unsafe extern "system" fn(*mut AppDomain) -> HRESULT,
    pub get_domain_manager: unsafe extern "system" fn(*mut AppDomain, *mut *mut c_void) -> HRESULT,
    pub get_evidence: unsafe extern "system" fn(*mut AppDomain, *mut *mut c_void) -> HRESULT,
    pub get_friendly_name: unsafe extern "system" fn(*mut AppDomain, *mut BSTR) -> HRESULT,
    pub get_base_directory: unsafe extern "system" fn(*mut AppDomain, *mut BSTR) -> HRESULT,
    pub get_relative_search_path: unsafe extern "system" fn(*mut AppDomain, *mut BSTR) -> HRESULT,
    pub get_shadow_copy_files: unsafe extern "system" fn(*mut AppDomain, *mut i16) -> HRESULT,
    pub get_assemblies: unsafe extern "system" fn(*mut AppDomain, *mut *mut SAFEARRAY) -> HRESULT,
    pub append_private_path: unsafe extern "system" fn(*mut AppDomain, BSTR) -> HRESULT,
    pub clear_private_path: unsafe extern "system" fn(*mut AppDomain) -> HRESULT,
    pub set_shadow_copy_path: unsafe extern "system" fn(*mut AppDomain, BSTR) -> HRESULT,
    pub clear_shadow_copy_path: unsafe extern "system" fn(*mut AppDomain) -> HRESULT,
    pub set_cache_path: unsafe extern "system" fn(*mut AppDomain, BSTR) -> HRESULT,
    pub set_data: unsafe extern "system" fn(*mut AppDomain, BSTR, VARIANT) -> HRESULT,
    pub get_data: unsafe extern "system" fn(*mut AppDomain, BSTR, *mut VARIANT) -> HRESULT,
    pub set_app_domain_policy: unsafe extern "system" fn(*mut AppDomain, *mut c_void) -> HRESULT,
    pub set_thread_principal: unsafe extern "system" fn(*mut AppDomain, *mut c_void) -> HRESULT,
    pub set_principal_policy: unsafe extern "system" fn(*mut AppDomain, i32) -> HRESULT,
    pub do_callback: unsafe extern "system" fn(*mut AppDomain, *mut c_void) -> HRESULT,
    pub get_dynamic_directory: unsafe extern "system" fn(*mut AppDomain, *mut BSTR) -> HRESULT,
}

#[repr(C)]
pub struct AppDomain {
    pub vtbl: *const AppDomainVtbl,
}

// _Assembly interface (mscorlib)
#[repr(C)]
pub struct AssemblyVtbl {
    // IUnknown
    pub query_interface:
        unsafe extern "system" fn(*mut Assembly, *const GUID, *mut *mut c_void) -> HRESULT,
    pub add_ref: unsafe extern "system" fn(*mut Assembly) -> u32,
    pub release: unsafe extern "system" fn(*mut Assembly) -> u32,
    // IDispatch
    pub get_type_info_count: unsafe extern "system" fn(*mut Assembly, *mut u32) -> HRESULT,
    pub get_type_info:
        unsafe extern "system" fn(*mut Assembly, u32, u32, *mut *mut c_void) -> HRESULT,
    pub get_ids_of_names: unsafe extern "system" fn(
        *mut Assembly,
        *const GUID,
        *mut *mut u16,
        u32,
        u32,
        *mut i32,
    ) -> HRESULT,
    pub invoke: unsafe extern "system" fn(
        *mut Assembly,
        i32,
        *const GUID,
        u32,
        u16,
        *mut c_void,
        *mut VARIANT,
        *mut c_void,
        *mut u32,
    ) -> HRESULT,
    // _Assembly
    pub get_to_string: unsafe extern "system" fn(*mut Assembly, *mut BSTR) -> HRESULT,
    pub equals: unsafe extern "system" fn(*mut Assembly, VARIANT, *mut i16) -> HRESULT,
    pub get_hash_code: unsafe extern "system" fn(*mut Assembly, *mut i32) -> HRESULT,
    pub get_type_2: unsafe extern "system" fn(*mut Assembly, *mut *mut c_void) -> HRESULT,
    pub get_code_base: unsafe extern "system" fn(*mut Assembly, *mut BSTR) -> HRESULT,
    pub get_escaped_code_base: unsafe extern "system" fn(*mut Assembly, *mut BSTR) -> HRESULT,
    pub get_name: unsafe extern "system" fn(*mut Assembly, *mut *mut c_void) -> HRESULT,
    pub get_full_name: unsafe extern "system" fn(*mut Assembly, *mut BSTR) -> HRESULT,
    pub get_entry_point: unsafe extern "system" fn(*mut Assembly, *mut *mut c_void) -> HRESULT,
    pub get_type_3: unsafe extern "system" fn(*mut Assembly, BSTR, *mut *mut c_void) -> HRESULT,
    pub get_type_4:
        unsafe extern "system" fn(*mut Assembly, BSTR, i16, *mut *mut c_void) -> HRESULT,
    pub get_exported_types:
        unsafe extern "system" fn(*mut Assembly, *mut *mut SAFEARRAY) -> HRESULT,
    pub get_types: unsafe extern "system" fn(*mut Assembly, *mut *mut SAFEARRAY) -> HRESULT,
    pub get_manifest_resource_stream:
        unsafe extern "system" fn(*mut Assembly, *mut c_void, BSTR, *mut *mut c_void) -> HRESULT,
    pub get_manifest_resource_stream_2:
        unsafe extern "system" fn(*mut Assembly, BSTR, *mut *mut c_void) -> HRESULT,
    pub get_file: unsafe extern "system" fn(*mut Assembly, BSTR, *mut *mut c_void) -> HRESULT,
    pub get_files: unsafe extern "system" fn(*mut Assembly, *mut *mut SAFEARRAY) -> HRESULT,
    pub get_files_2: unsafe extern "system" fn(*mut Assembly, i16, *mut *mut SAFEARRAY) -> HRESULT,
    pub get_manifest_resource_names:
        unsafe extern "system" fn(*mut Assembly, *mut *mut SAFEARRAY) -> HRESULT,
    pub get_manifest_resource_info:
        unsafe extern "system" fn(*mut Assembly, BSTR, *mut *mut c_void) -> HRESULT,
    pub get_location: unsafe extern "system" fn(*mut Assembly, *mut BSTR) -> HRESULT,
    pub get_evidence: unsafe extern "system" fn(*mut Assembly, *mut *mut c_void) -> HRESULT,
    pub get_custom_attributes:
        unsafe extern "system" fn(*mut Assembly, *mut c_void, i16, *mut *mut SAFEARRAY) -> HRESULT,
    pub get_custom_attributes_2:
        unsafe extern "system" fn(*mut Assembly, i16, *mut *mut SAFEARRAY) -> HRESULT,
    pub is_defined: unsafe extern "system" fn(*mut Assembly, *mut c_void, i16, *mut i16) -> HRESULT,
    pub get_object_data:
        unsafe extern "system" fn(*mut Assembly, *mut c_void, *mut c_void) -> HRESULT,
    pub add_module_resolve: unsafe extern "system" fn(*mut Assembly, *mut c_void) -> HRESULT,
    pub remove_module_resolve: unsafe extern "system" fn(*mut Assembly, *mut c_void) -> HRESULT,
    pub load_module:
        unsafe extern "system" fn(*mut Assembly, BSTR, *mut SAFEARRAY, *mut *mut c_void) -> HRESULT,
    pub load_module_2: unsafe extern "system" fn(
        *mut Assembly,
        BSTR,
        *mut SAFEARRAY,
        *mut SAFEARRAY,
        *mut *mut c_void,
    ) -> HRESULT,
    pub create_instance: unsafe extern "system" fn(*mut Assembly, BSTR, *mut VARIANT) -> HRESULT,
    pub create_instance_2:
        unsafe extern "system" fn(*mut Assembly, BSTR, i16, *mut VARIANT) -> HRESULT,
    pub create_instance_3: unsafe extern "system" fn(
        *mut Assembly,
        BSTR,
        i16,
        i32,
        *mut c_void,
        *mut SAFEARRAY,
        *mut c_void,
        *mut SAFEARRAY,
        *mut VARIANT,
    ) -> HRESULT,
    pub get_loaded_modules:
        unsafe extern "system" fn(*mut Assembly, *mut *mut SAFEARRAY) -> HRESULT,
    pub get_loaded_modules_2:
        unsafe extern "system" fn(*mut Assembly, i16, *mut *mut SAFEARRAY) -> HRESULT,
    pub get_modules: unsafe extern "system" fn(*mut Assembly, *mut *mut SAFEARRAY) -> HRESULT,
    pub get_modules_2:
        unsafe extern "system" fn(*mut Assembly, i16, *mut *mut SAFEARRAY) -> HRESULT,
    pub get_module: unsafe extern "system" fn(*mut Assembly, BSTR, *mut *mut c_void) -> HRESULT,
    pub get_referenced_assemblies:
        unsafe extern "system" fn(*mut Assembly, *mut *mut SAFEARRAY) -> HRESULT,
    pub get_global_assembly_cache: unsafe extern "system" fn(*mut Assembly, *mut i16) -> HRESULT,
}

#[repr(C)]
pub struct Assembly {
    pub vtbl: *const AssemblyVtbl,
}

// =============================================================================
// ICorDebug interfaces for .NET Core enumeration (Cheat Engine approach)
// =============================================================================

/// CLR_DEBUGGING_VERSION structure
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct CLR_DEBUGGING_VERSION {
    pub w_struct_version: u16,
    pub w_major: u16,
    pub w_minor: u16,
    pub w_build: u16,
    pub w_revision: u16,
}

/// CorDebugInterfaceVersion enum
#[repr(i32)]
#[derive(Debug, Clone, Copy)]
#[allow(dead_code, non_camel_case_types)]
pub enum CorDebugInterfaceVersion {
    CorDebugInvalidVersion = 0,
    CorDebugVersion_1_0 = 1,
    CorDebugVersion_1_1 = 2,
    CorDebugVersion_2_0 = 3,
    CorDebugVersion_4_0 = 4,
    CorDebugVersion_4_5 = 5,
}

// ICLRDebugging interface
#[repr(C)]
pub struct ICLRDebuggingVtbl {
    // IUnknown
    pub query_interface:
        unsafe extern "system" fn(*mut ICLRDebugging, *const GUID, *mut *mut c_void) -> HRESULT,
    pub add_ref: unsafe extern "system" fn(*mut ICLRDebugging) -> u32,
    pub release: unsafe extern "system" fn(*mut ICLRDebugging) -> u32,
    // ICLRDebugging
    pub open_virtual_process: unsafe extern "system" fn(
        *mut ICLRDebugging,
        u64,                        // moduleBaseAddress
        *mut c_void,                // pDataTarget (ICorDebugDataTarget)
        *mut c_void,                // pLibraryProvider (ICLRDebuggingLibraryProvider)
        *mut CLR_DEBUGGING_VERSION, // pMaxDebuggerSupportedVersion
        *const GUID,                // riidProcess
        *mut *mut c_void,           // ppProcess (ICorDebugProcess)
        *mut CLR_DEBUGGING_VERSION, // pVersion (out)
        *mut u32,                   // pdwFlags (out)
    ) -> HRESULT,
    pub can_unload_now: unsafe extern "system" fn(*mut ICLRDebugging, *mut c_void) -> HRESULT,
}

#[repr(C)]
pub struct ICLRDebugging {
    pub vtbl: *const ICLRDebuggingVtbl,
}

// ICLRDebuggingLibraryProvider interface
#[repr(C)]
#[allow(dead_code)]
pub struct ICLRDebuggingLibraryProviderVtbl {
    // IUnknown
    pub query_interface: unsafe extern "system" fn(
        *mut ICLRDebuggingLibraryProvider,
        *const GUID,
        *mut *mut c_void,
    ) -> HRESULT,
    pub add_ref: unsafe extern "system" fn(*mut ICLRDebuggingLibraryProvider) -> u32,
    pub release: unsafe extern "system" fn(*mut ICLRDebuggingLibraryProvider) -> u32,
    // ICLRDebuggingLibraryProvider
    pub provide_library: unsafe extern "system" fn(
        *mut ICLRDebuggingLibraryProvider,
        PCWSTR,           // pwszFileName
        u32,              // dwTimestamp
        u32,              // dwSizeOfImage
        *mut *mut c_void, // phModule (HMODULE*)
    ) -> HRESULT,
}

#[repr(C)]
#[allow(dead_code)]
pub struct ICLRDebuggingLibraryProvider {
    pub vtbl: *const ICLRDebuggingLibraryProviderVtbl,
}

// ICorDebugDataTarget interface (we need to implement this)
#[repr(C)]
pub struct ICorDebugDataTargetVtbl {
    // IUnknown
    pub query_interface: unsafe extern "system" fn(
        *mut ICorDebugDataTarget,
        *const GUID,
        *mut *mut c_void,
    ) -> HRESULT,
    pub add_ref: unsafe extern "system" fn(*mut ICorDebugDataTarget) -> u32,
    pub release: unsafe extern "system" fn(*mut ICorDebugDataTarget) -> u32,
    // ICorDebugDataTarget
    pub get_platform: unsafe extern "system" fn(*mut ICorDebugDataTarget, *mut u32) -> HRESULT,
    pub read_virtual:
        unsafe extern "system" fn(*mut ICorDebugDataTarget, u64, *mut u8, u32, *mut u32) -> HRESULT,
    pub get_thread_context:
        unsafe extern "system" fn(*mut ICorDebugDataTarget, u32, u32, u32, *mut u8) -> HRESULT,
}

#[repr(C)]
pub struct ICorDebugDataTarget {
    pub vtbl: *const ICorDebugDataTargetVtbl,
}

/// CorDebugPlatform enum for ICorDebugDataTarget::GetPlatform
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
#[allow(dead_code, non_camel_case_types)]
pub enum CorDebugPlatform {
    CORDB_PLATFORM_WINDOWS_X86 = 0,
    CORDB_PLATFORM_WINDOWS_AMD64 = 1,
    CORDB_PLATFORM_WINDOWS_IA64 = 2,
    CORDB_PLATFORM_MAC_PPC = 3,
    CORDB_PLATFORM_MAC_X86 = 4,
    CORDB_PLATFORM_WINDOWS_ARM = 5,
    CORDB_PLATFORM_MAC_AMD64 = 6,
    CORDB_PLATFORM_WINDOWS_ARM64 = 7,
}

// ICorDebugProcess interface (partial - just what we need)
#[repr(C)]
pub struct ICorDebugProcessVtbl {
    // IUnknown
    pub query_interface:
        unsafe extern "system" fn(*mut ICorDebugProcess, *const GUID, *mut *mut c_void) -> HRESULT,
    pub add_ref: unsafe extern "system" fn(*mut ICorDebugProcess) -> u32,
    pub release: unsafe extern "system" fn(*mut ICorDebugProcess) -> u32,
    // ICorDebugController
    pub stop: unsafe extern "system" fn(*mut ICorDebugProcess, u32) -> HRESULT,
    pub continue_: unsafe extern "system" fn(*mut ICorDebugProcess, i32) -> HRESULT,
    pub is_running: unsafe extern "system" fn(*mut ICorDebugProcess, *mut i32) -> HRESULT,
    pub has_queued_callbacks:
        unsafe extern "system" fn(*mut ICorDebugProcess, *mut c_void, *mut i32) -> HRESULT,
    pub enumerate_threads:
        unsafe extern "system" fn(*mut ICorDebugProcess, *mut *mut c_void) -> HRESULT,
    pub set_all_threads_debug_state:
        unsafe extern "system" fn(*mut ICorDebugProcess, u32, *mut c_void) -> HRESULT,
    pub detach: unsafe extern "system" fn(*mut ICorDebugProcess) -> HRESULT,
    pub terminate: unsafe extern "system" fn(*mut ICorDebugProcess, u32) -> HRESULT,
    pub can_commit_changes: unsafe extern "system" fn(
        *mut ICorDebugProcess,
        u32,
        *mut c_void,
        *mut *mut c_void,
    ) -> HRESULT,
    pub commit_changes: unsafe extern "system" fn(
        *mut ICorDebugProcess,
        u32,
        *mut c_void,
        *mut *mut c_void,
    ) -> HRESULT,
    // ICorDebugProcess
    pub get_id: unsafe extern "system" fn(*mut ICorDebugProcess, *mut u32) -> HRESULT,
    pub get_handle: unsafe extern "system" fn(*mut ICorDebugProcess, *mut *mut c_void) -> HRESULT,
    pub get_thread:
        unsafe extern "system" fn(*mut ICorDebugProcess, u32, *mut *mut c_void) -> HRESULT,
    pub enumerate_objects:
        unsafe extern "system" fn(*mut ICorDebugProcess, *mut *mut c_void) -> HRESULT,
    pub is_transition_stub:
        unsafe extern "system" fn(*mut ICorDebugProcess, u64, *mut i32) -> HRESULT,
    pub is_os_exception_unhandled:
        unsafe extern "system" fn(*mut ICorDebugProcess, *mut i32) -> HRESULT,
    pub modify_logswitch:
        unsafe extern "system" fn(*mut ICorDebugProcess, *mut u16, i32) -> HRESULT,
    pub enable_log_messages: unsafe extern "system" fn(*mut ICorDebugProcess, i32) -> HRESULT,
    pub get_threading_capabilities:
        unsafe extern "system" fn(*mut ICorDebugProcess, *mut u32) -> HRESULT,
    pub get_helper_thread_id: unsafe extern "system" fn(*mut ICorDebugProcess, *mut u32) -> HRESULT,
    pub enumerate_app_domains: unsafe extern "system" fn(
        *mut ICorDebugProcess,
        *mut *mut ICorDebugAppDomainEnum,
    ) -> HRESULT,
    pub get_object: unsafe extern "system" fn(*mut ICorDebugProcess, *mut *mut c_void) -> HRESULT,
    pub thread_for_fiber_cookie:
        unsafe extern "system" fn(*mut ICorDebugProcess, u32, *mut *mut c_void) -> HRESULT,
    pub get_desired_ngenstatus:
        unsafe extern "system" fn(*mut ICorDebugProcess, *mut u32, *mut u32) -> HRESULT,
}

#[repr(C)]
pub struct ICorDebugProcess {
    pub vtbl: *const ICorDebugProcessVtbl,
}

// ICorDebugAppDomainEnum interface
#[repr(C)]
pub struct ICorDebugAppDomainEnumVtbl {
    // IUnknown
    pub query_interface: unsafe extern "system" fn(
        *mut ICorDebugAppDomainEnum,
        *const GUID,
        *mut *mut c_void,
    ) -> HRESULT,
    pub add_ref: unsafe extern "system" fn(*mut ICorDebugAppDomainEnum) -> u32,
    pub release: unsafe extern "system" fn(*mut ICorDebugAppDomainEnum) -> u32,
    // ICorDebugEnum
    pub skip: unsafe extern "system" fn(*mut ICorDebugAppDomainEnum, u32) -> HRESULT,
    pub reset: unsafe extern "system" fn(*mut ICorDebugAppDomainEnum) -> HRESULT,
    pub clone: unsafe extern "system" fn(*mut ICorDebugAppDomainEnum, *mut *mut c_void) -> HRESULT,
    pub get_count: unsafe extern "system" fn(*mut ICorDebugAppDomainEnum, *mut u32) -> HRESULT,
    // ICorDebugAppDomainEnum
    pub next: unsafe extern "system" fn(
        *mut ICorDebugAppDomainEnum,
        u32,
        *mut *mut ICorDebugAppDomain,
        *mut u32,
    ) -> HRESULT,
}

#[repr(C)]
pub struct ICorDebugAppDomainEnum {
    pub vtbl: *const ICorDebugAppDomainEnumVtbl,
}

// ICorDebugAppDomain interface
#[repr(C)]
pub struct ICorDebugAppDomainVtbl {
    // IUnknown
    pub query_interface: unsafe extern "system" fn(
        *mut ICorDebugAppDomain,
        *const GUID,
        *mut *mut c_void,
    ) -> HRESULT,
    pub add_ref: unsafe extern "system" fn(*mut ICorDebugAppDomain) -> u32,
    pub release: unsafe extern "system" fn(*mut ICorDebugAppDomain) -> u32,
    // ICorDebugController
    pub stop: unsafe extern "system" fn(*mut ICorDebugAppDomain, u32) -> HRESULT,
    pub continue_: unsafe extern "system" fn(*mut ICorDebugAppDomain, i32) -> HRESULT,
    pub is_running: unsafe extern "system" fn(*mut ICorDebugAppDomain, *mut i32) -> HRESULT,
    pub has_queued_callbacks:
        unsafe extern "system" fn(*mut ICorDebugAppDomain, *mut c_void, *mut i32) -> HRESULT,
    pub enumerate_threads:
        unsafe extern "system" fn(*mut ICorDebugAppDomain, *mut *mut c_void) -> HRESULT,
    pub set_all_threads_debug_state:
        unsafe extern "system" fn(*mut ICorDebugAppDomain, u32, *mut c_void) -> HRESULT,
    pub detach: unsafe extern "system" fn(*mut ICorDebugAppDomain) -> HRESULT,
    pub terminate: unsafe extern "system" fn(*mut ICorDebugAppDomain, u32) -> HRESULT,
    pub can_commit_changes: unsafe extern "system" fn(
        *mut ICorDebugAppDomain,
        u32,
        *mut c_void,
        *mut *mut c_void,
    ) -> HRESULT,
    pub commit_changes: unsafe extern "system" fn(
        *mut ICorDebugAppDomain,
        u32,
        *mut c_void,
        *mut *mut c_void,
    ) -> HRESULT,
    // ICorDebugAppDomain
    pub get_process:
        unsafe extern "system" fn(*mut ICorDebugAppDomain, *mut *mut c_void) -> HRESULT,
    pub enumerate_assemblies: unsafe extern "system" fn(
        *mut ICorDebugAppDomain,
        *mut *mut ICorDebugAssemblyEnum,
    ) -> HRESULT,
    pub get_module_from_metadata_interface: unsafe extern "system" fn(
        *mut ICorDebugAppDomain,
        *mut c_void,
        *mut *mut c_void,
    ) -> HRESULT,
    pub enumerate_breakpoints:
        unsafe extern "system" fn(*mut ICorDebugAppDomain, *mut *mut c_void) -> HRESULT,
    pub enumerate_steppers:
        unsafe extern "system" fn(*mut ICorDebugAppDomain, *mut *mut c_void) -> HRESULT,
    pub is_attached: unsafe extern "system" fn(*mut ICorDebugAppDomain, *mut i32) -> HRESULT,
    pub get_name:
        unsafe extern "system" fn(*mut ICorDebugAppDomain, u32, *mut u32, *mut u16) -> HRESULT,
    pub get_object: unsafe extern "system" fn(*mut ICorDebugAppDomain, *mut *mut c_void) -> HRESULT,
    pub attach: unsafe extern "system" fn(*mut ICorDebugAppDomain) -> HRESULT,
    pub get_id: unsafe extern "system" fn(*mut ICorDebugAppDomain, *mut u32) -> HRESULT,
}

#[repr(C)]
pub struct ICorDebugAppDomain {
    pub vtbl: *const ICorDebugAppDomainVtbl,
}

// ICorDebugAssemblyEnum interface
#[repr(C)]
pub struct ICorDebugAssemblyEnumVtbl {
    // IUnknown
    pub query_interface: unsafe extern "system" fn(
        *mut ICorDebugAssemblyEnum,
        *const GUID,
        *mut *mut c_void,
    ) -> HRESULT,
    pub add_ref: unsafe extern "system" fn(*mut ICorDebugAssemblyEnum) -> u32,
    pub release: unsafe extern "system" fn(*mut ICorDebugAssemblyEnum) -> u32,
    // ICorDebugEnum
    pub skip: unsafe extern "system" fn(*mut ICorDebugAssemblyEnum, u32) -> HRESULT,
    pub reset: unsafe extern "system" fn(*mut ICorDebugAssemblyEnum) -> HRESULT,
    pub clone: unsafe extern "system" fn(*mut ICorDebugAssemblyEnum, *mut *mut c_void) -> HRESULT,
    pub get_count: unsafe extern "system" fn(*mut ICorDebugAssemblyEnum, *mut u32) -> HRESULT,
    // ICorDebugAssemblyEnum
    pub next: unsafe extern "system" fn(
        *mut ICorDebugAssemblyEnum,
        u32,
        *mut *mut ICorDebugAssembly,
        *mut u32,
    ) -> HRESULT,
}

#[repr(C)]
pub struct ICorDebugAssemblyEnum {
    pub vtbl: *const ICorDebugAssemblyEnumVtbl,
}

// ICorDebugAssembly interface
#[repr(C)]
pub struct ICorDebugAssemblyVtbl {
    // IUnknown
    pub query_interface:
        unsafe extern "system" fn(*mut ICorDebugAssembly, *const GUID, *mut *mut c_void) -> HRESULT,
    pub add_ref: unsafe extern "system" fn(*mut ICorDebugAssembly) -> u32,
    pub release: unsafe extern "system" fn(*mut ICorDebugAssembly) -> u32,
    // ICorDebugAssembly
    pub get_process: unsafe extern "system" fn(*mut ICorDebugAssembly, *mut *mut c_void) -> HRESULT,
    pub get_app_domain:
        unsafe extern "system" fn(*mut ICorDebugAssembly, *mut *mut c_void) -> HRESULT,
    pub enumerate_modules:
        unsafe extern "system" fn(*mut ICorDebugAssembly, *mut *mut ICorDebugModuleEnum) -> HRESULT,
    pub get_code_base:
        unsafe extern "system" fn(*mut ICorDebugAssembly, u32, *mut u32, *mut u16) -> HRESULT,
    pub get_name:
        unsafe extern "system" fn(*mut ICorDebugAssembly, u32, *mut u32, *mut u16) -> HRESULT,
}

#[repr(C)]
pub struct ICorDebugAssembly {
    pub vtbl: *const ICorDebugAssemblyVtbl,
}

// ICorDebugModuleEnum interface
#[repr(C)]
pub struct ICorDebugModuleEnumVtbl {
    // IUnknown
    pub query_interface: unsafe extern "system" fn(
        *mut ICorDebugModuleEnum,
        *const GUID,
        *mut *mut c_void,
    ) -> HRESULT,
    pub add_ref: unsafe extern "system" fn(*mut ICorDebugModuleEnum) -> u32,
    pub release: unsafe extern "system" fn(*mut ICorDebugModuleEnum) -> u32,
    // ICorDebugEnum
    pub skip: unsafe extern "system" fn(*mut ICorDebugModuleEnum, u32) -> HRESULT,
    pub reset: unsafe extern "system" fn(*mut ICorDebugModuleEnum) -> HRESULT,
    pub clone: unsafe extern "system" fn(*mut ICorDebugModuleEnum, *mut *mut c_void) -> HRESULT,
    pub get_count: unsafe extern "system" fn(*mut ICorDebugModuleEnum, *mut u32) -> HRESULT,
    // ICorDebugModuleEnum
    pub next: unsafe extern "system" fn(
        *mut ICorDebugModuleEnum,
        u32,
        *mut *mut ICorDebugModule,
        *mut u32,
    ) -> HRESULT,
}

#[repr(C)]
pub struct ICorDebugModuleEnum {
    pub vtbl: *const ICorDebugModuleEnumVtbl,
}

// ICorDebugModule interface
#[repr(C)]
pub struct ICorDebugModuleVtbl {
    // IUnknown
    pub query_interface:
        unsafe extern "system" fn(*mut ICorDebugModule, *const GUID, *mut *mut c_void) -> HRESULT,
    pub add_ref: unsafe extern "system" fn(*mut ICorDebugModule) -> u32,
    pub release: unsafe extern "system" fn(*mut ICorDebugModule) -> u32,
    // ICorDebugModule
    pub get_process: unsafe extern "system" fn(*mut ICorDebugModule, *mut *mut c_void) -> HRESULT,
    pub get_base_address: unsafe extern "system" fn(*mut ICorDebugModule, *mut u64) -> HRESULT,
    pub get_assembly: unsafe extern "system" fn(*mut ICorDebugModule, *mut *mut c_void) -> HRESULT,
    pub get_name:
        unsafe extern "system" fn(*mut ICorDebugModule, u32, *mut u32, *mut u16) -> HRESULT,
    pub enable_jit_debugging: unsafe extern "system" fn(*mut ICorDebugModule, i32, i32) -> HRESULT,
    pub enable_class_load_callbacks:
        unsafe extern "system" fn(*mut ICorDebugModule, i32) -> HRESULT,
    pub get_function_from_token:
        unsafe extern "system" fn(*mut ICorDebugModule, u32, *mut *mut c_void) -> HRESULT,
    pub get_function_from_rva:
        unsafe extern "system" fn(*mut ICorDebugModule, u64, *mut *mut c_void) -> HRESULT,
    pub get_class_from_token:
        unsafe extern "system" fn(*mut ICorDebugModule, u32, *mut *mut c_void) -> HRESULT,
    pub create_breakpoint:
        unsafe extern "system" fn(*mut ICorDebugModule, *mut *mut c_void) -> HRESULT,
    pub get_edit_and_continue_snapshot:
        unsafe extern "system" fn(*mut ICorDebugModule, *mut *mut c_void) -> HRESULT,
    pub get_metadata_interface:
        unsafe extern "system" fn(*mut ICorDebugModule, *const GUID, *mut *mut c_void) -> HRESULT,
    pub get_token: unsafe extern "system" fn(*mut ICorDebugModule, *mut u32) -> HRESULT,
    pub is_dynamic: unsafe extern "system" fn(*mut ICorDebugModule, *mut i32) -> HRESULT,
    pub get_global_variable_value:
        unsafe extern "system" fn(*mut ICorDebugModule, u32, *mut *mut c_void) -> HRESULT,
    pub get_size: unsafe extern "system" fn(*mut ICorDebugModule, *mut u32) -> HRESULT,
    pub is_in_memory: unsafe extern "system" fn(*mut ICorDebugModule, *mut i32) -> HRESULT,
}

#[repr(C)]
pub struct ICorDebugModule {
    pub vtbl: *const ICorDebugModuleVtbl,
}
