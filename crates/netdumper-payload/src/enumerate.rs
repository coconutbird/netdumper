//! Assembly enumeration for .NET runtimes using CLR hosting APIs.

use crate::clr_host::*;
use crate::context::EnumerationContext;
use crate::debug_target::MyCorDebugDataTarget;
use crate::library_provider::MyLibraryProvider;
use netdumper_shared::{AssemblyInfo, Error, Result, RuntimeType, enumerate_assemblies_internal};
use std::ffi::c_void;
use std::ptr;
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::Com::SAFEARRAY;
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress, LoadLibraryW};
use windows::Win32::System::Ole::{SafeArrayGetElement, SafeArrayGetLBound, SafeArrayGetUBound};
use windows::Win32::System::ProcessStatus::{EnumProcessModules, GetModuleFileNameExW};
use windows::Win32::System::Threading::GetCurrentProcess;
use windows::core::{BSTR, HRESULT, PCWSTR, w};

// IUnknown vtable for raw QueryInterface calls
#[repr(C)]
struct IUnknownVtbl {
    query_interface: unsafe extern "system" fn(
        *mut c_void,
        *const windows::core::GUID,
        *mut *mut c_void,
    ) -> HRESULT,
    add_ref: unsafe extern "system" fn(*mut c_void) -> u32,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
}

/// Enumerate all loaded assemblies in the current process using CLR APIs.
pub fn enumerate_assemblies(
    runtime_type: RuntimeType,
    ctx: &mut EnumerationContext,
) -> Result<Vec<AssemblyInfo>> {
    match runtime_type {
        RuntimeType::Framework => enumerate_framework_assemblies(ctx),
        RuntimeType::Core => enumerate_core_assemblies(ctx),
    }
}

/// Enumerate assemblies for .NET Framework using ICorRuntimeHost.
fn enumerate_framework_assemblies(ctx: &mut EnumerationContext) -> Result<Vec<AssemblyInfo>> {
    unsafe {
        let runtime_host = get_cor_runtime_host()?;

        // Start the runtime (may already be started)
        let hr = { ((*(*runtime_host).vtbl).start)(runtime_host) };
        if hr.is_err() && hr != HRESULT::from_win32(0x80131022) {
            // Ignore "already started" error
            ctx.warn(&format!("ICorRuntimeHost::Start returned 0x{:08X}", hr.0));
        }

        // Get the default AppDomain
        let mut unknown: *mut c_void = ptr::null_mut();
        let hr = {
            ((*(*runtime_host).vtbl).get_default_domain)(
                runtime_host,
                &mut unknown as *mut _ as *mut *mut windows::core::IUnknown,
            )
        };
        if hr.is_err() {
            return Err(Error::EnumerationFailed(format!(
                "GetDefaultDomain failed: 0x{:08X}",
                hr.0
            )));
        }

        // Query for _AppDomain interface using raw QueryInterface
        let mut app_domain: *mut AppDomain = ptr::null_mut();
        let unknown_vtbl = unknown as *mut *const IUnknownVtbl;
        let hr = {
            ((**unknown_vtbl).query_interface)(
                unknown,
                &IID_APP_DOMAIN,
                &mut app_domain as *mut _ as *mut *mut c_void,
            )
        };
        if hr.is_err() {
            return Err(Error::EnumerationFailed(format!(
                "QueryInterface for AppDomain failed: 0x{:08X}",
                hr.0
            )));
        }

        // Get assemblies from the AppDomain
        let assemblies = get_assemblies_from_domain(app_domain)?;

        // Cleanup
        {
            ((*(*app_domain).vtbl).release)(app_domain)
        };
        {
            ((*(*runtime_host).vtbl).release)(runtime_host)
        };

        Ok(assemblies)
    }
}

/// Enumerate assemblies for .NET Core using DAC/ISOSDacInterface.
fn enumerate_core_assemblies(ctx: &mut EnumerationContext) -> Result<Vec<AssemblyInfo>> {
    // Try the DAC/ISOSDacInterface approach first (System Informer's approach)
    match enumerate_core_via_dac(ctx) {
        Ok(assemblies) => {
            ctx.info(&format!(
                "DAC enumeration succeeded, found {} assemblies",
                assemblies.len()
            ));
            return Ok(assemblies);
        }
        Err(e) => {
            ctx.warn(&format!("DAC enumeration failed: {:?}", e));
        }
    }

    // Try the ICorDebug approach (based on Cheat Engine) as fallback
    ctx.info("Trying ICorDebug approach...");
    match enumerate_core_via_icordebug(ctx) {
        Ok(assemblies) => {
            ctx.info(&format!(
                "ICorDebug enumeration succeeded, found {} assemblies",
                assemblies.len()
            ));
            return Ok(assemblies);
        }
        Err(e) => {
            ctx.warn(&format!("ICorDebug enumeration failed: {:?}", e));
        }
    }

    // Fallback: enumerate loaded PE modules with CLR headers
    ctx.info("Falling back to PE module scanning...");
    enumerate_managed_modules()
}

/// Find the path to dbgshim.dll by looking at loaded .NET Core modules.
fn find_dbgshim_path() -> Option<String> {
    unsafe {
        let process = GetCurrentProcess();
        let mut modules: [HMODULE; 2048] = [HMODULE::default(); 2048];
        let mut bytes_needed: u32 = 0;

        if EnumProcessModules(
            process,
            modules.as_mut_ptr(),
            (modules.len() * std::mem::size_of::<HMODULE>()) as u32,
            &mut bytes_needed,
        )
        .is_err()
        {
            return None;
        }

        let count = bytes_needed as usize / std::mem::size_of::<HMODULE>();

        // Look for coreclr.dll or System.Private.CoreLib.dll to find the runtime directory
        for i in 0..count {
            let module = modules[i];
            if module.0.is_null() {
                continue;
            }

            let mut path_buf = [0u16; 512];
            let path_len = GetModuleFileNameExW(Some(process), Some(module), &mut path_buf);
            if path_len == 0 {
                continue;
            }

            let path = String::from_utf16_lossy(&path_buf[..path_len as usize]);
            let lower_path = path.to_lowercase();

            // Found coreclr.dll - dbgshim.dll should be in the same directory
            if lower_path.ends_with("coreclr.dll") {
                if let Some(dir) = path.rsplit_once('\\') {
                    let dbgshim_path = format!("{}\\dbgshim.dll", dir.0);
                    return Some(dbgshim_path);
                }
            }
        }
    }
    None
}

/// Get the base address and directory of coreclr.dll
fn get_coreclr_info() -> Option<(u64, String)> {
    unsafe {
        let process = GetCurrentProcess();
        let mut modules: [HMODULE; 2048] = [HMODULE::default(); 2048];
        let mut bytes_needed: u32 = 0;

        if EnumProcessModules(
            process,
            modules.as_mut_ptr(),
            (modules.len() * std::mem::size_of::<HMODULE>()) as u32,
            &mut bytes_needed,
        )
        .is_err()
        {
            return None;
        }

        let count = bytes_needed as usize / std::mem::size_of::<HMODULE>();

        for i in 0..count {
            let module = modules[i];
            if module.0.is_null() {
                continue;
            }

            let mut path_buf = [0u16; 512];
            let path_len = GetModuleFileNameExW(Some(process), Some(module), &mut path_buf);
            if path_len == 0 {
                continue;
            }

            let path = String::from_utf16_lossy(&path_buf[..path_len as usize]);
            let lower_path = path.to_lowercase();

            if lower_path.ends_with("coreclr.dll") {
                let base = module.0 as u64;
                if let Some((dir, _)) = path.rsplit_once('\\') {
                    return Some((base, dir.to_string()));
                }
            }
        }
    }
    None
}

/// Enumerate .NET Core assemblies via DAC/ISOSDacInterface (System Informer's approach).
/// Uses the unified shared DAC implementation with GetCurrentProcess().
fn enumerate_core_via_dac(ctx: &mut EnumerationContext) -> Result<Vec<AssemblyInfo>> {
    // Get coreclr.dll directory for finding mscordaccore.dll
    let (_coreclr_base, runtime_dir) = get_coreclr_info()
        .ok_or_else(|| Error::EnumerationFailed("coreclr.dll not found".into()))?;

    ctx.debug(&format!("Runtime directory: {}", runtime_dir));
    ctx.debug("Using shared DAC implementation with GetCurrentProcess()");

    // Use the shared implementation which uses ReadProcessMemory with GetCurrentProcess()
    enumerate_assemblies_internal(&runtime_dir)
}

/// CLRCreateInstance function type for dbgshim.dll
type CLRCreateInstanceFnDbgshim = unsafe extern "system" fn(
    clsid: *const windows::core::GUID,
    riid: *const windows::core::GUID,
    ppinterface: *mut *mut c_void,
) -> HRESULT;

// NOTE: enumerate_via_dac and get_assembly_info_from_dac were removed.
// They are now unified in netdumper-shared/src/dac_enum.rs

/// Try to enumerate .NET Core assemblies via ICorDebug interfaces.
fn enumerate_core_via_icordebug(ctx: &mut EnumerationContext) -> Result<Vec<AssemblyInfo>> {
    unsafe {
        // Step 1: Find and load dbgshim.dll
        let dbgshim_path = find_dbgshim_path()
            .ok_or_else(|| Error::EnumerationFailed("Could not find dbgshim.dll".into()))?;

        ctx.debug(&format!("Loading dbgshim from: {}", dbgshim_path));

        let dbgshim_path_wide: Vec<u16> = dbgshim_path
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let dbgshim = LoadLibraryW(PCWSTR::from_raw(dbgshim_path_wide.as_ptr()))
            .map_err(|e| Error::EnumerationFailed(format!("Failed to load dbgshim.dll: {}", e)))?;

        // Step 2: Get CLRCreateInstance from dbgshim.dll
        let clr_create_instance = GetProcAddress(dbgshim, windows::core::s!("CLRCreateInstance"))
            .ok_or_else(|| {
            Error::EnumerationFailed("CLRCreateInstance not found in dbgshim.dll".into())
        })?;
        let clr_create_instance: CLRCreateInstanceFnDbgshim =
            std::mem::transmute(clr_create_instance);

        ctx.debug("Got CLRCreateInstance from dbgshim.dll");

        // Step 3: Create ICLRDebugging
        let mut clr_debugging: *mut ICLRDebugging = ptr::null_mut();
        let hr = clr_create_instance(
            &CLSID_CLR_DEBUGGING,
            &IID_ICLR_DEBUGGING,
            &mut clr_debugging as *mut _ as *mut *mut c_void,
        );
        if hr.is_err() || clr_debugging.is_null() {
            return Err(Error::EnumerationFailed(format!(
                "CLRCreateInstance(ICLRDebugging) failed: 0x{:08X}",
                hr.0
            )));
        }

        ctx.debug("ICLRDebugging created successfully");

        // Step 4: Create our ICorDebugDataTarget
        let data_target = MyCorDebugDataTarget::new();

        // Step 5: Get coreclr.dll base address and directory
        let (coreclr_base, runtime_dir) = get_coreclr_info()
            .ok_or_else(|| Error::EnumerationFailed("coreclr.dll not found".into()))?;

        ctx.debug(&format!("coreclr.dll base: 0x{:016X}", coreclr_base));
        ctx.debug(&format!("Runtime directory: {}", runtime_dir));

        // Step 6: Create library provider (needed to locate mscordaccore.dll)
        let library_provider = MyLibraryProvider::new(runtime_dir);
        ctx.debug("Library provider created");

        // Step 7: Set up version info
        let mut max_version = CLR_DEBUGGING_VERSION {
            w_struct_version: 0,
            w_major: 10,
            w_minor: 0,
            w_build: 0,
            w_revision: 0,
        };
        let mut version_out = CLR_DEBUGGING_VERSION::default();
        let mut flags: u32 = 0;

        // Step 8: Call OpenVirtualProcess
        ctx.debug("Calling OpenVirtualProcess...");
        let mut cor_debug_process: *mut ICorDebugProcess = ptr::null_mut();
        let hr = ((*(*clr_debugging).vtbl).open_virtual_process)(
            clr_debugging,
            coreclr_base,
            data_target as *mut c_void,
            library_provider as *mut c_void, // Library provider to locate DAC DLL
            &mut max_version,
            &IID_ICOR_DEBUG_PROCESS,
            &mut cor_debug_process as *mut _ as *mut *mut c_void,
            &mut version_out,
            &mut flags,
        );

        if hr.is_err() || cor_debug_process.is_null() {
            // Clean up
            ((*(*library_provider).vtbl).release)(library_provider);
            ((*(*clr_debugging).vtbl).release)(clr_debugging);
            return Err(Error::EnumerationFailed(format!(
                "OpenVirtualProcess failed: 0x{:08X}",
                hr.0
            )));
        }

        ctx.info(&format!(
            "OpenVirtualProcess succeeded, CLR version: {}.{}.{}.{}",
            version_out.w_major, version_out.w_minor, version_out.w_build, version_out.w_revision
        ));
        ctx.debug(&format!("CLR_DEBUGGING_PROCESS_FLAGS: 0x{:08X}", flags));

        // Step 9: Enumerate AppDomains -> Assemblies -> Modules
        let assemblies = enumerate_via_process(cor_debug_process, ctx)?;

        // Cleanup
        ((*(*cor_debug_process).vtbl).release)(cor_debug_process);
        ((*(*library_provider).vtbl).release)(library_provider);
        ((*(*clr_debugging).vtbl).release)(clr_debugging);

        Ok(assemblies)
    }
}

/// Enumerate assemblies via ICorDebugProcess
unsafe fn enumerate_via_process(
    process: *mut ICorDebugProcess,
    ctx: &mut EnumerationContext,
) -> Result<Vec<AssemblyInfo>> {
    unsafe {
        let mut assemblies = Vec::new();

        // First try to call GetID to verify the interface is working
        let mut process_id: u32 = 0;
        let hr = ((*(*process).vtbl).get_id)(process, &mut process_id);
        ctx.debug(&format!(
            "GetID returned: 0x{:08X}, pid={}",
            hr.0, process_id
        ));

        // Get AppDomain enumerator
        let mut app_domain_enum: *mut ICorDebugAppDomainEnum = ptr::null_mut();
        let hr = ((*(*process).vtbl).enumerate_app_domains)(process, &mut app_domain_enum);
        ctx.debug(&format!(
            "EnumerateAppDomains returned: 0x{:08X}, enum={:p}",
            hr.0, app_domain_enum
        ));
        if hr.is_err() || app_domain_enum.is_null() {
            return Err(Error::EnumerationFailed(format!(
                "EnumerateAppDomains failed: 0x{:08X}",
                hr.0
            )));
        }

        // Get count of app domains
        let mut domain_count: u32 = 0;
        let _ = ((*(*app_domain_enum).vtbl).get_count)(app_domain_enum, &mut domain_count);
        ctx.debug(&format!("Found {} AppDomains", domain_count));

        // Enumerate each AppDomain
        loop {
            let mut app_domain: *mut ICorDebugAppDomain = ptr::null_mut();
            let mut fetched: u32 = 0;
            let hr = ((*(*app_domain_enum).vtbl).next)(
                app_domain_enum,
                1,
                &mut app_domain,
                &mut fetched,
            );
            if hr.is_err() || fetched == 0 || app_domain.is_null() {
                break;
            }

            // Enumerate assemblies in this AppDomain
            let domain_assemblies = enumerate_domain_assemblies(app_domain, ctx)?;
            assemblies.extend(domain_assemblies);

            ((*(*app_domain).vtbl).release)(app_domain);
        }

        ((*(*app_domain_enum).vtbl).release)(app_domain_enum);
        Ok(assemblies)
    }
}

/// Enumerate assemblies in an AppDomain
unsafe fn enumerate_domain_assemblies(
    app_domain: *mut ICorDebugAppDomain,
    ctx: &mut EnumerationContext,
) -> Result<Vec<AssemblyInfo>> {
    unsafe {
        let mut assemblies = Vec::new();

        // Get assembly enumerator
        let mut asm_enum: *mut ICorDebugAssemblyEnum = ptr::null_mut();
        let hr = ((*(*app_domain).vtbl).enumerate_assemblies)(app_domain, &mut asm_enum);
        if hr.is_err() || asm_enum.is_null() {
            return Err(Error::EnumerationFailed(format!(
                "EnumerateAssemblies failed: 0x{:08X}",
                hr.0
            )));
        }

        // Get count
        let mut asm_count: u32 = 0;
        let _ = ((*(*asm_enum).vtbl).get_count)(asm_enum, &mut asm_count);
        ctx.debug(&format!("AppDomain has {} assemblies", asm_count));

        // Enumerate each assembly
        loop {
            let mut assembly: *mut ICorDebugAssembly = ptr::null_mut();
            let mut fetched: u32 = 0;
            let hr = ((*(*asm_enum).vtbl).next)(asm_enum, 1, &mut assembly, &mut fetched);
            if hr.is_err() || fetched == 0 || assembly.is_null() {
                break;
            }

            // Enumerate modules in this assembly
            let modules = enumerate_assembly_modules(assembly, ctx)?;
            assemblies.extend(modules);

            ((*(*assembly).vtbl).release)(assembly);
        }

        ((*(*asm_enum).vtbl).release)(asm_enum);
        Ok(assemblies)
    }
}

/// Enumerate modules in an assembly
unsafe fn enumerate_assembly_modules(
    assembly: *mut ICorDebugAssembly,
    ctx: &mut EnumerationContext,
) -> Result<Vec<AssemblyInfo>> {
    unsafe {
        let mut modules = Vec::new();

        // Get module enumerator
        let mut mod_enum: *mut ICorDebugModuleEnum = ptr::null_mut();
        let hr = ((*(*assembly).vtbl).enumerate_modules)(assembly, &mut mod_enum);
        if hr.is_err() || mod_enum.is_null() {
            return Err(Error::EnumerationFailed(format!(
                "EnumerateModules failed: 0x{:08X}",
                hr.0
            )));
        }

        // Enumerate each module
        loop {
            let mut module: *mut ICorDebugModule = ptr::null_mut();
            let mut fetched: u32 = 0;
            let hr = ((*(*mod_enum).vtbl).next)(mod_enum, 1, &mut module, &mut fetched);
            if hr.is_err() || fetched == 0 || module.is_null() {
                break;
            }

            // Get module info
            if let Some(info) = get_module_info(module, ctx) {
                modules.push(info);
            }

            ((*(*module).vtbl).release)(module);
        }

        ((*(*mod_enum).vtbl).release)(mod_enum);
        Ok(modules)
    }
}

/// Get info from an ICorDebugModule
unsafe fn get_module_info(
    module: *mut ICorDebugModule,
    ctx: &mut EnumerationContext,
) -> Option<AssemblyInfo> {
    unsafe {
        // Get base address
        let mut base_address: u64 = 0;
        let hr = ((*(*module).vtbl).get_base_address)(module, &mut base_address);
        if hr.is_err() {
            ctx.warn(&format!("GetBaseAddress failed: 0x{:08X}", hr.0));
        }

        // Get size
        let mut size: u32 = 0;
        let hr = ((*(*module).vtbl).get_size)(module, &mut size);
        if hr.is_err() {
            // Size might not be available for all modules
            size = 0;
        }

        // Get name
        let mut name_buf = [0u16; 512];
        let mut name_len: u32 = 0;
        let hr = ((*(*module).vtbl).get_name)(module, 512, &mut name_len, name_buf.as_mut_ptr());
        let name = if hr.is_ok() && name_len > 0 {
            let len = (name_len as usize).saturating_sub(1); // Remove null terminator
            String::from_utf16_lossy(&name_buf[..len])
        } else {
            "Unknown".to_string()
        };

        // Extract just the filename from the path
        let display_name = name.rsplit('\\').next().unwrap_or(&name).to_string();
        let path = if name.contains('\\') {
            Some(name)
        } else {
            None
        };

        ctx.debug(&format!(
            "Module: {} @ 0x{:X} (size: {})",
            display_name, base_address, size
        ));

        let mut info = AssemblyInfo::new(display_name, base_address as usize, size as usize);
        info.path = path;

        Some(info)
    }
}

/// Enumerate loaded managed modules by scanning PE headers for CLR metadata.
fn enumerate_managed_modules() -> Result<Vec<AssemblyInfo>> {
    use windows::Win32::Foundation::HMODULE;
    use windows::Win32::System::ProcessStatus::{
        EnumProcessModules, GetModuleFileNameExW, GetModuleInformation, MODULEINFO,
    };
    use windows::Win32::System::Threading::GetCurrentProcess;

    let mut assemblies = Vec::new();

    unsafe {
        let process = GetCurrentProcess();
        let mut modules: [HMODULE; 2048] = [HMODULE::default(); 2048];
        let mut bytes_needed: u32 = 0;

        if EnumProcessModules(
            process,
            modules.as_mut_ptr(),
            (modules.len() * std::mem::size_of::<HMODULE>()) as u32,
            &mut bytes_needed,
        )
        .is_err()
        {
            return Err(Error::EnumerationFailed(
                "Failed to enumerate modules".into(),
            ));
        }

        let count = bytes_needed as usize / std::mem::size_of::<HMODULE>();

        for i in 0..count {
            let module = modules[i];
            if module.0 == std::ptr::null_mut() {
                continue;
            }

            // Get module file path
            let mut path_buf = [0u16; 512];
            let path_len = GetModuleFileNameExW(Some(process), Some(module), &mut path_buf);
            if path_len == 0 {
                continue;
            }
            let path = String::from_utf16_lossy(&path_buf[..path_len as usize]);

            // Skip non-dll files and system DLLs
            let lower_path = path.to_lowercase();
            if !lower_path.ends_with(".dll") && !lower_path.ends_with(".exe") {
                continue;
            }
            if lower_path.contains("\\windows\\") || lower_path.contains("\\system32\\") {
                continue;
            }

            // Get module info for size
            let mut mod_info = MODULEINFO::default();
            if GetModuleInformation(
                process,
                module,
                &mut mod_info,
                std::mem::size_of::<MODULEINFO>() as u32,
            )
            .is_err()
            {
                continue;
            }

            // Check if this is a managed assembly by checking for CLR header
            if is_managed_module(module.0 as usize, mod_info.SizeOfImage as usize) {
                let name = path.rsplit('\\').next().unwrap_or(&path).to_string();
                let mut info =
                    AssemblyInfo::new(name, module.0 as usize, mod_info.SizeOfImage as usize);
                info.path = Some(path);
                assemblies.push(info);
            }
        }
    }

    Ok(assemblies)
}

/// Check if a module is a managed .NET assembly by examining its PE headers using pelite.
fn is_managed_module(base_address: usize, size: usize) -> bool {
    use pelite::image::IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR;
    use pelite::pe32::{Pe as Pe32, PeView as PeView32};
    use pelite::pe64::{Pe, PeView};

    // Create a slice from the module's memory
    let bytes = unsafe { std::slice::from_raw_parts(base_address as *const u8, size) };

    // Try 64-bit PE first, then 32-bit
    if let Ok(pe) = PeView::from_bytes(bytes) {
        // Check for CLR header (COM descriptor)
        if let Some(dir) = pe
            .optional_header()
            .DataDirectory
            .get(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
        {
            return dir.VirtualAddress != 0 && dir.Size != 0;
        }
    } else if let Ok(pe) = PeView32::from_bytes(bytes) {
        if let Some(dir) = pe
            .optional_header()
            .DataDirectory
            .get(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
        {
            return dir.VirtualAddress != 0 && dir.Size != 0;
        }
    }

    false
}

/// Get ICorRuntimeHost interface.
unsafe fn get_cor_runtime_host() -> Result<*mut ICorRuntimeHost> {
    // Try CLRCreateInstance first (v4.0+)
    let mscoree = unsafe { GetModuleHandleW(w!("mscoree.dll")) };
    if mscoree.is_err() {
        return Err(Error::RuntimeNotFound);
    }
    let mscoree = mscoree.unwrap();

    // Try CLRCreateInstance
    if let Some(clr_create_instance) =
        unsafe { GetProcAddress(mscoree, windows::core::s!("CLRCreateInstance")) }
    {
        let clr_create_instance: CLRCreateInstanceFn =
            unsafe { std::mem::transmute(clr_create_instance) };

        let mut meta_host: *mut ICLRMetaHost = ptr::null_mut();
        let hr = unsafe {
            clr_create_instance(
                &CLSID_CLR_META_HOST,
                &IID_ICLR_META_HOST,
                &mut meta_host as *mut _ as *mut *mut c_void,
            )
        };

        if hr.is_ok() && !meta_host.is_null() {
            // Get runtime info for v4.0
            let mut runtime_info: *mut ICLRRuntimeInfo = ptr::null_mut();
            let hr = unsafe {
                ((*(*meta_host).vtbl).get_runtime)(
                    meta_host,
                    w!("v4.0.30319"),
                    &IID_ICLR_RUNTIME_INFO,
                    &mut runtime_info as *mut _ as *mut *mut c_void,
                )
            };

            if hr.is_ok() && !runtime_info.is_null() {
                // Get ICorRuntimeHost from runtime info
                let mut runtime_host: *mut ICorRuntimeHost = ptr::null_mut();
                let hr = unsafe {
                    ((*(*runtime_info).vtbl).get_interface)(
                        runtime_info,
                        &CLSID_COR_RUNTIME_HOST,
                        &IID_ICOR_RUNTIME_HOST,
                        &mut runtime_host as *mut _ as *mut *mut c_void,
                    )
                };

                unsafe { ((*(*runtime_info).vtbl).release)(runtime_info) };
                unsafe { ((*(*meta_host).vtbl).release)(meta_host) };

                if hr.is_ok() && !runtime_host.is_null() {
                    return Ok(runtime_host);
                }
            }
            unsafe { ((*(*meta_host).vtbl).release)(meta_host) };
        }
    }

    // Fall back to CorBindToRuntimeEx
    if let Some(cor_bind) =
        unsafe { GetProcAddress(mscoree, windows::core::s!("CorBindToRuntimeEx")) }
    {
        let cor_bind: CorBindToRuntimeExFn = unsafe { std::mem::transmute(cor_bind) };

        let mut runtime_host: *mut ICorRuntimeHost = ptr::null_mut();
        let hr = unsafe {
            cor_bind(
                PCWSTR::null(), // Use latest version
                w!("wks"),      // Workstation GC
                0,
                &CLSID_COR_RUNTIME_HOST,
                &IID_ICOR_RUNTIME_HOST,
                &mut runtime_host as *mut _ as *mut *mut c_void,
            )
        };

        if hr.is_ok() && !runtime_host.is_null() {
            return Ok(runtime_host);
        }
    }

    Err(Error::RuntimeNotFound)
}

/// Get ICLRMetaHost interface.
#[allow(dead_code)]
unsafe fn get_clr_meta_host() -> Result<*mut ICLRMetaHost> {
    let mscoree = unsafe { GetModuleHandleW(w!("mscoree.dll"))? };

    let clr_create_instance =
        unsafe { GetProcAddress(mscoree, windows::core::s!("CLRCreateInstance")) }
            .ok_or(Error::RuntimeNotFound)?;
    let clr_create_instance: CLRCreateInstanceFn =
        unsafe { std::mem::transmute(clr_create_instance) };

    let mut meta_host: *mut ICLRMetaHost = ptr::null_mut();
    let hr = unsafe {
        clr_create_instance(
            &CLSID_CLR_META_HOST,
            &IID_ICLR_META_HOST,
            &mut meta_host as *mut _ as *mut *mut c_void,
        )
    };

    if hr.is_err() || meta_host.is_null() {
        return Err(Error::RuntimeNotFound);
    }

    Ok(meta_host)
}

/// Get assemblies from an AppDomain.
unsafe fn get_assemblies_from_domain(app_domain: *mut AppDomain) -> Result<Vec<AssemblyInfo>> {
    let mut assemblies = Vec::new();

    // Get the SAFEARRAY of assemblies
    let mut sa: *mut SAFEARRAY = ptr::null_mut();
    let hr = unsafe { ((*(*app_domain).vtbl).get_assemblies)(app_domain, &mut sa) };
    if hr.is_err() || sa.is_null() {
        return Err(Error::EnumerationFailed(format!(
            "GetAssemblies failed: 0x{:08X}",
            hr.0
        )));
    }

    // Get array bounds (new API returns Result<i32>)
    let lower_bound = unsafe { SafeArrayGetLBound(sa, 1)? };
    let upper_bound = unsafe { SafeArrayGetUBound(sa, 1)? };

    // Iterate through assemblies
    for i in lower_bound..=upper_bound {
        let mut asm: *mut Assembly = ptr::null_mut();
        let hr = unsafe { SafeArrayGetElement(sa, &i, &mut asm as *mut _ as *mut c_void) };
        if hr.is_err() || asm.is_null() {
            continue;
        }

        // Get assembly info
        if let Some(info) = unsafe { get_assembly_info(asm) } {
            assemblies.push(info);
        }

        unsafe { ((*(*asm).vtbl).release)(asm) };
    }

    Ok(assemblies)
}

/// Get info from a single assembly.
unsafe fn get_assembly_info(asm: *mut Assembly) -> Option<AssemblyInfo> {
    // Get full name
    let mut full_name: BSTR = BSTR::default();
    let hr = unsafe { ((*(*asm).vtbl).get_full_name)(asm, &mut full_name) };
    let name = if hr.is_ok() && !full_name.is_empty() {
        full_name.to_string()
    } else {
        "Unknown".to_string()
    };

    // Get location (file path)
    let mut location: BSTR = BSTR::default();
    let hr = unsafe { ((*(*asm).vtbl).get_location)(asm, &mut location) };
    let path = if hr.is_ok() && !location.is_empty() {
        Some(location.to_string())
    } else {
        None
    };

    // Get code base
    let mut code_base: BSTR = BSTR::default();
    let _ = unsafe { ((*(*asm).vtbl).get_code_base)(asm, &mut code_base) };

    // For base address, we'd need to use reflection or other means
    // The _Assembly interface doesn't directly expose the base address
    // We'll set it to 0 for now and could enhance this later
    let mut info = AssemblyInfo::new(name, 0, 0);
    info.path = path;

    Some(info)
}
