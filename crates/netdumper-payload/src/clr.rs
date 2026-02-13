//! CLR runtime detection and interaction.

use netdumper_shared::{Error, Result, RuntimeType};
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::ProcessStatus::{EnumProcessModules, GetModuleBaseNameW};
use windows::Win32::System::Threading::GetCurrentProcess;
use windows::core::w;

/// Detect which .NET runtime is loaded in the current process.
pub fn detect_runtime() -> Result<RuntimeType> {
    // Check for .NET Core / .NET 5+ (coreclr.dll)
    let coreclr = unsafe { GetModuleHandleW(w!("coreclr.dll")) };
    if coreclr.is_ok() {
        return Ok(RuntimeType::Core);
    }

    // Check for .NET Framework (clr.dll for CLR 4.0+)
    let clr = unsafe { GetModuleHandleW(w!("clr.dll")) };
    if clr.is_ok() {
        return Ok(RuntimeType::Framework);
    }

    // Check for .NET Framework (mscorwks.dll for CLR 2.0)
    let mscorwks = unsafe { GetModuleHandleW(w!("mscorwks.dll")) };
    if mscorwks.is_ok() {
        return Ok(RuntimeType::Framework);
    }

    Err(Error::RuntimeNotFound)
}

/// List all loaded modules in current process (for debugging)
pub fn list_loaded_modules() -> Vec<String> {
    let mut modules = Vec::new();
    unsafe {
        let process = GetCurrentProcess();
        let mut module_handles: [HMODULE; 1024] = [HMODULE::default(); 1024];
        let mut bytes_needed: u32 = 0;

        if EnumProcessModules(
            process,
            module_handles.as_mut_ptr(),
            (module_handles.len() * std::mem::size_of::<HMODULE>()) as u32,
            &mut bytes_needed,
        )
        .is_ok()
        {
            let count = bytes_needed as usize / std::mem::size_of::<HMODULE>();
            for i in 0..count {
                let mut name_buf = [0u16; 260];
                let len = GetModuleBaseNameW(process, Some(module_handles[i]), &mut name_buf);
                if len > 0 {
                    let name = String::from_utf16_lossy(&name_buf[..len as usize]);
                    modules.push(name);
                }
            }
        }
    }
    modules
}

/// Get the base address of the CLR module.
#[allow(dead_code)]
pub fn get_clr_base(runtime_type: RuntimeType) -> Result<usize> {
    let module_name = match runtime_type {
        RuntimeType::Core => w!("coreclr.dll"),
        RuntimeType::Framework => w!("clr.dll"),
    };

    let handle = unsafe { GetModuleHandleW(module_name)? };
    Ok(handle.0 as usize)
}
