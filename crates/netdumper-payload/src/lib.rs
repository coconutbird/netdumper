//! DLL that gets injected into .NET Core or .NET Framework applications.

mod clr;
mod clr_host;
mod context;
mod debug_target;
mod enumerate;
mod library_provider;

use context::EnumerationContext;
use netdumper_shared::{IpcClient, RuntimeType};
use std::ffi::c_void;
use windows::Win32::System::Threading::GetCurrentProcessId;

/// DLL entry point for Windows.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(
    _hinst_dll: *mut c_void,
    fdw_reason: u32,
    _lpv_reserved: *mut c_void,
) -> i32 {
    const DLL_PROCESS_ATTACH: u32 = 1;

    if fdw_reason == DLL_PROCESS_ATTACH {
        // Spawn a thread to do the work to avoid loader lock issues
        std::thread::spawn(|| {
            if let Err(e) = run() {
                eprintln!("[netdumper] Error: {}", e);
            }
        });
    }

    1 // TRUE
}

fn run() -> netdumper_shared::Result<()> {
    // Get our PID and connect to the IPC
    let pid = unsafe { GetCurrentProcessId() };
    let mut ipc = match IpcClient::open(pid) {
        Ok(ipc) => ipc,
        Err(e) => {
            eprintln!("[netdumper] Failed to open IPC: {:?}", e);
            return Err(netdumper_shared::Error::RuntimeNotFound);
        }
    };

    ipc.info("Payload loaded, detecting runtime...");

    // Detect runtime
    let runtime_type = match clr::detect_runtime() {
        Ok(rt) => rt,
        Err(e) => {
            // Log all loaded modules for debugging
            let modules = clr::list_loaded_modules();
            ipc.error(&format!("Loaded modules ({}):", modules.len()));

            // Look for any CLR-related modules
            let clr_related: Vec<_> = modules
                .iter()
                .filter(|m| {
                    let lower = m.to_lowercase();
                    lower.contains("clr") || lower.contains("msco") || lower.contains("dotnet")
                })
                .collect();

            if !clr_related.is_empty() {
                ipc.warn("CLR-related modules found:");
                for m in &clr_related {
                    ipc.warn(&format!("  - {}", m));
                }
            } else {
                ipc.warn("No CLR-related modules found in process");
            }

            // Show all modules
            for module in &modules {
                ipc.debug(&format!("  - {}", module));
            }
            ipc.send_fatal(&format!("Failed to detect runtime: {}", e));
            ipc.set_finished();
            return Err(e);
        }
    };

    // Set runtime type in header
    let rt_code = match runtime_type {
        RuntimeType::Framework => 1,
        RuntimeType::Core => 2,
    };
    ipc.set_runtime_type(rt_code);
    ipc.info(&format!("Detected runtime: {:?}", runtime_type));

    // Wait for CLI to signal start
    ipc.info("Waiting for enumeration signal...");
    while !ipc.should_start() {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    ipc.info("Starting assembly enumeration...");

    // Create enumeration context for logging
    let mut ctx = EnumerationContext::new(&mut ipc);

    // Enumerate assemblies
    let assemblies = match enumerate::enumerate_assemblies(runtime_type, &mut ctx) {
        Ok(asms) => asms,
        Err(e) => {
            // Need to get ipc back from ctx for the fatal message
            drop(ctx);
            ipc.send_fatal(&format!("Failed to enumerate assemblies: {}", e));
            ipc.set_finished();
            return Err(e);
        }
    };

    // Drop ctx to get ipc back
    drop(ctx);
    ipc.info(&format!("Found {} assemblies", assemblies.len()));

    // Send each assembly
    for asm in &assemblies {
        ipc.send_assembly(&asm.name, asm.path.as_deref(), asm.base_address, asm.size);
    }

    // Signal completion
    ipc.send_enumeration_complete(assemblies.len() as u32);
    ipc.set_finished();

    Ok(())
}
