//! DLL injection for the payload.

use netdumper_shared::{Error, Result};
use std::ffi::CString;
use std::ptr;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx, VirtualFreeEx,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, OpenProcess, PROCESS_ALL_ACCESS, WaitForSingleObject,
};
use windows::core::s;

/// Inject the payload DLL into a target process.
pub fn inject_payload(pid: u32) -> Result<()> {
    // Get the path to the payload DLL
    let exe_path = std::env::current_exe().map_err(|e| Error::Other(e.to_string()))?;
    let payload_path = exe_path
        .parent()
        .ok_or_else(|| Error::Other("Failed to get exe directory".into()))?
        .join("netdumper_payload.dll");

    if !payload_path.exists() {
        return Err(Error::Other(format!(
            "Payload DLL not found at: {}",
            payload_path.display()
        )));
    }

    let payload_path_str = payload_path
        .to_str()
        .ok_or_else(|| Error::Other("Invalid path".into()))?;

    println!("Injecting payload from: {}", payload_path_str);

    unsafe { inject_dll(pid, payload_path_str) }
}

/// Perform the actual DLL injection using CreateRemoteThread + LoadLibraryA.
unsafe fn inject_dll(pid: u32, dll_path: &str) -> Result<()> {
    unsafe {
        // Open the target process
        let process = OpenProcess(PROCESS_ALL_ACCESS, false, pid)?;

        let result = inject_dll_impl(process, dll_path);

        // Clean up
        let _ = CloseHandle(process);

        result
    }
}

unsafe fn inject_dll_impl(process: HANDLE, dll_path: &str) -> Result<()> {
    unsafe {
        let dll_path_cstr =
            CString::new(dll_path).map_err(|e| Error::Other(format!("Invalid path: {}", e)))?;
        let dll_path_bytes = dll_path_cstr.as_bytes_with_nul();

        // Allocate memory in the target process for the DLL path
        let remote_mem = VirtualAllocEx(
            process,
            Some(ptr::null()),
            dll_path_bytes.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if remote_mem.is_null() {
            return Err(Error::Other(
                "Failed to allocate memory in target process".into(),
            ));
        }

        // Write the DLL path to the allocated memory
        let write_result = WriteProcessMemory(
            process,
            remote_mem,
            dll_path_bytes.as_ptr() as *const _,
            dll_path_bytes.len(),
            None,
        );

        if write_result.is_err() {
            VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE)?;
            return Err(Error::Other(
                "Failed to write to target process memory".into(),
            ));
        }

        // Get the address of LoadLibraryA
        let kernel32 = GetModuleHandleA(s!("kernel32.dll"))?;
        let load_library = GetProcAddress(kernel32, s!("LoadLibraryA"))
            .ok_or_else(|| Error::Other("Failed to get LoadLibraryA address".into()))?;

        // Create a remote thread to call LoadLibraryA with our DLL path
        let thread = CreateRemoteThread(
            process,
            None,
            0,
            Some(std::mem::transmute(load_library)),
            Some(remote_mem),
            0,
            None,
        )?;

        // Wait for the thread to complete
        WaitForSingleObject(thread, 10000);

        // Clean up
        let _ = CloseHandle(thread);
        let _ = VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);

        println!("Payload injected successfully!");
        Ok(())
    }
}
