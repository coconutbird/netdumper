mod external_dac;
mod inject;

use clap::{Parser, Subcommand};
use netdumper_shared::{AssemblyInfo, IpcHost, LogLevel, PacketId};
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::ProcessStatus::{EnumProcesses, GetModuleBaseNameW};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

#[derive(Parser)]
#[command(name = "netdumper")]
#[command(about = "A tool for dumping .NET assemblies from running processes")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List running .NET processes
    List,
    /// Dump assemblies from a process (uses injection)
    Dump {
        /// Process ID to target
        #[arg(short, long, group = "target")]
        pid: Option<u32>,
        /// Process name to target (e.g., "dnSpy.exe" or "dnSpy")
        #[arg(short, long, group = "target")]
        name: Option<String>,
    },
    /// Enumerate assemblies without injection (external mode)
    Enum {
        /// Process ID to target
        #[arg(short, long, group = "target")]
        pid: Option<u32>,
        /// Process name to target (e.g., "dnSpy.exe" or "dnSpy")
        #[arg(short, long, group = "target")]
        name: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::List => {
            println!("Listing .NET processes...");
            // TODO: Implement process listing
        }
        Commands::Dump { pid, name } => {
            let target_pid = match (pid, name) {
                (Some(p), _) => p,
                (None, Some(n)) => match find_process_by_name(&n) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("Error finding process '{}': {}", n, e);
                        std::process::exit(1);
                    }
                },
                (None, None) => {
                    eprintln!("Error: Must specify either --pid or --name");
                    std::process::exit(1);
                }
            };

            if let Err(e) = dump_assemblies(target_pid) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Enum { pid, name } => {
            let target_pid = match (pid, name) {
                (Some(p), _) => p,
                (None, Some(n)) => match find_process_by_name(&n) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("Error finding process '{}': {}", n, e);
                        std::process::exit(1);
                    }
                },
                (None, None) => {
                    eprintln!("Error: Must specify either --pid or --name");
                    std::process::exit(1);
                }
            };

            match external_dac::enumerate_external(target_pid) {
                Ok(assemblies) => {
                    println!("\n=== Loaded Assemblies ({}) ===\n", assemblies.len());
                    // Force evaluation by using black_box on the vector
                    let assemblies = std::hint::black_box(assemblies);
                    for asm in &assemblies {
                        // Use eprintln for now to debug
                        eprintln!("  {} ", asm.name);
                        if asm.base_address != 0 {
                            eprintln!("    Base: 0x{:X}", asm.base_address);
                        }
                        if asm.size != 0 {
                            eprintln!("    Size: 0x{:X}", asm.size);
                        }
                        if let Some(path) = &asm.path {
                            eprintln!("    Path: {}", path);
                        }
                        eprintln!();
                    }
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}

/// Find a process by name, returns the PID
fn find_process_by_name(name: &str) -> netdumper_shared::Result<u32> {
    let search_name = name.to_lowercase();
    let search_name_exe = if search_name.ends_with(".exe") {
        search_name.clone()
    } else {
        format!("{}.exe", search_name)
    };

    unsafe {
        let mut pids = [0u32; 4096];
        let mut bytes_returned: u32 = 0;

        EnumProcesses(
            pids.as_mut_ptr(),
            (pids.len() * std::mem::size_of::<u32>()) as u32,
            &mut bytes_returned,
        )?;

        let count = bytes_returned as usize / std::mem::size_of::<u32>();

        for &pid in &pids[..count] {
            if pid == 0 {
                continue;
            }

            if let Ok(process) =
                OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            {
                let mut name_buf = [0u16; 260];
                let len = GetModuleBaseNameW(process, None, &mut name_buf);
                let _ = CloseHandle(process);

                if len > 0 {
                    let proc_name =
                        String::from_utf16_lossy(&name_buf[..len as usize]).to_lowercase();
                    if proc_name == search_name || proc_name == search_name_exe {
                        println!("Found process '{}' with PID {}", proc_name, pid);
                        return Ok(pid);
                    }
                }
            }
        }
    }

    Err(netdumper_shared::Error::Other(format!(
        "Process '{}' not found",
        name
    )))
}

fn dump_assemblies(pid: u32) -> netdumper_shared::Result<()> {
    println!("Dumping assemblies from process {}...", pid);

    // Create IPC shared memory
    println!("Creating IPC channel...");
    let mut ipc = IpcHost::create(pid)
        .map_err(|e| netdumper_shared::Error::Other(format!("Failed to create IPC: {:?}", e)))?;

    // Inject the payload
    inject::inject_payload(pid)?;

    // Wait for payload to connect and detect runtime
    println!("Waiting for payload to initialize...");
    let timeout = std::time::Duration::from_secs(10);
    let start = std::time::Instant::now();

    // Process messages while waiting for runtime detection
    while ipc.get_runtime_type() == 0 {
        if start.elapsed() > timeout {
            return Err(netdumper_shared::Error::Other(
                "Timeout waiting for payload to detect runtime".into(),
            ));
        }
        process_messages(&mut ipc);
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    let runtime_name = match ipc.get_runtime_type() {
        1 => ".NET Framework",
        2 => ".NET Core",
        _ => "Unknown",
    };
    println!("Runtime detected: {}", runtime_name);

    // Signal payload to start enumeration
    println!("Starting assembly enumeration...");
    ipc.start_enumeration();

    // Collect assemblies
    let mut assemblies: Vec<AssemblyInfo> = Vec::new();
    let start = std::time::Instant::now();

    while !ipc.is_finished() {
        if start.elapsed() > timeout {
            return Err(netdumper_shared::Error::Other(
                "Timeout waiting for enumeration to complete".into(),
            ));
        }

        while let Some(packet) = ipc.try_read() {
            match packet.id() {
                PacketId::Log => {
                    let level = packet.log_level().unwrap_or(LogLevel::Info);
                    let msg = packet.message();
                    match level {
                        LogLevel::Debug => println!("[DEBUG] {}", msg),
                        LogLevel::Info => println!("[INFO] {}", msg),
                        LogLevel::Warning => println!("[WARN] {}", msg),
                        LogLevel::Error => eprintln!("[ERROR] {}", msg),
                    }
                }
                PacketId::Assembly => {
                    if let Some((name, path, base_address, size)) = packet.assembly_data() {
                        let mut info = AssemblyInfo::new(name, base_address, size);
                        info.path = path;
                        assemblies.push(info);
                    }
                }
                PacketId::EnumerationComplete => {
                    let count = packet.enumeration_count().unwrap_or(0);
                    println!("Enumeration complete: {} assemblies", count);
                }
                PacketId::Fatal => {
                    let msg = packet.message();
                    return Err(netdumper_shared::Error::Other(format!("Fatal: {}", msg)));
                }
                _ => {}
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    // Drain remaining messages (including assembly packets)
    while let Some(packet) = ipc.try_read() {
        match packet.id() {
            PacketId::Log => {
                let level = packet.log_level().unwrap_or(LogLevel::Info);
                let msg = packet.message();
                match level {
                    LogLevel::Debug => println!("[DEBUG] {}", msg),
                    LogLevel::Info => println!("[INFO] {}", msg),
                    LogLevel::Warning => println!("[WARN] {}", msg),
                    LogLevel::Error => eprintln!("[ERROR] {}", msg),
                }
            }
            PacketId::Assembly => {
                if let Some((name, path, base_address, size)) = packet.assembly_data() {
                    let mut info = AssemblyInfo::new(name, base_address, size);
                    info.path = path;
                    assemblies.push(info);
                }
            }
            PacketId::EnumerationComplete => {
                let count = packet.enumeration_count().unwrap_or(0);
                println!("Enumeration complete: {} assemblies", count);
            }
            PacketId::Fatal => {
                eprintln!("[FATAL] {}", packet.message());
            }
            _ => {}
        }
    }

    // Print results
    println!("\n=== Loaded Assemblies ({}) ===\n", assemblies.len());
    for asm in &assemblies {
        println!("  {} ", asm.name);
        if asm.base_address != 0 {
            println!("    Base: 0x{:X}", asm.base_address);
        }
        if asm.size != 0 {
            println!("    Size: 0x{:X}", asm.size);
        }
        if let Some(path) = &asm.path {
            println!("    Path: {}", path);
        }
        println!();
    }

    Ok(())
}

fn process_messages(ipc: &mut IpcHost) {
    while let Some(packet) = ipc.try_read() {
        match packet.id() {
            PacketId::Log => {
                let level = packet.log_level().unwrap_or(LogLevel::Info);
                let msg = packet.message();
                match level {
                    LogLevel::Debug => println!("[DEBUG] {}", msg),
                    LogLevel::Info => println!("[INFO] {}", msg),
                    LogLevel::Warning => println!("[WARN] {}", msg),
                    LogLevel::Error => eprintln!("[ERROR] {}", msg),
                }
            }
            PacketId::Fatal => {
                eprintln!("[FATAL] {}", packet.message());
            }
            _ => {}
        }
    }
}
