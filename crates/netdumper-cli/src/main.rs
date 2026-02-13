mod assembly;
mod dac;
mod error;

use clap::{Parser, Subcommand};
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::ProcessStatus::{EnumProcesses, GetModuleBaseNameW};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

pub use assembly::AssemblyInfo;
pub use error::{Error, Result};

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
    /// Enumerate assemblies from a process (read-only, no dumping)
    Enum {
        /// Process ID to target
        #[arg(short, long, group = "target")]
        pid: Option<u32>,
        /// Process name to target (e.g., "dnSpy.exe" or "dnSpy")
        #[arg(short, long, group = "target")]
        name: Option<String>,
    },
    /// Dump assemblies from a process to disk
    Dump {
        /// Process ID to target
        #[arg(short, long, group = "target")]
        pid: Option<u32>,
        /// Process name to target (e.g., "dnSpy.exe" or "dnSpy")
        #[arg(short, long, group = "target")]
        name: Option<String>,
        /// Output directory for dumped assemblies (default: ./dump_<pid>)
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Diagnose why .NET detection might be failing for a process
    Diagnose {
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
        Commands::Enum { pid, name } => {
            let target_pid = match resolve_target(pid, name) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };

            match dac::enumerate_assemblies_external(target_pid) {
                Ok(assemblies) => {
                    println!("\n=== Loaded Assemblies ({}) ===\n", assemblies.len());
                    for asm in &assemblies {
                        println!("  {}", asm.name);
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
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Dump { pid, name, output } => {
            let target_pid = match resolve_target(pid, name) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };

            let output_dir = output
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| std::path::PathBuf::from(format!("dump_{}", target_pid)));

            match dac::dump_assemblies_external(target_pid, &output_dir) {
                Ok(results) => {
                    let success_count = results.iter().filter(|r| r.success).count();
                    let fail_count = results.len() - success_count;

                    println!("\n=== Dump Results ===\n");
                    println!(
                        "Total: {} assemblies, {} succeeded, {} failed\n",
                        results.len(),
                        success_count,
                        fail_count
                    );

                    for result in &results {
                        if result.success {
                            println!(
                                "  [OK] {} -> {} ({} bytes)",
                                result.name,
                                result.output_path.display(),
                                result.size
                            );
                        } else {
                            println!(
                                "  [FAIL] {} - {}",
                                result.name,
                                result.error.as_deref().unwrap_or("Unknown error")
                            );
                        }
                    }

                    if success_count > 0 {
                        println!("\nDumped assemblies saved to: {}", output_dir.display());
                    }
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Diagnose { pid, name } => {
            let target_pid = match resolve_target(pid, name) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };

            println!(
                "\n=== .NET Detection Diagnostics for PID {} ===\n",
                target_pid
            );

            // Always run diagnostics first to get embedded CLR info
            let diag_result = dac::diagnose_process(target_pid);

            // Then try normal detection
            match dac::find_runtime_directory_by_pid(target_pid) {
                Ok(Some(info)) => {
                    println!("✓ .NET runtime detected!");
                    println!("  Type: {:?}", info.runtime_type);
                    println!("  Directory: {}", info.directory.display());
                    println!("  DAC path: {}", info.dac_path().display());
                    println!("  DAC exists: {}", info.dac_path().exists());

                    // Show embedded CLR info if available
                    if let Ok(ref diag) = diag_result {
                        if diag.has_embedded_clr {
                            println!("\n  Embedded CLR: Yes (single-file deployment)");
                            if let Some((major, minor, build, revision)) = diag.embedded_clr_version
                            {
                                println!(
                                    "  Embedded CLR version: {}.{}.{}.{}",
                                    major, minor, build, revision
                                );
                            }
                        }
                    }
                }
                Ok(None) => {
                    println!("✗ No .NET runtime detected via standard method\n");

                    // Show diagnostics
                    match diag_result {
                        Ok(diag) => {
                            println!("Executable has CLR header: {}", diag.exe_has_clr_header);
                            println!("Has embedded CLR (single-file): {}", diag.has_embedded_clr);

                            if let Some((major, minor, build, revision)) = diag.embedded_clr_version
                            {
                                println!(
                                    "Embedded CLR version: {}.{}.{}.{}",
                                    major, minor, build, revision
                                );
                            }

                            println!(
                                "\nPotential .NET modules found: {}",
                                diag.potential_dotnet_modules.len()
                            );
                            for m in &diag.potential_dotnet_modules {
                                println!("  - {}", m);
                            }

                            println!("\nTotal modules loaded: {}", diag.modules.len());
                            println!("\nLikely reason for detection failure:");
                            println!("{}", diag.failure_reason);

                            println!("\n--- All loaded modules ---");
                            for m in &diag.modules {
                                println!("  {}", m);
                            }
                        }
                        Err(e) => {
                            eprintln!("Diagnostics failed: {}", e);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error during detection: {}", e);
                }
            }
        }
    }
}

/// Resolve target PID from either --pid or --name
fn resolve_target(pid: Option<u32>, name: Option<String>) -> Result<u32> {
    match (pid, name) {
        (Some(p), _) => Ok(p),
        (None, Some(n)) => find_process_by_name(&n),
        (None, None) => Err(Error::Other("Must specify either --pid or --name".into())),
    }
}

/// Find a process by name, returns the PID
fn find_process_by_name(name: &str) -> Result<u32> {
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

    Err(Error::Other(format!("Process '{}' not found", name)))
}
