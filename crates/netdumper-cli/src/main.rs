mod assembly;
mod dump;
mod error;
mod pe;
mod process;
mod reader;
mod runtime;
mod target;

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
    /// Analyze a dumped assembly file to diagnose metadata issues
    Analyze {
        /// Path to the DLL file to analyze
        path: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::List => {
            println!("Scanning for .NET processes...\n");

            let processes = runtime::list_dotnet_processes();

            if processes.is_empty() {
                println!("No .NET processes found.");
                println!("\nNote: Some processes may require administrator privileges to access.");
            } else {
                println!("{:<8} {:<40} {:<12} INFO", "PID", "NAME", "RUNTIME");
                println!("{}", "-".repeat(80));

                for proc in &processes {
                    let runtime_str = match proc.runtime_type {
                        Some(runtime::RuntimeType::Core) => ".NET Core",
                        Some(runtime::RuntimeType::Framework) => ".NET Fx",
                        Some(runtime::RuntimeType::FrameworkLegacy) => ".NET 2/3.5",
                        None => "Unknown",
                    };

                    let info = if proc.is_embedded_clr {
                        if let Some((major, minor, build, rev)) = proc.clr_version {
                            format!("Single-file ({}.{}.{}.{})", major, minor, build, rev)
                        } else {
                            "Single-file".to_string()
                        }
                    } else {
                        String::new()
                    };

                    println!(
                        "{:<8} {:<40} {:<12} {}",
                        proc.pid,
                        if proc.name.len() > 40 {
                            format!("{}...", &proc.name[..37])
                        } else {
                            proc.name.clone()
                        },
                        runtime_str,
                        info
                    );
                }

                println!("\nTotal: {} .NET process(es)", processes.len());
            }
        }
        Commands::Enum { pid, name } => {
            let target_pid = match resolve_target(pid, name) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };

            match process::enumerate_assemblies_external(target_pid) {
                Ok(assemblies) => {
                    println!("\n=== Loaded Assemblies ({}) ===\n", assemblies.len());
                    for asm in &assemblies {
                        let flags: String = [
                            if asm.is_reflection {
                                Some("Reflection")
                            } else {
                                None
                            },
                            if !asm.is_pe_file { Some("NotPE") } else { None },
                        ]
                        .into_iter()
                        .flatten()
                        .collect::<Vec<_>>()
                        .join(", ");

                        if flags.is_empty() {
                            println!("  {}", asm.name);
                        } else {
                            println!("  {} [{}]", asm.name, flags);
                        }
                        if asm.base_address != 0 {
                            println!("    Base: 0x{:X}", asm.base_address);
                        }
                        if asm.metadata_address != 0 {
                            println!(
                                "    Metadata: 0x{:X} (size: 0x{:X})",
                                asm.metadata_address, asm.metadata_size
                            );
                        }
                        if asm.module_address != 0 {
                            println!("    Module: 0x{:X}", asm.module_address);
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

            match dump::dump_assemblies_external(target_pid, &output_dir) {
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
            let diag_result = runtime::diagnose_process(target_pid);

            // Then try normal detection
            match runtime::find_runtime_directory_by_pid(target_pid) {
                Ok(Some(info)) => {
                    println!("✓ .NET runtime detected!");
                    println!("  Type: {:?}", info.runtime_type);
                    println!("  Directory: {}", info.directory.display());
                    println!("  DAC path: {}", info.dac_path().display());
                    println!("  DAC exists: {}", info.dac_path().exists());

                    // Show embedded CLR info if available
                    if let Ok(ref diag) = diag_result
                        && diag.has_embedded_clr
                    {
                        println!("\n  Embedded CLR: Yes (single-file deployment)");
                        if let Some((major, minor, build, revision)) = diag.embedded_clr_version {
                            println!(
                                "  Embedded CLR version: {}.{}.{}.{}",
                                major, minor, build, revision
                            );
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
        Commands::Analyze { path } => {
            analyze_dump_file(&path);
        }
    }
}

fn analyze_dump_file(path: &str) {
    use crate::pe::{extract_assembly_metadata, extract_assembly_name_from_metadata_debug};

    println!("\n=== Analyzing {} ===\n", path);

    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to read file: {}", e);
            return;
        }
    };

    println!("File size: {} bytes", data.len());

    // Check DOS header
    if data.len() < 64 || data[0] != b'M' || data[1] != b'Z' {
        eprintln!("ERROR: Invalid DOS header (no MZ signature)");
        return;
    }
    println!("✓ DOS header valid (MZ signature)");

    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    println!("  e_lfanew: 0x{:X}", e_lfanew);

    if e_lfanew + 24 > data.len() {
        eprintln!("ERROR: e_lfanew points outside file");
        return;
    }

    // Check PE signature
    if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        eprintln!("ERROR: Invalid PE signature at offset 0x{:X}", e_lfanew);
        return;
    }
    println!("✓ PE signature valid");

    let coff_offset = e_lfanew + 4;
    let num_sections = u16::from_le_bytes([data[coff_offset + 2], data[coff_offset + 3]]);
    let size_of_opt_header =
        u16::from_le_bytes([data[coff_offset + 16], data[coff_offset + 17]]) as usize;

    println!("  Sections: {}", num_sections);
    println!("  Size of optional header: 0x{:X}", size_of_opt_header);

    let opt_offset = coff_offset + 20;
    let magic = u16::from_le_bytes([data[opt_offset], data[opt_offset + 1]]);
    let is_pe32_plus = magic == 0x20b;
    println!(
        "  PE format: {}",
        if is_pe32_plus { "PE32+" } else { "PE32" }
    );

    // Data directories offset
    let data_dir_offset = if is_pe32_plus {
        opt_offset + 112
    } else {
        opt_offset + 96
    };

    // CLI header (data directory 14)
    let cli_dir_offset = data_dir_offset + 14 * 8;
    if cli_dir_offset + 8 > data.len() {
        eprintln!("ERROR: CLI data directory outside file bounds");
        return;
    }

    let cli_rva = u32::from_le_bytes([
        data[cli_dir_offset],
        data[cli_dir_offset + 1],
        data[cli_dir_offset + 2],
        data[cli_dir_offset + 3],
    ]);
    let cli_size = u32::from_le_bytes([
        data[cli_dir_offset + 4],
        data[cli_dir_offset + 5],
        data[cli_dir_offset + 6],
        data[cli_dir_offset + 7],
    ]);

    println!("\nCLI Header:");
    println!("  RVA: 0x{:X}", cli_rva);
    println!("  Size: 0x{:X}", cli_size);

    if cli_rva == 0 {
        eprintln!("ERROR: No CLI header (not a .NET assembly or CLI RVA is 0)");
        return;
    }

    // Parse section headers to find CLI header file offset
    let section_table_offset = coff_offset + 20 + size_of_opt_header;
    println!("\nSections:");

    let mut cli_file_offset: Option<usize> = None;
    for i in 0..num_sections as usize {
        let sec_off = section_table_offset + i * 40;
        if sec_off + 40 > data.len() {
            break;
        }

        let name_bytes = &data[sec_off..sec_off + 8];
        let name = String::from_utf8_lossy(name_bytes)
            .trim_end_matches('\0')
            .to_string();

        let virt_size = u32::from_le_bytes([
            data[sec_off + 8],
            data[sec_off + 9],
            data[sec_off + 10],
            data[sec_off + 11],
        ]);
        let virt_addr = u32::from_le_bytes([
            data[sec_off + 12],
            data[sec_off + 13],
            data[sec_off + 14],
            data[sec_off + 15],
        ]);
        let raw_size = u32::from_le_bytes([
            data[sec_off + 16],
            data[sec_off + 17],
            data[sec_off + 18],
            data[sec_off + 19],
        ]);
        let raw_ptr = u32::from_le_bytes([
            data[sec_off + 20],
            data[sec_off + 21],
            data[sec_off + 22],
            data[sec_off + 23],
        ]);

        println!(
            "  {}: VA=0x{:X} VS=0x{:X} RawPtr=0x{:X} RawSize=0x{:X}",
            name, virt_addr, virt_size, raw_ptr, raw_size
        );

        // Check if CLI header RVA falls in this section
        if cli_rva >= virt_addr && cli_rva < virt_addr + virt_size {
            cli_file_offset = Some((raw_ptr + (cli_rva - virt_addr)) as usize);
        }
    }

    let cli_offset = match cli_file_offset {
        Some(off) => off,
        None => {
            eprintln!("ERROR: Could not resolve CLI RVA to file offset");
            return;
        }
    };

    println!("\nCLI header file offset: 0x{:X}", cli_offset);

    if cli_offset + 72 > data.len() {
        eprintln!("ERROR: CLI header extends beyond file");
        return;
    }

    // Show raw CLI header bytes
    println!("  Raw CLI header (first 72 bytes):");
    for row in 0..3 {
        let start = cli_offset + row * 24;
        let hex: Vec<String> = data[start..start + 24]
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect();
        println!("    {:04X}: {}", start, hex.join(" "));
    }

    // Read metadata RVA from CLI header
    let meta_rva = u32::from_le_bytes([
        data[cli_offset + 8],
        data[cli_offset + 9],
        data[cli_offset + 10],
        data[cli_offset + 11],
    ]);
    let meta_size = u32::from_le_bytes([
        data[cli_offset + 12],
        data[cli_offset + 13],
        data[cli_offset + 14],
        data[cli_offset + 15],
    ]);

    println!("\nMetadata:");
    println!("  RVA: 0x{:X}", meta_rva);
    println!("  Size: 0x{:X}", meta_size);

    if meta_rva == 0 || meta_size == 0 {
        eprintln!("ERROR: No metadata (RVA or size is 0)");
        return;
    }

    // Find metadata file offset
    let mut meta_file_offset: Option<usize> = None;
    for i in 0..num_sections as usize {
        let sec_off = section_table_offset + i * 40;
        if sec_off + 40 > data.len() {
            break;
        }

        let virt_size = u32::from_le_bytes([
            data[sec_off + 8],
            data[sec_off + 9],
            data[sec_off + 10],
            data[sec_off + 11],
        ]);
        let virt_addr = u32::from_le_bytes([
            data[sec_off + 12],
            data[sec_off + 13],
            data[sec_off + 14],
            data[sec_off + 15],
        ]);
        let raw_ptr = u32::from_le_bytes([
            data[sec_off + 20],
            data[sec_off + 21],
            data[sec_off + 22],
            data[sec_off + 23],
        ]);

        if meta_rva >= virt_addr && meta_rva < virt_addr + virt_size {
            meta_file_offset = Some((raw_ptr + (meta_rva - virt_addr)) as usize);
        }
    }

    let meta_offset = match meta_file_offset {
        Some(off) => off,
        None => {
            eprintln!("ERROR: Could not resolve metadata RVA to file offset");
            return;
        }
    };

    println!("  File offset: 0x{:X}", meta_offset);

    if meta_offset + meta_size as usize > data.len() {
        eprintln!(
            "ERROR: Metadata extends beyond file (offset 0x{:X} + size 0x{:X} = 0x{:X}, file len = 0x{:X})",
            meta_offset,
            meta_size,
            meta_offset + meta_size as usize,
            data.len()
        );
        return;
    }

    // Check BSJB signature
    let bsjb = &data[meta_offset..meta_offset + 4];
    if bsjb == [0x42, 0x53, 0x4A, 0x42] {
        println!("✓ BSJB signature found");
    } else {
        eprintln!(
            "ERROR: No BSJB signature at offset 0x{:X}. Found: {:02X} {:02X} {:02X} {:02X}",
            meta_offset, bsjb[0], bsjb[1], bsjb[2], bsjb[3]
        );
        return;
    }

    // Try full extraction
    match extract_assembly_name_from_metadata_debug(&data) {
        Ok(name) => println!("\n✓ Assembly name: {}", name),
        Err(e) => eprintln!("\nERROR: Metadata extraction failed: {:?}", e),
    }

    // Extract and display full assembly metadata
    println!("\nAssembly Metadata:");
    match extract_assembly_metadata(&data) {
        Some(meta) => {
            println!("  Name: {}", meta.name);
            println!("  Version: {}", meta.version_string());
            println!(
                "  Culture: {}",
                if meta.culture.is_empty() {
                    "neutral"
                } else {
                    &meta.culture
                }
            );
            println!(
                "  PublicKeyToken: {}",
                meta.public_key_token.as_deref().unwrap_or("null")
            );
            if let Some(pk) = &meta.public_key {
                if pk.len() <= 64 {
                    println!("  PublicKey: {}", pk);
                } else {
                    println!("  PublicKey: {}... ({} bytes)", &pk[..64], pk.len() / 2);
                }
            }
            println!("  Flags: 0x{:08X}", meta.flags);
            println!("\n  Full Name: {}", meta.full_name());
        }
        None => {
            println!("  (Could not extract - may be a netmodule or corrupted)");
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
