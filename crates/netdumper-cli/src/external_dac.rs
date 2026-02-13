//! External DAC enumeration - reads target process memory via ReadProcessMemory.
//!
//! This allows enumerating .NET assemblies without injecting any code.
//! This module is a thin wrapper around the shared DAC implementation.

use netdumper_shared::{AssemblyInfo, Result, enumerate_assemblies_external};

/// Enumerate assemblies from an external process using DAC
pub fn enumerate_external(pid: u32) -> Result<Vec<AssemblyInfo>> {
    println!(
        "Enumerating assemblies from process {} (external mode)...",
        pid
    );
    enumerate_assemblies_external(pid)
}
