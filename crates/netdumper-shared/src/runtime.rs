//! Runtime detection and host abstraction.

use crate::{AssemblyInfo, Result};

/// The type of .NET runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeType {
    /// .NET Framework (CLR 2.0/4.0)
    Framework,
    /// .NET Core / .NET 5+
    Core,
}

/// Trait for interacting with a .NET runtime host.
pub trait RuntimeHost {
    /// Get the type of runtime.
    fn runtime_type(&self) -> RuntimeType;

    /// Get the version string of the runtime.
    fn version(&self) -> Result<String>;

    /// Enumerate all loaded assemblies.
    fn enumerate_assemblies(&self) -> Result<Vec<AssemblyInfo>>;

    /// Get assembly by name.
    fn get_assembly(&self, name: &str) -> Result<Option<AssemblyInfo>>;
}
