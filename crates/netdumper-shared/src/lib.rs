//! Shared types and IPC protocol for netdumper
//!
//! Communication between CLI and DLL uses shared memory (file mapping).
//!
//! # Architecture
//!
//! The IPC system uses a ring buffer in shared memory for message passing:
//! - [`IpcHost`] - Created by CLI, owns the shared memory
//! - [`IpcClient`] - Opened by DLL, writes messages to the ring buffer

pub mod assembly;
#[cfg(windows)]
pub mod dac;
#[cfg(windows)]
pub mod dac_enum;
pub mod error;
#[cfg(windows)]
pub mod ipc;
pub mod messages;
pub mod runtime;

pub use assembly::AssemblyInfo;
#[cfg(windows)]
pub use dac::*;
#[cfg(windows)]
pub use dac_enum::{
    CLRDataTarget, enumerate_assemblies_external, enumerate_assemblies_internal,
    find_runtime_directory, find_runtime_directory_by_pid,
};
pub use error::{Error, Result};
#[cfg(windows)]
pub use ipc::*;
pub use messages::*;
pub use runtime::{RuntimeHost, RuntimeType};

/// Shared memory name format - includes PID for uniqueness
pub const SHARED_MEMORY_NAME_PREFIX: &str = "NETDUMPER_IPC_";

/// Size of the shared memory region (32KB)
pub const SHARED_MEMORY_SIZE: usize = 32 * 1024;

/// Magic value to identify valid shared memory ("NETD")
pub const MAGIC: u32 = 0x4E455444;
