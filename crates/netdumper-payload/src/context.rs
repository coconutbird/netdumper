//! Enumeration context for passing IPC and shared state through the call chain.

use netdumper_shared::IpcClient;

/// Context passed through enumeration functions for logging and IPC.
pub struct EnumerationContext<'a> {
    ipc: &'a mut IpcClient,
}

impl<'a> EnumerationContext<'a> {
    /// Create a new context wrapping an IPC client.
    pub fn new(ipc: &'a mut IpcClient) -> Self {
        Self { ipc }
    }

    /// Send a debug message.
    pub fn debug(&mut self, msg: &str) {
        self.ipc.debug(msg);
    }

    /// Send an info message.
    pub fn info(&mut self, msg: &str) {
        self.ipc.info(msg);
    }

    /// Send a warning message.
    pub fn warn(&mut self, msg: &str) {
        self.ipc.warn(msg);
    }

    /// Send an error message.
    pub fn error(&mut self, msg: &str) {
        self.ipc.error(msg);
    }
}
