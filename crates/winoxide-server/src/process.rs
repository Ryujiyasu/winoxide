//! Process management.

use std::sync::Arc;
use winoxide_types::*;
use winoxide_protocol::*;
use crate::handle::HandleTable;
use crate::object::{KernelObject, ObjectType};

/// Kernel process object.
#[derive(Debug)]
pub struct Process {
    pub pid: ProcessId,
    pub parent_pid: ProcessId,
    pub exit_code: i32,
    pub terminated: bool,
    pub handles: HandleTable,
}

impl Process {
    pub fn new(pid: ProcessId, parent_pid: ProcessId) -> Self {
        Self {
            pid,
            parent_pid,
            exit_code: 0,
            terminated: false,
            handles: HandleTable::new(),
        }
    }

    pub fn terminate(&mut self, exit_code: i32) {
        self.exit_code = exit_code;
        self.terminated = true;
    }
}

impl KernelObject for std::sync::Mutex<Process> {
    fn object_type(&self) -> ObjectType {
        ObjectType::Process
    }

    fn is_signaled(&self) -> bool {
        self.lock().unwrap().terminated
    }
}
