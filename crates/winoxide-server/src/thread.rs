//! Thread management.

use winoxide_types::*;
use winoxide_protocol::*;
use crate::object::{KernelObject, ObjectType};

/// Thread state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadState {
    Running,
    Suspended,
    Waiting,
    Terminated,
}

/// Kernel thread object.
#[derive(Debug)]
pub struct Thread {
    pub tid: ThreadId,
    pub pid: ProcessId,
    pub state: ThreadState,
    pub exit_code: i32,
    pub suspend_count: i32,
    pub priority: i32,
    pub base_priority: i32,
}

impl Thread {
    pub fn new(tid: ThreadId, pid: ProcessId) -> Self {
        Self {
            tid,
            pid,
            state: ThreadState::Running,
            exit_code: 0,
            suspend_count: 0,
            priority: 0,
            base_priority: 0,
        }
    }

    pub fn suspend(&mut self) -> i32 {
        let prev = self.suspend_count;
        self.suspend_count += 1;
        if self.state == ThreadState::Running {
            self.state = ThreadState::Suspended;
        }
        prev
    }

    pub fn resume(&mut self) -> i32 {
        let prev = self.suspend_count;
        if self.suspend_count > 0 {
            self.suspend_count -= 1;
            if self.suspend_count == 0 && self.state == ThreadState::Suspended {
                self.state = ThreadState::Running;
            }
        }
        prev
    }

    pub fn terminate(&mut self, exit_code: i32) {
        self.exit_code = exit_code;
        self.state = ThreadState::Terminated;
    }
}

impl KernelObject for std::sync::Mutex<Thread> {
    fn object_type(&self) -> ObjectType {
        ObjectType::Thread
    }

    fn is_signaled(&self) -> bool {
        self.lock().unwrap().state == ThreadState::Terminated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thread_suspend_resume() {
        let mut t = Thread::new(1, 1);
        assert_eq!(t.state, ThreadState::Running);

        assert_eq!(t.suspend(), 0);
        assert_eq!(t.state, ThreadState::Suspended);
        assert_eq!(t.suspend_count, 1);

        assert_eq!(t.suspend(), 1);
        assert_eq!(t.suspend_count, 2);

        assert_eq!(t.resume(), 2);
        assert_eq!(t.state, ThreadState::Suspended); // still suspended (count=1)

        assert_eq!(t.resume(), 1);
        assert_eq!(t.state, ThreadState::Running); // resumed
    }

    #[test]
    fn test_thread_terminate() {
        let thread = std::sync::Mutex::new(Thread::new(1, 1));
        assert!(!thread.is_signaled());
        thread.lock().unwrap().terminate(42);
        assert!(thread.is_signaled());
    }
}
