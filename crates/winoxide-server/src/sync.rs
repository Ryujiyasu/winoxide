//! Synchronization primitives — Event, Mutex, Semaphore.

use std::collections::VecDeque;
use winoxide_types::*;
use crate::object::{KernelObject, ObjectType};

// ============================================================
// Event
// ============================================================

/// NT Event object — can be manual-reset or auto-reset.
#[derive(Debug)]
pub struct Event {
    pub manual_reset: bool,
    pub signaled: bool,
}

impl Event {
    pub fn new(manual_reset: bool, initial_state: bool) -> Self {
        Self {
            manual_reset,
            signaled: initial_state,
        }
    }

    pub fn set(&mut self) {
        self.signaled = true;
    }

    pub fn reset(&mut self) {
        self.signaled = false;
    }

    pub fn pulse(&mut self) {
        self.signaled = true;
        // In a real implementation, wake waiting threads here
        if self.manual_reset {
            self.signaled = false;
        }
    }
}

impl KernelObject for std::sync::Mutex<Event> {
    fn object_type(&self) -> ObjectType {
        ObjectType::Event
    }

    fn is_signaled(&self) -> bool {
        self.lock().unwrap().signaled
    }

    fn satisfy_wait(&self) -> NTSTATUS {
        let mut event = self.lock().unwrap();
        if !event.manual_reset {
            event.signaled = false; // auto-reset
        }
        STATUS_SUCCESS
    }
}

// ============================================================
// Mutex (Mutant in NT terminology)
// ============================================================

/// NT Mutex (Mutant) object.
#[derive(Debug)]
pub struct Mutant {
    /// Owner thread ID (0 = not owned).
    pub owner_tid: u32,
    /// Recursion count.
    pub count: u32,
    /// Whether the mutex was abandoned by a terminated thread.
    pub abandoned: bool,
}

impl Mutant {
    pub fn new(owned: bool, owner_tid: u32) -> Self {
        Self {
            owner_tid: if owned { owner_tid } else { 0 },
            count: if owned { 1 } else { 0 },
            abandoned: false,
        }
    }

    /// Acquire the mutex for the given thread.
    pub fn acquire(&mut self, tid: u32) -> NTSTATUS {
        if self.owner_tid == 0 {
            self.owner_tid = tid;
            self.count = 1;
            STATUS_SUCCESS
        } else if self.owner_tid == tid {
            self.count += 1;
            STATUS_SUCCESS
        } else {
            STATUS_UNSUCCESSFUL // should not be called if not signaled
        }
    }

    /// Release the mutex.
    pub fn release(&mut self, tid: u32) -> Result<u32, NTSTATUS> {
        if self.owner_tid != tid {
            return Err(STATUS_MUTANT_NOT_OWNED);
        }
        self.count -= 1;
        let prev = self.count + 1;
        if self.count == 0 {
            self.owner_tid = 0;
        }
        Ok(prev)
    }
}

/// STATUS_MUTANT_NOT_OWNED
const STATUS_MUTANT_NOT_OWNED: NTSTATUS = 0xC0000046_u32 as i32;

impl KernelObject for std::sync::Mutex<Mutant> {
    fn object_type(&self) -> ObjectType {
        ObjectType::Mutex
    }

    fn is_signaled(&self) -> bool {
        self.lock().unwrap().owner_tid == 0
    }

    fn satisfy_wait(&self) -> NTSTATUS {
        // Caller must set owner after wait is satisfied
        STATUS_SUCCESS
    }
}

// ============================================================
// Semaphore
// ============================================================

/// NT Semaphore object.
#[derive(Debug)]
pub struct Semaphore {
    pub count: i32,
    pub max_count: i32,
}

impl Semaphore {
    pub fn new(initial: i32, max: i32) -> Self {
        Self {
            count: initial,
            max_count: max,
        }
    }

    /// Release (increment) the semaphore.
    pub fn release(&mut self, count: i32) -> Result<i32, NTSTATUS> {
        let prev = self.count;
        let new_count = self.count.checked_add(count).ok_or(STATUS_INVALID_PARAMETER)?;
        if new_count > self.max_count {
            return Err(STATUS_SEMAPHORE_LIMIT_EXCEEDED);
        }
        self.count = new_count;
        Ok(prev)
    }
}

const STATUS_SEMAPHORE_LIMIT_EXCEEDED: NTSTATUS = 0xC0000045_u32 as i32;

impl KernelObject for std::sync::Mutex<Semaphore> {
    fn object_type(&self) -> ObjectType {
        ObjectType::Semaphore
    }

    fn is_signaled(&self) -> bool {
        self.lock().unwrap().count > 0
    }

    fn satisfy_wait(&self) -> NTSTATUS {
        let mut sem = self.lock().unwrap();
        if sem.count > 0 {
            sem.count -= 1;
            STATUS_SUCCESS
        } else {
            STATUS_UNSUCCESSFUL
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_manual_reset() {
        let mut event = Event::new(true, false);
        assert!(!event.signaled);
        event.set();
        assert!(event.signaled);
        // Manual reset: signaled state persists until explicit reset
        event.reset();
        assert!(!event.signaled);
    }

    #[test]
    fn test_event_auto_reset() {
        let event = std::sync::Mutex::new(Event::new(false, true));
        assert!(event.is_signaled());
        // Auto-reset: satisfy_wait clears the signal
        event.satisfy_wait();
        assert!(!event.is_signaled());
    }

    #[test]
    fn test_mutant_acquire_release() {
        let mut m = Mutant::new(false, 0);
        assert_eq!(m.owner_tid, 0);

        // Acquire
        assert_eq!(m.acquire(42), STATUS_SUCCESS);
        assert_eq!(m.owner_tid, 42);
        assert_eq!(m.count, 1);

        // Recursive acquire
        assert_eq!(m.acquire(42), STATUS_SUCCESS);
        assert_eq!(m.count, 2);

        // Release
        assert_eq!(m.release(42), Ok(2));
        assert_eq!(m.count, 1);
        assert_eq!(m.release(42), Ok(1));
        assert_eq!(m.count, 0);
        assert_eq!(m.owner_tid, 0);
    }

    #[test]
    fn test_mutant_wrong_thread() {
        let mut m = Mutant::new(true, 1);
        assert!(m.release(2).is_err());
    }

    #[test]
    fn test_semaphore_basic() {
        let mut sem = Semaphore::new(2, 5);
        assert_eq!(sem.count, 2);

        // Release
        assert_eq!(sem.release(2), Ok(2));
        assert_eq!(sem.count, 4);

        // Exceed max
        assert!(sem.release(2).is_err());
    }

    #[test]
    fn test_semaphore_wait() {
        let sem = std::sync::Mutex::new(Semaphore::new(1, 10));
        assert!(sem.is_signaled());
        sem.satisfy_wait();
        assert!(!sem.is_signaled());
    }
}
