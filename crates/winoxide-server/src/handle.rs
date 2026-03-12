//! Handle table — maps integer handles to kernel objects.
//!
//! Each process has its own handle table. Handles are small integers (multiples of 4)
//! that index into a per-process table of object references.

use std::sync::Arc;
use winoxide_types::*;
use winoxide_protocol::ObjHandle;
use crate::object::KernelObject;

/// Entry in the handle table.
#[derive(Debug, Clone)]
struct HandleEntry {
    object: Arc<dyn KernelObject>,
    access: ACCESS_MASK,
    attributes: u32,
}

/// Per-process handle table.
#[derive(Debug)]
pub struct HandleTable {
    entries: Vec<Option<HandleEntry>>,
    /// Next handle value to try (optimization to avoid scanning from 0).
    next_free: usize,
}

/// Handles are multiples of 4 (Windows convention).
const HANDLE_STEP: u32 = 4;

impl HandleTable {
    pub fn new() -> Self {
        Self {
            entries: Vec::with_capacity(64),
            next_free: 0,
        }
    }

    /// Allocate a new handle for the given object.
    pub fn insert(
        &mut self,
        object: Arc<dyn KernelObject>,
        access: ACCESS_MASK,
        attributes: u32,
    ) -> ObjHandle {
        let entry = HandleEntry {
            object,
            access,
            attributes,
        };

        // Try to reuse a freed slot
        for i in self.next_free..self.entries.len() {
            if self.entries[i].is_none() {
                self.entries[i] = Some(entry);
                self.next_free = i + 1;
                return ((i + 1) as u32) * HANDLE_STEP;
            }
        }

        // Append new entry
        let index = self.entries.len();
        self.entries.push(Some(entry));
        self.next_free = index + 1;
        ((index + 1) as u32) * HANDLE_STEP
    }

    /// Look up the object for a handle.
    pub fn get(&self, handle: ObjHandle) -> Option<&Arc<dyn KernelObject>> {
        let index = (handle / HANDLE_STEP) as usize;
        if index == 0 || index > self.entries.len() {
            return None;
        }
        self.entries[index - 1].as_ref().map(|e| &e.object)
    }

    /// Get the access mask for a handle.
    pub fn get_access(&self, handle: ObjHandle) -> Option<ACCESS_MASK> {
        let index = (handle / HANDLE_STEP) as usize;
        if index == 0 || index > self.entries.len() {
            return None;
        }
        self.entries[index - 1].as_ref().map(|e| e.access)
    }

    /// Close a handle, returning the object if it existed.
    pub fn close(&mut self, handle: ObjHandle) -> Option<Arc<dyn KernelObject>> {
        let index = (handle / HANDLE_STEP) as usize;
        if index == 0 || index > self.entries.len() {
            return None;
        }
        let entry = self.entries[index - 1].take();
        if index - 1 < self.next_free {
            self.next_free = index - 1;
        }
        entry.map(|e| {
            e.object.on_close();
            e.object
        })
    }

    /// Number of active handles.
    pub fn count(&self) -> usize {
        self.entries.iter().filter(|e| e.is_some()).count()
    }
}

impl Default for HandleTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::ObjectType;

    #[derive(Debug)]
    struct DummyObj;
    impl KernelObject for DummyObj {
        fn object_type(&self) -> ObjectType {
            ObjectType::Event
        }
    }

    #[test]
    fn test_handle_table_basic() {
        let mut table = HandleTable::new();

        let h1 = table.insert(Arc::new(DummyObj), GENERIC_READ, 0);
        let h2 = table.insert(Arc::new(DummyObj), GENERIC_WRITE, 0);

        assert_eq!(h1, 4);  // first handle = 1 * 4
        assert_eq!(h2, 8);  // second handle = 2 * 4
        assert_eq!(table.count(), 2);

        assert!(table.get(h1).is_some());
        assert!(table.get(h2).is_some());
        assert!(table.get(0).is_none());
        assert!(table.get(12).is_none());
    }

    #[test]
    fn test_handle_close_and_reuse() {
        let mut table = HandleTable::new();

        let h1 = table.insert(Arc::new(DummyObj), GENERIC_READ, 0);
        let h2 = table.insert(Arc::new(DummyObj), GENERIC_READ, 0);

        // Close first handle
        assert!(table.close(h1).is_some());
        assert_eq!(table.count(), 1);
        assert!(table.get(h1).is_none());

        // New handle should reuse the freed slot
        let h3 = table.insert(Arc::new(DummyObj), GENERIC_READ, 0);
        assert_eq!(h3, h1); // reused!
        assert_eq!(table.count(), 2);
    }

    #[test]
    fn test_close_invalid_handle() {
        let mut table = HandleTable::new();
        assert!(table.close(0).is_none());
        assert!(table.close(999).is_none());
    }
}
