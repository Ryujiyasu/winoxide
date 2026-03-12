//! Base kernel object system.
//!
//! Every NT kernel object (process, thread, file, event, mutex, semaphore, etc.)
//! inherits from a common base with reference counting, naming, and wait support.

use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use winoxide_types::*;

/// Type tag for kernel objects.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ObjectType {
    Process,
    Thread,
    File,
    Event,
    Mutex,
    Semaphore,
    Timer,
    Section,
    Key, // Registry key
    Directory,
    Token,
    IoCompletion,
}

/// Trait that all kernel objects implement.
pub trait KernelObject: Send + Sync + std::fmt::Debug {
    /// Returns the object type.
    fn object_type(&self) -> ObjectType;

    /// Check if the object is in a signaled state (for wait operations).
    fn is_signaled(&self) -> bool {
        false
    }

    /// Called when a wait on this object is satisfied.
    fn satisfy_wait(&self) -> NTSTATUS {
        STATUS_SUCCESS
    }

    /// Close notification — called when the last handle to this object is closed.
    fn on_close(&self) {}
}

/// Object directory — the kernel namespace.
/// Maps NT object names (e.g., `\BaseNamedObjects\MyEvent`) to objects.
#[derive(Debug)]
pub struct ObjectDirectory {
    entries: Mutex<HashMap<String, Arc<dyn KernelObject>>>,
}

impl ObjectDirectory {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Insert a named object. Returns the previous object if the name was taken.
    pub fn insert(&self, name: String, obj: Arc<dyn KernelObject>) -> Option<Arc<dyn KernelObject>> {
        self.entries.lock().unwrap().insert(name, obj)
    }

    /// Look up an object by name.
    pub fn lookup(&self, name: &str) -> Option<Arc<dyn KernelObject>> {
        self.entries.lock().unwrap().get(name).cloned()
    }

    /// Remove an object by name.
    pub fn remove(&self, name: &str) -> Option<Arc<dyn KernelObject>> {
        self.entries.lock().unwrap().remove(name)
    }
}

impl Default for ObjectDirectory {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct TestObject;

    impl KernelObject for TestObject {
        fn object_type(&self) -> ObjectType {
            ObjectType::Event
        }

        fn is_signaled(&self) -> bool {
            true
        }
    }

    #[test]
    fn test_object_directory() {
        let dir = ObjectDirectory::new();
        let obj = Arc::new(TestObject);

        assert!(dir.lookup("test").is_none());
        dir.insert("test".to_string(), obj.clone());
        assert!(dir.lookup("test").is_some());
        assert_eq!(dir.lookup("test").unwrap().object_type(), ObjectType::Event);

        dir.remove("test");
        assert!(dir.lookup("test").is_none());
    }
}
