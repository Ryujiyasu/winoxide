//! CRT initialization and process startup.
//!
//! In MSVC, the actual entry point is not main() but rather _mainCRTStartup
//! or _wmainCRTStartup, which initializes the CRT and then calls main().

/// CRT initialization state.
pub struct CrtState {
    pub initialized: bool,
    pub argc: i32,
    pub argv: Vec<String>,
}

impl CrtState {
    pub fn new() -> Self {
        Self {
            initialized: false,
            argc: 0,
            argv: Vec::new(),
        }
    }

    /// Initialize the CRT with command-line arguments.
    pub fn initialize(&mut self, args: Vec<String>) {
        self.argc = args.len() as i32;
        self.argv = args;
        self.initialized = true;
    }

    /// _acmdln — get the command line as a single string.
    pub fn get_command_line(&self) -> String {
        self.argv.join(" ")
    }
}

impl Default for CrtState {
    fn default() -> Self {
        Self::new()
    }
}

/// __getmainargs — MSVC CRT function to retrieve argc/argv.
pub fn __getmainargs(
    state: &CrtState,
    argc: &mut i32,
    argv: &mut Vec<*const u8>,
) {
    *argc = state.argc;
    argv.clear();
    for arg in &state.argv {
        argv.push(arg.as_ptr());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crt_init() {
        let mut crt = CrtState::new();
        assert!(!crt.initialized);

        crt.initialize(vec!["test.exe".to_string(), "--flag".to_string()]);
        assert!(crt.initialized);
        assert_eq!(crt.argc, 2);
        assert_eq!(crt.get_command_line(), "test.exe --flag");
    }
}
