//! PE/COFF executable parser and loader.
//!
//! Parses Windows PE (Portable Executable) files — .exe and .dll.
//! Handles: DOS header, NT headers, sections, imports, exports, relocations.

pub mod header;
pub mod parser;
pub mod imports;
pub mod exports;
pub mod relocations;
pub mod loader;
