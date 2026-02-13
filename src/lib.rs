//! # Portex
//!
//! A self-contained PE (Portable Executable) file reader/writer library.
//!
//! This library provides types and utilities for parsing and manipulating
//! Windows PE files without external dependencies.
//!
//! ## Features
//!
//! - **Multiple loading modes**: Load from files, memory slices, or implement
//!   the `Reader` trait for custom sources (e.g., remote process memory).
//! - **Partial loading**: Use `PEHeaders` to parse just headers without loading
//!   the entire file - ideal for remote process scenarios.
//! - **Self-contained**: All PE structures defined from scratch, no Windows SDK.
//!
//! ## Example
//!
//! ```no_run
//! use portex::{PE, PEHeaders};
//!
//! // Load full PE from file
//! let pe = PE::from_file("example.exe").unwrap();
//! println!("64-bit: {}", pe.is_64bit());
//!
//! // Or just load headers (more efficient for large files)
//! let headers = PEHeaders::from_file("example.dll").unwrap();
//! println!("Entry point: {:#x}", headers.entry_point());
//! ```

pub mod coff;
pub mod data_dir;
pub mod dos;
pub mod error;
pub mod export;
pub mod import;
pub mod layout;
pub mod optional;
pub mod pe;
pub mod reader;
pub mod reloc;
pub mod section;

pub use error::{Error, Result};
pub use export::{ExportAddress, ExportDirectory, ExportTable, ExportedFunction};
pub use import::{ImportDescriptor, ImportTable, ImportThunk, ImportedDll};
pub use layout::LayoutConfig;
pub use pe::{PEHeaders, PE};
pub use reader::{BaseAddressReader, FileReader, Reader, SliceReader, VecReader};
pub use reloc::{RelocationBlock, RelocationEntry, RelocationTable, RelocationType};
pub use section::{Section, SectionHeader};

