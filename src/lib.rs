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
//! ## Architecture
//!
//! ### Parsing Patterns
//!
//! The library uses a consistent two-tier parsing pattern:
//!
//! 1. **Raw structures** use `parse(&[u8])` for parsing contiguous binary data:
//!    - `ImportDescriptor::parse(&[u8])`, `TlsDirectory::parse(&[u8], is_64bit)`
//!    - These parse a single fixed-size structure from a byte slice
//!
//! 2. **High-level tables** use `parse(rva, ..., read_fn)` for following RVA pointers:
//!    - `ImportTable::parse(rva, is_64bit, read_fn)`, `ResourceDirectory::parse(rva, size, read_fn)`
//!    - The `read_fn` closure enables reading from multiple locations (RVA resolution)
//!
//! ### Builder Pattern
//!
//! All builders (`ImportTableBuilder`, `ExportTableBuilder`, `ResourceBuilder`, etc.) use
//! immutable `build(&self)` methods that return serialized bytes without mutating the builder.
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

pub mod bound_import;
pub mod checksum;
pub mod clr;
pub mod coff;
pub mod data_dir;
pub mod debug;
pub mod delay_import;
pub mod dos;
pub mod error;
pub mod exception;
pub mod export;
pub mod import;
pub mod layout;
pub mod loadconfig;
pub mod optional;
pub mod pe;
pub mod reader;
pub mod reloc;
pub mod resource;
pub mod rich;
pub mod section;
pub mod security;
pub mod tls;
pub mod validation;

pub use bound_import::{
    BoundForwarderRef, BoundImportBuilder, BoundImportDescriptor, BoundImportDirectory,
};
pub use checksum::{calculate_checksum, checksum_field_offset, compute_pe_checksum};
pub use clr::CliHeader;
pub use data_dir::{DataDirectory, DataDirectoryType};
pub use debug::{CodeViewRsds, DebugDirectory, DebugInfo, DebugType};
pub use delay_import::{
    DelayImportBuilder, DelayImportDirectory, DelayImportThunk, DelayLoadDescriptor, DelayLoadedDll,
};
pub use error::{Error, Result};
pub use exception::{ExceptionDirectory, RuntimeFunction, UnwindCode, UnwindInfo, UnwindOpCode};
pub use export::{
    ExportAddress, ExportDirectory, ExportTable, ExportTableBuilder, ExportedFunction,
};
pub use import::{ImportDescriptor, ImportTable, ImportTableBuilder, ImportThunk, ImportedDll};
pub use layout::LayoutConfig;
pub use loadconfig::{LoadConfigDirectory, LoadConfigDirectory32, LoadConfigDirectory64};
pub use pe::{PE, PEHeaders};
pub use reader::{BaseAddressReader, FileReader, Reader, SliceReader, VecReader};
pub use reloc::{RelocationBlock, RelocationEntry, RelocationTable, RelocationType};
pub use resource::{
    Resource, ResourceBuilder, ResourceDirectory, ResourceEntry, ResourceId, ResourceType,
};
pub use rich::{RichEntry, RichHeader};
pub use section::{Section, SectionHeader};
pub use security::{
    Certificate, CertificateRevision, CertificateType, SecurityBuilder, SecurityDirectory,
};
pub use tls::{TlsDirectory, TlsDirectory32, TlsDirectory64, TlsInfo};
pub use validation::{ValidationCode, ValidationIssue, ValidationLevel, ValidationResult};
