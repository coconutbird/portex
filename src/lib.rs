//! # Portex
//!
//! A `no_std`-friendly PE (Portable Executable) image reader/writer library.
//!
//! This library provides types and utilities for parsing and manipulating
//! Windows PE executable images. It distinguishes raw files from loader-mapped
//! memory because their RVA-to-source translations are different.
//!
//! ## Features
//!
//! - **Multiple loading modes**: Load raw files or loader-mapped images from
//!   memory slices, or implement the `ReadAt` trait for custom sources (e.g.,
//!   remote process memory).
//! - **Partial loading**: Use `PeHeaders` to parse just headers without loading
//!   the entire file - ideal for remote process scenarios.
//! - **Self-contained**: All PE structures defined from scratch, no Windows SDK.
//! - **`no_std` mode**: Disable the `std` feature for `no_std + alloc` builds.
//!   The full PE API (parsers, builders, layout, validation, in-memory readers)
//!   stays available. Only entry points that genuinely need `std` —
//!   `PeImage::from_file`, `PeImage::write_to_file`, `PeHeaders::from_file`, the
//!   `FileReader`, and the `std::error::Error` / `From<io::Error>` impls —
//!   compile out.
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
//! use portex::{PeFile, PeHeaders};
//!
//! // PeFile preserves certificates, overlays, and raw file gaps.
//! # let bytes: &[u8] = &[];
//! let file = PeFile::parse(bytes).unwrap();
//! println!("64-bit: {}", file.image().is_64bit());
//!
//! // Or just load headers (more efficient for large files)
//! let headers = PeHeaders::from_slice(bytes).unwrap();
//! println!("Entry point: {:#x}", headers.entry_point());
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

/// Internal prelude — every source file does `use crate::prelude::*;` to pull
/// in the `alloc` types and macros the codebase relies on. Re-exporting them
/// here keeps each module file's import header to a single line and centralises
/// the `no_std`-aware imports so individual modules don't repeat `#[cfg]`
/// blocks. The items are all `alloc` re-exports, so under the `std` feature
/// they shadow identical-typed prelude items harmlessly.
pub(crate) mod prelude {
    pub use alloc::borrow::Cow;
    pub use alloc::collections::BTreeMap;
    pub use alloc::format;
    pub use alloc::string::{String, ToString};
    pub use alloc::vec;
    pub use alloc::vec::Vec;
}

pub mod bound_import;
pub mod builder;
pub mod checksum;
pub mod clr;
pub mod coff;
pub mod data_dir;
pub mod debug;
pub mod delay_import;
pub mod directories;
pub mod dos;
pub mod error;
pub mod exception;
pub mod export;
pub mod headers;
pub mod image;
pub mod import;
pub mod io;
pub mod layout;
pub mod loadconfig;
pub mod optional;
mod parse_utils;
pub mod pe;
pub mod pe_file;
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
pub use builder::PeBuilder;
pub use checksum::{calculate_checksum, checksum_field_offset, compute_pe_checksum};
pub use clr::{CliBuilder, CliHeader};
pub use coff::{CoffHeader, MachineType};
pub use data_dir::{DataDirectory, DataDirectoryType};
pub use debug::{CodeViewRsds, DebugBuilder, DebugDirectory, DebugInfo, DebugType};
pub use delay_import::{
    DelayImportBuilder, DelayImportDirectory, DelayImportThunk, DelayLoadDescriptor, DelayLoadedDll,
};
pub use error::{Error, Result};
pub use exception::{
    ExceptionBuilder, ExceptionDirectory, ExceptionTable, PackedExceptionDirectory,
    PackedRuntimeFunction, RuntimeFunction, UnwindCode, UnwindInfo, UnwindOpCode,
};
pub use export::{
    ExportAddress, ExportDirectory, ExportTable, ExportTableBuilder, ExportedFunction,
};
pub use import::{ImportDescriptor, ImportTable, ImportTableBuilder, ImportThunk, ImportedDll};
pub use layout::LayoutConfig;
pub use loadconfig::{
    LoadConfigBuilder, LoadConfigDirectory, LoadConfigDirectory32, LoadConfigDirectory64,
};
pub use optional::{OptionalHeader, OptionalHeader32, OptionalHeader64, Subsystem};
pub use pe::{MissingSectionData, ParseOptions, PeHeaders, PeImage, SourceLayout};
pub use pe_file::PeFile;
#[cfg(feature = "std")]
pub use reader::FileReader;
pub use reader::{BaseAddressReader, ReadAt, SeekReader, SliceReader, VecReader};
pub use reloc::{
    RelocationBlock, RelocationBuilder, RelocationEntry, RelocationTable, RelocationType,
};
pub use resource::{
    Resource, ResourceBuilder, ResourceDirectory, ResourceEntry, ResourceId, ResourceType,
};
pub use rich::{RichBuilder, RichEntry, RichHeader};
pub use section::{Section, SectionHeader};
pub use security::{
    Certificate, CertificateRevision, CertificateType, SecurityBuilder, SecurityDirectory,
};
pub use tls::{TlsBuilder, TlsDirectory, TlsDirectory32, TlsDirectory64, TlsInfo};
pub use validation::{ValidationCode, ValidationIssue, ValidationLevel, ValidationResult};
