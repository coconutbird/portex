//! Main PE file structure and parsing.
//!
//! This module provides the main [`PeImage`] and [`PeHeaders`] types for reading,
//! modifying, and writing Windows PE (Portable Executable) files.
//!
//! # Examples
//!
//! ## Loading and inspecting a PE file
//!
//! ```no_run
//! use portex::PeImage;
//!
//! # let file_bytes: &[u8] = &[];
//! let pe = PeImage::parse(file_bytes)?;
//!
//! // Check architecture
//! println!("64-bit: {}", pe.is_64bit());
//! println!("Entry point: {:#x}", pe.entry_point());
//! println!("Image base: {:#x}", pe.image_base());
//!
//! // List sections
//! for section in &pe.sections {
//!     println!("Section: {} (RVA: {:#x}, size: {})",
//!         section.name(),
//!         section.header.virtual_address,
//!         section.data.len());
//! }
//! # Ok::<(), portex::Error>(())
//! ```
//!
//! ## Loading just headers (efficient for large files)
//!
//! ```no_run
//! use portex::PeHeaders;
//!
//! # let file_bytes: &[u8] = &[];
//! // Just headers, no section data
//! let headers = PeHeaders::from_slice(file_bytes)?;
//! println!("Entry point: {:#x}", headers.entry_point());
//! println!("Number of sections: {}", headers.section_headers.len());
//! # Ok::<(), portex::Error>(())
//! ```
//!
//! ## Modifying and writing a PE file
//!
//! ```no_run
//! use portex::PeImage;
//!
//! # let file_bytes: &[u8] = &[];
//! let mut pe = PeImage::parse(file_bytes)?;
//!
//! // Modify entry point (access inner header directly)
//! match &mut pe.optional_header {
//!     portex::optional::OptionalHeader::Pe32(h) => h.address_of_entry_point = 0x1000,
//!     portex::optional::OptionalHeader::Pe32Plus(h) => h.address_of_entry_point = 0x1000,
//! }
//!
//! let rebuilt = pe.try_build()?;
//! assert!(!rebuilt.is_empty());
//! # Ok::<(), portex::Error>(())
//! ```

use crate::coff::{CoffHeader, PE_SIGNATURE, verify_pe_signature};
use crate::dos::DosHeader;
use crate::layout::{self, LayoutConfig};
use crate::optional::OptionalHeader;
use crate::prelude::*;
use crate::reader::{ReadAt, SliceReader};
use crate::section::{Section, SectionHeader};
use crate::{Error, Result};

#[cfg(feature = "std")]
use crate::reader::FileReader;
#[cfg(feature = "std")]
use std::fs::File;
#[cfg(feature = "std")]
use std::io::Write;
#[cfg(feature = "std")]
use std::path::Path;

/// Describes how PE bytes are laid out in their source.
///
/// Raw PE files store section payloads at [`SectionHeader::pointer_to_raw_data`],
/// while images mapped by a loader store them at their RVA
/// ([`SectionHeader::virtual_address`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SourceLayout {
    /// Raw file layout, as stored on disk or in a byte-for-byte file buffer.
    #[default]
    File,
    /// Loader-mapped image layout, where an RVA is an offset from the image base.
    Mapped,
}

/// Policy for section bytes that cannot be read from the source.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MissingSectionData {
    /// Reject truncated or unreadable section ranges.
    #[default]
    Error,
    /// Keep the section header and represent unavailable bytes as empty data.
    ///
    /// This is useful for remote mapped images where discardable pages may no
    /// longer be committed.
    Empty,
}

/// Options for parsing a PE image from an arbitrary byte source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseOptions {
    /// How RVAs map into the source.
    pub layout: SourceLayout,
    /// How unreadable section ranges are handled.
    pub missing_section_data: MissingSectionData,
    /// Actual load base for a relocated mapped image.
    pub runtime_image_base: Option<u64>,
}

impl ParseOptions {
    /// Strict raw-file parsing.
    pub const fn file() -> Self {
        Self {
            layout: SourceLayout::File,
            missing_section_data: MissingSectionData::Error,
            runtime_image_base: None,
        }
    }

    /// Strict loader-mapped image parsing.
    pub const fn mapped() -> Self {
        Self {
            layout: SourceLayout::Mapped,
            missing_section_data: MissingSectionData::Error,
            runtime_image_base: None,
        }
    }

    /// Allow section ranges that are absent from the source.
    pub const fn allow_missing_section_data(mut self) -> Self {
        self.missing_section_data = MissingSectionData::Empty;
        self
    }

    /// Record the actual base address of a relocated mapped image.
    pub const fn runtime_image_base(mut self, image_base: u64) -> Self {
        self.runtime_image_base = Some(image_base);
        self
    }
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self::file()
    }
}

/// Maximum number of sections accepted by the Windows image loader.
pub const MAX_NUMBER_OF_SECTIONS: usize = 96;

/// A parsed PE file with owned section data.
/// This is the main type for reading, modifying, and writing PE files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeImage {
    /// DOS header.
    pub dos_header: DosHeader,
    /// DOS stub (data between DOS header and PE signature).
    pub dos_stub: Vec<u8>,
    /// COFF file header.
    pub coff_header: CoffHeader,
    /// Optional header (PE32 or PE32+).
    pub optional_header: OptionalHeader,
    /// Sections with owned data.
    pub sections: Vec<Section>,
    pub(crate) source_layout: SourceLayout,
    pub(crate) runtime_image_base: Option<u64>,
}

/// Partial PE headers - just the headers without section data.
/// Useful for remote process scenarios or when you only need header info.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeHeaders {
    /// DOS header.
    pub dos_header: DosHeader,
    /// COFF file header.
    pub coff_header: CoffHeader,
    /// Optional header (PE32 or PE32+).
    pub optional_header: OptionalHeader,
    /// Section headers (no data).
    pub section_headers: Vec<SectionHeader>,
    /// Offset where PE signature was found.
    pub pe_offset: u64,
}

mod build;
mod directories_data;
mod directories_runtime;
mod edit;
mod headers;
mod inspect;
mod parse;
mod utilities;
mod validate;
