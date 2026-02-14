//! Error types for PE parsing and writing.
//!
//! Errors include context information (file offset, RVA, structure name) to help
//! diagnose issues when parsing or writing PE files.
//!
//! # Example
//!
//! ```no_run
//! use portex::{PE, Error};
//!
//! match PE::from_file("test.exe") {
//!     Ok(pe) => println!("Loaded PE"),
//!     Err(e) => {
//!         eprintln!("Error: {}", e);
//!         if let Some(ctx) = e.context() {
//!             eprintln!("  Context: {}", ctx);
//!         }
//!     }
//! }
//! ```

use std::fmt;
use std::io;

/// Result type alias for portex operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Context information about where an error occurred.
#[derive(Debug, Clone)]
pub struct ErrorContext {
    /// File offset where the error occurred (if known).
    pub file_offset: Option<u64>,
    /// RVA where the error occurred (if known).
    pub rva: Option<u32>,
    /// Name of the structure being parsed (if known).
    pub structure: Option<String>,
    /// Additional details about the error.
    pub details: Option<String>,
}

impl ErrorContext {
    /// Create an empty context.
    pub fn new() -> Self {
        Self {
            file_offset: None,
            rva: None,
            structure: None,
            details: None,
        }
    }

    /// Set the file offset.
    pub fn at_offset(mut self, offset: u64) -> Self {
        self.file_offset = Some(offset);
        self
    }

    /// Set the RVA.
    pub fn at_rva(mut self, rva: u32) -> Self {
        self.rva = Some(rva);
        self
    }

    /// Set the structure name.
    pub fn in_structure(mut self, name: impl Into<String>) -> Self {
        self.structure = Some(name.into());
        self
    }

    /// Set additional details.
    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }

    /// Check if context has any information.
    pub fn is_empty(&self) -> bool {
        self.file_offset.is_none()
            && self.rva.is_none()
            && self.structure.is_none()
            && self.details.is_none()
    }
}

impl Default for ErrorContext {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ErrorContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        if let Some(offset) = self.file_offset {
            parts.push(format!("offset {:#x}", offset));
        }
        if let Some(rva) = self.rva {
            parts.push(format!("RVA {:#x}", rva));
        }
        if let Some(ref structure) = self.structure {
            parts.push(format!("in {}", structure));
        }
        if let Some(ref details) = self.details {
            parts.push(details.clone());
        }
        write!(f, "{}", parts.join(", "))
    }
}

/// Errors that can occur during PE parsing or writing.
#[derive(Debug)]
pub struct Error {
    /// The error kind.
    pub kind: ErrorKind,
    /// Optional context about where the error occurred.
    pub context: Option<ErrorContext>,
}

/// The kind of error that occurred.
#[derive(Debug)]
#[non_exhaustive]
pub enum ErrorKind {
    /// I/O error during read/write operations.
    Io(io::Error),
    /// Invalid DOS signature (expected "MZ").
    InvalidDosSignature,
    /// Invalid PE signature (expected "PE\0\0").
    InvalidPeSignature,
    /// Invalid or unsupported machine type.
    InvalidMachineType(u16),
    /// Invalid optional header magic.
    InvalidOptionalHeaderMagic(u16),
    /// Buffer too small to contain expected data.
    BufferTooSmall { expected: usize, actual: usize },
    /// Invalid section data.
    InvalidSection(String),
    /// Invalid data directory.
    InvalidDataDirectory(String),
    /// Offset out of bounds.
    OffsetOutOfBounds { offset: usize, size: usize },
    /// Invalid RVA (could not read at address).
    InvalidRva(u32),
    /// Invalid UTF-8 string.
    InvalidUtf8,
}

impl Error {
    /// Create a new error with the given kind.
    pub fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            context: None,
        }
    }

    /// Add context to this error.
    pub fn with_context(mut self, context: ErrorContext) -> Self {
        self.context = Some(context);
        self
    }

    /// Add file offset context.
    pub fn at_offset(mut self, offset: u64) -> Self {
        let ctx = self.context.take().unwrap_or_default();
        self.context = Some(ctx.at_offset(offset));
        self
    }

    /// Add RVA context.
    pub fn at_rva(mut self, rva: u32) -> Self {
        let ctx = self.context.take().unwrap_or_default();
        self.context = Some(ctx.at_rva(rva));
        self
    }

    /// Add structure name context.
    pub fn in_structure(mut self, name: impl Into<String>) -> Self {
        let ctx = self.context.take().unwrap_or_default();
        self.context = Some(ctx.in_structure(name));
        self
    }

    /// Get the context if present.
    pub fn context(&self) -> Option<&ErrorContext> {
        self.context.as_ref()
    }

    /// Get the error kind.
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    // Convenience constructors for common errors

    /// Create an InvalidDosSignature error.
    pub fn invalid_dos_signature() -> Self {
        Self::new(ErrorKind::InvalidDosSignature)
    }

    /// Create an InvalidPeSignature error.
    pub fn invalid_pe_signature() -> Self {
        Self::new(ErrorKind::InvalidPeSignature)
    }

    /// Create an InvalidMachineType error.
    pub fn invalid_machine_type(machine: u16) -> Self {
        Self::new(ErrorKind::InvalidMachineType(machine))
    }

    /// Create an InvalidOptionalHeaderMagic error.
    pub fn invalid_optional_header_magic(magic: u16) -> Self {
        Self::new(ErrorKind::InvalidOptionalHeaderMagic(magic))
    }

    /// Create a BufferTooSmall error.
    pub fn buffer_too_small(expected: usize, actual: usize) -> Self {
        Self::new(ErrorKind::BufferTooSmall { expected, actual })
    }

    /// Create an InvalidSection error.
    pub fn invalid_section(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidSection(msg.into()))
    }

    /// Create an InvalidDataDirectory error.
    pub fn invalid_data_directory(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidDataDirectory(msg.into()))
    }

    /// Create an OffsetOutOfBounds error.
    pub fn offset_out_of_bounds(offset: usize, size: usize) -> Self {
        Self::new(ErrorKind::OffsetOutOfBounds { offset, size })
    }

    /// Create an InvalidRva error.
    pub fn invalid_rva(rva: u32) -> Self {
        Self::new(ErrorKind::InvalidRva(rva))
    }

    /// Create an InvalidUtf8 error.
    pub fn invalid_utf8() -> Self {
        Self::new(ErrorKind::InvalidUtf8)
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::Io(e) => write!(f, "I/O error: {e}"),
            ErrorKind::InvalidDosSignature => write!(f, "Invalid DOS signature (expected 'MZ')"),
            ErrorKind::InvalidPeSignature => {
                write!(f, "Invalid PE signature (expected 'PE\\0\\0')")
            }
            ErrorKind::InvalidMachineType(m) => write!(f, "Invalid machine type: {m:#06x}"),
            ErrorKind::InvalidOptionalHeaderMagic(m) => {
                write!(f, "Invalid optional header magic: {m:#06x}")
            }
            ErrorKind::BufferTooSmall { expected, actual } => {
                write!(
                    f,
                    "Buffer too small: expected {expected} bytes, got {actual}"
                )
            }
            ErrorKind::InvalidSection(msg) => write!(f, "Invalid section: {msg}"),
            ErrorKind::InvalidDataDirectory(msg) => write!(f, "Invalid data directory: {msg}"),
            ErrorKind::OffsetOutOfBounds { offset, size } => {
                write!(f, "Offset {offset:#x} out of bounds (size: {size})")
            }
            ErrorKind::InvalidRva(rva) => write!(f, "Invalid RVA: {rva:#x}"),
            ErrorKind::InvalidUtf8 => write!(f, "Invalid UTF-8 string"),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind)?;
        if let Some(ref ctx) = self.context
            && !ctx.is_empty()
        {
            write!(f, " ({})", ctx)?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.kind {
            ErrorKind::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::new(ErrorKind::Io(e))
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self::new(kind)
    }
}
