//! Error types for PE parsing and writing.

use std::fmt;
use std::io;

/// Result type alias for portex operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during PE parsing or writing.
#[derive(Debug)]
pub enum Error {
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

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::InvalidDosSignature => write!(f, "Invalid DOS signature (expected 'MZ')"),
            Error::InvalidPeSignature => write!(f, "Invalid PE signature (expected 'PE\\0\\0')"),
            Error::InvalidMachineType(m) => write!(f, "Invalid machine type: {m:#06x}"),
            Error::InvalidOptionalHeaderMagic(m) => {
                write!(f, "Invalid optional header magic: {m:#06x}")
            }
            Error::BufferTooSmall { expected, actual } => {
                write!(
                    f,
                    "Buffer too small: expected {expected} bytes, got {actual}"
                )
            }
            Error::InvalidSection(msg) => write!(f, "Invalid section: {msg}"),
            Error::InvalidDataDirectory(msg) => write!(f, "Invalid data directory: {msg}"),
            Error::OffsetOutOfBounds { offset, size } => {
                write!(f, "Offset {offset:#x} out of bounds (size: {size})")
            }
            Error::InvalidRva(rva) => write!(f, "Invalid RVA: {rva:#x}"),
            Error::InvalidUtf8 => write!(f, "Invalid UTF-8 string"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}
