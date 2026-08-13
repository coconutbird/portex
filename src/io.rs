//! Sequential streams and positional image readers.
//!
//! [`nostdio`] supplies `no_std`-capable sequential [`Read`], [`Write`], and
//! [`Seek`] traits. Portex's [`ReadAt`] trait remains positional so mapped or
//! remote images can be queried without sharing a stream cursor.

pub use nostdio::*;

#[cfg(feature = "std")]
pub use crate::reader::FileReader;
pub use crate::reader::{BaseAddressReader, ReadAt, SeekReader, SliceReader, VecReader};
