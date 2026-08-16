//! Positional reading traits and implementations for PE data sources.

use crate::prelude::*;
use crate::{Error, Result};
use core::cell::RefCell;
use nostdio::SeekFrom;

#[cfg(feature = "std")]
use std::fs::File;
#[cfg(feature = "std")]
use std::path::Path;

/// Trait for reading bytes from a source (file, memory, remote process, etc.).
///
/// Implement this trait to support reading PE structures from custom sources,
/// such as remote process memory via ReadProcessMemory.
pub trait ReadAt {
    /// Read bytes at the given offset into the buffer.
    /// Returns the number of bytes actually read.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize>;

    /// Get the total size of the source, if known.
    /// Returns None if the size is unknown (e.g., remote process).
    fn size(&self) -> Option<u64>;

    /// Read exact number of bytes at offset, returning error if not enough data.
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let expected = buf.len();
        let mut total = 0usize;

        while total < expected {
            let read_offset = offset
                .checked_add(total as u64)
                .ok_or_else(|| Error::offset_out_of_bounds(usize::MAX, expected))?;
            let count = self.read_at(read_offset, &mut buf[total..])?;
            if count == 0 {
                return Err(Error::buffer_too_small(expected, total));
            }
            if count > expected - total {
                return Err(Error::generic(
                    "ReadAt::read_at reported more bytes than the supplied buffer",
                ));
            }
            total = total
                .checked_add(count)
                .ok_or_else(|| Error::offset_out_of_bounds(usize::MAX, expected))?;
        }

        Ok(())
    }

    /// Read a u16 at the given offset (little-endian).
    fn read_u16_at(&self, offset: u64) -> Result<u16> {
        let mut buf = [0u8; 2];
        self.read_exact_at(offset, &mut buf)?;
        Ok(u16::from_le_bytes(buf))
    }

    /// Read a u32 at the given offset (little-endian).
    fn read_u32_at(&self, offset: u64) -> Result<u32> {
        let mut buf = [0u8; 4];
        self.read_exact_at(offset, &mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    /// Read a u64 at the given offset (little-endian).
    fn read_u64_at(&self, offset: u64) -> Result<u64> {
        let mut buf = [0u8; 8];
        self.read_exact_at(offset, &mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    /// Read an i32 at the given offset (little-endian).
    fn read_i32_at(&self, offset: u64) -> Result<i32> {
        let mut buf = [0u8; 4];
        self.read_exact_at(offset, &mut buf)?;
        Ok(i32::from_le_bytes(buf))
    }

    /// Read a block of bytes at offset, returning owned Vec.
    fn read_bytes_at(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        buf.try_reserve_exact(len)
            .map_err(|_| Error::generic("reader request is too large to allocate"))?;
        buf.resize(len, 0);
        self.read_exact_at(offset, &mut buf)?;
        Ok(buf)
    }
}

/// Adapter from a stateful [`nostdio::Read`] + [`nostdio::Seek`] source to
/// Portex's immutable positional [`ReadAt`] interface.
///
/// The adapter uses interior mutability and is therefore intended for
/// single-threaded access. Implement [`ReadAt`] directly for remote-process or
/// natively positional sources that can support concurrent reads.
pub struct SeekReader<R> {
    inner: RefCell<R>,
    size: Option<u64>,
}

impl<R> SeekReader<R> {
    /// Wrap a seekable stream with an optional known length.
    pub const fn new(inner: R, size: Option<u64>) -> Self {
        Self {
            inner: RefCell::new(inner),
            size,
        }
    }

    /// Consume the adapter and return the wrapped stream.
    pub fn into_inner(self) -> R {
        self.inner.into_inner()
    }

    /// Borrow the wrapped stream mutably without consuming the adapter.
    pub fn get_mut(&mut self) -> &mut R {
        self.inner.get_mut()
    }
}

impl<R: nostdio::Seek> SeekReader<R> {
    /// Discover the stream length while restoring its original position.
    pub fn with_discovered_size(mut inner: R) -> Result<Self> {
        let original = inner.stream_position().map_err(map_nostdio_error)?;
        let size = inner.seek(SeekFrom::End(0)).map_err(map_nostdio_error)?;
        inner
            .seek(SeekFrom::Start(original))
            .map_err(map_nostdio_error)?;
        Ok(Self::new(inner, Some(size)))
    }
}

impl<R: nostdio::Read + nostdio::Seek> ReadAt for SeekReader<R> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let mut inner = self
            .inner
            .try_borrow_mut()
            .map_err(|_| Error::generic("seekable reader is already borrowed"))?;
        inner
            .seek(SeekFrom::Start(offset))
            .map_err(map_nostdio_error)?;
        inner.read(buf).map_err(map_nostdio_error)
    }

    fn size(&self) -> Option<u64> {
        self.size
    }
}

impl<R> core::fmt::Debug for SeekReader<R> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SeekReader")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

pub(crate) fn map_nostdio_error(error: nostdio::IoError) -> Error {
    #[cfg(feature = "std")]
    {
        Error::from(error)
    }
    #[cfg(not(feature = "std"))]
    {
        Error::generic(error.to_string())
    }
}

/// Positional reader for byte slices (in-memory data).
#[derive(Debug, Clone)]
pub struct SliceReader<'a> {
    data: &'a [u8],
}

impl<'a> SliceReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn data(&self) -> &[u8] {
        self.data
    }
}

impl ReadAt for SliceReader<'_> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let offset = match usize::try_from(offset) {
            Ok(o) => o,
            Err(_) => return Ok(0), // Offset too large for this platform
        };
        if offset >= self.data.len() {
            return Ok(0);
        }
        let available = self.data.len() - offset;
        let to_read = buf.len().min(available);
        buf[..to_read].copy_from_slice(&self.data[offset..offset + to_read]);
        Ok(to_read)
    }

    fn size(&self) -> Option<u64> {
        Some(self.data.len() as u64)
    }
}

/// Positional reader for owned byte vectors.
#[derive(Debug, Clone)]
pub struct VecReader {
    data: Vec<u8>,
}

impl VecReader {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.data
    }
}

impl ReadAt for VecReader {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let offset = match usize::try_from(offset) {
            Ok(o) => o,
            Err(_) => return Ok(0), // Offset too large for this platform
        };
        if offset >= self.data.len() {
            return Ok(0);
        }
        let available = self.data.len() - offset;
        let to_read = buf.len().min(available);
        buf[..to_read].copy_from_slice(&self.data[offset..offset + to_read]);
        Ok(to_read)
    }

    fn size(&self) -> Option<u64> {
        Some(self.data.len() as u64)
    }
}

#[cfg(feature = "std")]
pub type FileReader = SeekReader<File>;

#[cfg(feature = "std")]
impl SeekReader<File> {
    /// Open a file for reading.
    #[must_use = "opening a file may fail"]
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::with_discovered_size(File::open(path)?)
    }

    /// Get the size of the file in bytes.
    #[must_use]
    pub fn file_size(&self) -> u64 {
        self.size.unwrap_or(0)
    }
}

/// Positional reader for a base address in the current process.
/// Useful for parsing already-loaded modules.
#[derive(Debug, Clone, Copy)]
pub struct BaseAddressReader {
    base: *const u8,
    size: Option<usize>,
}

impl BaseAddressReader {
    /// # Safety
    /// Caller must ensure memory at `base` is valid for `size` bytes.
    pub unsafe fn new(base: *const u8, size: Option<usize>) -> Self {
        Self { base, size }
    }

    /// # Safety
    /// Caller must ensure memory at `base` is valid.
    pub unsafe fn from_base(base: *const u8) -> Self {
        Self { base, size: None }
    }
}

impl ReadAt for BaseAddressReader {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let offset = match usize::try_from(offset) {
            Ok(o) => o,
            Err(_) => return Ok(0), // Offset too large for this platform
        };
        if let Some(size) = self.size {
            if offset >= size {
                return Ok(0);
            }
            let available = size - offset;
            let to_read = buf.len().min(available);
            unsafe {
                core::ptr::copy_nonoverlapping(self.base.add(offset), buf.as_mut_ptr(), to_read);
            }
            return Ok(to_read);
        }
        unsafe {
            core::ptr::copy_nonoverlapping(self.base.add(offset), buf.as_mut_ptr(), buf.len());
        }
        Ok(buf.len())
    }

    fn size(&self) -> Option<u64> {
        self.size.map(|s| s as u64)
    }
}

unsafe impl Send for BaseAddressReader {}
unsafe impl Sync for BaseAddressReader {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slice_reader() {
        let data = [0x4D, 0x5A, 0x90, 0x00];
        let reader = SliceReader::new(&data);
        assert_eq!(reader.size(), Some(4));
        assert_eq!(reader.read_u16_at(0).unwrap(), 0x5A4D);
    }

    #[test]
    fn test_vec_reader() {
        let data = vec![0x4D, 0x5A, 0x90, 0x00];
        let reader = VecReader::new(data);
        assert_eq!(reader.read_u16_at(0).unwrap(), 0x5A4D);
    }

    #[test]
    fn test_read_past_end() {
        let data = [0x4D, 0x5A];
        let reader = SliceReader::new(&data);
        let mut buf = [0u8; 4];
        let n = reader.read_at(0, &mut buf).unwrap();
        assert_eq!(n, 2);
    }
}
