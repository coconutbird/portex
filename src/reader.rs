//! Reader trait and implementations for reading PE data from various sources.

use crate::{Error, Result};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Trait for reading bytes from a source (file, memory, remote process, etc.).
///
/// Implement this trait to support reading PE structures from custom sources,
/// such as remote process memory via ReadProcessMemory.
pub trait Reader {
    /// Read bytes at the given offset into the buffer.
    /// Returns the number of bytes actually read.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize>;

    /// Get the total size of the source, if known.
    /// Returns None if the size is unknown (e.g., remote process).
    fn size(&self) -> Option<u64>;

    /// Read exact number of bytes at offset, returning error if not enough data.
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let n = self.read_at(offset, buf)?;
        if n < buf.len() {
            return Err(Error::BufferTooSmall {
                expected: buf.len(),
                actual: n,
            });
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
        let mut buf = vec![0u8; len];
        self.read_exact_at(offset, &mut buf)?;
        Ok(buf)
    }
}

/// Reader implementation for byte slices (in-memory data).
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

impl Reader for SliceReader<'_> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let offset = offset as usize;
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

/// Reader implementation for owned byte vectors.
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

impl Reader for VecReader {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let offset = offset as usize;
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

/// Reader implementation for files on disk.
pub struct FileReader {
    file: std::cell::RefCell<File>,
    size: u64,
}

impl FileReader {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut file = File::open(path)?;
        let size = file.seek(SeekFrom::End(0))?;
        Ok(Self {
            file: std::cell::RefCell::new(file),
            size,
        })
    }

    pub fn file_size(&self) -> u64 {
        self.size
    }
}

impl Reader for FileReader {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let mut file = self.file.borrow_mut();
        file.seek(SeekFrom::Start(offset))?;
        let n = file.read(buf)?;
        Ok(n)
    }

    fn size(&self) -> Option<u64> {
        Some(self.size)
    }
}

/// Reader for a base address in the current process.
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

impl Reader for BaseAddressReader {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let offset = offset as usize;
        if let Some(size) = self.size {
            if offset >= size {
                return Ok(0);
            }
            let available = size - offset;
            let to_read = buf.len().min(available);
            unsafe {
                std::ptr::copy_nonoverlapping(self.base.add(offset), buf.as_mut_ptr(), to_read);
            }
            return Ok(to_read);
        }
        unsafe {
            std::ptr::copy_nonoverlapping(self.base.add(offset), buf.as_mut_ptr(), buf.len());
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
