//! Data Directory structures and parsing.

use crate::reader::Reader;
use crate::{Error, Result};

/// Data directory indices.
pub mod index {
    pub const EXPORT: usize = 0;
    pub const IMPORT: usize = 1;
    pub const RESOURCE: usize = 2;
    pub const EXCEPTION: usize = 3;
    pub const SECURITY: usize = 4;
    pub const BASERELOC: usize = 5;
    pub const DEBUG: usize = 6;
    pub const ARCHITECTURE: usize = 7;
    pub const GLOBALPTR: usize = 8;
    pub const TLS: usize = 9;
    pub const LOAD_CONFIG: usize = 10;
    pub const BOUND_IMPORT: usize = 11;
    pub const IAT: usize = 12;
    pub const DELAY_IMPORT: usize = 13;
    pub const CLR_RUNTIME: usize = 14;
    pub const RESERVED: usize = 15;
}

/// Number of data directories in PE32+.
pub const NUMBER_OF_DIRECTORY_ENTRIES: usize = 16;

/// Data Directory entry (IMAGE_DATA_DIRECTORY).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct DataDirectory {
    /// RVA (Relative Virtual Address) of the table.
    pub virtual_address: u32,
    /// Size of the table in bytes.
    pub size: u32,
}

impl DataDirectory {
    /// Size of a data directory entry in bytes.
    pub const SIZE: usize = 8;

    /// Parse a data directory from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(Error::BufferTooSmall {
                expected: Self::SIZE,
                actual: data.len(),
            });
        }

        Ok(Self {
            virtual_address: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            size: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
        })
    }

    /// Write the data directory to a byte buffer.
    pub fn write(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() < Self::SIZE {
            return Err(Error::BufferTooSmall {
                expected: Self::SIZE,
                actual: buf.len(),
            });
        }

        buf[0..4].copy_from_slice(&self.virtual_address.to_le_bytes());
        buf[4..8].copy_from_slice(&self.size.to_le_bytes());

        Ok(())
    }

    /// Check if this directory entry is present (non-zero).
    pub fn is_present(&self) -> bool {
        self.virtual_address != 0 || self.size != 0
    }

    /// Parse a data directory from a Reader at the given offset.
    pub fn read_from<R: Reader>(reader: &R, offset: u64) -> Result<Self> {
        let mut buf = [0u8; Self::SIZE];
        reader.read_exact_at(offset, &mut buf)?;
        Self::parse(&buf)
    }

    /// Read multiple data directories from a Reader.
    pub fn read_directories<R: Reader>(reader: &R, offset: u64, count: usize) -> Result<Vec<Self>> {
        let mut dirs = Vec::with_capacity(count);
        for i in 0..count {
            let dir_offset = offset + (i * Self::SIZE) as u64;
            dirs.push(Self::read_from(reader, dir_offset)?);
        }
        Ok(dirs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_directory_size() {
        assert_eq!(DataDirectory::SIZE, 8);
    }

    #[test]
    fn test_data_directory_roundtrip() {
        let dir = DataDirectory {
            virtual_address: 0x1000,
            size: 0x200,
        };

        let mut buf = [0u8; 8];
        dir.write(&mut buf).unwrap();

        let parsed = DataDirectory::parse(&buf).unwrap();
        assert_eq!(dir, parsed);
        assert!(parsed.is_present());
    }

    #[test]
    fn test_data_directory_not_present() {
        let dir = DataDirectory::default();
        assert!(!dir.is_present());
    }
}
