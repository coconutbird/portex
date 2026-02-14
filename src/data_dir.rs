//! Data Directory structures and parsing.

use crate::reader::Reader;
use crate::{Error, Result};

/// Data directory type - type-safe enum for data directory indices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(usize)]
pub enum DataDirectoryType {
    /// Export table (.edata)
    Export = 0,
    /// Import table (.idata)
    Import = 1,
    /// Resource table (.rsrc)
    Resource = 2,
    /// Exception table (.pdata)
    Exception = 3,
    /// Certificate/Security table
    Security = 4,
    /// Base relocation table (.reloc)
    BaseReloc = 5,
    /// Debug directory
    Debug = 6,
    /// Architecture-specific data
    Architecture = 7,
    /// Global pointer register value
    GlobalPtr = 8,
    /// Thread local storage (.tls)
    Tls = 9,
    /// Load configuration
    LoadConfig = 10,
    /// Bound import table
    BoundImport = 11,
    /// Import address table
    Iat = 12,
    /// Delay import descriptor
    DelayImport = 13,
    /// CLR runtime header
    ClrRuntime = 14,
    /// Reserved
    Reserved = 15,
}

impl DataDirectoryType {
    /// Get the index value.
    pub const fn as_index(self) -> usize {
        self as usize
    }

    /// Try to create from an index.
    pub const fn from_index(index: usize) -> Option<Self> {
        match index {
            0 => Some(Self::Export),
            1 => Some(Self::Import),
            2 => Some(Self::Resource),
            3 => Some(Self::Exception),
            4 => Some(Self::Security),
            5 => Some(Self::BaseReloc),
            6 => Some(Self::Debug),
            7 => Some(Self::Architecture),
            8 => Some(Self::GlobalPtr),
            9 => Some(Self::Tls),
            10 => Some(Self::LoadConfig),
            11 => Some(Self::BoundImport),
            12 => Some(Self::Iat),
            13 => Some(Self::DelayImport),
            14 => Some(Self::ClrRuntime),
            15 => Some(Self::Reserved),
            _ => None,
        }
    }

    /// Get the name of this directory type.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Export => "Export",
            Self::Import => "Import",
            Self::Resource => "Resource",
            Self::Exception => "Exception",
            Self::Security => "Security",
            Self::BaseReloc => "BaseReloc",
            Self::Debug => "Debug",
            Self::Architecture => "Architecture",
            Self::GlobalPtr => "GlobalPtr",
            Self::Tls => "TLS",
            Self::LoadConfig => "LoadConfig",
            Self::BoundImport => "BoundImport",
            Self::Iat => "IAT",
            Self::DelayImport => "DelayImport",
            Self::ClrRuntime => "CLR",
            Self::Reserved => "Reserved",
        }
    }

    /// Iterate over all directory types.
    pub fn all() -> impl Iterator<Item = Self> {
        (0..16).filter_map(Self::from_index)
    }
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
            return Err(Error::buffer_too_small(Self::SIZE, data.len()));
        }

        Ok(Self {
            virtual_address: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            size: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
        })
    }

    /// Write the data directory to a byte buffer.
    pub fn write(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() < Self::SIZE {
            return Err(Error::buffer_too_small(Self::SIZE, buf.len()));
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

    #[test]
    fn test_data_directory_type_roundtrip() {
        for dir_type in DataDirectoryType::all() {
            let index = dir_type.as_index();
            let recovered = DataDirectoryType::from_index(index).unwrap();
            assert_eq!(dir_type, recovered);
            assert!(!dir_type.name().is_empty());
        }
    }

    #[test]
    fn test_data_directory_type_values() {
        assert_eq!(DataDirectoryType::Export.as_index(), 0);
        assert_eq!(DataDirectoryType::Import.as_index(), 1);
        assert_eq!(DataDirectoryType::Resource.as_index(), 2);
        assert_eq!(DataDirectoryType::BaseReloc.as_index(), 5);
        assert_eq!(DataDirectoryType::Tls.as_index(), 9);
        assert_eq!(DataDirectoryType::LoadConfig.as_index(), 10);
    }
}
