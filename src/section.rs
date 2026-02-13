//! Section Header structures and parsing.

use crate::reader::Reader;
use crate::{Error, Result};

/// Section characteristics flags.
pub mod characteristics {
    /// Section contains executable code.
    pub const CODE: u32 = 0x00000020;
    /// Section contains initialized data.
    pub const INITIALIZED_DATA: u32 = 0x00000040;
    /// Section contains uninitialized data.
    pub const UNINITIALIZED_DATA: u32 = 0x00000080;
    /// Section cannot be cached.
    pub const NO_CACHE: u32 = 0x04000000;
    /// Section is not pageable.
    pub const NO_PAGE: u32 = 0x08000000;
    /// Section is shared.
    pub const SHARED: u32 = 0x10000000;
    /// Section is executable.
    pub const EXECUTE: u32 = 0x20000000;
    /// Section is readable.
    pub const READ: u32 = 0x40000000;
    /// Section is writable.
    pub const WRITE: u32 = 0x80000000;
}

/// Section Header (IMAGE_SECTION_HEADER).
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C)]
pub struct SectionHeader {
    /// Section name (8-byte null-padded ASCII).
    pub name: [u8; 8],
    /// Virtual size of the section.
    pub virtual_size: u32,
    /// RVA of the section.
    pub virtual_address: u32,
    /// Size of raw data on disk.
    pub size_of_raw_data: u32,
    /// File offset to raw data.
    pub pointer_to_raw_data: u32,
    /// File offset to relocations.
    pub pointer_to_relocations: u32,
    /// File offset to line numbers.
    pub pointer_to_linenumbers: u32,
    /// Number of relocations.
    pub number_of_relocations: u16,
    /// Number of line numbers.
    pub number_of_linenumbers: u16,
    /// Section characteristics.
    pub characteristics: u32,
}

impl SectionHeader {
    /// Size of a section header in bytes.
    pub const SIZE: usize = 40;

    /// Parse a section header from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(Error::BufferTooSmall {
                expected: Self::SIZE,
                actual: data.len(),
            });
        }

        let mut name = [0u8; 8];
        name.copy_from_slice(&data[0..8]);

        Ok(Self {
            name,
            virtual_size: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            virtual_address: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
            size_of_raw_data: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
            pointer_to_raw_data: u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
            pointer_to_relocations: u32::from_le_bytes([data[24], data[25], data[26], data[27]]),
            pointer_to_linenumbers: u32::from_le_bytes([data[28], data[29], data[30], data[31]]),
            number_of_relocations: u16::from_le_bytes([data[32], data[33]]),
            number_of_linenumbers: u16::from_le_bytes([data[34], data[35]]),
            characteristics: u32::from_le_bytes([data[36], data[37], data[38], data[39]]),
        })
    }

    /// Write the section header to a byte buffer.
    pub fn write(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() < Self::SIZE {
            return Err(Error::BufferTooSmall {
                expected: Self::SIZE,
                actual: buf.len(),
            });
        }

        buf[0..8].copy_from_slice(&self.name);
        buf[8..12].copy_from_slice(&self.virtual_size.to_le_bytes());
        buf[12..16].copy_from_slice(&self.virtual_address.to_le_bytes());
        buf[16..20].copy_from_slice(&self.size_of_raw_data.to_le_bytes());
        buf[20..24].copy_from_slice(&self.pointer_to_raw_data.to_le_bytes());
        buf[24..28].copy_from_slice(&self.pointer_to_relocations.to_le_bytes());
        buf[28..32].copy_from_slice(&self.pointer_to_linenumbers.to_le_bytes());
        buf[32..34].copy_from_slice(&self.number_of_relocations.to_le_bytes());
        buf[34..36].copy_from_slice(&self.number_of_linenumbers.to_le_bytes());
        buf[36..40].copy_from_slice(&self.characteristics.to_le_bytes());

        Ok(())
    }

    /// Get the section name as a string (trimmed of null bytes).
    pub fn name_str(&self) -> &str {
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(8);
        std::str::from_utf8(&self.name[..end]).unwrap_or("")
    }

    /// Check if the section is executable.
    pub fn is_executable(&self) -> bool {
        self.characteristics & characteristics::EXECUTE != 0
    }

    /// Check if the section is readable.
    pub fn is_readable(&self) -> bool {
        self.characteristics & characteristics::READ != 0
    }

    /// Check if the section is writable.
    pub fn is_writable(&self) -> bool {
        self.characteristics & characteristics::WRITE != 0
    }

    /// Parse a section header from a Reader at the given offset.
    pub fn read_from<R: Reader>(reader: &R, offset: u64) -> Result<Self> {
        let mut buf = [0u8; Self::SIZE];
        reader.read_exact_at(offset, &mut buf)?;
        Self::parse(&buf)
    }

    /// Read multiple section headers from a Reader.
    pub fn read_sections<R: Reader>(reader: &R, offset: u64, count: usize) -> Result<Vec<Self>> {
        let mut sections = Vec::with_capacity(count);
        for i in 0..count {
            let section_offset = offset + (i * Self::SIZE) as u64;
            sections.push(Self::read_from(reader, section_offset)?);
        }
        Ok(sections)
    }

    /// Serialize to a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0u8; Self::SIZE];
        self.write(&mut buf).expect("buffer size is correct");
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_section_header_size() {
        assert_eq!(SectionHeader::SIZE, 40);
    }

    #[test]
    fn test_section_header_name() {
        let mut header = SectionHeader {
            name: [0; 8],
            virtual_size: 0,
            virtual_address: 0,
            size_of_raw_data: 0,
            pointer_to_raw_data: 0,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: 0,
        };
        header.name[..6].copy_from_slice(b".text\0");
        assert_eq!(header.name_str(), ".text");
    }

    #[test]
    fn test_section_header_roundtrip() {
        let mut header = SectionHeader {
            name: [0; 8],
            virtual_size: 0x1000,
            virtual_address: 0x1000,
            size_of_raw_data: 0x800,
            pointer_to_raw_data: 0x400,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: characteristics::CODE | characteristics::EXECUTE | characteristics::READ,
        };
        header.name[..5].copy_from_slice(b".text");

        let mut buf = [0u8; 40];
        header.write(&mut buf).unwrap();

        let parsed = SectionHeader::parse(&buf).unwrap();
        assert_eq!(header, parsed);
        assert!(parsed.is_executable());
        assert!(parsed.is_readable());
        assert!(!parsed.is_writable());
    }
}
