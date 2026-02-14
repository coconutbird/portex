//! Section Header structures and parsing.

use crate::reader::Reader;
use crate::{Error, Result};
use std::borrow::Cow;

/// Section characteristics flags.
pub mod characteristics {
    pub const CODE: u32 = 0x00000020;
    pub const INITIALIZED_DATA: u32 = 0x00000040;
    pub const UNINITIALIZED_DATA: u32 = 0x00000080;
    pub const LINK_INFO: u32 = 0x00000200;
    pub const LINK_REMOVE: u32 = 0x00000800;
    pub const LINK_COMDAT: u32 = 0x00001000;
    pub const GPREL: u32 = 0x00008000;
    pub const ALIGN_1BYTES: u32 = 0x00100000;
    pub const ALIGN_2BYTES: u32 = 0x00200000;
    pub const ALIGN_4BYTES: u32 = 0x00300000;
    pub const ALIGN_8BYTES: u32 = 0x00400000;
    pub const ALIGN_16BYTES: u32 = 0x00500000;
    pub const ALIGN_32BYTES: u32 = 0x00600000;
    pub const ALIGN_64BYTES: u32 = 0x00700000;
    pub const ALIGN_128BYTES: u32 = 0x00800000;
    pub const ALIGN_256BYTES: u32 = 0x00900000;
    pub const ALIGN_512BYTES: u32 = 0x00A00000;
    pub const ALIGN_1024BYTES: u32 = 0x00B00000;
    pub const ALIGN_2048BYTES: u32 = 0x00C00000;
    pub const ALIGN_4096BYTES: u32 = 0x00D00000;
    pub const ALIGN_8192BYTES: u32 = 0x00E00000;
    pub const NRELOC_OVFL: u32 = 0x01000000;
    pub const DISCARDABLE: u32 = 0x02000000;
    pub const NOT_CACHED: u32 = 0x04000000;
    pub const NOT_PAGED: u32 = 0x08000000;
    pub const SHARED: u32 = 0x10000000;
    pub const EXECUTE: u32 = 0x20000000;
    pub const READ: u32 = 0x40000000;
    pub const WRITE: u32 = 0x80000000;
}

/// IMAGE_SECTION_HEADER - 40 bytes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

impl SectionHeader {
    pub const SIZE: usize = 40;

    /// Get the section name as a string (trimmed of null bytes).
    ///
    /// PE section names are not guaranteed to be valid UTF-8. This method
    /// returns a `Cow<str>` that will be borrowed if the name is valid UTF-8,
    /// or owned with lossy conversion if it contains invalid bytes.
    #[must_use]
    pub fn name_str(&self) -> Cow<'_, str> {
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(8);
        String::from_utf8_lossy(&self.name[..end])
    }

    /// Get the section name as raw bytes (without null padding).
    #[must_use]
    pub fn name_bytes(&self) -> &[u8] {
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(8);
        &self.name[..end]
    }

    /// Set the section name from a string.
    pub fn set_name(&mut self, name: &str) {
        self.name = [0u8; 8];
        let bytes = name.as_bytes();
        let len = bytes.len().min(8);
        self.name[..len].copy_from_slice(&bytes[..len]);
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

    /// Check if the section contains code.
    pub fn contains_code(&self) -> bool {
        self.characteristics & characteristics::CODE != 0
    }

    /// Check if this RVA falls within this section.
    pub fn contains_rva(&self, rva: u32) -> bool {
        let size = self.virtual_size.max(self.size_of_raw_data);
        rva >= self.virtual_address && rva < self.virtual_address + size
    }

    /// Convert an RVA to file offset within this section.
    pub fn rva_to_offset(&self, rva: u32) -> Option<u32> {
        if self.contains_rva(rva) {
            Some(self.pointer_to_raw_data + (rva - self.virtual_address))
        } else {
            None
        }
    }

    /// Parse a section header from bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(Error::buffer_too_small(Self::SIZE, data.len()));
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

    /// Write the section header to a buffer.
    pub fn write(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() < Self::SIZE {
            return Err(Error::buffer_too_small(Self::SIZE, buf.len()));
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

/// A section with its header and owned data.
/// This is the main type for working with sections during PE modification.
#[derive(Debug, Clone)]
pub struct Section {
    /// Section header (will be updated during layout).
    pub header: SectionHeader,
    /// Raw section data (owned).
    pub data: Vec<u8>,
}

impl Section {
    /// Create a new section with the given name and characteristics.
    pub fn new(name: &str, characteristics: u32) -> Self {
        let mut header = SectionHeader {
            name: [0u8; 8],
            virtual_size: 0,
            virtual_address: 0,
            size_of_raw_data: 0,
            pointer_to_raw_data: 0,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics,
        };
        header.set_name(name);
        Self {
            header,
            data: Vec::new(),
        }
    }

    /// Create a section from a header and data.
    pub fn from_header_and_data(header: SectionHeader, data: Vec<u8>) -> Self {
        Self { header, data }
    }

    /// Get the section name.
    #[must_use]
    pub fn name(&self) -> Cow<'_, str> {
        self.header.name_str()
    }

    /// Set the section data.
    pub fn set_data(&mut self, data: Vec<u8>) {
        self.data = data;
        self.header.virtual_size = self.data.len() as u32;
    }

    /// Append data to the section.
    pub fn append_data(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
        self.header.virtual_size = self.data.len() as u32;
    }

    /// Check if an RVA falls within this section.
    pub fn contains_rva(&self, rva: u32) -> bool {
        self.header.contains_rva(rva)
    }

    /// Get data at an RVA offset within this section.
    pub fn data_at_rva(&self, rva: u32, len: usize) -> Option<&[u8]> {
        if !self.contains_rva(rva) {
            return None;
        }
        let offset = (rva - self.header.virtual_address) as usize;
        if offset + len <= self.data.len() {
            Some(&self.data[offset..offset + len])
        } else {
            None
        }
    }

    /// Get mutable data at an RVA offset within this section.
    pub fn data_at_rva_mut(&mut self, rva: u32, len: usize) -> Option<&mut [u8]> {
        if !self.contains_rva(rva) {
            return None;
        }
        let offset = (rva - self.header.virtual_address) as usize;
        if offset + len <= self.data.len() {
            Some(&mut self.data[offset..offset + len])
        } else {
            None
        }
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
            name: [0u8; 8],
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
        header.set_name(".text");
        assert_eq!(header.name_str(), ".text");
    }

    #[test]
    fn test_section_header_roundtrip() {
        let original = SectionHeader {
            name: *b".text\0\0\0",
            virtual_size: 0x1000,
            virtual_address: 0x1000,
            size_of_raw_data: 0x200,
            pointer_to_raw_data: 0x200,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: characteristics::CODE
                | characteristics::EXECUTE
                | characteristics::READ,
        };

        let bytes = original.to_bytes();
        let parsed = SectionHeader::parse(&bytes).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_section_new() {
        let section = Section::new(".test", characteristics::READ | characteristics::WRITE);
        assert_eq!(section.name(), ".test");
        assert!(section.header.is_readable());
        assert!(section.header.is_writable());
    }

    #[test]
    fn test_section_data_at_rva() {
        let mut section = Section::new(".data", characteristics::READ);
        section.header.virtual_address = 0x2000;
        section.set_data(vec![0x11, 0x22, 0x33, 0x44, 0x55]);

        assert!(section.contains_rva(0x2000));
        assert!(section.contains_rva(0x2004));
        assert!(!section.contains_rva(0x1FFF));
        assert!(!section.contains_rva(0x2005));

        assert_eq!(section.data_at_rva(0x2001, 2), Some(&[0x22, 0x33][..]));
        assert_eq!(section.data_at_rva(0x2000, 10), None); // too long
    }
}
