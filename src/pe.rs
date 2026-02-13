//! Main PE file structure and parsing.

use crate::coff::{verify_pe_signature, CoffHeader, PE_SIGNATURE};
use crate::dos::DosHeader;
use crate::optional::OptionalHeader;
use crate::reader::{FileReader, Reader, SliceReader};
use crate::section::SectionHeader;
use crate::Result;
use std::fs::File;
use std::io::Write;
use std::path::Path;

/// A parsed PE file with full data.
#[derive(Debug, Clone)]
pub struct PE {
    /// DOS header.
    pub dos_header: DosHeader,
    /// DOS stub (data between DOS header and PE signature).
    pub dos_stub: Vec<u8>,
    /// COFF file header.
    pub coff_header: CoffHeader,
    /// Optional header (PE32 or PE32+).
    pub optional_header: OptionalHeader,
    /// Section headers.
    pub sections: Vec<SectionHeader>,
    /// Raw file data.
    data: Vec<u8>,
}

/// Partial PE headers - just the headers without raw data.
/// Useful for remote process scenarios or when you only need header info.
#[derive(Debug, Clone)]
pub struct PEHeaders {
    /// DOS header.
    pub dos_header: DosHeader,
    /// COFF file header.
    pub coff_header: CoffHeader,
    /// Optional header (PE32 or PE32+).
    pub optional_header: OptionalHeader,
    /// Section headers.
    pub sections: Vec<SectionHeader>,
    /// Offset where PE signature was found.
    pub pe_offset: u64,
}

impl PE {
    /// Parse a PE file from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let reader = SliceReader::new(data);
        let headers = PEHeaders::read_from(&reader, 0)?;
        
        // Read DOS stub
        let dos_stub = reader.read_bytes_at(
            DosHeader::SIZE as u64,
            headers.pe_offset as usize - DosHeader::SIZE,
        )?;

        Ok(Self {
            dos_header: headers.dos_header,
            dos_stub,
            coff_header: headers.coff_header,
            optional_header: headers.optional_header,
            sections: headers.sections,
            data: data.to_vec(),
        })
    }

    /// Load a PE file from disk.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let reader = FileReader::open(path)?;
        let size = reader.file_size() as usize;
        let data = reader.read_bytes_at(0, size)?;
        Self::parse(&data)
    }

    /// Create from owned data.
    pub fn from_vec(data: Vec<u8>) -> Result<Self> {
        let pe = Self::parse(&data)?;
        Ok(Self { data, ..pe })
    }

    /// Get the raw file data.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get mutable access to raw data.
    pub fn data_mut(&mut self) -> &mut Vec<u8> {
        &mut self.data
    }

    /// Consume and return the raw data.
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }

    /// Check if this is a 64-bit PE file.
    pub fn is_64bit(&self) -> bool {
        self.optional_header.is_pe32plus()
    }

    /// Check if this is a DLL.
    pub fn is_dll(&self) -> bool {
        self.coff_header.is_dll()
    }

    /// Get a section by name.
    pub fn section_by_name(&self, name: &str) -> Option<&SectionHeader> {
        self.sections.iter().find(|s| s.name_str() == name)
    }

    /// Get the raw data for a section.
    pub fn section_data(&self, section: &SectionHeader) -> Option<&[u8]> {
        let start = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;
        if start + size <= self.data.len() {
            Some(&self.data[start..start + size])
        } else {
            None
        }
    }

    /// Convert an RVA to a file offset.
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        rva_to_file_offset(&self.sections, rva)
    }

    /// Read data at an RVA.
    pub fn read_at_rva(&self, rva: u32, len: usize) -> Option<&[u8]> {
        let offset = self.rva_to_offset(rva)?;
        if offset + len <= self.data.len() {
            Some(&self.data[offset..offset + len])
        } else {
            None
        }
    }

    /// Write data at an RVA.
    pub fn write_at_rva(&mut self, rva: u32, data: &[u8]) -> Option<()> {
        let offset = self.rva_to_offset(rva)?;
        if offset + data.len() <= self.data.len() {
            self.data[offset..offset + data.len()].copy_from_slice(data);
            Some(())
        } else {
            None
        }
    }

    /// Get mutable section data.
    pub fn section_data_mut(&mut self, section: &SectionHeader) -> Option<&mut [u8]> {
        let start = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;
        if start + size <= self.data.len() {
            Some(&mut self.data[start..start + size])
        } else {
            None
        }
    }

    /// Rebuild the PE file from modified headers.
    /// This updates the header bytes in the internal data buffer.
    pub fn rebuild_headers(&mut self) {
        let pe_offset = self.dos_header.e_lfanew as usize;

        // Write DOS header
        self.dos_header.write(&mut self.data[0..DosHeader::SIZE]).ok();

        // Write PE signature
        self.data[pe_offset..pe_offset + 4].copy_from_slice(&PE_SIGNATURE.to_le_bytes());

        // Write COFF header
        let coff_offset = pe_offset + 4;
        self.coff_header
            .write(&mut self.data[coff_offset..coff_offset + CoffHeader::SIZE])
            .ok();

        // Write optional header
        let optional_offset = coff_offset + CoffHeader::SIZE;
        let optional_size = self.optional_header.size();
        self.optional_header
            .write(&mut self.data[optional_offset..optional_offset + optional_size])
            .ok();

        // Write section headers
        let sections_offset = optional_offset + self.coff_header.size_of_optional_header as usize;
        for (i, section) in self.sections.iter().enumerate() {
            let offset = sections_offset + i * SectionHeader::SIZE;
            section
                .write(&mut self.data[offset..offset + SectionHeader::SIZE])
                .ok();
        }
    }

    /// Build a complete PE file as a byte vector.
    /// This creates a new buffer with all headers and section data.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = self.data.clone();

        let pe_offset = self.dos_header.e_lfanew as usize;

        // Write DOS header
        self.dos_header.write(&mut result[0..DosHeader::SIZE]).ok();

        // Write PE signature
        result[pe_offset..pe_offset + 4].copy_from_slice(&PE_SIGNATURE.to_le_bytes());

        // Write COFF header
        let coff_offset = pe_offset + 4;
        self.coff_header
            .write(&mut result[coff_offset..coff_offset + CoffHeader::SIZE])
            .ok();

        // Write optional header
        let optional_offset = coff_offset + CoffHeader::SIZE;
        let optional_size = self.optional_header.size();
        self.optional_header
            .write(&mut result[optional_offset..optional_offset + optional_size])
            .ok();

        // Write section headers
        let sections_offset = optional_offset + self.coff_header.size_of_optional_header as usize;
        for (i, section) in self.sections.iter().enumerate() {
            let offset = sections_offset + i * SectionHeader::SIZE;
            section
                .write(&mut result[offset..offset + SectionHeader::SIZE])
                .ok();
        }

        result
    }

    /// Write the PE file to disk.
    pub fn write_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let bytes = self.to_bytes();
        let mut file = File::create(path)?;
        file.write_all(&bytes)?;
        Ok(())
    }

    /// Write with rebuilt headers to disk.
    pub fn save<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        self.rebuild_headers();
        let mut file = File::create(path)?;
        file.write_all(&self.data)?;
        Ok(())
    }
}

impl PEHeaders {
    /// Read PE headers from any Reader implementation.
    /// This is the main entry point for partial/remote loading.
    pub fn read_from<R: Reader>(reader: &R, base_offset: u64) -> Result<Self> {
        // Parse DOS header
        let dos_header = DosHeader::read_from(reader, base_offset)?;

        // Get PE header offset
        let pe_offset = base_offset + dos_header.e_lfanew as u64;

        // Verify PE signature
        verify_pe_signature(reader, pe_offset)?;

        // Parse COFF header (4 bytes after PE signature)
        let coff_offset = pe_offset + 4;
        let coff_header = CoffHeader::read_from(reader, coff_offset)?;

        // Parse optional header
        let optional_offset = coff_offset + CoffHeader::SIZE as u64;
        let optional_header = OptionalHeader::read_from(reader, optional_offset)?;

        // Parse section headers
        let sections_offset = optional_offset + coff_header.size_of_optional_header as u64;
        let sections = SectionHeader::read_sections(
            reader,
            sections_offset,
            coff_header.number_of_sections as usize,
        )?;

        Ok(Self {
            dos_header,
            coff_header,
            optional_header,
            sections,
            pe_offset,
        })
    }

    /// Read headers from a file on disk.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let reader = FileReader::open(path)?;
        Self::read_from(&reader, 0)
    }

    /// Read headers from a byte slice.
    pub fn from_slice(data: &[u8]) -> Result<Self> {
        let reader = SliceReader::new(data);
        Self::read_from(&reader, 0)
    }

    /// Check if this is a 64-bit PE.
    pub fn is_64bit(&self) -> bool {
        self.optional_header.is_pe32plus()
    }

    /// Check if this is a DLL.
    pub fn is_dll(&self) -> bool {
        self.coff_header.is_dll()
    }

    /// Get a section by name.
    pub fn section_by_name(&self, name: &str) -> Option<&SectionHeader> {
        self.sections.iter().find(|s| s.name_str() == name)
    }

    /// Convert an RVA to a file offset.
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        rva_to_file_offset(&self.sections, rva)
    }

    /// Get the entry point RVA.
    pub fn entry_point(&self) -> u32 {
        self.optional_header.address_of_entry_point()
    }

    /// Get the image base.
    pub fn image_base(&self) -> u64 {
        self.optional_header.image_base()
    }
}

/// Convert an RVA to a file offset using section table.
pub fn rva_to_file_offset(sections: &[SectionHeader], rva: u32) -> Option<usize> {
    for section in sections {
        let section_rva = section.virtual_address;
        let section_size = section.virtual_size.max(section.size_of_raw_data);
        if rva >= section_rva && rva < section_rva + section_size {
            let offset_in_section = rva - section_rva;
            return Some(section.pointer_to_raw_data as usize + offset_in_section as usize);
        }
    }
    None
}

/// Convert a file offset to an RVA using section table.
pub fn file_offset_to_rva(sections: &[SectionHeader], offset: usize) -> Option<u32> {
    let offset = offset as u32;
    for section in sections {
        let raw_start = section.pointer_to_raw_data;
        let raw_size = section.size_of_raw_data;
        if offset >= raw_start && offset < raw_start + raw_size {
            let offset_in_section = offset - raw_start;
            return Some(section.virtual_address + offset_in_section);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    #[test]
    fn test_parse_invalid_dos_signature() {
        let data = vec![0u8; 256];
        let result = PE::parse(&data);
        assert!(matches!(result, Err(Error::InvalidDosSignature)));
    }

    #[test]
    fn test_parse_buffer_too_small() {
        let data = vec![0x4D, 0x5A]; // Just MZ
        let result = PE::parse(&data);
        assert!(matches!(result, Err(Error::BufferTooSmall { .. })));
    }

    #[test]
    fn test_headers_parse_invalid() {
        let data = vec![0u8; 256];
        let result = PEHeaders::from_slice(&data);
        assert!(matches!(result, Err(Error::InvalidDosSignature)));
    }
}
