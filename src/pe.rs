//! Main PE file structure and parsing.

use crate::coff::{verify_pe_signature, CoffHeader, PE_SIGNATURE};
use crate::dos::DosHeader;
use crate::layout::{self, LayoutConfig};
use crate::optional::OptionalHeader;
use crate::reader::{FileReader, Reader, SliceReader};
use crate::section::{Section, SectionHeader};
use crate::Result;
use std::fs::File;
use std::io::Write;
use std::path::Path;

/// A parsed PE file with owned section data.
/// This is the main type for reading, modifying, and writing PE files.
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
    /// Sections with owned data.
    pub sections: Vec<Section>,
}

/// Partial PE headers - just the headers without section data.
/// Useful for remote process scenarios or when you only need header info.
#[derive(Debug, Clone)]
pub struct PEHeaders {
    /// DOS header.
    pub dos_header: DosHeader,
    /// COFF file header.
    pub coff_header: CoffHeader,
    /// Optional header (PE32 or PE32+).
    pub optional_header: OptionalHeader,
    /// Section headers (no data).
    pub section_headers: Vec<SectionHeader>,
    /// Offset where PE signature was found.
    pub pe_offset: u64,
}

impl PE {
    /// Parse a PE file from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let reader = SliceReader::new(data);
        let headers = PEHeaders::read_from(&reader, 0)?;

        // Read DOS stub
        let dos_stub_size = headers.pe_offset as usize - DosHeader::SIZE;
        let dos_stub = if dos_stub_size > 0 {
            data[DosHeader::SIZE..DosHeader::SIZE + dos_stub_size].to_vec()
        } else {
            Vec::new()
        };

        // Read section data
        let mut sections = Vec::with_capacity(headers.section_headers.len());
        for header in headers.section_headers {
            let start = header.pointer_to_raw_data as usize;
            let size = header.size_of_raw_data as usize;
            let section_data = if start > 0 && size > 0 && start + size <= data.len() {
                data[start..start + size].to_vec()
            } else {
                Vec::new()
            };
            sections.push(Section::from_header_and_data(header, section_data));
        }

        Ok(Self {
            dos_header: headers.dos_header,
            dos_stub,
            coff_header: headers.coff_header,
            optional_header: headers.optional_header,
            sections,
        })
    }

    /// Load a PE file from disk.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let data = std::fs::read(path)?;
        Self::parse(&data)
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
    pub fn section_by_name(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name() == name)
    }

    /// Get a mutable section by name.
    pub fn section_by_name_mut(&mut self, name: &str) -> Option<&mut Section> {
        self.sections.iter_mut().find(|s| s.name() == name)
    }

    /// Find the section containing an RVA.
    pub fn section_by_rva(&self, rva: u32) -> Option<&Section> {
        self.sections.iter().find(|s| s.contains_rva(rva))
    }

    /// Find the mutable section containing an RVA.
    pub fn section_by_rva_mut(&mut self, rva: u32) -> Option<&mut Section> {
        self.sections.iter_mut().find(|s| s.contains_rva(rva))
    }

    /// Read data at an RVA.
    pub fn read_at_rva(&self, rva: u32, len: usize) -> Option<&[u8]> {
        self.section_by_rva(rva)?.data_at_rva(rva, len)
    }

    /// Write data at an RVA.
    pub fn write_at_rva(&mut self, rva: u32, data: &[u8]) -> Option<()> {
        let section = self.section_by_rva_mut(rva)?;
        let slice = section.data_at_rva_mut(rva, data.len())?;
        slice.copy_from_slice(data);
        Some(())
    }

    /// Convert an RVA to a file offset.
    pub fn rva_to_offset(&self, rva: u32) -> Option<u32> {
        for section in &self.sections {
            if let Some(offset) = section.header.rva_to_offset(rva) {
                return Some(offset);
            }
        }
        None
    }

    /// Add a new section.
    pub fn add_section(&mut self, section: Section) {
        self.sections.push(section);
        self.coff_header.number_of_sections = self.sections.len() as u16;
    }

    /// Remove a section by name.
    pub fn remove_section(&mut self, name: &str) -> Option<Section> {
        let idx = self.sections.iter().position(|s| s.name() == name)?;
        self.coff_header.number_of_sections = (self.sections.len() - 1) as u16;
        Some(self.sections.remove(idx))
    }

    /// Get the entry point RVA.
    pub fn entry_point(&self) -> u32 {
        self.optional_header.address_of_entry_point()
    }

    /// Get the image base.
    pub fn image_base(&self) -> u64 {
        self.optional_header.image_base()
    }

    /// Get a data directory entry.
    pub fn data_directory(&self, index: usize) -> Option<&crate::data_dir::DataDirectory> {
        self.optional_header.data_directories().get(index)
    }

    /// Parse the import table.
    pub fn imports(&self) -> Result<crate::import::ImportTable> {
        use crate::data_dir::index::IMPORT;

        let dir = self.data_directory(IMPORT).filter(|d| d.is_present());
        match dir {
            Some(d) => {
                let read_fn = |rva: u32, len: usize| -> Option<Vec<u8>> {
                    self.read_at_rva(rva, len).map(|s| s.to_vec())
                };
                crate::import::ImportTable::parse(d.virtual_address, self.is_64bit(), read_fn)
            }
            None => Ok(crate::import::ImportTable::default()),
        }
    }

    /// Parse the export table.
    pub fn exports(&self) -> Result<crate::export::ExportTable> {
        use crate::data_dir::index::EXPORT;

        let dir = self.data_directory(EXPORT).filter(|d| d.is_present());
        match dir {
            Some(d) => {
                let read_fn = |rva: u32, len: usize| -> Option<Vec<u8>> {
                    self.read_at_rva(rva, len).map(|s| s.to_vec())
                };
                crate::export::ExportTable::parse(d.virtual_address, d.size, read_fn)
            }
            None => Ok(crate::export::ExportTable::default()),
        }
    }

    /// Parse the relocation table.
    pub fn relocations(&self) -> Result<crate::reloc::RelocationTable> {
        use crate::data_dir::index::BASERELOC;

        let dir = self.data_directory(BASERELOC).filter(|d| d.is_present());
        match dir {
            Some(d) => {
                let read_fn = |rva: u32, len: usize| -> Option<Vec<u8>> {
                    self.read_at_rva(rva, len).map(|s| s.to_vec())
                };
                crate::reloc::RelocationTable::parse(d.virtual_address, d.size, read_fn)
            }
            None => Ok(crate::reloc::RelocationTable::default()),
        }
    }

    /// Set the import table by building a new .idata section.
    /// This will create or replace the existing import section.
    pub fn set_imports(&mut self, imports: crate::import::ImportTable) {
        use crate::data_dir::index::{IMPORT, IAT};
        use crate::import::ImportTableBuilder;
        use crate::section::characteristics::{READ, INITIALIZED_DATA};

        if imports.is_empty() {
            // Remove import section and clear data directories
            self.remove_section(".idata");
            let dirs = self.optional_header.data_directories_mut();
            if let Some(dir) = dirs.get_mut(IMPORT) {
                dir.virtual_address = 0;
                dir.size = 0;
            }
            if let Some(dir) = dirs.get_mut(IAT) {
                dir.virtual_address = 0;
                dir.size = 0;
            }
            return;
        }

        // Remove old import section if exists
        self.remove_section(".idata");

        // We need to know where the section will be placed
        // First, update layout to get current state
        self.update_layout();

        // Calculate where the new section will be placed
        let config = LayoutConfig::from_optional_header(&self.optional_header);
        let last_section_rva_end = self.sections.last()
            .map(|s| s.header.virtual_address + s.header.virtual_size)
            .unwrap_or(config.section_alignment);
        let new_section_rva = config.align_section(last_section_rva_end);

        // Build the import section
        let builder = ImportTableBuilder::new(self.is_64bit(), new_section_rva);
        let (section_data, iat_rva, iat_size) = builder.build(&imports);

        // Create the section
        let mut section = Section::new(".idata", READ | INITIALIZED_DATA);
        section.set_data(section_data);

        // Add the section
        self.add_section(section);

        // Update data directories (after add_section updates layout)
        let import_rva = new_section_rva;
        let import_size = (imports.dlls.len() + 1) as u32 * crate::import::ImportDescriptor::SIZE as u32;

        let dirs = self.optional_header.data_directories_mut();
        if let Some(dir) = dirs.get_mut(IMPORT) {
            dir.virtual_address = import_rva;
            dir.size = import_size;
        }
        if let Some(dir) = dirs.get_mut(IAT) {
            dir.virtual_address = iat_rva;
            dir.size = iat_size;
        }
    }

    /// Set the export table by building a new .edata section.
    /// This will create or replace the existing export section.
    pub fn set_exports(&mut self, exports: crate::export::ExportTable) {
        use crate::data_dir::index::EXPORT;
        use crate::export::ExportTableBuilder;
        use crate::section::characteristics::{READ, INITIALIZED_DATA};

        if exports.is_empty() && exports.dll_name.is_empty() {
            // Remove export section and clear data directory
            self.remove_section(".edata");
            let dirs = self.optional_header.data_directories_mut();
            if let Some(dir) = dirs.get_mut(EXPORT) {
                dir.virtual_address = 0;
                dir.size = 0;
            }
            return;
        }

        // Remove old export section if exists
        self.remove_section(".edata");

        // Update layout to get current state
        self.update_layout();

        // Calculate where the new section will be placed
        let config = LayoutConfig::from_optional_header(&self.optional_header);
        let last_section_rva_end = self.sections.last()
            .map(|s| s.header.virtual_address + s.header.virtual_size)
            .unwrap_or(config.section_alignment);
        let new_section_rva = config.align_section(last_section_rva_end);

        // Build the export section
        let builder = ExportTableBuilder::new(new_section_rva);
        let (section_data, export_size) = builder.build(&exports);

        // Create the section
        let mut section = Section::new(".edata", READ | INITIALIZED_DATA);
        section.set_data(section_data);

        // Add the section
        self.add_section(section);

        // Update data directory
        let dirs = self.optional_header.data_directories_mut();
        if let Some(dir) = dirs.get_mut(EXPORT) {
            dir.virtual_address = new_section_rva;
            dir.size = export_size;
        }
    }

    /// Recalculate layout (section RVAs, file offsets, sizes).
    /// Call this after modifying sections before writing.
    pub fn update_layout(&mut self) {
        let config = LayoutConfig::from_optional_header(&self.optional_header);
        
        // Calculate headers size
        let headers_size = layout::headers_size(
            self.sections.len(),
            self.optional_header.size(),
        ) as u32;

        // Update optional header's size_of_headers
        self.set_size_of_headers(config.align_file(headers_size));

        // Layout sections
        layout::layout_sections(&mut self.sections, &config, headers_size);

        // Update size_of_image
        let size_of_image = layout::calculate_size_of_image(&self.sections, &config);
        self.set_size_of_image(size_of_image);

        // Update COFF header
        self.coff_header.number_of_sections = self.sections.len() as u16;
        self.coff_header.size_of_optional_header = self.optional_header.size() as u16;
    }

    fn set_size_of_headers(&mut self, size: u32) {
        match &mut self.optional_header {
            OptionalHeader::Pe32(h) => h.size_of_headers = size,
            OptionalHeader::Pe32Plus(h) => h.size_of_headers = size,
        }
    }

    fn set_size_of_image(&mut self, size: u32) {
        match &mut self.optional_header {
            OptionalHeader::Pe32(h) => h.size_of_image = size,
            OptionalHeader::Pe32Plus(h) => h.size_of_image = size,
        }
    }

    /// Build the PE file as a byte vector.
    pub fn build(&mut self) -> Vec<u8> {
        // Update layout first
        self.update_layout();

        // Calculate total file size
        let mut file_size = self.optional_header.size_of_headers();
        for section in &self.sections {
            if section.header.pointer_to_raw_data > 0 {
                let end = section.header.pointer_to_raw_data + section.header.size_of_raw_data;
                file_size = file_size.max(end);
            }
        }

        let mut output = vec![0u8; file_size as usize];

        // Write DOS header
        self.dos_header.write(&mut output[0..DosHeader::SIZE]).ok();

        // Write DOS stub
        let stub_start = DosHeader::SIZE;
        let stub_end = stub_start + self.dos_stub.len();
        if stub_end <= output.len() {
            output[stub_start..stub_end].copy_from_slice(&self.dos_stub);
        }

        // Write PE signature
        let pe_offset = self.dos_header.e_lfanew as usize;
        output[pe_offset..pe_offset + 4].copy_from_slice(&PE_SIGNATURE.to_le_bytes());

        // Write COFF header
        let coff_offset = pe_offset + 4;
        self.coff_header
            .write(&mut output[coff_offset..coff_offset + CoffHeader::SIZE])
            .ok();

        // Write optional header
        let optional_offset = coff_offset + CoffHeader::SIZE;
        let optional_size = self.optional_header.size();
        self.optional_header
            .write(&mut output[optional_offset..optional_offset + optional_size])
            .ok();

        // Write section headers
        let sections_offset = optional_offset + self.coff_header.size_of_optional_header as usize;
        for (i, section) in self.sections.iter().enumerate() {
            let offset = sections_offset + i * SectionHeader::SIZE;
            section.header
                .write(&mut output[offset..offset + SectionHeader::SIZE])
                .ok();
        }

        // Write section data
        for section in &self.sections {
            let start = section.header.pointer_to_raw_data as usize;
            let aligned_size = section.header.size_of_raw_data as usize;
            if start > 0 && aligned_size > 0 && start + aligned_size <= output.len() {
                let data_len = section.data.len().min(aligned_size);
                output[start..start + data_len].copy_from_slice(&section.data[..data_len]);
                // Padding is already zeros
            }
        }

        output
    }

    /// Write the PE file to disk.
    pub fn write_to_file<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let bytes = self.build();
        let mut file = File::create(path)?;
        file.write_all(&bytes)?;
        Ok(())
    }
}

impl PEHeaders {
    /// Read PE headers from any Reader implementation.
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
        let section_headers = SectionHeader::read_sections(
            reader,
            sections_offset,
            coff_header.number_of_sections as usize,
        )?;

        Ok(Self {
            dos_header,
            coff_header,
            optional_header,
            section_headers,
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

    /// Get a section header by name.
    pub fn section_by_name(&self, name: &str) -> Option<&SectionHeader> {
        self.section_headers.iter().find(|s| s.name_str() == name)
    }

    /// Convert an RVA to a file offset.
    pub fn rva_to_offset(&self, rva: u32) -> Option<u32> {
        for section in &self.section_headers {
            if let Some(offset) = section.rva_to_offset(rva) {
                return Some(offset);
            }
        }
        None
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
