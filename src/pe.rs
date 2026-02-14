//! Main PE file structure and parsing.
//!
//! This module provides the main [`PE`] and [`PEHeaders`] types for reading,
//! modifying, and writing Windows PE (Portable Executable) files.
//!
//! # Examples
//!
//! ## Loading and inspecting a PE file
//!
//! ```no_run
//! use portex::PE;
//!
//! // Load from file
//! let pe = PE::from_file("example.exe")?;
//!
//! // Check architecture
//! println!("64-bit: {}", pe.is_64bit());
//! println!("Entry point: {:#x}", pe.entry_point());
//! println!("Image base: {:#x}", pe.image_base());
//!
//! // List sections
//! for section in &pe.sections {
//!     println!("Section: {} (RVA: {:#x}, size: {})",
//!         section.name(),
//!         section.header.virtual_address,
//!         section.data.len());
//! }
//! # Ok::<(), portex::Error>(())
//! ```
//!
//! ## Loading just headers (efficient for large files)
//!
//! ```no_run
//! use portex::PEHeaders;
//!
//! // Just headers, no section data
//! let headers = PEHeaders::from_file("large.exe")?;
//! println!("Entry point: {:#x}", headers.entry_point());
//! println!("Number of sections: {}", headers.section_headers.len());
//! # Ok::<(), portex::Error>(())
//! ```
//!
//! ## Modifying and writing a PE file
//!
//! ```no_run
//! use portex::PE;
//!
//! let mut pe = PE::from_file("input.exe")?;
//!
//! // Modify entry point (access inner header directly)
//! match &mut pe.optional_header {
//!     portex::optional::OptionalHeader::Pe32(h) => h.address_of_entry_point = 0x1000,
//!     portex::optional::OptionalHeader::Pe32Plus(h) => h.address_of_entry_point = 0x1000,
//! }
//!
//! // Write to new file
//! pe.write_to_file("output.exe")?;
//! # Ok::<(), portex::Error>(())
//! ```

use crate::Result;
use crate::coff::{CoffHeader, PE_SIGNATURE, verify_pe_signature};
use crate::dos::DosHeader;
use crate::layout::{self, LayoutConfig};
use crate::optional::OptionalHeader;
use crate::reader::{FileReader, Reader, SliceReader};
use crate::section::{Section, SectionHeader};
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
    #[must_use = "parsing returns a PE structure that should be used"]
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
    #[must_use = "loading returns a PE structure that should be used"]
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let data = std::fs::read(path)?;
        Self::parse(&data)
    }

    /// Check if this is a 64-bit PE file.
    #[must_use]
    pub fn is_64bit(&self) -> bool {
        self.optional_header.is_pe32plus()
    }

    /// Check if this is a DLL.
    #[must_use]
    pub fn is_dll(&self) -> bool {
        self.coff_header.is_dll()
    }

    /// Get a section by name.
    #[must_use]
    pub fn section_by_name(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name() == name)
    }

    /// Get a mutable section by name.
    pub fn section_by_name_mut(&mut self, name: &str) -> Option<&mut Section> {
        self.sections.iter_mut().find(|s| s.name() == name)
    }

    /// Find the section containing an RVA.
    #[must_use]
    pub fn section_by_rva(&self, rva: u32) -> Option<&Section> {
        self.sections.iter().find(|s| s.contains_rva(rva))
    }

    /// Find the mutable section containing an RVA.
    #[must_use]
    pub fn section_by_rva_mut(&mut self, rva: u32) -> Option<&mut Section> {
        self.sections.iter_mut().find(|s| s.contains_rva(rva))
    }

    /// Read data at an RVA.
    #[must_use]
    pub fn read_at_rva(&self, rva: u32, len: usize) -> Option<&[u8]> {
        self.section_by_rva(rva)?.data_at_rva(rva, len)
    }

    /// Write data at an RVA.
    #[must_use]
    pub fn write_at_rva(&mut self, rva: u32, data: &[u8]) -> Option<()> {
        let section = self.section_by_rva_mut(rva)?;
        let slice = section.data_at_rva_mut(rva, data.len())?;
        slice.copy_from_slice(data);
        Some(())
    }

    /// Convert an RVA to a file offset.
    #[must_use]
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
    #[must_use]
    pub fn entry_point(&self) -> u32 {
        self.optional_header.address_of_entry_point()
    }

    /// Get the image base.
    #[must_use]
    pub fn image_base(&self) -> u64 {
        self.optional_header.image_base()
    }

    /// Get a data directory entry by type.
    #[must_use]
    pub fn data_directory(
        &self,
        dir_type: crate::data_dir::DataDirectoryType,
    ) -> Option<&crate::data_dir::DataDirectory> {
        self.optional_header
            .data_directories()
            .get(dir_type.as_index())
    }

    /// Get a data directory entry by index (for advanced use).
    #[must_use]
    pub fn data_directory_by_index(&self, index: usize) -> Option<&crate::data_dir::DataDirectory> {
        self.optional_header.data_directories().get(index)
    }

    /// Parse the import table.
    #[must_use = "parsing returns an import table that should be used"]
    pub fn imports(&self) -> Result<crate::import::ImportTable> {
        use crate::data_dir::DataDirectoryType;

        let dir = self
            .data_directory(DataDirectoryType::Import)
            .filter(|d| d.is_present());
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
    #[must_use = "parsing returns an export table that should be used"]
    pub fn exports(&self) -> Result<crate::export::ExportTable> {
        use crate::data_dir::DataDirectoryType;

        let dir = self
            .data_directory(DataDirectoryType::Export)
            .filter(|d| d.is_present());
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
    #[must_use = "parsing returns a relocation table that should be used"]
    pub fn relocations(&self) -> Result<crate::reloc::RelocationTable> {
        use crate::data_dir::DataDirectoryType;

        let dir = self
            .data_directory(DataDirectoryType::BaseReloc)
            .filter(|d| d.is_present());
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

    /// Update a data directory entry by type.
    pub fn set_data_directory(
        &mut self,
        dir_type: crate::data_dir::DataDirectoryType,
        rva: u32,
        size: u32,
    ) {
        let dirs = self.optional_header.data_directories_mut();
        if let Some(dir) = dirs.get_mut(dir_type.as_index()) {
            dir.virtual_address = rva;
            dir.size = size;
        }
    }

    /// Update a data directory entry by index (for advanced use).
    pub fn set_data_directory_by_index(&mut self, index: usize, rva: u32, size: u32) {
        let dirs = self.optional_header.data_directories_mut();
        if let Some(dir) = dirs.get_mut(index) {
            dir.virtual_address = rva;
            dir.size = size;
        }
    }

    /// Clear a data directory entry.
    pub fn clear_data_directory(&mut self, dir_type: crate::data_dir::DataDirectoryType) {
        self.set_data_directory(dir_type, 0, 0);
    }

    /// Append data to a section and return the RVA where it was placed.
    /// Returns None if the section doesn't exist.
    pub fn append_to_section(&mut self, section_name: &str, data: &[u8]) -> Option<u32> {
        let section = self
            .sections
            .iter_mut()
            .find(|s| s.name() == section_name)?;
        let rva = section.header.virtual_address + section.header.virtual_size;
        section.append_data(data);
        Some(rva)
    }

    /// Update imports: tries in-place replacement first, otherwise appends to target section.
    /// If target_section is None, uses the section containing existing imports, or ".rdata", or last section.
    /// Returns the import RVA on success.
    pub fn update_imports(
        &mut self,
        imports: crate::import::ImportTable,
        target_section: Option<&str>,
    ) -> Result<u32> {
        use crate::data_dir::DataDirectoryType;
        use crate::import::ImportTableBuilder;

        if imports.is_empty() {
            self.clear_data_directory(DataDirectoryType::Import);
            self.clear_data_directory(DataDirectoryType::Iat);
            return Ok(0);
        }

        // Calculate required size
        let builder_temp = ImportTableBuilder::new(self.is_64bit(), 0);
        let required_size = builder_temp.calculate_size(&imports);

        // Check if we can replace in-place
        let existing_dir = self.data_directory(DataDirectoryType::Import).cloned();
        if let Some(ref dir) = existing_dir
            && dir.is_present()
            && dir.size as usize >= required_size
        {
            // Can replace in-place
            let builder = ImportTableBuilder::new(self.is_64bit(), dir.virtual_address);
            let (data, iat_rva, iat_size) = builder.build(&imports);

            if self.write_at_rva(dir.virtual_address, &data).is_some() {
                let import_size =
                    (imports.dlls.len() + 1) as u32 * crate::import::ImportDescriptor::SIZE as u32;
                self.set_data_directory(
                    DataDirectoryType::Import,
                    dir.virtual_address,
                    import_size,
                );
                self.set_data_directory(DataDirectoryType::Iat, iat_rva, iat_size);
                return Ok(dir.virtual_address);
            }
        }

        // Find target section to append to:
        // 1. User-specified section
        // 2. Section containing existing imports (if any)
        // 3. .rdata
        // 4. Last section
        let section_name: String = target_section
            .map(|s| s.to_string())
            .or_else(|| {
                // Try to find section containing existing import directory
                if let Some(ref dir) = existing_dir
                    && dir.is_present()
                    && let Some(section) = self.section_by_rva(dir.virtual_address)
                {
                    return Some(section.name().to_string());
                }
                None
            })
            .or_else(|| {
                if self.section_by_name(".rdata").is_some() {
                    Some(".rdata".to_string())
                } else {
                    self.sections.last().map(|s| s.name().to_string())
                }
            })
            .unwrap_or_else(|| ".rdata".to_string());

        // Find section index (needed to avoid borrow issues)
        let section_idx = self.sections.iter().position(|s| s.name() == section_name);
        let section_idx = match section_idx {
            Some(idx) => idx,
            None => return Err(crate::Error::invalid_section(section_name)),
        };

        // Calculate RVA where data will be placed
        let append_rva = {
            let section = &self.sections[section_idx];
            section.header.virtual_address + section.header.virtual_size
        };

        // Build import data at the append RVA
        let builder = ImportTableBuilder::new(self.is_64bit(), append_rva);
        let (data, iat_rva, iat_size) = builder.build(&imports);

        // Append to section
        self.sections[section_idx].append_data(&data);

        // Update data directories
        let import_size =
            (imports.dlls.len() + 1) as u32 * crate::import::ImportDescriptor::SIZE as u32;
        self.set_data_directory(DataDirectoryType::Import, append_rva, import_size);
        self.set_data_directory(DataDirectoryType::Iat, iat_rva, iat_size);

        Ok(append_rva)
    }

    /// Update exports: tries in-place replacement first, otherwise appends to target section.
    /// If target_section is None, uses the section containing existing exports, or ".rdata", or last section.
    /// Returns the export RVA on success.
    pub fn update_exports(
        &mut self,
        exports: crate::export::ExportTable,
        target_section: Option<&str>,
    ) -> Result<u32> {
        use crate::data_dir::DataDirectoryType;
        use crate::export::ExportTableBuilder;

        if exports.is_empty() && exports.dll_name.is_empty() {
            self.clear_data_directory(DataDirectoryType::Export);
            return Ok(0);
        }

        // Calculate required size
        let builder_temp = ExportTableBuilder::new(0);
        let required_size = builder_temp.calculate_size(&exports);

        // Check if we can replace in-place
        let existing_dir = self.data_directory(DataDirectoryType::Export).cloned();
        if let Some(ref dir) = existing_dir
            && dir.is_present()
            && dir.size as usize >= required_size
        {
            // Can replace in-place
            let builder = ExportTableBuilder::new(dir.virtual_address);
            let (data, export_size) = builder.build(&exports);

            if self.write_at_rva(dir.virtual_address, &data).is_some() {
                self.set_data_directory(
                    DataDirectoryType::Export,
                    dir.virtual_address,
                    export_size,
                );
                return Ok(dir.virtual_address);
            }
        }

        // Find target section to append to:
        // 1. User-specified section
        // 2. Section containing existing exports (if any)
        // 3. .rdata
        // 4. Last section
        let section_name: String = target_section
            .map(|s| s.to_string())
            .or_else(|| {
                // Try to find section containing existing export directory
                if let Some(ref dir) = existing_dir
                    && dir.is_present()
                    && let Some(section) = self.section_by_rva(dir.virtual_address)
                {
                    return Some(section.name().to_string());
                }
                None
            })
            .or_else(|| {
                if self.section_by_name(".rdata").is_some() {
                    Some(".rdata".to_string())
                } else {
                    self.sections.last().map(|s| s.name().to_string())
                }
            })
            .unwrap_or_else(|| ".rdata".to_string());

        // Find section index (needed to avoid borrow issues)
        let section_idx = self.sections.iter().position(|s| s.name() == section_name);
        let section_idx = match section_idx {
            Some(idx) => idx,
            None => return Err(crate::Error::invalid_section(section_name)),
        };

        // Calculate RVA where data will be placed
        let append_rva = {
            let section = &self.sections[section_idx];
            section.header.virtual_address + section.header.virtual_size
        };

        // Build export data at the append RVA
        let builder = ExportTableBuilder::new(append_rva);
        let (data, export_size) = builder.build(&exports);

        // Append to section
        self.sections[section_idx].append_data(&data);

        // Update data directory
        self.set_data_directory(DataDirectoryType::Export, append_rva, export_size);

        Ok(append_rva)
    }

    /// Recalculate layout (section RVAs, file offsets, sizes) and update headers in place.
    /// Call this after modifying sections if you want to persist layout changes to the PE struct.
    pub fn update_layout(&mut self) {
        let config = LayoutConfig::from_optional_header(&self.optional_header);

        // Calculate headers size
        let headers_size =
            layout::headers_size(self.sections.len(), self.optional_header.size()) as u32;

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
    /// This method does not mutate self - it computes layout on a clone.
    pub fn build(&self) -> Vec<u8> {
        // Clone and update layout
        let mut pe = self.clone();
        pe.update_layout();
        pe.write_bytes()
    }

    /// Write the PE bytes without updating layout.
    /// Use this if you've already called update_layout() and want to avoid redundant work.
    fn write_bytes(&self) -> Vec<u8> {
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
        self.dos_header
            .write(&mut output[0..DosHeader::SIZE])
            .expect("DOS header write failed: buffer size was calculated");

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
            .expect("COFF header write failed: buffer size was calculated");

        // Write optional header
        let optional_offset = coff_offset + CoffHeader::SIZE;
        let optional_size = self.optional_header.size();
        self.optional_header
            .write(&mut output[optional_offset..optional_offset + optional_size])
            .expect("Optional header write failed: buffer size was calculated");

        // Write section headers
        let sections_offset = optional_offset + self.coff_header.size_of_optional_header as usize;
        for (i, section) in self.sections.iter().enumerate() {
            let offset = sections_offset + i * SectionHeader::SIZE;
            section
                .header
                .write(&mut output[offset..offset + SectionHeader::SIZE])
                .expect("Section header write failed: buffer size was calculated");
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
    /// This method does not mutate self - it computes layout on a clone.
    pub fn write_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let bytes = self.build();
        let mut file = File::create(path)?;
        file.write_all(&bytes)?;
        Ok(())
    }

    // ========== New PE Integration Methods ==========

    /// Parse the TLS directory.
    pub fn tls(&self) -> Result<Option<crate::tls::TlsInfo>> {
        use crate::data_dir::DataDirectoryType;

        let dir = self
            .data_directory(DataDirectoryType::Tls)
            .filter(|d| d.is_present());
        match dir {
            Some(d) => {
                let read_fn = |rva: u32, len: usize| -> Option<Vec<u8>> {
                    self.read_at_rva(rva, len).map(|s| s.to_vec())
                };
                Ok(Some(crate::tls::TlsInfo::parse(
                    d.virtual_address,
                    d.size,
                    self.image_base(),
                    self.is_64bit(),
                    read_fn,
                )?))
            }
            None => Ok(None),
        }
    }

    /// Parse the debug directory.
    pub fn debug_info(&self) -> Result<Option<crate::debug::DebugInfo>> {
        use crate::data_dir::DataDirectoryType;

        let dir = self
            .data_directory(DataDirectoryType::Debug)
            .filter(|d| d.is_present());
        match dir {
            Some(d) => {
                let read_fn = |rva: u32, len: usize| -> Option<Vec<u8>> {
                    self.read_at_rva(rva, len).map(|s| s.to_vec())
                };
                Ok(Some(crate::debug::DebugInfo::parse(
                    d.virtual_address,
                    d.size,
                    read_fn,
                )?))
            }
            None => Ok(None),
        }
    }

    /// Parse the rich header (if present).
    pub fn rich_header(&self) -> Option<crate::rich::RichHeader> {
        crate::rich::RichHeader::parse(&self.dos_stub)
    }

    /// Parse the exception directory (.pdata).
    pub fn exception_directory(&self) -> Result<crate::exception::ExceptionDirectory> {
        use crate::data_dir::DataDirectoryType;

        let dir = self
            .data_directory(DataDirectoryType::Exception)
            .filter(|d| d.is_present());
        match dir {
            Some(d) => {
                let read_fn = |rva: u32, len: usize| -> Option<Vec<u8>> {
                    self.read_at_rva(rva, len).map(|s| s.to_vec())
                };
                crate::exception::ExceptionDirectory::parse(d.virtual_address, d.size, read_fn)
            }
            None => Ok(crate::exception::ExceptionDirectory::default()),
        }
    }

    /// Parse the load config directory.
    pub fn load_config(&self) -> Result<Option<crate::loadconfig::LoadConfigDirectory>> {
        use crate::data_dir::DataDirectoryType;

        let dir = self
            .data_directory(DataDirectoryType::LoadConfig)
            .filter(|d| d.is_present());
        match dir {
            Some(d) => {
                let data = self
                    .read_at_rva(d.virtual_address, d.size as usize)
                    .ok_or(crate::Error::invalid_rva(d.virtual_address))?;
                Ok(Some(crate::loadconfig::LoadConfigDirectory::parse(
                    data,
                    self.is_64bit(),
                )?))
            }
            None => Ok(None),
        }
    }

    /// Parse the resource directory (metadata only).
    ///
    /// To also load the actual resource data, use `resources_with_data()`.
    pub fn resources(&self) -> Result<crate::resource::ResourceDirectory> {
        use crate::data_dir::DataDirectoryType;

        let dir = self
            .data_directory(DataDirectoryType::Resource)
            .filter(|d| d.is_present());
        match dir {
            Some(d) => {
                let read_fn = |rva: u32, len: usize| -> Option<Vec<u8>> {
                    self.read_at_rva(rva, len).map(|s| s.to_vec())
                };
                crate::resource::ResourceDirectory::parse(d.virtual_address, d.size, read_fn)
            }
            None => Ok(crate::resource::ResourceDirectory::default()),
        }
    }

    /// Parse the resource directory including resource data.
    ///
    /// This is slower than `resources()` but loads each resource's data into the `Resource::data` field.
    pub fn resources_with_data(&self) -> Result<crate::resource::ResourceDirectory> {
        use crate::data_dir::DataDirectoryType;

        let dir = self
            .data_directory(DataDirectoryType::Resource)
            .filter(|d| d.is_present());
        match dir {
            Some(d) => {
                let read_fn = |rva: u32, len: usize| -> Option<Vec<u8>> {
                    self.read_at_rva(rva, len).map(|s| s.to_vec())
                };
                crate::resource::ResourceDirectory::parse_with_data(
                    d.virtual_address,
                    d.size,
                    read_fn,
                )
            }
            None => Ok(crate::resource::ResourceDirectory::default()),
        }
    }

    /// Update relocations: tries in-place replacement first, otherwise appends to target section.
    pub fn update_relocations(
        &mut self,
        relocs: crate::reloc::RelocationTable,
        target_section: Option<&str>,
    ) -> Result<u32> {
        use crate::data_dir::DataDirectoryType;

        if relocs.blocks.is_empty() {
            self.clear_data_directory(DataDirectoryType::BaseReloc);
            return Ok(0);
        }

        let data = relocs.build();
        let required_size = data.len();

        // Check if we can replace in-place
        let existing_dir = self.data_directory(DataDirectoryType::BaseReloc).cloned();
        if let Some(ref dir) = existing_dir
            && dir.is_present()
            && dir.size as usize >= required_size
            && self.write_at_rva(dir.virtual_address, &data).is_some()
        {
            self.set_data_directory(
                DataDirectoryType::BaseReloc,
                dir.virtual_address,
                data.len() as u32,
            );
            return Ok(dir.virtual_address);
        }

        // Find target section
        let section_name: String = target_section
            .map(|s| s.to_string())
            .or_else(|| {
                if let Some(ref dir) = existing_dir
                    && dir.is_present()
                    && let Some(section) = self.section_by_rva(dir.virtual_address)
                {
                    return Some(section.name().to_string());
                }
                None
            })
            .or_else(|| {
                if self.section_by_name(".reloc").is_some() {
                    Some(".reloc".to_string())
                } else if self.section_by_name(".rdata").is_some() {
                    Some(".rdata".to_string())
                } else {
                    self.sections.last().map(|s| s.name().to_string())
                }
            })
            .unwrap_or_else(|| ".reloc".to_string());

        let section_idx = self.sections.iter().position(|s| s.name() == section_name);
        let section_idx = match section_idx {
            Some(idx) => idx,
            None => return Err(crate::Error::invalid_section(section_name)),
        };

        let append_rva = {
            let section = &self.sections[section_idx];
            section.header.virtual_address + section.header.virtual_size
        };

        self.sections[section_idx].append_data(&data);
        self.set_data_directory(DataDirectoryType::BaseReloc, append_rva, data.len() as u32);

        Ok(append_rva)
    }

    /// Update resources: tries in-place replacement first, otherwise appends to target section.
    pub fn update_resources(
        &mut self,
        builder: &crate::resource::ResourceBuilder,
        target_section: Option<&str>,
    ) -> Result<u32> {
        use crate::data_dir::DataDirectoryType;

        let required_size = builder.calculate_size();
        if required_size == 0 {
            self.clear_data_directory(DataDirectoryType::Resource);
            return Ok(0);
        }

        // Check if we can replace in-place
        let existing_dir = self.data_directory(DataDirectoryType::Resource).cloned();
        if let Some(ref dir) = existing_dir
            && dir.is_present()
            && dir.size as usize >= required_size
        {
            let (data, size) = builder.build(dir.virtual_address);
            if self.write_at_rva(dir.virtual_address, &data).is_some() {
                self.set_data_directory(DataDirectoryType::Resource, dir.virtual_address, size);
                return Ok(dir.virtual_address);
            }
        }

        // Find target section
        let section_name: String = target_section
            .map(|s| s.to_string())
            .or_else(|| {
                if let Some(ref dir) = existing_dir
                    && dir.is_present()
                    && let Some(section) = self.section_by_rva(dir.virtual_address)
                {
                    return Some(section.name().to_string());
                }
                None
            })
            .or_else(|| {
                if self.section_by_name(".rsrc").is_some() {
                    Some(".rsrc".to_string())
                } else if self.section_by_name(".rdata").is_some() {
                    Some(".rdata".to_string())
                } else {
                    self.sections.last().map(|s| s.name().to_string())
                }
            })
            .unwrap_or_else(|| ".rsrc".to_string());

        let section_idx = self.sections.iter().position(|s| s.name() == section_name);
        let section_idx = match section_idx {
            Some(idx) => idx,
            None => return Err(crate::Error::invalid_section(section_name)),
        };

        let append_rva = {
            let section = &self.sections[section_idx];
            section.header.virtual_address + section.header.virtual_size
        };

        let (data, size) = builder.build(append_rva);
        self.sections[section_idx].append_data(&data);
        self.set_data_directory(DataDirectoryType::Resource, append_rva, size);

        Ok(append_rva)
    }

    /// Calculate and return the PE checksum.
    pub fn calculate_checksum(&self) -> u32 {
        let data = self.build();
        crate::checksum::compute_pe_checksum(&data).unwrap_or(0)
    }

    /// Update the checksum field in the optional header.
    pub fn update_checksum(&mut self) {
        let checksum = self.calculate_checksum();
        match &mut self.optional_header {
            OptionalHeader::Pe32(h) => h.check_sum = checksum,
            OptionalHeader::Pe32Plus(h) => h.check_sum = checksum,
        }
    }

    /// Read resource data at the given RVA.
    pub fn read_resource_data(&self, resource: &crate::resource::Resource) -> Option<Vec<u8>> {
        self.read_at_rva(resource.data_rva, resource.size as usize)
            .map(|s| s.to_vec())
    }

    // ========== Validation ==========

    /// Validate PE structural integrity.
    ///
    /// Returns a collection of validation issues (errors and warnings).
    /// An empty result means the PE passed all validation checks.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use portex::PE;
    ///
    /// let pe = PE::from_file("test.exe").unwrap();
    /// let result = pe.validate();
    ///
    /// if result.has_errors() {
    ///     for issue in result.errors() {
    ///         eprintln!("Error: {}", issue);
    ///     }
    /// }
    /// ```
    #[must_use]
    pub fn validate(&self) -> crate::validation::ValidationResult {
        use crate::validation::{ValidationCode, ValidationIssue, ValidationResult};

        let mut result = ValidationResult::new();

        // Check DOS signature
        if self.dos_header.e_magic != 0x5A4D {
            result.push(ValidationIssue::error(
                ValidationCode::InvalidDosSignature,
                "DOS signature is not 'MZ'",
            ));
        }

        // Check sections exist
        if self.sections.is_empty() {
            result.push(ValidationIssue::warning(
                ValidationCode::NoSections,
                "PE has no sections",
            ));
        }

        // Check file alignment
        let file_align = self.optional_header.file_alignment();
        if file_align == 0 || (file_align & (file_align - 1)) != 0 || file_align < 512 {
            result.push(ValidationIssue::error(
                ValidationCode::InvalidFileAlignment,
                format!("Invalid file alignment: {:#x}", file_align),
            ));
        }

        // Check section alignment
        let section_align = self.optional_header.section_alignment();
        if section_align == 0 || (section_align & (section_align - 1)) != 0 {
            result.push(ValidationIssue::error(
                ValidationCode::InvalidSectionAlignment,
                format!("Invalid section alignment: {:#x}", section_align),
            ));
        }

        // Check entry point is within a section (or is 0 for DLLs)
        let entry = self.optional_header.address_of_entry_point();
        if entry != 0 {
            let entry_in_section = self.sections.iter().any(|s| s.header.contains_rva(entry));
            if !entry_in_section {
                result.push(ValidationIssue::warning(
                    ValidationCode::EntryPointOutOfBounds,
                    format!("Entry point {:#x} is not within any section", entry),
                ));
            }
        }

        // Check for overlapping sections (file offsets)
        for (i, s1) in self.sections.iter().enumerate() {
            if s1.header.pointer_to_raw_data == 0 || s1.header.size_of_raw_data == 0 {
                continue;
            }
            let s1_end = s1.header.pointer_to_raw_data + s1.header.size_of_raw_data;
            for s2 in self.sections.iter().skip(i + 1) {
                if s2.header.pointer_to_raw_data == 0 || s2.header.size_of_raw_data == 0 {
                    continue;
                }
                let s2_end = s2.header.pointer_to_raw_data + s2.header.size_of_raw_data;
                // Check overlap
                if s1.header.pointer_to_raw_data < s2_end && s2.header.pointer_to_raw_data < s1_end
                {
                    result.push(
                        ValidationIssue::error(
                            ValidationCode::OverlappingSections,
                            format!(
                                "Sections '{}' and '{}' overlap in file",
                                s1.header.name_str(),
                                s2.header.name_str()
                            ),
                        )
                        .with_context(format!(
                            "{}: {:#x}-{:#x}, {}: {:#x}-{:#x}",
                            s1.header.name_str(),
                            s1.header.pointer_to_raw_data,
                            s1_end,
                            s2.header.name_str(),
                            s2.header.pointer_to_raw_data,
                            s2_end
                        )),
                    );
                }
            }
        }

        // Check for overlapping sections (virtual addresses)
        for (i, s1) in self.sections.iter().enumerate() {
            if s1.header.virtual_size == 0 {
                continue;
            }
            let s1_end = s1.header.virtual_address + s1.header.virtual_size;
            for s2 in self.sections.iter().skip(i + 1) {
                if s2.header.virtual_size == 0 {
                    continue;
                }
                let s2_end = s2.header.virtual_address + s2.header.virtual_size;
                if s1.header.virtual_address < s2_end && s2.header.virtual_address < s1_end {
                    result.push(
                        ValidationIssue::error(
                            ValidationCode::OverlappingSections,
                            format!(
                                "Sections '{}' and '{}' overlap in virtual memory",
                                s1.header.name_str(),
                                s2.header.name_str()
                            ),
                        )
                        .with_context(format!(
                            "{}: {:#x}-{:#x}, {}: {:#x}-{:#x}",
                            s1.header.name_str(),
                            s1.header.virtual_address,
                            s1_end,
                            s2.header.name_str(),
                            s2.header.virtual_address,
                            s2_end
                        )),
                    );
                }
            }
        }

        // Check data directories point to valid sections
        use crate::data_dir::DataDirectoryType;
        for dir_type in DataDirectoryType::all() {
            if let Some(dir) = self.data_directory(dir_type)
                && dir.is_present()
            {
                let rva = dir.virtual_address;
                let in_section = self.sections.iter().any(|s| s.header.contains_rva(rva));
                if !in_section {
                    result.push(
                        ValidationIssue::warning(
                            ValidationCode::InvalidDataDirectoryRva,
                            format!(
                                "Data directory {} RVA {:#x} is not within any section",
                                dir_type.name(),
                                rva
                            ),
                        )
                        .with_context(dir_type.name().to_string()),
                    );
                }
            }
        }

        // Check checksum (only warn if non-zero and doesn't match)
        let stored_checksum = match &self.optional_header {
            OptionalHeader::Pe32(h) => h.check_sum,
            OptionalHeader::Pe32Plus(h) => h.check_sum,
        };
        if stored_checksum != 0 {
            let computed = self.calculate_checksum();
            if stored_checksum != computed {
                result.push(ValidationIssue::warning(
                    ValidationCode::InvalidChecksum,
                    format!(
                        "Checksum mismatch: stored {:#x}, computed {:#x}",
                        stored_checksum, computed
                    ),
                ));
            }
        }

        result
    }
}

impl PEHeaders {
    /// Read PE headers from any Reader implementation.
    #[must_use = "parsing returns PE headers that should be used"]
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
    #[must_use = "loading returns PE headers that should be used"]
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let reader = FileReader::open(path)?;
        Self::read_from(&reader, 0)
    }

    /// Read headers from a byte slice.
    #[must_use = "parsing returns PE headers that should be used"]
    pub fn from_slice(data: &[u8]) -> Result<Self> {
        let reader = SliceReader::new(data);
        Self::read_from(&reader, 0)
    }

    /// Check if this is a 64-bit PE.
    #[must_use]
    pub fn is_64bit(&self) -> bool {
        self.optional_header.is_pe32plus()
    }

    /// Check if this is a DLL.
    #[must_use]
    pub fn is_dll(&self) -> bool {
        self.coff_header.is_dll()
    }

    /// Get a section header by name.
    #[must_use]
    pub fn section_by_name(&self, name: &str) -> Option<&SectionHeader> {
        self.section_headers.iter().find(|s| s.name_str() == name)
    }

    /// Convert an RVA to a file offset.
    #[must_use]
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

    #[test]
    fn test_parse_invalid_dos_signature() {
        let data = vec![0u8; 256];
        let result = PE::parse(&data);
        assert!(matches!(
            result,
            Err(ref e) if matches!(e.kind, crate::error::ErrorKind::InvalidDosSignature)
        ));
    }

    #[test]
    fn test_parse_buffer_too_small() {
        let data = vec![0x4D, 0x5A]; // Just MZ
        let result = PE::parse(&data);
        assert!(matches!(
            result,
            Err(ref e) if matches!(e.kind, crate::error::ErrorKind::BufferTooSmall { .. })
        ));
    }

    #[test]
    fn test_headers_parse_invalid() {
        let data = vec![0u8; 256];
        let result = PEHeaders::from_slice(&data);
        assert!(matches!(
            result,
            Err(ref e) if matches!(e.kind, crate::error::ErrorKind::InvalidDosSignature)
        ));
    }
}
