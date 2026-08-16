use super::*;

impl PeImage {
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

    /// Read an owned RVA range, including ranges in the PE headers and ranges
    /// that cross contiguous section boundaries.
    #[must_use]
    pub fn read_rva(&self, rva: u32, len: usize) -> Option<Vec<u8>> {
        if len == 0 {
            return Some(Vec::new());
        }

        let end_rva = u64::from(rva).checked_add(len as u64)?;
        if end_rva > u64::from(self.optional_header.size_of_image()) {
            return None;
        }
        if !self.contains_rva_range(rva, len) {
            return None;
        }

        let mut output = Vec::new();
        output.try_reserve_exact(len).ok()?;
        let mut current_rva = rva;
        while output.len() < len {
            if current_rva < self.optional_header.size_of_headers() {
                let header_bytes = self.build_headers().ok()?;
                let start = current_rva as usize;
                let header_limit = self.optional_header.size_of_headers() as usize;
                let available = header_limit.checked_sub(start)?;
                let count = available.min(len - output.len());
                if count == 0 {
                    return None;
                }
                let initialized = header_bytes.len().saturating_sub(start).min(count);
                if initialized != 0 {
                    output.extend_from_slice(&header_bytes[start..start + initialized]);
                }
                output.resize(output.len() + count - initialized, 0);
                current_rva = current_rva.checked_add(u32::try_from(count).ok()?)?;
                continue;
            }

            let section = self.section_by_rva(current_rva)?;
            let section_offset = current_rva.checked_sub(section.header.virtual_address)? as usize;
            let available = section.data.len().checked_sub(section_offset)?;
            let count = available.min(len - output.len());
            if count == 0 {
                return None;
            }
            output.extend_from_slice(&section.data[section_offset..section_offset + count]);
            current_rva = current_rva.checked_add(u32::try_from(count).ok()?)?;
        }

        Some(output)
    }

    /// Test whether an RVA range is available without allocating or copying it.
    #[must_use]
    pub fn contains_rva_range(&self, rva: u32, len: usize) -> bool {
        if len == 0 {
            return rva <= self.optional_header.size_of_image();
        }
        let Ok(len_u64) = u64::try_from(len) else {
            return false;
        };
        let Some(end) = u64::from(rva).checked_add(len_u64) else {
            return false;
        };
        if end > u64::from(self.optional_header.size_of_image()) {
            return false;
        }

        let mut current = rva;
        let mut remaining = len;
        while remaining != 0 {
            if current < self.optional_header.size_of_headers() {
                let available = (self.optional_header.size_of_headers() - current) as usize;
                let count = available.min(remaining);
                let Ok(count_u32) = u32::try_from(count) else {
                    return false;
                };
                let Some(next) = current.checked_add(count_u32) else {
                    return false;
                };
                current = next;
                remaining -= count;
                continue;
            }
            let Some(section) = self.section_by_rva(current) else {
                return false;
            };
            let Some(relative) = current.checked_sub(section.header.virtual_address) else {
                return false;
            };
            let Some(available) = section.data.len().checked_sub(relative as usize) else {
                return false;
            };
            let count = available.min(remaining);
            if count == 0 {
                return false;
            }
            let Ok(count_u32) = u32::try_from(count) else {
                return false;
            };
            let Some(next) = current.checked_add(count_u32) else {
                return false;
            };
            current = next;
            remaining -= count;
        }
        true
    }

    /// Write data at an RVA.
    #[must_use]
    pub fn write_at_rva(&mut self, rva: u32, data: &[u8]) -> Option<()> {
        let section = self.section_by_rva_mut(rva)?;
        let slice = section.data_at_rva_mut(rva, data.len())?;
        slice.copy_from_slice(data);
        Some(())
    }

    /// Convert an RVA to an image-relative source offset for the requested layout.
    ///
    /// When using [`Self::read_from`] with a nonzero `base_offset`, add that base
    /// to the returned value before reading from the original source.
    #[must_use]
    pub fn rva_to_source_offset(&self, rva: u32, layout: SourceLayout) -> Option<u32> {
        if rva >= self.optional_header.size_of_image() {
            return None;
        }

        match layout {
            SourceLayout::Mapped => Some(rva),
            SourceLayout::File => {
                if rva < self.optional_header.size_of_headers() {
                    return Some(rva);
                }
                self.sections
                    .iter()
                    .find_map(|section| section.header.rva_to_offset(rva))
            }
        }
    }

    /// Convert an RVA to a raw-file offset.
    #[must_use]
    pub fn rva_to_offset(&self, rva: u32) -> Option<u32> {
        self.rva_to_source_offset(rva, SourceLayout::File)
    }

    /// Add a new section.
    pub fn add_section(&mut self, section: Section) {
        self.try_add_section(section)
            .expect("too many PE sections: use try_add_section() for fallible updates");
    }

    /// Add a section while enforcing the executable-image section limit.
    pub fn try_add_section(&mut self, section: Section) -> Result<()> {
        if self.sections.len() >= MAX_NUMBER_OF_SECTIONS {
            return Err(Error::invalid_section(format!(
                "section count would exceed the PE image limit of {}",
                MAX_NUMBER_OF_SECTIONS
            )));
        }
        u32::try_from(section.data.len())
            .map_err(|_| Error::invalid_section("section data exceeds u32"))?;
        self.sections.push(section);
        self.coff_header.number_of_sections = u16::try_from(self.sections.len())
            .map_err(|_| Error::invalid_section("section count exceeds u16"))?;
        Ok(())
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

    /// Layout used by the source from which this image was parsed.
    #[must_use]
    pub const fn source_layout(&self) -> SourceLayout {
        self.source_layout
    }

    /// Actual mapped base, or the preferred image base when not explicitly set.
    #[must_use]
    pub fn runtime_image_base(&self) -> u64 {
        self.runtime_image_base.unwrap_or_else(|| self.image_base())
    }

    /// Override the actual mapped base used for absolute-address directories.
    pub fn set_runtime_image_base(&mut self, runtime_image_base: u64) {
        self.runtime_image_base = Some(runtime_image_base);
    }

    /// Convert an RVA to a VA using the actual mapped base when known.
    #[must_use]
    pub fn rva_to_runtime_va(&self, rva: u32) -> Option<u64> {
        self.rva_to_va_at(rva, self.runtime_image_base())
    }

    /// Convert a runtime VA to an RVA using the actual mapped base when known.
    #[must_use]
    pub fn runtime_va_to_rva(&self, va: u64) -> Option<u32> {
        self.va_to_rva_at(va, self.runtime_image_base())
    }

    /// Convert an RVA to a VA using the preferred image base.
    #[must_use]
    pub fn rva_to_va(&self, rva: u32) -> Option<u64> {
        self.rva_to_va_at(rva, self.image_base())
    }

    /// Convert an RVA to a VA using an explicit runtime image base.
    #[must_use]
    pub fn rva_to_va_at(&self, rva: u32, runtime_image_base: u64) -> Option<u64> {
        (rva < self.optional_header.size_of_image())
            .then(|| runtime_image_base.checked_add(u64::from(rva)))?
    }

    /// Convert a preferred-base VA to an RVA.
    #[must_use]
    pub fn va_to_rva(&self, va: u64) -> Option<u32> {
        self.va_to_rva_at(va, self.image_base())
    }

    /// Convert a VA to an RVA using an explicit runtime image base.
    #[must_use]
    pub fn va_to_rva_at(&self, va: u64, runtime_image_base: u64) -> Option<u32> {
        let relative = va.checked_sub(runtime_image_base)?;
        let rva = u32::try_from(relative).ok()?;
        (rva < self.optional_header.size_of_image()).then_some(rva)
    }

    /// Return the raw bytes covered by a standard RVA-based data directory.
    ///
    /// This is the lossless fallback for versioned or architecture-specific
    /// directory formats. The Security directory is intentionally rejected
    /// because its address is a file offset; use [`crate::PeFile::directory_data`]
    /// for a complete raw-file view.
    pub fn directory_data(
        &self,
        dir_type: crate::data_dir::DataDirectoryType,
    ) -> Result<Option<Vec<u8>>> {
        use crate::data_dir::DataDirectoryType;

        let Some(directory) = self.data_directory(dir_type).filter(|dir| dir.is_present()) else {
            return Ok(None);
        };
        if dir_type == DataDirectoryType::Security {
            return Err(Error::invalid_data_directory(
                "the Security directory uses a file offset; parse the image with PeFile",
            ));
        }
        if directory.virtual_address == 0 || directory.size == 0 {
            return Err(Error::invalid_data_directory(format!(
                "{} directory has only one of address/size set",
                dir_type.name()
            )));
        }

        self.read_rva(directory.virtual_address, directory.size as usize)
            .map(Some)
            .ok_or_else(|| {
                Error::invalid_data_directory(format!(
                    "{} directory range {:#x}..+{:#x} is not readable",
                    dir_type.name(),
                    directory.virtual_address,
                    directory.size
                ))
            })
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
                let read_fn = |rva: u32, len: usize| -> Option<Vec<u8>> { self.read_rva(rva, len) };
                crate::import::ImportTable::parse_sized(
                    d.virtual_address,
                    d.size,
                    self.is_64bit(),
                    read_fn,
                )
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
                let read_fn = |rva: u32, len: usize| -> Option<Vec<u8>> { self.read_rva(rva, len) };
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
                let read_fn = |rva: u32, len: usize| -> Option<Vec<u8>> { self.read_rva(rva, len) };
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
        self.set_data_directory_by_index(dir_type.as_index(), rva, size)
            .expect("a standard data-directory index always fits the optional header");
    }

    /// Update a data directory entry by index (for advanced use).
    pub fn set_data_directory_by_index(&mut self, index: usize, rva: u32, size: u32) -> Result<()> {
        let base_size = match &self.optional_header {
            OptionalHeader::Pe32(_) => crate::optional::OptionalHeader32::BASE_SIZE,
            OptionalHeader::Pe32Plus(_) => crate::optional::OptionalHeader64::BASE_SIZE,
        };
        let max_count = (u16::MAX as usize - base_size) / crate::data_dir::DataDirectory::SIZE;
        if index >= max_count {
            return Err(Error::invalid_data_directory(format!(
                "directory index {} cannot fit in a PE optional header",
                index
            )));
        }
        let dirs = self.optional_header.data_directories_mut();
        if dirs.len() <= index {
            dirs.resize(index + 1, crate::data_dir::DataDirectory::default());
        }
        dirs[index].virtual_address = rva;
        dirs[index].size = size;

        let count = dirs.len() as u32;
        match &mut self.optional_header {
            OptionalHeader::Pe32(header) => header.number_of_rva_and_sizes = count,
            OptionalHeader::Pe32Plus(header) => header.number_of_rva_and_sizes = count,
        }
        Ok(())
    }

    pub(super) fn ensure_data_directory_slot(
        &mut self,
        dir_type: crate::data_dir::DataDirectoryType,
    ) -> Result<()> {
        let index = dir_type.as_index();
        if self.optional_header.data_directories().len() <= index {
            self.set_data_directory_by_index(index, 0, 0)?;
        }
        Ok(())
    }

    /// Clear a data directory entry.
    pub fn clear_data_directory(&mut self, dir_type: crate::data_dir::DataDirectoryType) {
        self.set_data_directory(dir_type, 0, 0);
    }

    /// Append data to a section and return the RVA where it was placed.
    /// Returns None if the section doesn't exist.
    pub fn append_to_section(&mut self, section_name: &str, data: &[u8]) -> Option<u32> {
        self.try_append_to_section(section_name, data).ok()
    }

    /// Append data to a section with checked layout and address arithmetic.
    pub fn try_append_to_section(&mut self, section_name: &str, data: &[u8]) -> Result<u32> {
        self.try_update_layout()?;
        let section = self
            .sections
            .iter_mut()
            .find(|section| section.name() == section_name)
            .ok_or_else(|| Error::invalid_section(section_name))?;
        let offset = section.try_append_data(data)?;
        let rva = section
            .header
            .virtual_address
            .checked_add(offset)
            .ok_or_else(|| Error::invalid_section("appended section-data RVA overflow"))?;
        self.try_update_layout()?;
        Ok(rva)
    }
}
