use super::*;

impl PeImage {
    pub(super) fn prepare_section_append(&mut self, section_index: usize) -> Result<u32> {
        self.try_update_layout()?;
        let section = self
            .sections
            .get(section_index)
            .ok_or_else(|| Error::invalid_section("section index is out of range"))?;
        let offset = u32::try_from(section.data.len())
            .map_err(|_| Error::invalid_section("section data exceeds u32"))?;
        section
            .header
            .virtual_address
            .checked_add(offset)
            .ok_or_else(|| Error::invalid_section("appended section-data RVA overflow"))
    }

    pub(super) fn commit_section_append(
        &mut self,
        section_index: usize,
        expected_rva: u32,
        data: &[u8],
    ) -> Result<()> {
        let mut candidate = self.clone();
        let section = candidate
            .sections
            .get_mut(section_index)
            .ok_or_else(|| Error::invalid_section("section index is out of range"))?;
        let offset = section.try_append_data(data)?;
        candidate.try_update_layout()?;
        let section = &candidate.sections[section_index];
        let actual_rva = section
            .header
            .virtual_address
            .checked_add(offset)
            .ok_or_else(|| Error::invalid_section("appended section-data RVA overflow"))?;
        if actual_rva != expected_rva {
            return Err(Error::invalid_section(
                "target section moved while appending address-bearing data",
            ));
        }
        *self = candidate;
        Ok(())
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
        self.ensure_data_directory_slot(DataDirectoryType::Iat)?;

        // Calculate required size
        let builder_temp = ImportTableBuilder::new(self.is_64bit(), 0);
        let required_size = builder_temp.try_calculate_size(&imports)?;

        // Check if we can replace in-place
        let existing_dir = self.data_directory(DataDirectoryType::Import).cloned();
        if let Some(ref dir) = existing_dir
            && dir.is_present()
            && dir.size as usize >= required_size
        {
            // Can replace in-place
            let builder = ImportTableBuilder::new(self.is_64bit(), dir.virtual_address);
            let (data, iat_rva, iat_size) = builder.try_build(&imports)?;

            if self.write_at_rva(dir.virtual_address, &data).is_some() {
                let import_size = import_descriptor_table_size(imports.dlls.len())?;
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
        let append_rva = self.prepare_section_append(section_idx)?;

        // Build import data at the append RVA
        let builder = ImportTableBuilder::new(self.is_64bit(), append_rva);
        let (data, iat_rva, iat_size) = builder.try_build(&imports)?;

        // Append to section
        self.commit_section_append(section_idx, append_rva, &data)?;

        // Update data directories
        let import_size = import_descriptor_table_size(imports.dlls.len())?;
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
        self.ensure_data_directory_slot(DataDirectoryType::Export)?;

        // Calculate required size
        let builder_temp = ExportTableBuilder::new(0);
        let required_size = builder_temp.try_calculate_size(&exports)?;

        // Check if we can replace in-place
        let existing_dir = self.data_directory(DataDirectoryType::Export).cloned();
        if let Some(ref dir) = existing_dir
            && dir.is_present()
            && dir.size as usize >= required_size
        {
            // Can replace in-place
            let builder = ExportTableBuilder::new(dir.virtual_address);
            let (data, export_size) = builder.try_build(&exports)?;

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
        let append_rva = self.prepare_section_append(section_idx)?;

        // Build export data at the append RVA
        let builder = ExportTableBuilder::new(append_rva);
        let (data, export_size) = builder.try_build(&exports)?;

        // Append to section
        self.commit_section_append(section_idx, append_rva, &data)?;

        // Update data directory
        self.set_data_directory(DataDirectoryType::Export, append_rva, export_size);

        Ok(append_rva)
    }

    /// Recalculate layout, panicking if manually-constructed state cannot be
    /// represented. Prefer [`Self::try_update_layout`] for fallible workflows.
    pub fn update_layout(&mut self) {
        self.try_update_layout().expect(
            "PE layout failed: use PeImage::try_update_layout() to handle invalid structures",
        );
    }

    /// Recalculate section RVAs/file offsets and all derived header fields.
    ///
    /// The update is atomic: if an address, size, or aggregate overflows, the
    /// image is left unchanged.
    pub fn try_update_layout(&mut self) -> Result<()> {
        let config = LayoutConfig::from_optional_header(&self.optional_header);
        validate_layout_config(&config)?;
        if self.sections.len() > MAX_NUMBER_OF_SECTIONS {
            return Err(Error::invalid_section(format!(
                "section count {} exceeds the PE image limit of {}",
                self.sections.len(),
                MAX_NUMBER_OF_SECTIONS
            )));
        }

        // Calculate headers size
        let pe_offset = usize::try_from(self.dos_header.e_lfanew)
            .map_err(|_| Error::invalid_section("e_lfanew is negative"))?;
        if pe_offset < DosHeader::SIZE {
            return Err(Error::invalid_section(
                "e_lfanew places the PE header inside the DOS header",
            ));
        }
        let actual_optional_size = self.optional_header.size();
        let declared_optional_size = usize::from(self.coff_header.size_of_optional_header);
        let serialized_optional_size = actual_optional_size.max(declared_optional_size);
        let serialized_optional_size_u16 = u16::try_from(serialized_optional_size)
            .map_err(|_| Error::invalid_section("optional header exceeds u16"))?;
        let headers_size =
            layout::headers_size_at(pe_offset, self.sections.len(), serialized_optional_size)
                .and_then(|size| u32::try_from(size).ok())
                .ok_or_else(|| Error::invalid_section("header table exceeds u32"))?;
        let size_of_headers = layout::checked_align_up(headers_size, config.file_alignment)
            .ok_or_else(|| Error::invalid_section("SizeOfHeaders exceeds u32"))?;

        // Work on a clone so an overflow cannot leave half-updated sections.
        let mut sections = self.sections.clone();
        layout::try_layout_sections(&mut sections, &config, headers_size)?;

        // Update size_of_image
        let size_of_image = layout::try_calculate_size_of_image(&sections, &config)?;
        let aggregates = calculate_optional_layout_fields(&sections)?;
        let section_count = u16::try_from(sections.len())
            .map_err(|_| Error::invalid_section("section count exceeds u16"))?;
        let directory_count = u32::try_from(self.optional_header.data_directories().len())
            .map_err(|_| Error::invalid_data_directory("data-directory count exceeds u32"))?;

        self.sections = sections;
        self.set_size_of_headers(size_of_headers);
        self.set_size_of_image(size_of_image);
        self.apply_optional_layout_fields(aggregates, directory_count);

        // Update COFF header
        self.coff_header.number_of_sections = section_count;
        self.coff_header.size_of_optional_header = serialized_optional_size_u16;
        Ok(())
    }

    fn apply_optional_layout_fields(&mut self, fields: OptionalLayoutFields, count: u32) {
        match &mut self.optional_header {
            OptionalHeader::Pe32(header) => {
                header.size_of_code = fields.size_of_code;
                header.size_of_initialized_data = fields.size_of_initialized_data;
                header.size_of_uninitialized_data = fields.size_of_uninitialized_data;
                header.base_of_code = fields.base_of_code;
                header.base_of_data = fields.base_of_data;
                header.number_of_rva_and_sizes = count;
            }
            OptionalHeader::Pe32Plus(header) => {
                header.size_of_code = fields.size_of_code;
                header.size_of_initialized_data = fields.size_of_initialized_data;
                header.size_of_uninitialized_data = fields.size_of_uninitialized_data;
                header.base_of_code = fields.base_of_code;
                header.number_of_rva_and_sizes = count;
            }
        }
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

    // ========== Section Management ==========

    /// Remove a section by index. Returns the removed section, or None if index is out of bounds.
    ///
    /// **Warning**: Removing a section may break the PE if other data directories
    /// or code reference data in that section. Use with caution.
    pub fn remove_section_at(&mut self, index: usize) -> Option<Section> {
        if index < self.sections.len() {
            self.coff_header.number_of_sections = (self.sections.len() - 1) as u16;
            Some(self.sections.remove(index))
        } else {
            None
        }
    }

    /// Find a section by name.
    pub fn find_section(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name() == name)
    }

    /// Find a section by name (mutable).
    pub fn find_section_mut(&mut self, name: &str) -> Option<&mut Section> {
        self.sections.iter_mut().find(|s| s.name() == name)
    }

    /// Resize a section's data. If new size is larger, pads with zeros.
    /// If smaller, truncates the data.
    ///
    /// Returns true if the section was found and resized, false otherwise.
    pub fn resize_section(&mut self, name: &str, new_size: usize) -> bool {
        self.try_resize_section(name, new_size).unwrap_or(false)
    }

    /// Resize a section after checking that its virtual size fits in a PE
    /// section header. Returns `Ok(false)` if no section has that name.
    pub fn try_resize_section(&mut self, name: &str, new_size: usize) -> Result<bool> {
        let new_size_u32 = u32::try_from(new_size)
            .map_err(|_| Error::invalid_section("section size exceeds u32"))?;
        if let Some(section) = self.find_section_mut(name) {
            section.data.resize(new_size, 0);
            section.mapped_raw_size = None;
            section.mapped_data_len = 0;
            section.header.virtual_size = new_size_u32;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Add a new section with the given name, data, and characteristics.
    /// This is a convenience method that creates a Section from parts.
    /// The section layout (RVA, file offset) will be calculated on the next `update_layout()` or `build()`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use portex::PeImage;
    /// use portex::section::characteristics;
    ///
    /// # let file_bytes: &[u8] = &[];
    /// let mut pe = PeImage::parse(file_bytes)?;
    /// pe.add_section_with_data(".newsec", vec![0u8; 0x1000], characteristics::INITIALIZED_DATA | characteristics::READ);
    /// let rebuilt = pe.try_build()?;
    /// assert!(!rebuilt.is_empty());
    /// # Ok::<(), portex::Error>(())
    /// ```
    pub fn add_section_with_data(&mut self, name: &str, data: Vec<u8>, characteristics: u32) {
        self.try_add_section_with_data(name, data, characteristics)
            .expect("invalid PE section: use try_add_section_with_data() for fallible updates");
    }

    /// Add a section from its ergonomic parts with checked count/data size.
    pub fn try_add_section_with_data(
        &mut self,
        name: &str,
        data: Vec<u8>,
        characteristics: u32,
    ) -> Result<()> {
        let mut header = SectionHeader::default();
        header.set_name(name);
        header.characteristics = characteristics;
        self.try_add_section(Section::from_header_and_data(header, data))
    }
}

fn import_descriptor_table_size(dll_count: usize) -> Result<u32> {
    dll_count
        .checked_add(1)
        .and_then(|count| count.checked_mul(crate::import::ImportDescriptor::SIZE))
        .and_then(|size| u32::try_from(size).ok())
        .ok_or_else(|| Error::invalid_data_directory("import descriptor table exceeds u32"))
}

#[derive(Debug, Clone, Copy)]
pub(super) struct OptionalLayoutFields {
    pub(super) size_of_code: u32,
    pub(super) size_of_initialized_data: u32,
    pub(super) size_of_uninitialized_data: u32,
    pub(super) base_of_code: u32,
    pub(super) base_of_data: u32,
}

fn validate_layout_config(config: &LayoutConfig) -> Result<()> {
    let file = config.file_alignment;
    let section = config.section_alignment;
    if section == 0 || !section.is_power_of_two() {
        return Err(Error::invalid_section(format!(
            "invalid SectionAlignment {:#x}",
            section
        )));
    }
    let low_alignment = section < 0x1000;
    if file == 0
        || !file.is_power_of_two()
        || file > 0x1_0000
        || file > section
        || (low_alignment && file != section)
        || (!low_alignment && file < 0x200)
    {
        return Err(Error::invalid_section(format!(
            "invalid FileAlignment {:#x} for SectionAlignment {:#x}",
            file, section
        )));
    }
    Ok(())
}

pub(super) fn calculate_optional_layout_fields(
    sections: &[Section],
) -> Result<OptionalLayoutFields> {
    use crate::section::characteristics;

    let mut fields = OptionalLayoutFields {
        size_of_code: 0,
        size_of_initialized_data: 0,
        size_of_uninitialized_data: 0,
        base_of_code: 0,
        base_of_data: 0,
    };
    for section in sections {
        let flags = section.header.characteristics;
        if flags & characteristics::CODE != 0 {
            fields.size_of_code = fields
                .size_of_code
                .checked_add(section.header.size_of_raw_data)
                .ok_or_else(|| Error::invalid_section("SizeOfCode exceeds u32"))?;
            fields.base_of_code =
                minimum_nonzero(fields.base_of_code, section.header.virtual_address);
        }
        if flags & characteristics::INITIALIZED_DATA != 0 {
            fields.size_of_initialized_data = fields
                .size_of_initialized_data
                .checked_add(section.header.size_of_raw_data)
                .ok_or_else(|| Error::invalid_section("SizeOfInitializedData exceeds u32"))?;
            fields.base_of_data =
                minimum_nonzero(fields.base_of_data, section.header.virtual_address);
        }
        if flags & characteristics::UNINITIALIZED_DATA != 0 {
            fields.size_of_uninitialized_data = fields
                .size_of_uninitialized_data
                .checked_add(section.header.virtual_size)
                .ok_or_else(|| Error::invalid_section("SizeOfUninitializedData exceeds u32"))?;
            fields.base_of_data =
                minimum_nonzero(fields.base_of_data, section.header.virtual_address);
        }
    }
    Ok(fields)
}

fn minimum_nonzero(current: u32, candidate: u32) -> u32 {
    if current == 0 {
        candidate
    } else if candidate == 0 {
        current
    } else {
        current.min(candidate)
    }
}
