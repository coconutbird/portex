use super::*;

impl PeImage {
    // ========== Validation ==========

    /// Validate PE structural integrity.
    ///
    /// Returns a collection of validation issues (errors and warnings).
    /// An empty result means the PE passed all validation checks.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use portex::PeImage;
    ///
    /// # let file_bytes: &[u8] = &[];
    /// let pe = PeImage::parse(file_bytes).unwrap();
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

        if self.coff_header.number_of_sections as usize != self.sections.len() {
            result.push(ValidationIssue::error(
                ValidationCode::InconsistentSectionCount,
                format!(
                    "COFF declares {} sections, but {} section records are present",
                    self.coff_header.number_of_sections,
                    self.sections.len()
                ),
            ));
        }
        if self.sections.len() > MAX_NUMBER_OF_SECTIONS {
            result.push(ValidationIssue::error(
                ValidationCode::InconsistentSectionCount,
                format!(
                    "section count {} exceeds the PE image limit of {}",
                    self.sections.len(),
                    MAX_NUMBER_OF_SECTIONS
                ),
            ));
        }

        let expected_optional_size = self.optional_header.size();
        if (self.coff_header.size_of_optional_header as usize) < expected_optional_size {
            result.push(ValidationIssue::error(
                ValidationCode::InconsistentOptionalHeader,
                format!(
                    "COFF optional-header size is {}, but parsed fields require at least {} bytes",
                    self.coff_header.size_of_optional_header, expected_optional_size
                ),
            ));
        }
        let (directory_count, directory_len) = match &self.optional_header {
            OptionalHeader::Pe32(header) => (
                header.number_of_rva_and_sizes as usize,
                header.data_directories.len(),
            ),
            OptionalHeader::Pe32Plus(header) => (
                header.number_of_rva_and_sizes as usize,
                header.data_directories.len(),
            ),
        };
        if directory_count != directory_len {
            result.push(ValidationIssue::error(
                ValidationCode::InconsistentOptionalHeader,
                format!(
                    "NumberOfRvaAndSizes is {}, but {} directory entries are present",
                    directory_count, directory_len
                ),
            ));
        }

        let machine_magic_matches = crate::coff::MachineType::from_u16(self.coff_header.machine)
            .is_none_or(|machine| {
                machine == crate::coff::MachineType::Unknown
                    || machine.is_64_bit() == self.is_64bit()
            });
        if !machine_magic_matches {
            result.push(ValidationIssue::error(
                ValidationCode::MachineMagicMismatch,
                format!(
                    "machine {:#x} is inconsistent with the optional-header width",
                    self.coff_header.machine
                ),
            ));
        }

        // Check file alignment
        let file_align = self.optional_header.file_alignment();
        let section_align = self.optional_header.section_alignment();
        let low_alignment = section_align != 0 && section_align < 0x1000;
        if file_align == 0
            || !file_align.is_power_of_two()
            || file_align > 0x1_0000
            || (low_alignment && file_align != section_align)
            || (!low_alignment && file_align < 512)
        {
            result.push(ValidationIssue::error(
                ValidationCode::InvalidFileAlignment,
                format!("Invalid file alignment: {:#x}", file_align),
            ));
        }

        // Check section alignment
        if section_align == 0 || !section_align.is_power_of_two() {
            result.push(ValidationIssue::error(
                ValidationCode::InvalidSectionAlignment,
                format!("Invalid section alignment: {:#x}", section_align),
            ));
        }
        if section_align != 0 && file_align > section_align {
            result.push(ValidationIssue::error(
                ValidationCode::InvalidSectionAlignment,
                format!(
                    "file alignment {:#x} exceeds section alignment {:#x}",
                    file_align, section_align
                ),
            ));
        }

        if self.dos_header.e_lfanew < DosHeader::SIZE as i32 {
            result.push(ValidationIssue::error(
                ValidationCode::InconsistentHeadersSize,
                "e_lfanew places the PE header inside the DOS header",
            ));
        }
        let minimum_headers_size = layout::headers_size_at(
            usize::try_from(self.dos_header.e_lfanew).unwrap_or(0),
            self.sections.len(),
            self.optional_header.size(),
        )
        .and_then(|size| u32::try_from(size).ok());
        if let Some(minimum) = minimum_headers_size
            && self.optional_header.size_of_headers() < minimum
        {
            result.push(ValidationIssue::error(
                ValidationCode::InconsistentHeadersSize,
                format!(
                    "SizeOfHeaders {:#x} is smaller than the header table ending at {:#x}",
                    self.optional_header.size_of_headers(),
                    minimum
                ),
            ));
        }
        if file_align != 0
            && !self
                .optional_header
                .size_of_headers()
                .is_multiple_of(file_align)
        {
            result.push(ValidationIssue::error(
                ValidationCode::InconsistentHeadersSize,
                format!(
                    "SizeOfHeaders {:#x} is not aligned to FileAlignment {:#x}",
                    self.optional_header.size_of_headers(),
                    file_align
                ),
            ));
        }

        if file_align != 0 && file_align.is_power_of_two() {
            let declared_optional_size = usize::from(self.coff_header.size_of_optional_header);
            let expected_headers = usize::try_from(self.dos_header.e_lfanew)
                .ok()
                .and_then(|pe_offset| {
                    layout::headers_size_at(pe_offset, self.sections.len(), declared_optional_size)
                })
                .and_then(|size| u32::try_from(size).ok())
                .and_then(|size| layout::checked_align_up(size, file_align));
            if let Some(expected) = expected_headers
                && self.optional_header.size_of_headers() != expected
            {
                result.push(ValidationIssue::error(
                    ValidationCode::InconsistentHeadersSize,
                    format!(
                        "SizeOfHeaders is {:#x}, expected {:#x}",
                        self.optional_header.size_of_headers(),
                        expected
                    ),
                ));
            }
        }

        if section_align != 0 && section_align.is_power_of_two() {
            let config = LayoutConfig::from_optional_header(&self.optional_header);
            match layout::try_calculate_size_of_image(&self.sections, &config) {
                Ok(expected) if expected != self.optional_header.size_of_image() => {
                    result.push(ValidationIssue::error(
                        ValidationCode::InconsistentImageSize,
                        format!(
                            "SizeOfImage is {:#x}, expected {:#x}",
                            self.optional_header.size_of_image(),
                            expected
                        ),
                    ));
                }
                Err(error) => result.push(
                    ValidationIssue::error(
                        ValidationCode::InvalidSectionLayout,
                        "section ranges cannot produce a valid SizeOfImage",
                    )
                    .with_context(error.to_string()),
                ),
                _ => {}
            }
        }

        match super::edit::calculate_optional_layout_fields(&self.sections) {
            Ok(expected) => {
                let (size_of_code, initialized, uninitialized, base_of_code, base_of_data) =
                    match &self.optional_header {
                        OptionalHeader::Pe32(header) => (
                            header.size_of_code,
                            header.size_of_initialized_data,
                            header.size_of_uninitialized_data,
                            header.base_of_code,
                            Some(header.base_of_data),
                        ),
                        OptionalHeader::Pe32Plus(header) => (
                            header.size_of_code,
                            header.size_of_initialized_data,
                            header.size_of_uninitialized_data,
                            header.base_of_code,
                            None,
                        ),
                    };
                if size_of_code != expected.size_of_code
                    || initialized != expected.size_of_initialized_data
                    || uninitialized != expected.size_of_uninitialized_data
                    || base_of_code != expected.base_of_code
                    || base_of_data.is_some_and(|value| value != expected.base_of_data)
                {
                    // These fields are linker summaries rather than loader
                    // invariants. In particular, Microsoft's linker can count
                    // auxiliary code sections in SizeOfInitializedData even
                    // when they only carry IMAGE_SCN_CNT_CODE. Report the
                    // discrepancy without rejecting otherwise valid images.
                    result.push(
                        ValidationIssue::warning(
                            ValidationCode::InconsistentOptionalHeader,
                            "linker-derived optional-header code/data summaries differ from section characteristics",
                        )
                        .with_context(format!(
                            "declared code={size_of_code:#x}, initialized={initialized:#x}, uninitialized={uninitialized:#x}, base_of_code={base_of_code:#x}, base_of_data={base_of_data:?}; section-derived code={:#x}, initialized={:#x}, uninitialized={:#x}, base_of_code={:#x}, base_of_data={:#x}",
                            expected.size_of_code,
                            expected.size_of_initialized_data,
                            expected.size_of_uninitialized_data,
                            expected.base_of_code,
                            expected.base_of_data,
                        )),
                    );
                }
            }
            Err(error) => result.push(
                ValidationIssue::error(
                    ValidationCode::InvalidSectionLayout,
                    "section aggregates exceed PE limits",
                )
                .with_context(error.to_string()),
            ),
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
            let s1_end =
                u64::from(s1.header.pointer_to_raw_data) + u64::from(s1.header.size_of_raw_data);
            for s2 in self.sections.iter().skip(i + 1) {
                if s2.header.pointer_to_raw_data == 0 || s2.header.size_of_raw_data == 0 {
                    continue;
                }
                let s2_end = u64::from(s2.header.pointer_to_raw_data)
                    + u64::from(s2.header.size_of_raw_data);
                // Check overlap
                if u64::from(s1.header.pointer_to_raw_data) < s2_end
                    && u64::from(s2.header.pointer_to_raw_data) < s1_end
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

        for section in &self.sections {
            if file_align != 0
                && section.header.pointer_to_raw_data != 0
                && !section
                    .header
                    .pointer_to_raw_data
                    .is_multiple_of(file_align)
            {
                result.push(
                    ValidationIssue::error(
                        ValidationCode::MisalignedSection,
                        format!(
                            "section '{}' raw offset {:#x} is not aligned to {:#x}",
                            section.name(),
                            section.header.pointer_to_raw_data,
                            file_align
                        ),
                    )
                    .with_context(section.name().to_string()),
                );
            }
            if section_align != 0 && !section.header.virtual_address.is_multiple_of(section_align) {
                result.push(
                    ValidationIssue::error(
                        ValidationCode::MisalignedSection,
                        format!(
                            "section '{}' RVA {:#x} is not aligned to {:#x}",
                            section.name(),
                            section.header.virtual_address,
                            section_align
                        ),
                    )
                    .with_context(section.name().to_string()),
                );
            }
            if file_align != 0
                && section.header.size_of_raw_data != 0
                && !section.header.size_of_raw_data.is_multiple_of(file_align)
            {
                result.push(
                    ValidationIssue::error(
                        ValidationCode::MisalignedSection,
                        format!(
                            "section '{}' raw size {:#x} is not aligned to {:#x}",
                            section.name(),
                            section.header.size_of_raw_data,
                            file_align
                        ),
                    )
                    .with_context(section.name().to_string()),
                );
            }
            if section.data.is_empty() && section.header.size_of_raw_data != 0 {
                result.push(
                    ValidationIssue::warning(
                        ValidationCode::EmptySectionWithSize,
                        format!(
                            "section '{}' declares raw data but no bytes were loaded",
                            section.name()
                        ),
                    )
                    .with_context(section.name().to_string()),
                );
            }
        }

        // Check for overlapping sections (virtual addresses)
        for (i, s1) in self.sections.iter().enumerate() {
            if s1.header.virtual_size.max(s1.header.size_of_raw_data) == 0 {
                continue;
            }
            let s1_end = u64::from(s1.header.virtual_address)
                + u64::from(s1.header.virtual_size.max(s1.header.size_of_raw_data));
            for s2 in self.sections.iter().skip(i + 1) {
                if s2.header.virtual_size.max(s2.header.size_of_raw_data) == 0 {
                    continue;
                }
                let s2_end = u64::from(s2.header.virtual_address)
                    + u64::from(s2.header.virtual_size.max(s2.header.size_of_raw_data));
                if u64::from(s1.header.virtual_address) < s2_end
                    && u64::from(s2.header.virtual_address) < s1_end
                {
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
                if dir_type != DataDirectoryType::GlobalPtr
                    && (dir.virtual_address == 0 || dir.size == 0)
                {
                    result.push(
                        ValidationIssue::error(
                            ValidationCode::InvalidDataDirectoryRange,
                            format!(
                                "data directory {} has only one of address/size set",
                                dir_type.name()
                            ),
                        )
                        .with_context(dir_type.name().to_string()),
                    );
                    continue;
                }
                if matches!(
                    dir_type,
                    DataDirectoryType::Architecture | DataDirectoryType::Reserved
                ) {
                    result.push(
                        ValidationIssue::error(
                            ValidationCode::ReservedDataDirectory,
                            format!("reserved data directory {} must be zero", dir_type.name()),
                        )
                        .with_context(dir_type.name().to_string()),
                    );
                    continue;
                }
                if dir_type == DataDirectoryType::GlobalPtr && dir.size != 0 {
                    result.push(
                        ValidationIssue::error(
                            ValidationCode::ReservedDataDirectory,
                            "Global Pointer directory size must be zero",
                        )
                        .with_context(dir_type.name().to_string()),
                    );
                }
                if dir_type == DataDirectoryType::Security {
                    // Its address is a file offset and PE intentionally does not
                    // own overlay bytes. PeFile validates the actual range.
                    continue;
                }
                let rva = dir.virtual_address;
                let in_image = u64::from(rva)
                    .checked_add(u64::from(dir.size))
                    .is_some_and(|end| end <= u64::from(self.optional_header.size_of_image()));
                let range_readable = usize::try_from(dir.size)
                    .ok()
                    .is_some_and(|size| self.contains_rva_range(rva, size));
                if !in_image || !range_readable {
                    result.push(
                        ValidationIssue::warning(
                            ValidationCode::InvalidDataDirectoryRange,
                            format!(
                                "data directory {} range {:#x}..+{:#x} is outside the image",
                                dir_type.name(),
                                rva,
                                dir.size
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
