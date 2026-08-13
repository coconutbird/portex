use super::*;

impl PeImage {
    /// Parse the bound import directory.
    ///
    /// Bound imports are a legacy optimization for faster DLL loading.
    pub fn bound_imports(&self) -> Result<Option<crate::bound_import::BoundImportDirectory>> {
        use crate::data_dir::DataDirectoryType;

        let dir = self
            .data_directory(DataDirectoryType::BoundImport)
            .filter(|d| d.is_present());
        match dir {
            Some(d) => {
                let data = self
                    .read_rva(d.virtual_address, d.size as usize)
                    .ok_or_else(|| crate::Error::invalid_rva(d.virtual_address))?;
                Ok(Some(crate::bound_import::BoundImportDirectory::parse(
                    &data,
                )?))
            }
            None => Ok(None),
        }
    }

    /// Update bound imports: tries in-place replacement first, otherwise appends to target section.
    ///
    /// Bound imports are a legacy optimization that pre-resolves import addresses at link time.
    /// Returns the RVA where the bound import data was written.
    pub fn update_bound_imports(
        &mut self,
        directory: crate::bound_import::BoundImportDirectory,
        target_section: Option<&str>,
    ) -> Result<u32> {
        use crate::data_dir::DataDirectoryType;

        if directory.descriptors.is_empty() {
            self.clear_data_directory(DataDirectoryType::BoundImport);
            return Ok(0);
        }
        self.ensure_data_directory_slot(DataDirectoryType::BoundImport)?;

        let builder = crate::bound_import::BoundImportBuilder::new();
        let (data, encoded_size) = builder.try_build(&directory)?;
        let required_size = data.len();

        // Check if we can replace in-place
        let existing_dir = self.data_directory(DataDirectoryType::BoundImport).cloned();
        if let Some(ref dir) = existing_dir
            && dir.is_present()
            && dir.size as usize >= required_size
            && self.write_at_rva(dir.virtual_address, &data).is_some()
        {
            self.set_data_directory(
                DataDirectoryType::BoundImport,
                dir.virtual_address,
                encoded_size,
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
                if self.section_by_name(".rdata").is_some() {
                    Some(".rdata".to_string())
                } else {
                    self.sections.last().map(|s| s.name().to_string())
                }
            })
            .unwrap_or_else(|| ".rdata".to_string());

        let section_idx = self.sections.iter().position(|s| s.name() == section_name);
        let section_idx = match section_idx {
            Some(idx) => idx,
            None => return Err(crate::Error::invalid_section(section_name)),
        };

        let append_rva = self.prepare_section_append(section_idx)?;

        self.commit_section_append(section_idx, append_rva, &data)?;
        self.set_data_directory(DataDirectoryType::BoundImport, append_rva, encoded_size);

        Ok(append_rva)
    }

    /// Parse the delay-load import directory.
    ///
    /// Delay-loaded DLLs are loaded on first use, not at startup.
    pub fn delay_imports(&self) -> Result<crate::delay_import::DelayImportDirectory> {
        self.delay_imports_at_image_base(self.runtime_image_base())
    }

    /// Parse delay-load imports using an explicit base for legacy VA-based
    /// descriptors. Modern descriptors use RVAs and are unaffected.
    pub fn delay_imports_at_image_base(
        &self,
        runtime_image_base: u64,
    ) -> Result<crate::delay_import::DelayImportDirectory> {
        use crate::data_dir::DataDirectoryType;

        let dir = self
            .data_directory(DataDirectoryType::DelayImport)
            .filter(|d| d.is_present());
        let is_64bit = matches!(
            self.optional_header,
            crate::optional::OptionalHeader::Pe32Plus(_)
        );
        match dir {
            Some(d) => {
                let read_fn = |rva: u32, len: usize| -> Option<Vec<u8>> { self.read_rva(rva, len) };
                crate::delay_import::DelayImportDirectory::parse_sized_with_image_base(
                    d.virtual_address,
                    d.size,
                    runtime_image_base,
                    is_64bit,
                    read_fn,
                )
            }
            None => Ok(crate::delay_import::DelayImportDirectory::default()),
        }
    }

    /// Update delay imports: tries in-place replacement first, otherwise appends to target section.
    ///
    /// Delay-load imports allow DLLs to be loaded on first use rather than at startup.
    /// Returns the RVA where the delay import data was written.
    pub fn update_delay_imports(
        &mut self,
        directory: &crate::delay_import::DelayImportDirectory,
        target_section: Option<&str>,
    ) -> Result<u32> {
        use crate::data_dir::DataDirectoryType;

        if directory.dlls.is_empty() {
            self.clear_data_directory(DataDirectoryType::DelayImport);
            return Ok(0);
        }
        self.ensure_data_directory_slot(DataDirectoryType::DelayImport)?;

        // Determine if 64-bit
        let is_64bit = matches!(
            self.optional_header,
            crate::optional::OptionalHeader::Pe32Plus(_)
        );

        // Find target section first to get the base RVA
        let existing_dir = self.data_directory(DataDirectoryType::DelayImport).cloned();
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
                if self.section_by_name(".rdata").is_some() {
                    Some(".rdata".to_string())
                } else if self.section_by_name(".didat").is_some() {
                    Some(".didat".to_string())
                } else {
                    self.sections.last().map(|s| s.name().to_string())
                }
            })
            .unwrap_or_else(|| ".rdata".to_string());

        let section_idx = self.sections.iter().position(|s| s.name() == section_name);
        let section_idx = match section_idx {
            Some(idx) => idx,
            None => return Err(crate::Error::invalid_section(section_name)),
        };

        // Calculate the RVA where we'll place the data
        let base_rva = self.prepare_section_append(section_idx)?;

        let builder = crate::delay_import::DelayImportBuilder::new(is_64bit, base_rva);
        let (data, encoded_size) = builder.try_build(&directory.dlls)?;
        let required_size = data.len();

        // Check if we can replace in-place
        if let Some(ref dir) = existing_dir
            && dir.is_present()
            && dir.size as usize >= required_size
        {
            // For in-place, we need to rebuild with the existing RVA
            let existing_builder =
                crate::delay_import::DelayImportBuilder::new(is_64bit, dir.virtual_address);
            let (existing_data, existing_size) = existing_builder.try_build(&directory.dlls)?;
            if self
                .write_at_rva(dir.virtual_address, &existing_data)
                .is_some()
            {
                self.set_data_directory(
                    DataDirectoryType::DelayImport,
                    dir.virtual_address,
                    existing_size,
                );
                return Ok(dir.virtual_address);
            }
        }

        // Append to section
        self.commit_section_append(section_idx, base_rva, &data)?;
        self.set_data_directory(DataDirectoryType::DelayImport, base_rva, encoded_size);

        Ok(base_rva)
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
                let read_fn = |rva: u32, len: usize| -> Option<Vec<u8>> { self.read_rva(rva, len) };
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
                let read_fn = |rva: u32, len: usize| -> Option<Vec<u8>> { self.read_rva(rva, len) };
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
        self.ensure_data_directory_slot(DataDirectoryType::BaseReloc)?;

        let data = relocs.try_build()?;
        let required_size = data.len();
        let encoded_size = u32::try_from(required_size)
            .map_err(|_| Error::invalid_data_directory("relocation table exceeds u32"))?;

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
                encoded_size,
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

        let append_rva = self.prepare_section_append(section_idx)?;

        self.commit_section_append(section_idx, append_rva, &data)?;
        self.set_data_directory(DataDirectoryType::BaseReloc, append_rva, encoded_size);

        Ok(append_rva)
    }

    /// Update resources: tries in-place replacement first, otherwise appends to target section.
    ///
    /// The directory must have been parsed with `resources_with_data()` so that
    /// the resource data is available.
    pub fn update_resources(
        &mut self,
        directory: &crate::resource::ResourceDirectory,
        target_section: Option<&str>,
    ) -> Result<u32> {
        use crate::data_dir::DataDirectoryType;

        if directory.resources.is_empty() {
            self.clear_data_directory(DataDirectoryType::Resource);
            return Ok(0);
        }
        self.ensure_data_directory_slot(DataDirectoryType::Resource)?;

        let builder =
            crate::resource::ResourceBuilder::from_directory(directory).ok_or_else(|| {
                crate::Error::generic("Resource data not available - use resources_with_data()")
            })?;

        let required_size = builder.try_calculate_size()?;

        // Check if we can replace in-place
        let existing_dir = self.data_directory(DataDirectoryType::Resource).cloned();
        if let Some(ref dir) = existing_dir
            && dir.is_present()
            && dir.size as usize >= required_size
        {
            let (data, size) = builder.try_build(dir.virtual_address)?;
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

        let append_rva = self.prepare_section_append(section_idx)?;

        let (data, size) = builder.try_build(append_rva)?;
        self.commit_section_append(section_idx, append_rva, &data)?;
        self.set_data_directory(DataDirectoryType::Resource, append_rva, size);

        Ok(append_rva)
    }

    /// Update resources from a builder: for creating new resources from scratch.
    ///
    /// Use this when building new resources rather than modifying existing ones.
    /// For modifying existing resources, use `update_resources()` with a parsed `ResourceDirectory`.
    pub fn update_resources_from_builder(
        &mut self,
        builder: &crate::resource::ResourceBuilder,
        target_section: Option<&str>,
    ) -> Result<u32> {
        use crate::data_dir::DataDirectoryType;

        let required_size = builder.try_calculate_size()?;
        if required_size == 0 {
            self.clear_data_directory(DataDirectoryType::Resource);
            return Ok(0);
        }
        self.ensure_data_directory_slot(DataDirectoryType::Resource)?;

        // Check if we can replace in-place
        let existing_dir = self.data_directory(DataDirectoryType::Resource).cloned();
        if let Some(ref dir) = existing_dir
            && dir.is_present()
            && dir.size as usize >= required_size
        {
            let (data, size) = builder.try_build(dir.virtual_address)?;
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

        let append_rva = self.prepare_section_append(section_idx)?;

        let (data, size) = builder.try_build(append_rva)?;
        self.commit_section_append(section_idx, append_rva, &data)?;
        self.set_data_directory(DataDirectoryType::Resource, append_rva, size);

        Ok(append_rva)
    }
}
