use super::*;

impl PeImage {
    /// Parse the TLS directory.
    pub fn tls(&self) -> Result<Option<crate::tls::TlsInfo>> {
        self.tls_at_image_base(self.runtime_image_base())
    }

    /// Parse the TLS directory using the image's actual runtime base.
    ///
    /// A loader relocates the VA fields in a mapped TLS directory. Pass the
    /// module's current base here when parsing an ASLR-relocated mapped image.
    pub fn tls_at_image_base(
        &self,
        runtime_image_base: u64,
    ) -> Result<Option<crate::tls::TlsInfo>> {
        use crate::data_dir::DataDirectoryType;

        let dir = self
            .data_directory(DataDirectoryType::Tls)
            .filter(|d| d.is_present());
        match dir {
            Some(d) => {
                let read_fn = |rva: u32, len: usize| -> Option<Vec<u8>> { self.read_rva(rva, len) };
                Ok(Some(crate::tls::TlsInfo::parse(
                    d.virtual_address,
                    d.size,
                    runtime_image_base,
                    self.is_64bit(),
                    read_fn,
                )?))
            }
            None => Ok(None),
        }
    }

    /// Update the TLS directory.
    ///
    /// Creates or replaces the TLS directory with new data.
    /// If target_section is None, uses ".rdata" or the last section.
    ///
    /// # Arguments
    /// * `tls_info` - The TLS information to write
    /// * `target_section` - Optional section to place the TLS data
    ///
    /// Returns the RVA where the TLS directory was written.
    pub fn update_tls(
        &mut self,
        tls_info: &crate::tls::TlsInfo,
        target_section: Option<&str>,
    ) -> Result<u32> {
        use crate::data_dir::DataDirectoryType;
        use crate::tls::TlsBuilder;
        self.ensure_data_directory_slot(DataDirectoryType::Tls)?;

        // Find target section
        let section_name: String = target_section
            .map(|s| s.to_string())
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
            None => return Err(crate::Error::invalid_section(&section_name)),
        };

        // Calculate append RVA
        let append_rva = self.prepare_section_append(section_idx)?;

        // Build TLS data with correct RVA
        let builder = TlsBuilder::new(append_rva, self.image_base(), self.is_64bit());
        let (data, dir_size) = builder.try_build_from_info(tls_info)?;

        // Append data to section
        self.commit_section_append(section_idx, append_rva, &data)?;
        self.set_data_directory(DataDirectoryType::Tls, append_rva, dir_size);

        Ok(append_rva)
    }

    /// Parse the debug directory.
    pub fn debug_info(&self) -> Result<Option<crate::debug::DebugInfo>> {
        use crate::data_dir::DataDirectoryType;

        let dir = self
            .data_directory(DataDirectoryType::Debug)
            .filter(|d| d.is_present());
        match dir {
            Some(d) => {
                let read_fn = |rva: u32, len: usize| -> Option<Vec<u8>> { self.read_rva(rva, len) };
                Ok(Some(crate::debug::DebugInfo::parse(
                    d.virtual_address,
                    d.size,
                    read_fn,
                )?))
            }
            None => Ok(None),
        }
    }

    /// Update the debug directory with a CodeView entry pointing to a PDB.
    ///
    /// This is the most common debug directory format. Creates a single CodeView RSDS entry.
    /// If target_section is None, uses ".rdata" or the last section.
    ///
    /// # Arguments
    /// * `codeview` - The CodeView info containing PDB path and GUID
    /// * `target_section` - Optional section to place the debug data
    ///
    /// Returns the RVA where the debug directory was written.
    pub fn update_debug_codeview(
        &mut self,
        codeview: &crate::debug::CodeViewRsds,
        target_section: Option<&str>,
    ) -> Result<u32> {
        use crate::data_dir::DataDirectoryType;
        use crate::debug::DebugBuilder;
        self.ensure_data_directory_slot(DataDirectoryType::Debug)?;

        // Find target section
        let section_name: String = target_section
            .map(|s| s.to_string())
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
            None => return Err(crate::Error::invalid_section(&section_name)),
        };

        // Calculate append RVA
        let append_rva = self.prepare_section_append(section_idx)?;

        // Build debug data with correct RVA
        let builder = DebugBuilder::new(append_rva);
        let (data, dir_size, _) = builder.try_build_codeview(codeview)?;

        // Append data to section
        self.commit_section_append(section_idx, append_rva, &data)?;
        self.set_data_directory(DataDirectoryType::Debug, append_rva, dir_size);

        Ok(append_rva)
    }

    /// Update the debug directory from a DebugInfo structure.
    ///
    /// Returns the RVA where the debug directory was written.
    pub fn update_debug(
        &mut self,
        debug_info: &crate::debug::DebugInfo,
        target_section: Option<&str>,
    ) -> Result<u32> {
        use crate::data_dir::DataDirectoryType;
        use crate::debug::DebugBuilder;

        // No debug info to write
        if debug_info.directories.is_empty() {
            self.clear_data_directory(DataDirectoryType::Debug);
            return Ok(0);
        }
        self.ensure_data_directory_slot(DataDirectoryType::Debug)?;

        // Find target section
        let section_name: String = target_section
            .map(|s| s.to_string())
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
            None => return Err(crate::Error::invalid_section(&section_name)),
        };

        // Calculate append RVA
        let append_rva = self.prepare_section_append(section_idx)?;

        // Rebuild every entry together with its preserved raw payload.
        let builder = DebugBuilder::new(append_rva);
        let (data, dir_size, _) = builder.try_build(debug_info)?;

        // Append data to section
        self.commit_section_append(section_idx, append_rva, &data)?;
        self.set_data_directory(DataDirectoryType::Debug, append_rva, dir_size);

        Ok(append_rva)
    }

    /// Parse the CLI header (IMAGE_COR20_HEADER) for .NET assemblies.
    ///
    /// Returns `None` if the CLR data directory is not present.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use portex::PeImage;
    ///
    /// # let file_bytes: &[u8] = &[];
    /// let pe = PeImage::parse(file_bytes)?;
    /// if let Some(cli) = pe.clr_header()? {
    ///     println!("Metadata at RVA {:#x}", cli.metadata_rva);
    /// }
    /// # Ok::<(), portex::Error>(())
    /// ```
    pub fn clr_header(&self) -> Result<Option<crate::clr::CliHeader>> {
        use crate::data_dir::DataDirectoryType;

        let dir = self
            .data_directory(DataDirectoryType::ClrRuntime)
            .filter(|d| d.is_present());
        match dir {
            Some(d) => {
                if d.size < crate::clr::CliHeader::SIZE as u32 {
                    return Err(Error::invalid_data_directory(format!(
                        "CLR header is {} bytes, expected at least {}",
                        d.size,
                        crate::clr::CliHeader::SIZE
                    )));
                }
                let data = self
                    .read_rva(d.virtual_address, crate::clr::CliHeader::SIZE)
                    .ok_or_else(|| crate::Error::invalid_rva(d.virtual_address))?;
                Ok(Some(crate::clr::CliHeader::parse(&data)?))
            }
            None => Ok(None),
        }
    }

    /// Return the raw CLR metadata blob for hand-off to a metadata crate.
    ///
    /// Portex deliberately stops at this boundary; metadata streams and tables
    /// belong to crates such as `clrmeta`.
    pub fn clr_metadata(&self) -> Result<Option<Vec<u8>>> {
        let Some(header) = self.clr_header()? else {
            return Ok(None);
        };
        if header.metadata_rva == 0 || header.metadata_size == 0 {
            return Err(Error::invalid_data_directory(
                "CLR header has only one of metadata RVA/size set",
            ));
        }
        self.read_rva(header.metadata_rva, header.metadata_size as usize)
            .map(Some)
            .ok_or_else(|| Error::invalid_rva(header.metadata_rva))
    }

    /// Parse the rich header (if present).
    pub fn rich_header(&self) -> Option<crate::rich::RichHeader> {
        let pe_offset = usize::try_from(self.dos_header.e_lfanew).ok()?;
        let stub_size = pe_offset.checked_sub(crate::dos::DosHeader::SIZE)?;
        if self.dos_stub.len() != stub_size {
            return None;
        }

        let mut bytes = vec![0; pe_offset.checked_add(4)?];
        self.dos_header.write(&mut bytes).ok()?;
        bytes[crate::dos::DosHeader::SIZE..pe_offset].copy_from_slice(&self.dos_stub);
        bytes[pe_offset..pe_offset + 4].copy_from_slice(&crate::coff::PE_SIGNATURE.to_le_bytes());
        crate::rich::RichHeader::parse(&bytes)
    }

    /// Parse the exception directory using the current machine's ABI.
    pub fn exception_table(&self) -> Result<Option<crate::exception::ExceptionTable>> {
        use crate::data_dir::DataDirectoryType;

        let Some(directory) = self
            .data_directory(DataDirectoryType::Exception)
            .filter(|directory| directory.is_present())
        else {
            return Ok(None);
        };
        let read = |rva: u32, len: usize| self.read_rva(rva, len);
        crate::exception::ExceptionTable::parse(
            self.coff_header.machine,
            directory.virtual_address,
            directory.size,
            read,
        )
        .map(Some)
    }

    /// Parse an AMD64 exception directory (`RUNTIME_FUNCTION[]`).
    ///
    /// Prefer [`Self::exception_table`] for code that may inspect ARM-family
    /// or otherwise architecture-specific images.
    pub fn exception_directory(&self) -> Result<crate::exception::ExceptionDirectory> {
        match self.exception_table()? {
            Some(crate::exception::ExceptionTable::X64(directory)) => Ok(directory),
            Some(_) => Err(Error::invalid_data_directory(
                "exception_directory() is AMD64-only; use exception_table()",
            )),
            None => Ok(crate::exception::ExceptionDirectory::default()),
        }
    }

    /// Write an architecture-aware exception table.
    pub fn update_exception_table(
        &mut self,
        table: &crate::exception::ExceptionTable,
        target_section: Option<&str>,
    ) -> Result<u32> {
        use crate::data_dir::DataDirectoryType;
        self.ensure_data_directory_slot(DataDirectoryType::Exception)?;

        let machine_matches = match table {
            crate::exception::ExceptionTable::X64(_) => {
                self.coff_header.machine == crate::coff::MachineType::Amd64 as u16
            }
            crate::exception::ExceptionTable::Arm(_) => matches!(
                crate::coff::MachineType::from_u16(self.coff_header.machine),
                Some(
                    crate::coff::MachineType::Arm
                        | crate::coff::MachineType::ArmNt
                        | crate::coff::MachineType::Thumb
                )
            ),
            crate::exception::ExceptionTable::Arm64(_) => matches!(
                crate::coff::MachineType::from_u16(self.coff_header.machine),
                Some(
                    crate::coff::MachineType::Arm64
                        | crate::coff::MachineType::Arm64Ec
                        | crate::coff::MachineType::Arm64X
                )
            ),
            crate::exception::ExceptionTable::Raw { machine, .. } => {
                *machine == self.coff_header.machine
            }
        };
        if !machine_matches {
            return Err(Error::invalid_data_directory(
                "exception-table encoding does not match the PE machine",
            ));
        }

        let data = table.try_to_bytes()?;
        let size = u32::try_from(data.len())
            .map_err(|_| Error::invalid_data_directory("exception table exceeds u32"))?;
        let section_name = target_section
            .map(str::to_string)
            .or_else(|| self.section_by_name(".pdata").map(|_| ".pdata".to_string()))
            .or_else(|| self.section_by_name(".rdata").map(|_| ".rdata".to_string()))
            .or_else(|| {
                self.sections
                    .last()
                    .map(|section| section.name().to_string())
            })
            .ok_or_else(|| Error::invalid_section("no section available for exception data"))?;
        let section_index = self
            .sections
            .iter()
            .position(|section| section.name() == section_name)
            .ok_or_else(|| Error::invalid_section(&section_name))?;
        let rva = self.prepare_section_append(section_index)?;
        self.commit_section_append(section_index, rva, &data)?;
        self.set_data_directory(DataDirectoryType::Exception, rva, size);
        Ok(rva)
    }

    /// Update the exception directory (.pdata).
    ///
    /// Creates or replaces the exception directory with new function entries.
    /// If target_section is None, uses ".pdata" or ".rdata" or the last section.
    ///
    /// # Arguments
    /// * `directory` - The exception directory to write
    /// * `target_section` - Optional section to place the exception data
    ///
    /// Returns the RVA where the exception directory was written.
    pub fn update_exception(
        &mut self,
        directory: &crate::exception::ExceptionDirectory,
        target_section: Option<&str>,
    ) -> Result<u32> {
        use crate::data_dir::DataDirectoryType;
        use crate::exception::ExceptionBuilder;
        self.ensure_data_directory_slot(DataDirectoryType::Exception)?;

        // Find target section
        let section_name: String = target_section
            .map(|s| s.to_string())
            .or_else(|| {
                if self.section_by_name(".pdata").is_some() {
                    Some(".pdata".to_string())
                } else if self.section_by_name(".rdata").is_some() {
                    Some(".rdata".to_string())
                } else {
                    self.sections.last().map(|s| s.name().to_string())
                }
            })
            .unwrap_or_else(|| ".pdata".to_string());

        let section_idx = self.sections.iter().position(|s| s.name() == section_name);
        let section_idx = match section_idx {
            Some(idx) => idx,
            None => return Err(crate::Error::invalid_section(&section_name)),
        };

        // Build exception data
        let (data, dir_size) = ExceptionBuilder::try_build_from(directory)?;

        // Calculate append RVA
        let append_rva = self.prepare_section_append(section_idx)?;

        // Append data to section
        self.commit_section_append(section_idx, append_rva, &data)?;
        self.set_data_directory(DataDirectoryType::Exception, append_rva, dir_size);

        Ok(append_rva)
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
                    .read_rva(d.virtual_address, d.size as usize)
                    .ok_or(crate::Error::invalid_rva(d.virtual_address))?;
                Ok(Some(crate::loadconfig::LoadConfigDirectory::parse(
                    &data,
                    self.is_64bit(),
                )?))
            }
            None => Ok(None),
        }
    }

    /// Update the load config directory.
    ///
    /// Creates or replaces the LoadConfig directory with new data.
    /// If target_section is None, uses ".rdata" or the last section.
    ///
    /// # Arguments
    /// * `config` - The LoadConfig directory to write
    /// * `target_section` - Optional section to place the LoadConfig data
    ///
    /// Returns the RVA where the LoadConfig directory was written.
    pub fn update_load_config(
        &mut self,
        config: &crate::loadconfig::LoadConfigDirectory,
        target_section: Option<&str>,
    ) -> Result<u32> {
        use crate::data_dir::DataDirectoryType;
        use crate::loadconfig::LoadConfigBuilder;
        self.ensure_data_directory_slot(DataDirectoryType::LoadConfig)?;

        // Find target section
        let section_name: String = target_section
            .map(|s| s.to_string())
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
            None => return Err(crate::Error::invalid_section(&section_name)),
        };

        // Build LoadConfig data
        let builder = LoadConfigBuilder::new(self.is_64bit());
        let (data, dir_size) = builder.try_build(config)?;

        // Calculate append RVA
        let append_rva = self.prepare_section_append(section_idx)?;

        // Append data to section
        self.commit_section_append(section_idx, append_rva, &data)?;
        self.set_data_directory(DataDirectoryType::LoadConfig, append_rva, dir_size);

        Ok(append_rva)
    }

    pub(crate) fn clear_security(&mut self) {
        use crate::data_dir::DataDirectoryType;
        self.clear_data_directory(DataDirectoryType::Security);
    }
}
