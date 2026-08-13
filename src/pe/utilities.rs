use super::*;

impl PeImage {
    /// Calculate and return the PE checksum.
    pub fn calculate_checksum(&self) -> u32 {
        self.try_calculate_checksum()
            .expect("checksum calculation failed: use try_calculate_checksum()")
    }

    /// Calculate the checksum without panicking on invalid edited state.
    pub fn try_calculate_checksum(&self) -> Result<u32> {
        let data = self.try_build()?;
        crate::checksum::compute_pe_checksum(&data)
            .ok_or_else(|| Error::invalid_section("serialized image has no checksum field"))
    }

    /// Update the checksum field in the optional header.
    pub fn update_checksum(&mut self) {
        self.try_update_checksum()
            .expect("checksum update failed: use try_update_checksum()")
    }

    /// Update the optional-header checksum without panicking.
    pub fn try_update_checksum(&mut self) -> Result<()> {
        let checksum = self.try_calculate_checksum()?;
        match &mut self.optional_header {
            OptionalHeader::Pe32(h) => h.check_sum = checksum,
            OptionalHeader::Pe32Plus(h) => h.check_sum = checksum,
        }
        Ok(())
    }

    /// Recompute derived layout fields and the checksum.
    pub fn try_finalize(&mut self) -> Result<()> {
        self.try_update_layout()?;
        self.try_update_checksum()
    }

    /// Rebuild all executable-image directories that Portex can serialize.
    ///
    /// This method re-parses and re-serializes all supported data directories:
    /// - Imports
    /// - Exports
    /// - Relocations
    /// - Resources
    /// - Bound and delay imports
    /// - TLS, debug, exception, and load-configuration tables
    ///
    /// This is useful after making structural changes to sections to ensure all
    /// data directory content is properly aligned and laid out.
    ///
    /// The operation is atomic and appends rebuilt tables to one section. When
    /// no target is supplied, the last section is used so existing section RVAs
    /// do not move. It intentionally does not touch Security (raw-file state),
    /// CLR metadata, or directories whose encoding Portex does not own.
    ///
    /// # Errors
    ///
    /// Returns an error if any data directory fails to parse or rebuild.
    pub fn rebuild_supported_directories(&mut self, target_section: Option<&str>) -> Result<()> {
        // Parse all directories first before modifying anything
        let imports = self.imports()?;
        let exports = self.exports()?;
        let relocations = self.relocations()?;
        let resources = self.resources_with_data()?;
        let bound_imports = self.bound_imports()?;
        let delay_imports = self.delay_imports()?;
        let tls = self.tls()?;
        let debug = self.debug_info()?;
        let exceptions = self.exception_table()?;
        let load_config = self.load_config()?;

        let selected_section = target_section
            .map(ToString::to_string)
            .or_else(|| {
                self.sections
                    .last()
                    .map(|section| section.name().to_string())
            })
            .ok_or_else(|| Error::invalid_section("image has no target section"))?;
        if self.section_by_name(&selected_section).is_none() {
            return Err(Error::invalid_section(&selected_section));
        }
        let target_section = Some(selected_section.as_str());
        let mut rebuilt = self.clone();

        // Rebuild each one (only if non-empty)
        if !imports.is_empty() {
            rebuilt.update_imports(imports, target_section)?;
        }
        if !exports.is_empty() {
            rebuilt.update_exports(exports, target_section)?;
        }
        if !relocations.is_empty() {
            rebuilt.update_relocations(relocations, target_section)?;
        }
        if !resources.resources.is_empty() {
            rebuilt.update_resources(&resources, target_section)?;
        }
        if let Some(bound) = bound_imports
            && !bound.descriptors.is_empty()
        {
            rebuilt.update_bound_imports(bound, target_section)?;
        }
        if !delay_imports.dlls.is_empty() {
            rebuilt.update_delay_imports(&delay_imports, target_section)?;
        }
        if let Some(tls) = tls {
            rebuilt.update_tls(&tls, target_section)?;
        }
        if let Some(debug) = debug {
            rebuilt.update_debug(&debug, target_section)?;
        }
        if let Some(exceptions) = exceptions {
            rebuilt.update_exception_table(&exceptions, target_section)?;
        }
        if let Some(load_config) = load_config {
            rebuilt.update_load_config(&load_config, target_section)?;
        }

        rebuilt.try_finalize()?;
        *self = rebuilt;
        Ok(())
    }

    /// Read resource data at the given RVA.
    pub fn read_resource_data(&self, resource: &crate::resource::Resource) -> Option<Vec<u8>> {
        self.read_rva(resource.data_rva, resource.size as usize)
    }
}
