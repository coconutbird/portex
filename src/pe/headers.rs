use super::*;

impl PeHeaders {
    /// Read PE headers from any [`ReadAt`] implementation.
    #[must_use = "parsing returns PE headers that should be used"]
    pub fn read_from<R: ReadAt>(reader: &R, base_offset: u64) -> Result<Self> {
        // Parse DOS header
        let dos_header = DosHeader::read_from(reader, base_offset)?;

        // Get PE header offset
        let relative_pe_offset = u64::try_from(dos_header.e_lfanew)
            .map_err(|_| Error::invalid_section("e_lfanew is negative"))?;
        if relative_pe_offset < DosHeader::SIZE as u64 {
            return Err(Error::invalid_section(
                "e_lfanew places the PE header inside the DOS header",
            ));
        }
        let pe_offset = base_offset
            .checked_add(relative_pe_offset)
            .ok_or_else(|| Error::invalid_section("PE header offset overflow"))?;

        // Verify PE signature
        verify_pe_signature(reader, pe_offset)?;

        // Parse COFF header (4 bytes after PE signature)
        let coff_offset = pe_offset
            .checked_add(4)
            .ok_or_else(|| Error::invalid_section("COFF header offset overflow"))?;
        let coff_header = CoffHeader::read_from(reader, coff_offset)?;

        let section_count = coff_header.number_of_sections as usize;
        if section_count > MAX_NUMBER_OF_SECTIONS {
            return Err(Error::invalid_section(format!(
                "section count {} exceeds the PE image limit of {}",
                section_count, MAX_NUMBER_OF_SECTIONS
            )));
        }

        // Parse optional header
        let optional_offset = coff_offset
            .checked_add(CoffHeader::SIZE as u64)
            .ok_or_else(|| Error::invalid_section("optional-header offset overflow"))?;
        let optional_header = OptionalHeader::read_sized_from(
            reader,
            optional_offset,
            coff_header.size_of_optional_header as usize,
        )?;

        // Parse section headers
        let sections_offset = optional_offset
            .checked_add(coff_header.size_of_optional_header as u64)
            .ok_or_else(|| Error::invalid_section("section-table offset overflow"))?;
        let section_headers = SectionHeader::read_sections(reader, sections_offset, section_count)?;

        Ok(Self {
            dos_header,
            coff_header,
            optional_header,
            section_headers,
            pe_offset,
        })
    }

    /// Read headers from a file on disk.
    #[cfg(feature = "std")]
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

    /// Convert an RVA to an image-relative source offset for the requested layout.
    ///
    /// When [`Self::read_from`] was called with a nonzero `base_offset`, add that
    /// base to the returned value before reading from the original source.
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
                self.section_headers
                    .iter()
                    .find_map(|section| section.rva_to_offset(rva))
            }
        }
    }

    /// Convert an RVA to a raw-file offset.
    #[must_use]
    pub fn rva_to_offset(&self, rva: u32) -> Option<u32> {
        self.rva_to_source_offset(rva, SourceLayout::File)
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
        let result = PeImage::parse(&data);
        assert!(matches!(
            result,
            Err(ref e) if matches!(e.kind, crate::error::ErrorKind::InvalidDosSignature)
        ));
    }

    #[test]
    fn test_parse_buffer_too_small() {
        let data = vec![0x4D, 0x5A]; // Just MZ
        let result = PeImage::parse(&data);
        assert!(matches!(
            result,
            Err(ref e) if matches!(e.kind, crate::error::ErrorKind::BufferTooSmall { .. })
        ));
    }

    #[test]
    fn test_headers_parse_invalid() {
        let data = vec![0u8; 256];
        let result = PeHeaders::from_slice(&data);
        assert!(matches!(
            result,
            Err(ref e) if matches!(e.kind, crate::error::ErrorKind::InvalidDosSignature)
        ));
    }
}
