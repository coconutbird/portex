use super::*;

impl PeImage {
    /// Create a new PE builder for constructing PEs from scratch.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use portex::{MachineType, PeImage, Subsystem};
    /// use portex::section::characteristics;
    ///
    /// let pe = PeImage::builder()
    ///     .machine(MachineType::Amd64)
    ///     .subsystem(Subsystem::WindowsCui)
    ///     .add_section(".text", vec![0xCC; 256], characteristics::CODE | characteristics::EXECUTE | characteristics::READ)
    ///     .build();
    /// ```
    pub fn builder() -> crate::builder::PeBuilder {
        crate::builder::PeBuilder::new()
    }

    /// Parse raw PE file bytes from a byte slice.
    ///
    /// This expects file layout even though the bytes themselves are already in
    /// memory. Use [`Self::parse_mapped`] for an image laid out by a PE loader.
    #[must_use = "parsing returns a PE structure that should be used"]
    pub fn parse(data: &[u8]) -> Result<Self> {
        Self::parse_with_layout(data, SourceLayout::File)
    }

    /// Parse a loader-mapped PE image from a byte slice.
    ///
    /// The slice must begin at the image base. Section payloads are read from
    /// their RVAs rather than from `PointerToRawData` file offsets.
    #[must_use = "parsing returns a PE structure that should be used"]
    pub fn parse_mapped(data: &[u8]) -> Result<Self> {
        Self::parse_with_layout(data, SourceLayout::Mapped)
    }

    /// Parse a loader-mapped image at its actual (possibly relocated) base.
    pub fn parse_mapped_at(data: &[u8], runtime_image_base: u64) -> Result<Self> {
        Self::parse_with_options(
            data,
            ParseOptions::mapped().runtime_image_base(runtime_image_base),
        )
    }

    /// Parse PE bytes using an explicit source layout.
    #[must_use = "parsing returns a PE structure that should be used"]
    pub fn parse_with_layout(data: &[u8], layout: SourceLayout) -> Result<Self> {
        let reader = SliceReader::new(data);
        Self::read_from(&reader, 0, layout)
    }

    /// Parse PE bytes with explicit strictness and source-layout options.
    pub fn parse_with_options(data: &[u8], options: ParseOptions) -> Result<Self> {
        let reader = SliceReader::new(data);
        Self::read_from_with_options(&reader, 0, options)
    }

    /// Read a complete PE from any [`ReadAt`] source using an explicit layout.
    ///
    /// `base_offset` is the source offset of the image's DOS header. For a
    /// [`crate::BaseAddressReader`] created at a module base, pass `0` and use
    /// [`SourceLayout::Mapped`]. A remote-process reader that addresses the whole
    /// process can instead pass the module's base address as `base_offset`.
    #[must_use = "parsing returns a PE structure that should be used"]
    pub fn read_from<R: ReadAt>(
        reader: &R,
        base_offset: u64,
        layout: SourceLayout,
    ) -> Result<Self> {
        Self::read_from_with_options(
            reader,
            base_offset,
            ParseOptions {
                layout,
                missing_section_data: MissingSectionData::Error,
                runtime_image_base: None,
            },
        )
    }

    /// Read a loader-mapped image and retain its actual load base for parsing
    /// directories that contain absolute VAs.
    pub fn read_mapped_from<R: ReadAt>(
        reader: &R,
        source_offset: u64,
        runtime_image_base: u64,
    ) -> Result<Self> {
        Self::read_from_with_options(
            reader,
            source_offset,
            ParseOptions::mapped().runtime_image_base(runtime_image_base),
        )
    }

    /// Read a complete image with explicit parsing options.
    pub fn read_from_with_options<R: ReadAt>(
        reader: &R,
        base_offset: u64,
        options: ParseOptions,
    ) -> Result<Self> {
        let headers = PeHeaders::read_from(reader, base_offset)?;

        // Read DOS stub
        let dos_stub_start = base_offset
            .checked_add(DosHeader::SIZE as u64)
            .ok_or_else(|| Error::invalid_section("DOS stub offset overflow"))?;
        let dos_stub_size = headers
            .pe_offset
            .checked_sub(dos_stub_start)
            .and_then(|size| usize::try_from(size).ok())
            .ok_or_else(|| Error::invalid_section("PE header overlaps the DOS header"))?;
        let dos_stub = if dos_stub_size > 0 {
            Self::read_source_bytes(
                reader,
                dos_stub_start,
                dos_stub_size,
                MissingSectionData::Error,
            )?
        } else {
            Vec::new()
        };

        // Read section data
        let mut sections = Vec::with_capacity(headers.section_headers.len());
        for header in headers.section_headers {
            if options.layout == SourceLayout::File
                && header.size_of_raw_data != 0
                && header.pointer_to_raw_data == 0
            {
                return Err(Error::invalid_section(format!(
                    "section '{}' has raw bytes but a zero file pointer",
                    header.name_str()
                )));
            }
            let source_range = match options.layout {
                SourceLayout::File => (header.pointer_to_raw_data != 0
                    && header.size_of_raw_data != 0)
                    .then_some((header.pointer_to_raw_data, header.size_of_raw_data as usize)),
                SourceLayout::Mapped => {
                    let mapped_size = header.virtual_size.max(header.size_of_raw_data);
                    (mapped_size != 0).then_some((header.virtual_address, mapped_size as usize))
                }
            };

            let section_data = match source_range {
                Some((relative_offset, size)) => {
                    let source_offset = base_offset
                        .checked_add(relative_offset as u64)
                        .ok_or_else(|| Error::invalid_section("section source offset overflow"))?;
                    Self::read_source_bytes(
                        reader,
                        source_offset,
                        size,
                        options.missing_section_data,
                    )?
                }
                None => Vec::new(),
            };
            sections.push(match options.layout {
                SourceLayout::File => Section::from_header_and_data(header, section_data),
                SourceLayout::Mapped => Section::from_mapped_header_and_data(header, section_data),
            });
        }

        Ok(Self {
            dos_header: headers.dos_header,
            dos_stub,
            coff_header: headers.coff_header,
            optional_header: headers.optional_header,
            sections,
            source_layout: options.layout,
            runtime_image_base: options.runtime_image_base,
        })
    }

    /// Read a source range according to the selected missing-data policy.
    fn read_source_bytes<R: ReadAt>(
        reader: &R,
        offset: u64,
        len: usize,
        missing_data: MissingSectionData,
    ) -> Result<Vec<u8>> {
        if len == 0 {
            return Ok(Vec::new());
        }

        let end = match offset.checked_add(len as u64) {
            Some(end) => end,
            None => {
                return match missing_data {
                    MissingSectionData::Error => {
                        Err(Error::invalid_section("section source range overflow"))
                    }
                    MissingSectionData::Empty => Ok(Vec::new()),
                };
            }
        };
        if reader.size().is_some_and(|source_size| end > source_size) {
            return match missing_data {
                MissingSectionData::Error => Err(Error::buffer_too_small(
                    usize::try_from(end).unwrap_or(usize::MAX),
                    usize::try_from(reader.size().unwrap_or(0)).unwrap_or(usize::MAX),
                )),
                MissingSectionData::Empty => Ok(Vec::new()),
            };
        }

        let mut data = Vec::new();
        data.try_reserve_exact(len)
            .map_err(|_| Error::generic("section source range is too large to allocate"))?;
        data.resize(len, 0);
        let mut total_read = 0usize;
        while total_read < len {
            let read_offset = offset + total_read as u64;
            let count = reader.read_at(read_offset, &mut data[total_read..])?;
            if count == 0 {
                return match missing_data {
                    MissingSectionData::Error => Err(Error::buffer_too_small(len, total_read)),
                    MissingSectionData::Empty => Ok(Vec::new()),
                };
            }
            if count > len - total_read {
                return Err(Error::generic(
                    "ReadAt::read_at reported more bytes than the supplied buffer",
                ));
            }
            total_read += count;
        }
        Ok(data)
    }

    /// Load a PE file from disk.
    #[cfg(feature = "std")]
    #[must_use = "loading returns a PE structure that should be used"]
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let data = std::fs::read(path)?;
        Self::parse(&data)
    }

    /// Read a raw PE image from a sequential `nostdio` stream.
    ///
    /// This normalized image intentionally drops any file overlay. Use
    /// [`crate::PeFile::from_stream`] when certificates or arbitrary trailing
    /// bytes must be retained.
    pub fn from_stream<R: nostdio::Read>(stream: &mut R) -> Result<Self> {
        let mut data = Vec::new();
        stream
            .read_to_end(&mut data)
            .map_err(crate::reader::map_nostdio_error)?;
        Self::parse(&data)
    }
}
