//! Lossless raw-file container for PE images, overlays, and certificates.

use core::ops::{Deref, DerefMut, Range};

use crate::data_dir::DataDirectoryType;
use crate::prelude::*;
use crate::reader::ReadAt;
use crate::security::{SecurityBuilder, SecurityDirectory};
use crate::{Error, PeImage, Result};

#[cfg(feature = "std")]
use std::fs::File;
#[cfg(feature = "std")]
use std::io::Write;
#[cfg(feature = "std")]
use std::path::Path;

/// A raw PE file together with bytes outside the mapped image.
///
/// [`PeImage`] owns normalized headers and sections and can therefore represent
/// either raw-file or loader-mapped input. `PeFile` adds the raw-only state that
/// cannot exist in a mapped image: the file overlay and the attribute
/// certificate table. Use this type when byte-preserving overlays or
/// Authenticode certificates matter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeFile {
    /// Parsed executable image.
    pub image: PeImage,
    overlay: Vec<u8>,
    certificate_range: Option<Range<usize>>,
    source_layout: RawLayoutFingerprint,
    preserved_regions: Vec<PreservedRegion>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RawLayoutFingerprint {
    pe_offset: usize,
    optional_header_size: usize,
    size_of_headers: usize,
    sections: Vec<(u32, u32)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PreservedRegion {
    range: Range<usize>,
    data: Vec<u8>,
}

impl PeFile {
    /// Wrap a normalized image as a raw file with no overlay.
    pub fn new(mut image: PeImage) -> Result<Self> {
        image.try_update_layout()?;
        let source_layout = RawLayoutFingerprint::from_image(&image)?;
        Ok(Self {
            image,
            overlay: Vec::new(),
            certificate_range: None,
            source_layout,
            preserved_regions: Vec::new(),
        })
    }

    /// Borrow the normalized executable image.
    #[must_use]
    pub const fn image(&self) -> &PeImage {
        &self.image
    }

    /// Borrow the normalized executable image for editing.
    pub fn image_mut(&mut self) -> &mut PeImage {
        &mut self.image
    }

    /// Parse a complete raw PE file.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let image = PeImage::parse(data)?;
        let image_end = raw_image_end(&image)?;
        if image_end > data.len() {
            return Err(Error::buffer_too_small(image_end, data.len()));
        }

        let certificate_range = match image
            .data_directory(DataDirectoryType::Security)
            .filter(|directory| directory.is_present())
        {
            Some(directory) => {
                if directory.virtual_address == 0 || directory.size == 0 {
                    return Err(Error::invalid_data_directory(
                        "Security directory has only one of file offset/size set",
                    ));
                }
                let start = directory.virtual_address as usize;
                let end = start
                    .checked_add(directory.size as usize)
                    .ok_or_else(|| Error::invalid_data_directory("certificate range overflow"))?;
                if end > data.len() {
                    return Err(Error::invalid_data_directory(format!(
                        "certificate range {:#x}..{:#x} exceeds file size {:#x}",
                        start,
                        end,
                        data.len()
                    )));
                }
                if start < image_end {
                    return Err(Error::invalid_data_directory(format!(
                        "certificate table at {:#x} overlaps the mapped image ending at {:#x}",
                        start, image_end
                    )));
                }
                if !start.is_multiple_of(8) {
                    return Err(Error::invalid_data_directory(format!(
                        "certificate table offset {:#x} is not 8-byte aligned",
                        start
                    )));
                }
                SecurityDirectory::parse(&data[start..end])?;
                Some((start - image_end)..(end - image_end))
            }
            None => None,
        };

        let source_layout = RawLayoutFingerprint::from_image(&image)?;
        let preserved_regions = collect_preserved_regions(data, &image, image_end)?;

        Ok(Self {
            image,
            overlay: data[image_end..].to_vec(),
            certificate_range,
            source_layout,
            preserved_regions,
        })
    }

    /// Read and parse a complete raw PE file from a [`ReadAt`].
    ///
    /// The reader must report its size because an overlay has no header field
    /// that identifies its end.
    pub fn read_from<R: ReadAt>(reader: &R, base_offset: u64) -> Result<Self> {
        let source_size = reader
            .size()
            .ok_or_else(|| Error::generic("PeFile requires a ReadAt source with a known size"))?;
        let length = source_size
            .checked_sub(base_offset)
            .and_then(|size| usize::try_from(size).ok())
            .ok_or_else(|| Error::offset_out_of_bounds(usize::MAX, usize::MAX))?;
        let bytes = reader.read_bytes_at(base_offset, length)?;
        Self::parse(&bytes)
    }

    /// Load a complete raw PE file from disk.
    #[cfg(feature = "std")]
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::parse(&std::fs::read(path)?)
    }

    /// Read a complete raw PE file from a sequential `nostdio` stream.
    pub fn from_stream<R: nostdio::Read>(stream: &mut R) -> Result<Self> {
        let mut data = Vec::new();
        stream
            .read_to_end(&mut data)
            .map_err(crate::reader::map_nostdio_error)?;
        Self::parse(&data)
    }

    /// Return all bytes after the headers and raw section data.
    #[must_use]
    pub fn overlay(&self) -> &[u8] {
        &self.overlay
    }

    /// Return the overlay for in-place byte edits.
    ///
    /// The slice cannot be resized, so any stored certificate location remains
    /// valid. Use [`Self::set_overlay`] when replacing the complete overlay.
    pub fn overlay_mut(&mut self) -> &mut [u8] {
        &mut self.overlay
    }

    /// Replace the complete overlay and clear the Security directory.
    ///
    /// Use [`Self::set_security`] after this method to install a new certificate
    /// table in the replacement bytes.
    pub fn set_overlay(&mut self, overlay: Vec<u8>) {
        self.overlay = overlay;
        self.certificate_range = None;
        self.image.clear_security();
    }

    /// Whether raw header/section gaps from the parsed source can still be
    /// restored safely during the next build.
    #[must_use]
    pub fn preserves_source_gaps(&self) -> bool {
        RawLayoutFingerprint::from_image(&self.image)
            .is_ok_and(|layout| layout == self.source_layout)
    }

    /// Consume the container and return the normalized executable image.
    #[must_use]
    pub fn into_image(self) -> PeImage {
        self.image
    }

    /// Return the certificate-table range relative to the overlay.
    #[must_use]
    pub fn certificate_overlay_range(&self) -> Option<Range<usize>> {
        self.certificate_range.clone()
    }

    /// Parse the attribute certificate table.
    pub fn security(&self) -> Result<Option<SecurityDirectory>> {
        let Some(range) = &self.certificate_range else {
            return Ok(None);
        };
        let data = self.overlay.get(range.clone()).ok_or_else(|| {
            Error::invalid_data_directory("stored certificate range exceeds the overlay")
        })?;
        Ok(Some(SecurityDirectory::parse(data)?))
    }

    /// Return raw bytes for any standard data directory.
    pub fn directory_data(&self, dir_type: DataDirectoryType) -> Result<Option<Vec<u8>>> {
        if dir_type != DataDirectoryType::Security {
            return self.image.directory_data(dir_type);
        }
        let Some(range) = &self.certificate_range else {
            return Ok(None);
        };
        self.overlay
            .get(range.clone())
            .map(|bytes| Some(bytes.to_vec()))
            .ok_or_else(|| Error::invalid_data_directory("certificate range exceeds the overlay"))
    }

    /// Parse debug entries from the raw file, including payloads that are
    /// reachable only through `PointerToRawData` and therefore disappear from
    /// a loader-mapped image.
    pub fn debug_info(&self) -> Result<Option<crate::debug::DebugInfo>> {
        let raw = self.try_build()?;
        let image = PeImage::parse(&raw)?;
        let Some(directory) = image
            .data_directory(DataDirectoryType::Debug)
            .copied()
            .filter(|directory| directory.is_present())
        else {
            return Ok(None);
        };
        let read_rva = |rva: u32, size: usize| image.read_rva(rva, size);
        let read_file = |offset: u32, size: usize| {
            let start = usize::try_from(offset).ok()?;
            let end = start.checked_add(size)?;
            raw.get(start..end).map(<[u8]>::to_vec)
        };
        crate::debug::DebugInfo::parse_with_file(
            directory.virtual_address,
            directory.size,
            read_rva,
            read_file,
        )
        .map(Some)
    }

    /// Replace or add the attribute certificate table while preserving other
    /// overlay bytes.
    pub fn set_security(&mut self, directory: &SecurityDirectory) -> Result<()> {
        if directory.certificates.is_empty() {
            self.clear_security();
            return Ok(());
        }

        let certificate_data = SecurityBuilder::new().try_build(directory)?;
        let range = if let Some(old_range) = self.certificate_range.take() {
            if old_range.end > self.overlay.len() || old_range.start > old_range.end {
                return Err(Error::invalid_data_directory(
                    "stored certificate range exceeds the overlay",
                ));
            }
            let start = old_range.start;
            self.overlay
                .splice(old_range, certificate_data.iter().copied());
            start..start + certificate_data.len()
        } else {
            let start = align_up_usize(self.overlay.len(), 8)
                .ok_or_else(|| Error::invalid_data_directory("overlay size overflow"))?;
            self.overlay.resize(start, 0);
            self.overlay.extend_from_slice(&certificate_data);
            start..start + certificate_data.len()
        };

        self.certificate_range = Some(range);
        Ok(())
    }

    /// Remove the certificate table and its bytes while preserving the rest of
    /// the overlay.
    pub fn clear_security(&mut self) {
        if let Some(range) = self.certificate_range.take()
            && range.start <= range.end
            && range.end <= self.overlay.len()
        {
            self.overlay.drain(range);
        }
        self.image.clear_security();
    }

    /// Build a raw PE file with its overlay and certificate table.
    pub fn try_build(&self) -> Result<Vec<u8>> {
        let mut pe = self.image.clone();
        let certificate_size = self
            .certificate_range
            .as_ref()
            .map(|range| {
                u32::try_from(range.len()).map_err(|_| {
                    Error::invalid_data_directory("certificate table size exceeds u32")
                })
            })
            .transpose()?;
        if let Some(size) = certificate_size {
            // Reserve the entry before layout in case the source used fewer
            // than the five directory slots needed for Security.
            pe.set_data_directory(DataDirectoryType::Security, 1, size);
        } else {
            pe.clear_security();
        }
        let preserve_layout = RawLayoutFingerprint::from_image(&pe)? == self.source_layout
            && pe.current_layout_can_hold_data()?;
        let first_pass = if preserve_layout {
            pe.try_build_current_layout()?
        } else {
            pe.try_update_layout()?;
            pe.try_build_current_layout()?
        };
        let base_size = first_pass.len();

        let prefix_padding = if let Some(range) = &self.certificate_range {
            if range.start > range.end || range.end > self.overlay.len() {
                return Err(Error::invalid_data_directory(
                    "stored certificate range exceeds the overlay",
                ));
            }
            let certificate_position = base_size
                .checked_add(range.start)
                .ok_or_else(|| Error::invalid_data_directory("certificate offset overflow"))?;
            padding_for(certificate_position, 8)
        } else {
            0
        };

        if let Some(range) = &self.certificate_range {
            let certificate_offset = base_size
                .checked_add(prefix_padding)
                .and_then(|offset| offset.checked_add(range.start))
                .and_then(|offset| u32::try_from(offset).ok())
                .ok_or_else(|| Error::invalid_data_directory("certificate offset exceeds u32"))?;
            let certificate_size = certificate_size.ok_or_else(|| {
                Error::invalid_data_directory("certificate range is missing its encoded size")
            })?;
            pe.set_data_directory(
                DataDirectoryType::Security,
                certificate_offset,
                certificate_size,
            );
        } else {
            pe.clear_security();
        }

        let mut output = if preserve_layout {
            pe.try_build_current_layout()?
        } else {
            pe.try_build()?
        };
        if preserve_layout {
            restore_preserved_regions(&mut output, &self.preserved_regions)?;
        }
        output.resize(
            output
                .len()
                .checked_add(prefix_padding)
                .ok_or_else(|| Error::invalid_data_directory("file size overflow"))?,
            0,
        );
        output.extend_from_slice(&self.overlay);
        Ok(output)
    }

    /// Build a raw PE file, panicking if its manually-constructed state is
    /// invalid. Prefer [`Self::try_build`] for untrusted state.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        self.try_build()
            .expect("PeFile build failed: use PeFile::try_build() to handle invalid structures")
    }

    /// Write the complete raw PE file to disk.
    #[cfg(feature = "std")]
    pub fn write_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let bytes = self.try_build()?;
        let mut file = File::create(path)?;
        file.write_all(&bytes)?;
        Ok(())
    }

    /// Serialize the complete raw file to a `nostdio` stream.
    pub fn write_to<W: nostdio::Write>(&self, stream: &mut W) -> Result<()> {
        stream
            .write_all(&self.try_build()?)
            .map_err(crate::reader::map_nostdio_error)
    }
}

impl TryFrom<PeImage> for PeFile {
    type Error = Error;

    fn try_from(image: PeImage) -> Result<Self> {
        Self::new(image)
    }
}

impl Deref for PeFile {
    type Target = PeImage;

    fn deref(&self) -> &Self::Target {
        &self.image
    }
}

impl DerefMut for PeFile {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.image
    }
}

fn raw_image_end(pe: &PeImage) -> Result<usize> {
    let mut image_end = pe.optional_header.size_of_headers() as usize;
    for section in &pe.sections {
        let header = &section.header;
        if header.pointer_to_raw_data == 0 || header.size_of_raw_data == 0 {
            continue;
        }
        let end = (header.pointer_to_raw_data as usize)
            .checked_add(header.size_of_raw_data as usize)
            .ok_or_else(|| Error::invalid_section("section file range overflow"))?;
        image_end = image_end.max(end);
    }
    Ok(image_end)
}

impl RawLayoutFingerprint {
    fn from_image(image: &PeImage) -> Result<Self> {
        let pe_offset = usize::try_from(image.dos_header.e_lfanew)
            .map_err(|_| Error::invalid_section("e_lfanew is negative"))?;
        Ok(Self {
            pe_offset,
            optional_header_size: image.coff_header.size_of_optional_header as usize,
            size_of_headers: image.optional_header.size_of_headers() as usize,
            sections: image
                .sections
                .iter()
                .map(|section| {
                    (
                        section.header.pointer_to_raw_data,
                        section.header.size_of_raw_data,
                    )
                })
                .collect(),
        })
    }
}

fn collect_preserved_regions(
    data: &[u8],
    image: &PeImage,
    image_end: usize,
) -> Result<Vec<PreservedRegion>> {
    let pe_offset = usize::try_from(image.dos_header.e_lfanew)
        .map_err(|_| Error::invalid_section("e_lfanew is negative"))?;
    let optional_start = pe_offset
        .checked_add(4 + crate::CoffHeader::SIZE)
        .ok_or_else(|| Error::invalid_section("optional-header offset overflow"))?;
    let parsed_optional_end = optional_start
        .checked_add(image.optional_header.size())
        .ok_or_else(|| Error::invalid_section("optional-header size overflow"))?;
    let declared_optional_end = optional_start
        .checked_add(image.coff_header.size_of_optional_header as usize)
        .ok_or_else(|| Error::invalid_section("optional-header size overflow"))?;
    let section_table_end = declared_optional_end
        .checked_add(
            image
                .sections
                .len()
                .checked_mul(crate::SectionHeader::SIZE)
                .ok_or_else(|| Error::invalid_section("section-table size overflow"))?,
        )
        .ok_or_else(|| Error::invalid_section("section-table offset overflow"))?;

    let mut regions = Vec::new();
    push_preserved_region(
        &mut regions,
        data,
        parsed_optional_end..declared_optional_end,
    )?;

    let mut occupied: Vec<Range<usize>> = image
        .sections
        .iter()
        .filter(|section| {
            section.header.pointer_to_raw_data != 0 && section.header.size_of_raw_data != 0
        })
        .map(|section| {
            let start = section.header.pointer_to_raw_data as usize;
            let end = start
                .checked_add(section.header.size_of_raw_data as usize)
                .ok_or_else(|| Error::invalid_section("section file range overflow"))?;
            Ok(start..end)
        })
        .collect::<Result<_>>()?;
    occupied.sort_by_key(|range| range.start);

    let mut cursor = section_table_end.min(image_end);
    for range in occupied {
        if range.end <= cursor {
            continue;
        }
        if range.start > cursor {
            push_preserved_region(&mut regions, data, cursor..range.start.min(image_end))?;
        }
        cursor = cursor.max(range.end.min(image_end));
        if cursor >= image_end {
            break;
        }
    }
    if cursor < image_end {
        push_preserved_region(&mut regions, data, cursor..image_end)?;
    }
    Ok(regions)
}

fn push_preserved_region(
    regions: &mut Vec<PreservedRegion>,
    source: &[u8],
    range: Range<usize>,
) -> Result<()> {
    if range.start >= range.end {
        return Ok(());
    }
    let bytes = source
        .get(range.clone())
        .ok_or_else(|| Error::buffer_too_small(range.end, source.len()))?;
    regions.push(PreservedRegion {
        range,
        data: bytes.to_vec(),
    });
    Ok(())
}

fn restore_preserved_regions(output: &mut [u8], regions: &[PreservedRegion]) -> Result<()> {
    for region in regions {
        let target = output.get_mut(region.range.clone()).ok_or_else(|| {
            Error::invalid_section("preserved raw-file region exceeds rebuilt image")
        })?;
        if target.len() != region.data.len() {
            return Err(Error::invalid_section(
                "preserved raw-file region changed size",
            ));
        }
        target.copy_from_slice(&region.data);
    }
    Ok(())
}

fn align_up_usize(value: usize, alignment: usize) -> Option<usize> {
    let padding = padding_for(value, alignment);
    value.checked_add(padding)
}

fn padding_for(value: usize, alignment: usize) -> usize {
    if alignment == 0 {
        return 0;
    }
    let remainder = value % alignment;
    if remainder == 0 {
        0
    } else {
        alignment - remainder
    }
}
