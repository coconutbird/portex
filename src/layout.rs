//! PE layout calculations for file and section alignment.

use crate::coff::CoffHeader;
use crate::dos::DosHeader;
use crate::optional::OptionalHeader;
use crate::prelude::format;
use crate::section::{Section, SectionHeader};
use crate::{Error, Result};

/// Align a value up without wrapping.
#[inline]
pub fn checked_align_up(value: u32, alignment: u32) -> Option<u32> {
    if alignment == 0 {
        return Some(value);
    }
    let remainder = value % alignment;
    if remainder == 0 {
        Some(value)
    } else {
        value.checked_add(alignment - remainder)
    }
}

/// Align a value up to the given alignment.
#[inline]
pub fn align_up(value: u32, alignment: u32) -> u32 {
    checked_align_up(value, alignment).unwrap_or(u32::MAX - (u32::MAX % alignment.max(1)))
}

/// Align a value down to the given alignment.
#[inline]
pub fn align_down(value: u32, alignment: u32) -> u32 {
    if alignment == 0 {
        return value;
    }
    value - value % alignment
}

/// Layout configuration for PE building.
#[derive(Debug, Clone)]
pub struct LayoutConfig {
    /// File alignment (typically 0x200).
    pub file_alignment: u32,
    /// Section alignment (typically 0x1000).
    pub section_alignment: u32,
}

impl Default for LayoutConfig {
    fn default() -> Self {
        Self {
            file_alignment: 0x200,
            section_alignment: 0x1000,
        }
    }
}

impl LayoutConfig {
    /// Create config from optional header.
    pub fn from_optional_header(opt: &OptionalHeader) -> Self {
        Self {
            file_alignment: opt.file_alignment(),
            section_alignment: opt.section_alignment(),
        }
    }

    /// Align to file alignment.
    pub fn align_file(&self, value: u32) -> u32 {
        align_up(value, self.file_alignment)
    }

    /// Align to section alignment.
    pub fn align_section(&self, value: u32) -> u32 {
        align_up(value, self.section_alignment)
    }
}

/// Calculate the size of all headers (DOS + PE sig + COFF + Optional + Section table).
pub fn headers_size(num_sections: usize, optional_header_size: usize) -> usize {
    DosHeader::SIZE              // DOS header
        + 4                      // PE signature
        + CoffHeader::SIZE       // COFF header
        + optional_header_size   // Optional header
        + num_sections * SectionHeader::SIZE // Section table
}

/// Calculate the end of the PE headers for a PE signature at `pe_offset`.
///
/// Unlike [`headers_size`], this accounts for the DOS stub and any padding
/// before the PE signature through the header's `e_lfanew` value.
pub fn headers_size_at(
    pe_offset: usize,
    num_sections: usize,
    optional_header_size: usize,
) -> Option<usize> {
    let section_table_size = num_sections.checked_mul(SectionHeader::SIZE)?;
    pe_offset
        .checked_add(4 + CoffHeader::SIZE)
        .and_then(|size| size.checked_add(optional_header_size))
        .and_then(|size| size.checked_add(section_table_size))
}

/// Recalculate section layout (RVAs and file offsets).
/// Returns the total file size.
pub fn layout_sections(sections: &mut [Section], config: &LayoutConfig, headers_size: u32) -> u32 {
    try_layout_sections(sections, config, headers_size)
        .expect("PE layout overflow: use try_layout_sections() for fallible layout")
}

/// Recalculate section layout with checked size and address arithmetic.
pub fn try_layout_sections(
    sections: &mut [Section],
    config: &LayoutConfig,
    headers_size: u32,
) -> Result<u32> {
    // First section starts after headers, aligned to section alignment
    let mut current_rva = checked_align_up(headers_size, config.section_alignment)
        .ok_or_else(|| Error::invalid_section("first section RVA exceeds u32"))?;
    let mut current_file_offset = checked_align_up(headers_size, config.file_alignment)
        .ok_or_else(|| Error::invalid_section("first section file offset exceeds u32"))?;

    for section in sections.iter_mut() {
        let data_size = u32::try_from(section.data.len()).map_err(|_| {
            Error::invalid_section(format!("section '{}' data exceeds u32", section.name()))
        })?;
        let old_raw_size = section.header.size_of_raw_data;
        let preserved_raw_size = section.preserved_raw_size();
        let initialized_size = preserved_raw_size.unwrap_or(data_size);

        // Preserve valid gaps in parsed images. New sections (address zero) and
        // sections displaced by a preceding growth are assigned the next slot.
        let existing_rva = section.header.virtual_address;
        section.header.virtual_address = if existing_rva >= current_rva
            && (config.section_alignment == 0
                || existing_rva.is_multiple_of(config.section_alignment))
        {
            existing_rva
        } else {
            current_rva
        };

        // Set file offset
        let existing_file_offset = section.header.pointer_to_raw_data;
        section.header.pointer_to_raw_data = if initialized_size == 0 {
            0
        } else if existing_file_offset >= current_file_offset
            && existing_file_offset != 0
            && (config.file_alignment == 0
                || existing_file_offset.is_multiple_of(config.file_alignment))
        {
            existing_file_offset
        } else {
            current_file_offset
        };

        // Raw file padding is not part of VirtualSize. Preserve the parsed
        // value unless data grew beyond the old raw extent; this also keeps BSS
        // sections (VirtualSize > 0, no raw bytes) intact.
        let virtual_size = if section.header.virtual_size == 0 {
            data_size
        } else if data_size > old_raw_size {
            section.header.virtual_size.max(data_size)
        } else {
            section.header.virtual_size
        };
        section.header.virtual_size = virtual_size;
        section.header.size_of_raw_data = match preserved_raw_size {
            Some(size) => size,
            None => checked_align_up(initialized_size, config.file_alignment).ok_or_else(|| {
                Error::invalid_section(format!(
                    "section '{}' raw size exceeds u32 after alignment",
                    section.name()
                ))
            })?,
        };

        // Advance RVA (aligned to section alignment)
        let mapped_size = virtual_size.max(section.header.size_of_raw_data).max(1);
        let section_end = section
            .header
            .virtual_address
            .checked_add(mapped_size)
            .ok_or_else(|| {
                Error::invalid_section(format!(
                    "section '{}' virtual range overflows",
                    section.name()
                ))
            })?;
        current_rva = checked_align_up(section_end, config.section_alignment).ok_or_else(|| {
            Error::invalid_section(format!(
                "section '{}' virtual end exceeds u32 after alignment",
                section.name()
            ))
        })?;

        // Advance file offset (aligned to file alignment)
        if initialized_size != 0 {
            current_file_offset = section
                .header
                .pointer_to_raw_data
                .checked_add(section.header.size_of_raw_data)
                .ok_or_else(|| {
                    Error::invalid_section(format!(
                        "section '{}' raw-file range overflows",
                        section.name()
                    ))
                })?;
        }
    }

    Ok(current_file_offset)
}

/// Calculate size_of_image (total virtual size, aligned to section alignment).
pub fn calculate_size_of_image(sections: &[Section], config: &LayoutConfig) -> u32 {
    try_calculate_size_of_image(sections, config)
        .expect("PE image-size overflow: use try_calculate_size_of_image()")
}

/// Calculate `SizeOfImage` with checked address arithmetic.
pub fn try_calculate_size_of_image(sections: &[Section], config: &LayoutConfig) -> Result<u32> {
    if sections.is_empty() {
        return checked_align_up(0x1000, config.section_alignment)
            .ok_or_else(|| Error::invalid_section("minimum image size exceeds u32"));
    }

    sections
        .iter()
        .map(|section| {
            let mapped_size = section
                .header
                .virtual_size
                .max(section.header.size_of_raw_data)
                .max(1);
            let end = section
                .header
                .virtual_address
                .checked_add(mapped_size)
                .ok_or_else(|| {
                    Error::invalid_section(format!(
                        "section '{}' virtual range overflows",
                        section.name()
                    ))
                })?;
            checked_align_up(end, config.section_alignment).ok_or_else(|| {
                Error::invalid_section(format!(
                    "section '{}' virtual end exceeds u32 after alignment",
                    section.name()
                ))
            })
        })
        .try_fold(0u32, |maximum, size| size.map(|size| maximum.max(size)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_align_up() {
        assert_eq!(align_up(0, 0x200), 0);
        assert_eq!(align_up(1, 0x200), 0x200);
        assert_eq!(align_up(0x200, 0x200), 0x200);
        assert_eq!(align_up(0x201, 0x200), 0x400);
        assert_eq!(align_up(0x1000, 0x1000), 0x1000);
        assert_eq!(align_up(0x1001, 0x1000), 0x2000);
    }

    #[test]
    fn test_align_down() {
        assert_eq!(align_down(0, 0x200), 0);
        assert_eq!(align_down(0x1FF, 0x200), 0);
        assert_eq!(align_down(0x200, 0x200), 0x200);
        assert_eq!(align_down(0x3FF, 0x200), 0x200);
    }
}
