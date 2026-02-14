//! PE layout calculations for file and section alignment.

use crate::coff::CoffHeader;
use crate::dos::DosHeader;
use crate::optional::OptionalHeader;
use crate::section::{Section, SectionHeader};

/// Align a value up to the given alignment.
#[inline]
pub fn align_up(value: u32, alignment: u32) -> u32 {
    if alignment == 0 {
        return value;
    }
    (value + alignment - 1) & !(alignment - 1)
}

/// Align a value down to the given alignment.
#[inline]
pub fn align_down(value: u32, alignment: u32) -> u32 {
    if alignment == 0 {
        return value;
    }
    value & !(alignment - 1)
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

/// Recalculate section layout (RVAs and file offsets).
/// Returns the total file size.
pub fn layout_sections(sections: &mut [Section], config: &LayoutConfig, headers_size: u32) -> u32 {
    // First section starts after headers, aligned to section alignment
    let mut current_rva = config.align_section(headers_size);
    let mut current_file_offset = config.align_file(headers_size);

    for section in sections.iter_mut() {
        // Set virtual address
        section.header.virtual_address = current_rva;

        // Set file offset
        section.header.pointer_to_raw_data = if section.data.is_empty() {
            0
        } else {
            current_file_offset
        };

        // Calculate sizes
        let virtual_size = section.data.len() as u32;
        section.header.virtual_size = virtual_size;
        section.header.size_of_raw_data = config.align_file(virtual_size);

        // Advance RVA (aligned to section alignment)
        current_rva += config.align_section(virtual_size.max(1));

        // Advance file offset (aligned to file alignment)
        if !section.data.is_empty() {
            current_file_offset += section.header.size_of_raw_data;
        }
    }

    current_file_offset
}

/// Calculate size_of_image (total virtual size, aligned to section alignment).
pub fn calculate_size_of_image(sections: &[Section], config: &LayoutConfig) -> u32 {
    if sections.is_empty() {
        return config.align_section(0x1000); // Minimum
    }

    let last = &sections[sections.len() - 1];
    let end_rva =
        last.header.virtual_address + config.align_section(last.header.virtual_size.max(1));
    end_rva
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
