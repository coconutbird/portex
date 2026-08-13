//! Base relocation table parsing and building.
//!
//! This module provides types for reading and writing PE base relocation tables,
//! used when the image is loaded at a different address than its preferred base.
//!
//! # Examples
//!
//! ## Listing relocations from a PE file
//!
//! ```no_run
//! use portex::PeImage;
//!
//! # let file_bytes: &[u8] = &[];
//! let pe = PeImage::parse(file_bytes)?;
//!
//! let relocs = pe.relocations()?;
//! for block in &relocs.blocks {
//!     println!("Block at page RVA {:#x}", block.page_rva);
//!     for entry in &block.entries {
//!         println!("  Type: {:?}, Offset: {:#x}",
//!             entry.reloc_type, entry.offset);
//!     }
//! }
//! # Ok::<(), portex::Error>(())
//! ```
//!
//! ## Adding relocations to a PE file
//!
//! ```no_run
//! use portex::{PeImage, RelocationBlock, RelocationEntry, RelocationTable, RelocationType};
//!
//! # let file_bytes: &[u8] = &[];
//! let mut pe = PeImage::parse(file_bytes)?;
//!
//! // Build relocation table by creating blocks directly
//! let table = RelocationTable {
//!     blocks: vec![
//!         RelocationBlock {
//!             page_rva: 0x1000,
//!             block_size: 12, // 8-byte header + 2 entries * 2 bytes
//!             entries: vec![
//!                 RelocationEntry { reloc_type: RelocationType::Dir64, offset: 0x100 },
//!                 RelocationEntry { reloc_type: RelocationType::Dir64, offset: 0x200 },
//!             ],
//!         },
//!     ],
//! };
//!
//! // Update PE with relocations
//! pe.update_relocations(table, None)?;
//! let rebuilt = pe.try_build()?;
//! assert!(!rebuilt.is_empty());
//! # Ok::<(), portex::Error>(())
//! ```

use crate::prelude::*;
use crate::{Error, Result};

/// Relocation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocationType {
    /// No relocation (padding).
    Absolute,
    /// High 16 bits of 32-bit address.
    High,
    /// Low 16 bits of 32-bit address.
    Low,
    /// Full 32-bit address (HIGHLOW).
    HighLow,
    /// High 16 bits adjusted for sign extension.
    HighAdj,
    /// Machine-specific (type 5): MIPS JMPADDR, ARM MOV32, RISC-V HIGH20.
    MachineSpecific5,
    /// Section index (reserved).
    Section,
    /// Machine-specific (type 7): REL32, THUMB MOV32, RISC-V LOW12I.
    MachineSpecific7,
    /// RISC-V low 12 bits S-type.
    RiscvLow12S,
    /// MIPS 16-bit jump address.
    MipsJmpAddr16,
    /// 64-bit address (DIR64).
    Dir64,
    /// Relocation type not known to this version of the crate.
    Unknown(u8),
}

impl RelocationType {
    /// Parse from the type bits (high 4 bits of entry).
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Absolute,
            1 => Self::High,
            2 => Self::Low,
            3 => Self::HighLow,
            4 => Self::HighAdj,
            5 => Self::MachineSpecific5,
            6 => Self::Section,
            7 => Self::MachineSpecific7,
            8 => Self::RiscvLow12S,
            9 => Self::MipsJmpAddr16,
            10 => Self::Dir64,
            other => Self::Unknown(other & 0x0f),
        }
    }

    /// Return the four-bit on-disk relocation code.
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Absolute => 0,
            Self::High => 1,
            Self::Low => 2,
            Self::HighLow => 3,
            Self::HighAdj => 4,
            Self::MachineSpecific5 => 5,
            Self::Section => 6,
            Self::MachineSpecific7 => 7,
            Self::RiscvLow12S => 8,
            Self::MipsJmpAddr16 => 9,
            Self::Dir64 => 10,
            Self::Unknown(value) => value & 0x0f,
        }
    }
}

/// A single relocation entry within a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelocationEntry {
    /// Relocation type.
    pub reloc_type: RelocationType,
    /// Offset from the block's page RVA (12 bits).
    pub offset: u16,
}

impl RelocationEntry {
    /// Parse from a 16-bit value.
    pub fn from_u16(value: u16) -> Self {
        Self {
            reloc_type: RelocationType::from_u8((value >> 12) as u8),
            offset: value & 0x0FFF,
        }
    }

    /// Convert to a 16-bit value.
    pub fn to_u16(&self) -> u16 {
        (u16::from(self.reloc_type.as_u8()) << 12) | (self.offset & 0x0FFF)
    }

    /// Check if this is a padding entry.
    pub fn is_padding(&self) -> bool {
        matches!(self.reloc_type, RelocationType::Absolute)
    }
}

/// IMAGE_BASE_RELOCATION header - 8 bytes
/// Represents a block of relocations for a single 4KB page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelocationBlock {
    /// Page RVA (base address for this block's relocations).
    pub page_rva: u32,
    /// Total size of this block including header.
    pub block_size: u32,
    /// Relocation entries for this page.
    pub entries: Vec<RelocationEntry>,
}

impl RelocationBlock {
    pub const HEADER_SIZE: usize = 8;

    /// Parse a relocation block from bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::HEADER_SIZE {
            return Err(Error::buffer_too_small(Self::HEADER_SIZE, data.len()));
        }

        let page_rva = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let block_size_raw = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

        let block_size = block_size_raw as usize;
        if block_size < Self::HEADER_SIZE || !block_size.is_multiple_of(4) {
            return Err(Error::invalid_data_directory(format!(
                "invalid base-relocation block size {}",
                block_size
            )));
        }
        if !page_rva.is_multiple_of(0x1000) {
            return Err(Error::invalid_data_directory(format!(
                "base-relocation page RVA {page_rva:#x} is not 4-KiB aligned"
            )));
        }

        // Number of entries = (block_size - header_size) / 2
        let num_entries = (block_size - Self::HEADER_SIZE) / 2;

        if data.len() < block_size {
            return Err(Error::buffer_too_small(block_size, data.len()));
        }

        let mut entries = Vec::with_capacity(num_entries);
        for i in 0..num_entries {
            let offset = Self::HEADER_SIZE + i * 2;
            let value = u16::from_le_bytes([data[offset], data[offset + 1]]);
            entries.push(RelocationEntry::from_u16(value));
        }

        Ok(Self {
            page_rva,
            block_size: block_size_raw,
            entries,
        })
    }

    /// Calculate the RVA for a specific entry.
    pub fn rva_for_entry(&self, entry: &RelocationEntry) -> u32 {
        self.checked_rva_for_entry(entry).unwrap_or(u32::MAX)
    }

    /// Calculate an entry RVA without wrapping.
    pub fn checked_rva_for_entry(&self, entry: &RelocationEntry) -> Option<u32> {
        self.page_rva.checked_add(u32::from(entry.offset))
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.try_to_bytes()
            .expect("relocation block build failed: use try_to_bytes()")
    }

    /// Serialize a block with checked size and 12-bit offsets.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>> {
        if !self.page_rva.is_multiple_of(0x1000) {
            return Err(Error::invalid_data_directory(format!(
                "base-relocation page RVA {:#x} is not 4-KiB aligned",
                self.page_rva
            )));
        }
        for entry in &self.entries {
            if entry.offset > 0x0fff {
                return Err(Error::invalid_data_directory(format!(
                    "relocation offset {:#x} exceeds 12 bits",
                    entry.offset
                )));
            }
            if matches!(entry.reloc_type, RelocationType::Unknown(value) if value > 0x0f) {
                return Err(Error::invalid_data_directory(
                    "relocation type exceeds four bits",
                ));
            }
            self.page_rva
                .checked_add(u32::from(entry.offset))
                .ok_or_else(|| {
                    Error::invalid_data_directory("base-relocation target RVA overflow")
                })?;
        }
        let entry_count = self.entries.len() + usize::from(!self.entries.len().is_multiple_of(2));
        let size = entry_count
            .checked_mul(2)
            .and_then(|size| Self::HEADER_SIZE.checked_add(size))
            .ok_or_else(|| Error::invalid_data_directory("relocation block size overflow"))?;
        let size_u32 = u32::try_from(size)
            .map_err(|_| Error::invalid_data_directory("relocation block exceeds u32"))?;
        let mut buf = vec![0u8; size];

        buf[0..4].copy_from_slice(&self.page_rva.to_le_bytes());
        buf[4..8].copy_from_slice(&size_u32.to_le_bytes());

        for (i, entry) in self.entries.iter().enumerate() {
            let offset = Self::HEADER_SIZE + i * 2;
            buf[offset..offset + 2].copy_from_slice(&entry.to_u16().to_le_bytes());
        }
        // An odd entry count requires one IMAGE_REL_BASED_ABSOLUTE padding word;
        // the zero-initialized buffer already contains it.

        Ok(buf)
    }
}

/// The complete relocation table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RelocationTable {
    /// List of relocation blocks.
    pub blocks: Vec<RelocationBlock>,
}

impl RelocationTable {
    /// Parse relocation table from a PE file.
    /// `reloc_rva` is the RVA from the data directory.
    /// `reloc_size` is the size from the data directory.
    /// `read_at_rva` is a closure that reads bytes at an RVA.
    pub fn parse<F>(reloc_rva: u32, reloc_size: u32, read_at_rva: F) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        let mut blocks = Vec::new();
        let mut offset = 0u32;

        while offset < reloc_size {
            let entry_rva = reloc_rva.checked_add(offset).ok_or_else(|| {
                Error::invalid_data_directory("base-relocation table RVA overflow")
            })?;
            let remaining = reloc_size.checked_sub(offset).ok_or_else(|| {
                Error::invalid_data_directory("base-relocation table size underflow")
            })?;
            if remaining < RelocationBlock::HEADER_SIZE as u32 {
                let tail = crate::parse_utils::read_exact_rva(
                    &read_at_rva,
                    entry_rva,
                    remaining as usize,
                    "base-relocation tail",
                )?;
                if tail.iter().all(|byte| *byte == 0) {
                    break;
                }
                return Err(Error::invalid_data_directory(
                    "truncated base-relocation block header",
                ));
            }

            let header = crate::parse_utils::read_exact_rva(
                &read_at_rva,
                entry_rva,
                RelocationBlock::HEADER_SIZE,
                "base-relocation block header",
            )?;

            let page_rva = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
            let block_size = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);

            // Some linkers pad the declared directory with an all-zero tail.
            if page_rva == 0 && block_size == 0 {
                let tail = crate::parse_utils::read_exact_rva(
                    &read_at_rva,
                    entry_rva,
                    remaining as usize,
                    "base-relocation zero tail",
                )?;
                if tail.iter().all(|byte| *byte == 0) {
                    break;
                }
                return Err(Error::invalid_data_directory(
                    "zero base-relocation block is followed by nonzero data",
                ));
            }

            if block_size > remaining {
                return Err(Error::invalid_data_directory(format!(
                    "base-relocation block size {block_size} exceeds {remaining} remaining bytes"
                )));
            }
            let data = crate::parse_utils::read_exact_rva(
                &read_at_rva,
                entry_rva,
                block_size as usize,
                "base-relocation block",
            )?;

            let block = RelocationBlock::parse(&data)?;
            offset = offset.checked_add(block_size).ok_or_else(|| {
                Error::invalid_data_directory("base-relocation table size overflow")
            })?;
            if offset > reloc_size {
                return Err(Error::invalid_data_directory(format!(
                    "base-relocation block extends past directory size {}",
                    reloc_size
                )));
            }
            blocks.push(block);
        }

        Ok(Self { blocks })
    }

    /// Check if the relocation table is empty.
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Get total count of relocations (excluding padding).
    pub fn relocation_count(&self) -> usize {
        self.blocks
            .iter()
            .flat_map(|b| &b.entries)
            .filter(|e| !e.is_padding())
            .count()
    }

    /// Apply relocations to a buffer.
    /// `delta` is the difference between actual load address and preferred base.
    /// `buffer` is the loaded image.
    /// `is_64bit` determines relocation size for DIR64 entries.
    pub fn apply(&self, buffer: &mut [u8], delta: i64, is_64bit: bool) {
        let _ = self.try_apply(buffer, i128::from(delta), is_64bit);
    }

    /// Apply all supported base relocations and fail on malformed ranges or an
    /// architecture-specific relocation that cannot be interpreted generically.
    pub fn try_apply(&self, buffer: &mut [u8], delta: i128, is_64bit: bool) -> Result<usize> {
        let mut applied = 0usize;
        for block in &self.blocks {
            let mut index = 0usize;
            while index < block.entries.len() {
                let entry = &block.entries[index];
                if entry.is_padding() {
                    index += 1;
                    continue;
                }

                let target_rva = block
                    .page_rva
                    .checked_add(u32::from(entry.offset))
                    .ok_or_else(|| {
                        Error::invalid_data_directory("base-relocation target RVA overflow")
                    })?;
                let rva = target_rva as usize;

                match entry.reloc_type {
                    RelocationType::HighLow => {
                        let end = checked_target_end(rva, 4, buffer.len(), target_rva)?;
                        let value = u32::from_le_bytes([
                            buffer[rva],
                            buffer[rva + 1],
                            buffer[rva + 2],
                            buffer[rva + 3],
                        ]);
                        let new_value = (i128::from(value) + delta) as u32;
                        buffer[rva..end].copy_from_slice(&new_value.to_le_bytes());
                    }
                    RelocationType::Dir64 if is_64bit => {
                        let end = checked_target_end(rva, 8, buffer.len(), target_rva)?;
                        let value = u64::from_le_bytes([
                            buffer[rva],
                            buffer[rva + 1],
                            buffer[rva + 2],
                            buffer[rva + 3],
                            buffer[rva + 4],
                            buffer[rva + 5],
                            buffer[rva + 6],
                            buffer[rva + 7],
                        ]);
                        let new_value = (i128::from(value) + delta) as u64;
                        buffer[rva..end].copy_from_slice(&new_value.to_le_bytes());
                    }
                    RelocationType::High => {
                        let end = checked_target_end(rva, 2, buffer.len(), target_rva)?;
                        let value = u16::from_le_bytes([buffer[rva], buffer[rva + 1]]);
                        let full = i128::from(value) << 16;
                        let new_full = full + delta;
                        let new_value = ((new_full >> 16) & 0xFFFF) as u16;
                        buffer[rva..end].copy_from_slice(&new_value.to_le_bytes());
                    }
                    RelocationType::Low => {
                        let end = checked_target_end(rva, 2, buffer.len(), target_rva)?;
                        let value = u16::from_le_bytes([buffer[rva], buffer[rva + 1]]);
                        let new_value = ((i128::from(value) + delta) & 0xFFFF) as u16;
                        buffer[rva..end].copy_from_slice(&new_value.to_le_bytes());
                    }
                    RelocationType::HighAdj => {
                        let end = checked_target_end(rva, 2, buffer.len(), target_rva)?;
                        let adjustment = block.entries.get(index + 1).ok_or_else(|| {
                            Error::invalid_data_directory(
                                "HIGHADJ relocation is missing its adjustment word",
                            )
                        })?;
                        let low = i128::from(adjustment.to_u16() as i16);
                        let high =
                            i128::from(u16::from_le_bytes([buffer[rva], buffer[rva + 1]])) << 16;
                        let relocated = high + low + delta + 0x8000;
                        let new_value = ((relocated >> 16) & 0xFFFF) as u16;
                        buffer[rva..end].copy_from_slice(&new_value.to_le_bytes());
                        index += 1;
                    }
                    RelocationType::Dir64 => {
                        return Err(Error::invalid_data_directory(
                            "DIR64 relocation appears in a PE32 image",
                        ));
                    }
                    unsupported => {
                        return Err(Error::invalid_data_directory(format!(
                            "relocation type {:?} requires machine-specific handling",
                            unsupported
                        )));
                    }
                }
                applied += 1;
                index += 1;
            }
        }
        Ok(applied)
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.try_to_bytes()
            .expect("relocation table build failed: use try_to_bytes()")
    }

    /// Serialize each block with checked table-size arithmetic.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>> {
        let mut output = Vec::new();
        for block in &self.blocks {
            let bytes = block.try_to_bytes()?;
            output
                .len()
                .checked_add(bytes.len())
                .and_then(|size| u32::try_from(size).ok())
                .ok_or_else(|| {
                    Error::invalid_data_directory("base-relocation table exceeds u32")
                })?;
            output.extend(bytes);
        }
        Ok(output)
    }

    /// Calculate total size when serialized.
    pub fn calculate_size(&self) -> usize {
        self.blocks
            .iter()
            .map(|b| {
                let entry_count = b.entries.len();
                // Pad to 4-byte boundary
                let padded_count = if entry_count % 2 == 1 {
                    entry_count + 1
                } else {
                    entry_count
                };
                RelocationBlock::HEADER_SIZE + padded_count * 2
            })
            .sum()
    }

    /// Add a relocation entry at a specific RVA.
    pub fn add_relocation(&mut self, rva: u32, reloc_type: RelocationType) {
        let page_rva = rva & !0xFFF; // Round down to 4KB page
        let offset = (rva & 0xFFF) as u16;

        // Find or create block for this page
        let block = if let Some(block) = self.blocks.iter_mut().find(|b| b.page_rva == page_rva) {
            block
        } else {
            self.blocks.push(RelocationBlock {
                page_rva,
                block_size: 0, // Will be calculated on serialize
                entries: Vec::new(),
            });
            self.blocks.last_mut().unwrap()
        };

        block.entries.push(RelocationEntry { reloc_type, offset });
    }

    /// Add a HIGHLOW (32-bit) relocation.
    pub fn add_highlow(&mut self, rva: u32) {
        self.add_relocation(rva, RelocationType::HighLow);
    }

    /// Add a DIR64 (64-bit) relocation.
    pub fn add_dir64(&mut self, rva: u32) {
        self.add_relocation(rva, RelocationType::Dir64);
    }

    /// Sort blocks by page RVA and ensure each block is padded to 4-byte boundary.
    /// Modifies self in place.
    pub fn normalize(&mut self) {
        // Sort blocks
        self.blocks.sort_by_key(|b| b.page_rva);

        // Pad each block to 4-byte boundary
        for block in &mut self.blocks {
            if block.entries.len() % 2 == 1 {
                block.entries.push(RelocationEntry {
                    reloc_type: RelocationType::Absolute,
                    offset: 0,
                });
            }
            // Update block_size
            block.block_size = (RelocationBlock::HEADER_SIZE + block.entries.len() * 2) as u32;
        }
    }

    /// Create a normalized copy without modifying self.
    pub fn normalized(&self) -> Self {
        let mut copy = self.clone();
        copy.normalize();
        copy
    }

    /// Build relocation table bytes, normalizing a copy internally.
    /// Does not modify self.
    pub fn build(&self) -> Vec<u8> {
        self.try_build()
            .expect("relocation build failed: use try_build() for fallible serialization")
    }

    /// Build normalized relocation bytes with checked block/table sizes.
    pub fn try_build(&self) -> Result<Vec<u8>> {
        self.normalized().try_to_bytes()
    }
}

fn checked_target_end(start: usize, width: usize, buffer_len: usize, rva: u32) -> Result<usize> {
    let end = start
        .checked_add(width)
        .ok_or_else(|| Error::invalid_data_directory("relocation target range overflow"))?;
    if end > buffer_len {
        return Err(Error::invalid_rva(rva));
    }
    Ok(end)
}

/// Builder for relocation tables.
///
/// This provides a fluent interface for building relocation tables.
///
/// # Example
///
/// ```
/// use portex::reloc::RelocationBuilder;
///
/// let mut builder = RelocationBuilder::new();
///
/// // Add relocations (automatically grouped by page)
/// builder.add_dir64(0x1000);
/// builder.add_dir64(0x1008);
/// builder.add_highlow(0x2000);
///
/// let (data, size) = builder.build();
/// assert!(size > 0);
/// ```
#[derive(Debug, Clone, Default)]
pub struct RelocationBuilder {
    table: RelocationTable,
}

impl RelocationBuilder {
    /// Create a new relocation builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create from an existing relocation table.
    pub fn from_table(table: RelocationTable) -> Self {
        Self { table }
    }

    /// Add a relocation entry at a specific RVA.
    pub fn add_relocation(&mut self, rva: u32, reloc_type: RelocationType) -> &mut Self {
        self.table.add_relocation(rva, reloc_type);
        self
    }

    /// Add a HIGHLOW (32-bit) relocation.
    pub fn add_highlow(&mut self, rva: u32) -> &mut Self {
        self.table.add_highlow(rva);
        self
    }

    /// Add a DIR64 (64-bit) relocation.
    pub fn add_dir64(&mut self, rva: u32) -> &mut Self {
        self.table.add_dir64(rva);
        self
    }

    /// Get the number of relocations added.
    pub fn relocation_count(&self) -> usize {
        self.table.relocation_count()
    }

    /// Calculate the total size when serialized.
    pub fn calculate_size(&self) -> usize {
        self.table.normalized().calculate_size()
    }

    /// Build the relocation table.
    /// Returns (data, size).
    pub fn build(&self) -> (Vec<u8>, u32) {
        let data = self.table.build();
        let size = data.len() as u32;
        (data, size)
    }

    /// Get the underlying table (normalized).
    pub fn into_table(self) -> RelocationTable {
        self.table.normalized()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relocation_entry_roundtrip() {
        let entry = RelocationEntry {
            reloc_type: RelocationType::HighLow,
            offset: 0x123,
        };
        let value = entry.to_u16();
        let parsed = RelocationEntry::from_u16(value);
        assert_eq!(entry.reloc_type, parsed.reloc_type);
        assert_eq!(entry.offset, parsed.offset);
    }

    #[test]
    fn test_relocation_entry_padding() {
        let entry = RelocationEntry::from_u16(0);
        assert!(entry.is_padding());

        let entry2 = RelocationEntry::from_u16(0x3123); // HIGHLOW
        assert!(!entry2.is_padding());
    }

    #[test]
    fn test_relocation_block_parse() {
        let mut data = vec![0u8; 16];
        data[0..4].copy_from_slice(&0x1000u32.to_le_bytes()); // page_rva
        data[4..8].copy_from_slice(&16u32.to_le_bytes()); // block_size (header + 4 entries)
        data[8..10].copy_from_slice(&0x3010u16.to_le_bytes()); // HIGHLOW at 0x10
        data[10..12].copy_from_slice(&0x3020u16.to_le_bytes()); // HIGHLOW at 0x20
        data[12..14].copy_from_slice(&0x0000u16.to_le_bytes()); // padding
        data[14..16].copy_from_slice(&0xA030u16.to_le_bytes()); // DIR64 at 0x30

        let block = RelocationBlock::parse(&data).unwrap();
        assert_eq!(block.page_rva, 0x1000);
        assert_eq!(block.entries.len(), 4);
        assert_eq!(block.entries[0].reloc_type, RelocationType::HighLow);
        assert_eq!(block.entries[0].offset, 0x10);
        assert!(block.entries[2].is_padding());
        assert_eq!(block.entries[3].reloc_type, RelocationType::Dir64);
    }

    #[test]
    fn test_relocation_table_builder() {
        let mut table = RelocationTable::default();

        // Add some relocations across different pages
        table.add_highlow(0x1010);
        table.add_highlow(0x1020);
        table.add_dir64(0x2008);
        table.add_highlow(0x1030); // Same page as first two

        let data = table.build();

        // Parse it back
        let read_fn = |rva: u32, len: usize| -> Option<Vec<u8>> {
            let offset = rva as usize;
            if offset >= data.len() {
                return None;
            }
            let available = (data.len() - offset).min(len);
            Some(data[offset..offset + available].to_vec())
        };

        let parsed = RelocationTable::parse(0, data.len() as u32, read_fn).unwrap();
        assert_eq!(parsed.blocks.len(), 2); // Two pages: 0x1000 and 0x2000
        assert_eq!(parsed.relocation_count(), 4);
    }

    #[test]
    fn test_relocation_builder() {
        let mut builder = RelocationBuilder::new();

        builder
            .add_dir64(0x1000)
            .add_dir64(0x1008)
            .add_highlow(0x2000);

        assert_eq!(builder.relocation_count(), 3);

        let (data, size) = builder.build();
        assert!(size > 0);
        assert_eq!(data.len(), size as usize);

        // Parse it back
        let read_fn = |rva: u32, len: usize| -> Option<Vec<u8>> {
            let offset = rva as usize;
            if offset >= data.len() {
                return None;
            }
            let available = (data.len() - offset).min(len);
            Some(data[offset..offset + available].to_vec())
        };

        let parsed = RelocationTable::parse(0, size, read_fn).unwrap();
        assert_eq!(parsed.blocks.len(), 2);
        assert_eq!(parsed.relocation_count(), 3);
    }
}
