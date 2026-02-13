//! Base relocation table parsing and building.
//!
//! This module provides types for reading and writing PE base relocation tables,
//! used when the image is loaded at a different address than its preferred base.

use crate::{Error, Result};

/// Relocation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RelocationType {
    /// No relocation (padding).
    Absolute = 0,
    /// High 16 bits of 32-bit address.
    High = 1,
    /// Low 16 bits of 32-bit address.
    Low = 2,
    /// Full 32-bit address (HIGHLOW).
    HighLow = 3,
    /// High 16 bits adjusted for sign extension.
    HighAdj = 4,
    /// Machine-specific (type 5): MIPS JMPADDR, ARM MOV32, RISC-V HIGH20.
    MachineSpecific5 = 5,
    /// Section index (reserved).
    Section = 6,
    /// Machine-specific (type 7): REL32, THUMB MOV32, RISC-V LOW12I.
    MachineSpecific7 = 7,
    /// RISC-V low 12 bits S-type.
    RiscvLow12S = 8,
    /// MIPS 16-bit jump address.
    MipsJmpAddr16 = 9,
    /// 64-bit address (DIR64).
    Dir64 = 10,
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
            _ => Self::Absolute, // Unknown types treated as padding
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
        ((self.reloc_type as u16) << 12) | (self.offset & 0x0FFF)
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
            return Err(Error::BufferTooSmall {
                expected: Self::HEADER_SIZE,
                actual: data.len(),
            });
        }

        let page_rva = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let block_size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

        // Number of entries = (block_size - header_size) / 2
        let num_entries = (block_size as usize - Self::HEADER_SIZE) / 2;

        if data.len() < block_size as usize {
            return Err(Error::BufferTooSmall {
                expected: block_size as usize,
                actual: data.len(),
            });
        }

        let mut entries = Vec::with_capacity(num_entries);
        for i in 0..num_entries {
            let offset = Self::HEADER_SIZE + i * 2;
            let value = u16::from_le_bytes([data[offset], data[offset + 1]]);
            entries.push(RelocationEntry::from_u16(value));
        }

        Ok(Self {
            page_rva,
            block_size,
            entries,
        })
    }

    /// Calculate the RVA for a specific entry.
    pub fn rva_for_entry(&self, entry: &RelocationEntry) -> u32 {
        self.page_rva + entry.offset as u32
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let size = Self::HEADER_SIZE + self.entries.len() * 2;
        let mut buf = vec![0u8; size];

        buf[0..4].copy_from_slice(&self.page_rva.to_le_bytes());
        buf[4..8].copy_from_slice(&(size as u32).to_le_bytes());

        for (i, entry) in self.entries.iter().enumerate() {
            let offset = Self::HEADER_SIZE + i * 2;
            buf[offset..offset + 2].copy_from_slice(&entry.to_u16().to_le_bytes());
        }

        buf
    }
}

/// The complete relocation table.
#[derive(Debug, Clone, Default)]
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
            // Read block header
            let data = read_at_rva(reloc_rva + offset, reloc_size as usize - offset as usize)
                .ok_or(Error::InvalidRva(reloc_rva + offset))?;

            if data.len() < RelocationBlock::HEADER_SIZE {
                break;
            }

            let page_rva = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            let block_size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

            // End of relocation table
            if page_rva == 0 || block_size == 0 {
                break;
            }

            let block = RelocationBlock::parse(&data)?;
            offset += block_size;
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
        for block in &self.blocks {
            for entry in &block.entries {
                if entry.is_padding() {
                    continue;
                }

                let rva = block.rva_for_entry(entry) as usize;
                if rva >= buffer.len() {
                    continue;
                }

                match entry.reloc_type {
                    RelocationType::HighLow => {
                        if rva + 4 <= buffer.len() {
                            let value = u32::from_le_bytes([
                                buffer[rva], buffer[rva + 1], buffer[rva + 2], buffer[rva + 3],
                            ]);
                            let new_value = (value as i64 + delta) as u32;
                            buffer[rva..rva + 4].copy_from_slice(&new_value.to_le_bytes());
                        }
                    }
                    RelocationType::Dir64 => {
                        if is_64bit && rva + 8 <= buffer.len() {
                            let value = u64::from_le_bytes([
                                buffer[rva], buffer[rva + 1], buffer[rva + 2], buffer[rva + 3],
                                buffer[rva + 4], buffer[rva + 5], buffer[rva + 6], buffer[rva + 7],
                            ]);
                            let new_value = (value as i64 + delta) as u64;
                            buffer[rva..rva + 8].copy_from_slice(&new_value.to_le_bytes());
                        }
                    }
                    RelocationType::High => {
                        if rva + 2 <= buffer.len() {
                            let value = u16::from_le_bytes([buffer[rva], buffer[rva + 1]]);
                            let full = (value as i64) << 16;
                            let new_full = full + delta;
                            let new_value = ((new_full >> 16) & 0xFFFF) as u16;
                            buffer[rva..rva + 2].copy_from_slice(&new_value.to_le_bytes());
                        }
                    }
                    RelocationType::Low => {
                        if rva + 2 <= buffer.len() {
                            let value = u16::from_le_bytes([buffer[rva], buffer[rva + 1]]);
                            let new_value = ((value as i64 + delta) & 0xFFFF) as u16;
                            buffer[rva..rva + 2].copy_from_slice(&new_value.to_le_bytes());
                        }
                    }
                    _ => {} // Other types not commonly used
                }
            }
        }
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();
        for block in &self.blocks {
            output.extend(block.to_bytes());
        }
        output
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
}

