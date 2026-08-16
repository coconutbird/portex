//! Rich Header parsing and building.
//!
//! The Rich Header is an undocumented structure inserted by Microsoft linker
//! between the DOS stub and PE signature. It contains build tool information.

use crate::prelude::*;
use crate::{Error, Result};

/// Rich header magic value ("Rich" XORed with key).
const RICH_MAGIC: u32 = 0x68636952; // "Rich"

/// DanS marker value (before XOR).
const DANS_MAGIC: u32 = 0x536E6144; // "DanS"

/// A single Rich header entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RichEntry {
    /// Product ID (compiler/tool identifier).
    pub product_id: u16,
    /// Build number.
    pub build_number: u16,
    /// Use count.
    pub use_count: u32,
}

impl RichEntry {
    /// Create from raw comp_id value.
    pub fn from_comp_id(comp_id: u32, use_count: u32) -> Self {
        Self {
            product_id: (comp_id >> 16) as u16,
            build_number: (comp_id & 0xFFFF) as u16,
            use_count,
        }
    }

    /// Convert to comp_id value.
    pub fn to_comp_id(&self) -> u32 {
        ((self.product_id as u32) << 16) | (self.build_number as u32)
    }

    /// Get a description of the product (if known).
    pub fn product_name(&self) -> &'static str {
        match self.product_id {
            0x0001 => "Import (old)",
            0x0002 => "Linker (old)",
            0x0004 => "CVTRES (old)",
            0x0005 => "Import",
            0x0006 => "Linker",
            0x0007 => "Export",
            0x000A => "CVTRES",
            0x000B => "MASM",
            0x000F => "Linker",
            0x0010 => "C",
            0x0011 => "C++",
            0x0013 => "Resource",
            0x0040 => "MSIL",
            0x0093 => "Linker14",
            0x0094 => "Export14",
            0x0095 => "MASM14",
            0x0102 => "CVTRES14",
            0x0103 => "C14",
            0x0104 => "C++14",
            0x0105 => "Import14",
            0x0106 => "Resource14",
            0x0109 => "CVTPGD",
            0x0261 => "C++/CLI",
            0x0262 => "CPPASM",
            0x0263 => "Import16",
            0x0264 => "Export16",
            0x0265 => "MASM16",
            _ => "Unknown",
        }
    }
}

/// Parsed Rich Header.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RichHeader {
    /// XOR key used for encoding.
    pub key: u32,
    /// List of tool entries.
    pub entries: Vec<RichEntry>,
    /// Offset in file where Rich header starts (after DOS stub).
    pub offset: usize,
    /// Total size of the Rich header.
    pub size: usize,
}

impl RichHeader {
    /// Find and parse Rich header from DOS stub area.
    /// `data` should start from beginning of file.
    /// Returns None if no Rich header found.
    pub fn parse(data: &[u8]) -> Option<Self> {
        // A Rich header lives between the fixed DOS header and the PE header.
        if data.len() < 0x40 {
            return None;
        }

        // Get PE offset from DOS header
        let pe_offset =
            u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
        if pe_offset.checked_add(4)? > data.len() || pe_offset < 0x40 + 24 {
            return None;
        }

        // Search backwards for the literal "Rich" marker followed by its XOR
        // key. Older Portex versions incorrectly XORed the marker, so accept
        // that spelling while parsing but never emit it.
        let search_area = &data[0x40..pe_offset];
        if search_area.len() < 8 {
            return None;
        }
        for i in (0..=search_area.len() - 8).rev() {
            let value = u32::from_le_bytes([
                search_area[i],
                search_area[i + 1],
                search_area[i + 2],
                search_area[i + 3],
            ]);

            let key = u32::from_le_bytes([
                search_area[i + 4],
                search_area[i + 5],
                search_area[i + 6],
                search_area[i + 7],
            ]);
            if value != RICH_MAGIC && value ^ key != RICH_MAGIC {
                continue;
            }
            let rich_offset = i + 0x40;
            if rich_offset < 0x40 + 16 {
                continue;
            }
            for start_offset in (0x40..=rich_offset - 16).rev() {
                let encoded_dans = u32::from_le_bytes([
                    data[start_offset],
                    data[start_offset + 1],
                    data[start_offset + 2],
                    data[start_offset + 3],
                ]);
                let entries_size = rich_offset - start_offset - 16;
                if encoded_dans ^ key != DANS_MAGIC || !entries_size.is_multiple_of(8) {
                    continue;
                }
                if data[start_offset + 4..start_offset + 16]
                    .chunks_exact(4)
                    .any(|word| u32::from_le_bytes([word[0], word[1], word[2], word[3]]) != key)
                {
                    continue;
                }

                let mut entries = Vec::with_capacity(entries_size / 8);
                for chunk in data[start_offset + 16..rich_offset].chunks_exact(8) {
                    let comp_id =
                        u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) ^ key;
                    let count = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]) ^ key;
                    if comp_id != 0 || count != 0 {
                        entries.push(RichEntry::from_comp_id(comp_id, count));
                    }
                }
                return Some(Self {
                    key,
                    entries,
                    offset: start_offset,
                    size: rich_offset + 8 - start_offset,
                });
            }
        }
        None
    }

    /// Build Rich header bytes.
    pub fn build(&self) -> Vec<u8> {
        self.try_build()
            .expect("Rich-header build failed: use try_build()")
    }

    /// Build a Rich header with checked entry-size arithmetic.
    pub fn try_build(&self) -> Result<Vec<u8>> {
        // Size: DanS (4) + padding (12) + entries (8 each) + Rich (4) + key (4)
        let size = self
            .entries
            .len()
            .checked_mul(8)
            .and_then(|size| size.checked_add(24))
            .ok_or_else(|| Error::generic("Rich-header size overflow"))?;
        let mut buf = vec![0u8; size];

        let key = self.key;

        // DanS marker (XORed)
        buf[0..4].copy_from_slice(&(DANS_MAGIC ^ key).to_le_bytes());

        // Padding (3 dwords, all XORed with key)
        buf[4..8].copy_from_slice(&key.to_le_bytes());
        buf[8..12].copy_from_slice(&key.to_le_bytes());
        buf[12..16].copy_from_slice(&key.to_le_bytes());

        // Entries
        for (i, entry) in self.entries.iter().enumerate() {
            let offset = 16 + i * 8;
            buf[offset..offset + 4].copy_from_slice(&(entry.to_comp_id() ^ key).to_le_bytes());
            buf[offset + 4..offset + 8].copy_from_slice(&(entry.use_count ^ key).to_le_bytes());
        }

        // Rich marker
        let rich_offset = 16 + self.entries.len() * 8;
        buf[rich_offset..rich_offset + 4].copy_from_slice(&RICH_MAGIC.to_le_bytes());
        buf[rich_offset + 4..rich_offset + 8].copy_from_slice(&key.to_le_bytes());

        Ok(buf)
    }

    /// Calculate a checksum/key from the entries (simplified).
    /// A real implementation would include DOS header in calculation.
    pub fn calculate_key(entries: &[RichEntry], dos_header: &[u8]) -> u32 {
        let mut checksum = 0u32;

        // Include DOS header bytes (rotated sum)
        for (i, &byte) in dos_header.iter().take(0x3C).enumerate() {
            checksum = checksum.wrapping_add((byte as u32).rotate_left(i as u32));
        }

        // Include entries
        for entry in entries {
            let comp_id = entry.to_comp_id();
            checksum = checksum.wrapping_add(comp_id.rotate_left(entry.use_count & 0x1F));
        }

        checksum
    }

    /// Check if the Rich header is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Builder for Rich headers.
///
/// Rich headers contain build tool information inserted by Microsoft linkers.
/// This builder helps create Rich headers with proper XOR encoding.
///
/// # Example
///
/// ```
/// use portex::rich::{RichBuilder, RichEntry};
///
/// let mut builder = RichBuilder::new();
///
/// // Add build tool entries
/// builder.add_entry(RichEntry {
///     product_id: 0x0104,   // C++ compiler
///     build_number: 30729,  // VS version
///     use_count: 5,
/// });
///
/// // Build with a specific key
/// let (data, size) = builder.build_with_key(0x12345678);
/// assert!(size > 0);
/// ```
#[derive(Debug, Clone, Default)]
pub struct RichBuilder {
    entries: Vec<RichEntry>,
}

impl RichBuilder {
    /// Create a new Rich builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create from an existing Rich header.
    pub fn from_header(header: &RichHeader) -> Self {
        Self {
            entries: header.entries.clone(),
        }
    }

    /// Add a build tool entry.
    pub fn add_entry(&mut self, entry: RichEntry) -> &mut Self {
        self.entries.push(entry);
        self
    }

    /// Add a build tool entry by components.
    pub fn add(&mut self, product_id: u16, build_number: u16, use_count: u32) -> &mut Self {
        self.entries.push(RichEntry {
            product_id,
            build_number,
            use_count,
        });
        self
    }

    /// Get the number of entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Calculate the size of the built Rich header.
    pub fn calculate_size(&self) -> usize {
        self.try_calculate_size()
            .expect("Rich-header size overflow: use try_calculate_size()")
    }

    /// Calculate the encoded size with checked arithmetic.
    pub fn try_calculate_size(&self) -> Result<usize> {
        self.entries
            .len()
            .checked_mul(8)
            .and_then(|size| size.checked_add(24))
            .ok_or_else(|| Error::generic("Rich-header size overflow"))
    }

    /// Build with a specific XOR key.
    /// Returns (data, size).
    pub fn build_with_key(&self, key: u32) -> (Vec<u8>, u32) {
        self.try_build_with_key(key)
            .expect("Rich-header build failed: use try_build_with_key()")
    }

    /// Build with a specific key and checked encoded size.
    pub fn try_build_with_key(&self, key: u32) -> Result<(Vec<u8>, u32)> {
        let size = self.try_calculate_size()?;
        let header = RichHeader {
            key,
            entries: self.entries.clone(),
            offset: 0,
            size,
        };
        let data = header.try_build()?;
        let size = u32::try_from(header.size)
            .map_err(|_| Error::generic("Rich-header size exceeds u32"))?;
        Ok((data, size))
    }

    /// Build with a calculated key based on the DOS header.
    /// Returns (data, size).
    pub fn build_with_dos_header(&self, dos_header: &[u8]) -> (Vec<u8>, u32) {
        self.try_build_with_dos_header(dos_header)
            .expect("Rich-header build failed: use try_build_with_dos_header()")
    }

    /// Build using a calculated key with checked encoded size.
    pub fn try_build_with_dos_header(&self, dos_header: &[u8]) -> Result<(Vec<u8>, u32)> {
        let key = RichHeader::calculate_key(&self.entries, dos_header);
        self.try_build_with_key(key)
    }

    /// Build into a RichHeader struct with a specific key.
    pub fn into_header(self, key: u32) -> RichHeader {
        let size = self.calculate_size();
        RichHeader {
            key,
            entries: self.entries,
            offset: 0,
            size,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rich_entry_roundtrip() {
        let entry = RichEntry {
            product_id: 0x0104, // C++14
            build_number: 30729,
            use_count: 5,
        };

        let comp_id = entry.to_comp_id();
        let parsed = RichEntry::from_comp_id(comp_id, entry.use_count);
        assert_eq!(entry.product_id, parsed.product_id);
        assert_eq!(entry.build_number, parsed.build_number);
    }

    #[test]
    fn test_rich_header_build_parse() {
        let header = RichHeader {
            key: 0x12345678,
            entries: vec![
                RichEntry {
                    product_id: 0x0104,
                    build_number: 30729,
                    use_count: 5,
                },
                RichEntry {
                    product_id: 0x0105,
                    build_number: 30729,
                    use_count: 1,
                },
            ],
            offset: 0,
            size: 0,
        };

        let built = header.build();

        // Create minimal PE structure for parsing
        let mut pe_data = vec![0u8; 0x200];
        pe_data[0] = b'M';
        pe_data[1] = b'Z';
        pe_data[0x3C..0x40].copy_from_slice(&0x100u32.to_le_bytes()); // PE at 0x100

        // Insert Rich header at 0x80
        pe_data[0x80..0x80 + built.len()].copy_from_slice(&built);

        let parsed = RichHeader::parse(&pe_data).expect("Failed to parse Rich header");
        assert_eq!(parsed.key, header.key);
        assert_eq!(parsed.entries.len(), header.entries.len());
    }

    #[test]
    fn test_rich_builder() {
        let mut builder = RichBuilder::new();

        builder.add(0x0104, 30729, 5).add(0x0105, 30729, 1);

        assert_eq!(builder.entry_count(), 2);

        let (data, size) = builder.build_with_key(0xABCD1234);
        assert!(size > 0);
        assert_eq!(data.len(), size as usize);
        assert_eq!(size as usize, builder.calculate_size());

        // Verify by parsing
        let mut pe_data = vec![0u8; 0x200];
        pe_data[0] = b'M';
        pe_data[1] = b'Z';
        pe_data[0x3C..0x40].copy_from_slice(&0x100u32.to_le_bytes());
        pe_data[0x80..0x80 + data.len()].copy_from_slice(&data);

        let parsed = RichHeader::parse(&pe_data).unwrap();
        assert_eq!(parsed.key, 0xABCD1234);
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].product_id, 0x0104);
        assert_eq!(parsed.entries[1].product_id, 0x0105);
    }

    #[test]
    fn pe_image_parses_rich_header_from_its_dos_stub() {
        let mut image = crate::PeBuilder::new().try_build().unwrap();
        let (encoded, _) = RichBuilder::new()
            .add(0x0104, 30729, 5)
            .try_build_with_key(0x1234_5678)
            .unwrap();
        let start = image.dos_stub.len() - encoded.len();
        image.dos_stub[start..].copy_from_slice(&encoded);

        let parsed = image.rich_header().unwrap();
        assert_eq!(parsed.key, 0x1234_5678);
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].product_id, 0x0104);
    }

    #[test]
    fn test_rich_builder_from_header() {
        let original = RichHeader {
            key: 0x11223344,
            entries: vec![RichEntry {
                product_id: 0x0104,
                build_number: 30729,
                use_count: 3,
            }],
            offset: 0,
            size: 0,
        };

        let builder = RichBuilder::from_header(&original);
        assert_eq!(builder.entry_count(), 1);

        let header = builder.into_header(0x55667788);
        assert_eq!(header.key, 0x55667788);
        assert_eq!(header.entries.len(), 1);
    }
}
