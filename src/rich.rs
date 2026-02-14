//! Rich Header parsing and building.
//!
//! The Rich Header is an undocumented structure inserted by Microsoft linker
//! between the DOS stub and PE signature. It contains build tool information.

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
#[derive(Debug, Clone, Default)]
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
        // Minimum: DOS header (64) + some stub
        if data.len() < 0x80 {
            return None;
        }

        // Get PE offset from DOS header
        let pe_offset =
            u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
        if pe_offset >= data.len() || pe_offset < 0x80 {
            return None;
        }

        // Search backwards from PE header for "Rich" marker
        // Rich header ends with: "Rich" XOR key, key, key, key
        let search_area = &data[0x80..pe_offset];
        let mut rich_pos = None;

        for i in (0..search_area.len().saturating_sub(4)).rev() {
            let value = u32::from_le_bytes([
                search_area[i],
                search_area[i + 1],
                search_area[i + 2],
                search_area[i + 3],
            ]);

            // Check if this could be "Rich" XORed with something
            let possible_key = value ^ RICH_MAGIC;

            // Verify by checking if next dword is the same key
            if i + 8 <= search_area.len() {
                let next = u32::from_le_bytes([
                    search_area[i + 4],
                    search_area[i + 5],
                    search_area[i + 6],
                    search_area[i + 7],
                ]);
                if next == possible_key {
                    rich_pos = Some((i + 0x80, possible_key));
                    break;
                }
            }
        }

        let (rich_offset, key) = rich_pos?;

        // Now search backwards for DanS marker
        let mut dans_offset = None;
        let header_area = &data[0x80..rich_offset];

        for i in 0..header_area.len().saturating_sub(4) {
            let value = u32::from_le_bytes([
                header_area[i],
                header_area[i + 1],
                header_area[i + 2],
                header_area[i + 3],
            ]);

            if value ^ key == DANS_MAGIC {
                dans_offset = Some(i + 0x80);
                break;
            }
        }

        let start_offset = dans_offset?;

        // Parse entries between DanS and Rich
        // Format: DanS, padding (3 dwords), then pairs of (comp_id, count)
        let mut entries = Vec::new();
        let entry_area = &data[start_offset + 16..rich_offset]; // Skip DanS + 3 padding dwords

        for chunk in entry_area.chunks(8) {
            if chunk.len() < 8 {
                break;
            }

            let comp_id_xor = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            let count_xor = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);

            let comp_id = comp_id_xor ^ key;
            let count = count_xor ^ key;

            if comp_id != 0 || count != 0 {
                entries.push(RichEntry::from_comp_id(comp_id, count));
            }
        }

        Some(Self {
            key,
            entries,
            offset: start_offset,
            size: rich_offset + 8 - start_offset, // Include "Rich" + key
        })
    }

    /// Build Rich header bytes.
    pub fn build(&self) -> Vec<u8> {
        // Size: DanS (4) + padding (12) + entries (8 each) + Rich (4) + key (4)
        let size = 16 + self.entries.len() * 8 + 8;
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
        buf[rich_offset..rich_offset + 4].copy_from_slice(&(RICH_MAGIC ^ key).to_le_bytes());
        buf[rich_offset + 4..rich_offset + 8].copy_from_slice(&key.to_le_bytes());

        buf
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
}
