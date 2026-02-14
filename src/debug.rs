//! Debug directory parsing and building.
//!
//! The debug directory contains debugging information such as PDB paths.

use crate::{Error, Result};

/// Debug types (IMAGE_DEBUG_TYPE_*).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DebugType {
    Unknown = 0,
    Coff = 1,
    CodeView = 2,
    Fpo = 3,
    Misc = 4,
    Exception = 5,
    Fixup = 6,
    OmapToSrc = 7,
    OmapFromSrc = 8,
    Borland = 9,
    Reserved10 = 10,
    Clsid = 11,
    VcFeature = 12,
    Pogo = 13,
    Iltcg = 14,
    Mpx = 15,
    Repro = 16,
    ExDllCharacteristics = 20,
}

impl DebugType {
    pub fn from_u32(value: u32) -> Self {
        match value {
            1 => Self::Coff,
            2 => Self::CodeView,
            3 => Self::Fpo,
            4 => Self::Misc,
            5 => Self::Exception,
            6 => Self::Fixup,
            7 => Self::OmapToSrc,
            8 => Self::OmapFromSrc,
            9 => Self::Borland,
            10 => Self::Reserved10,
            11 => Self::Clsid,
            12 => Self::VcFeature,
            13 => Self::Pogo,
            14 => Self::Iltcg,
            15 => Self::Mpx,
            16 => Self::Repro,
            20 => Self::ExDllCharacteristics,
            _ => Self::Unknown,
        }
    }
}

/// IMAGE_DEBUG_DIRECTORY - 28 bytes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DebugDirectory {
    /// Reserved (must be zero).
    pub characteristics: u32,
    /// Time/date stamp.
    pub time_date_stamp: u32,
    /// Major version.
    pub major_version: u16,
    /// Minor version.
    pub minor_version: u16,
    /// Debug type.
    pub debug_type: u32,
    /// Size of debug data.
    pub size_of_data: u32,
    /// RVA of debug data (when loaded).
    pub address_of_raw_data: u32,
    /// File offset of debug data.
    pub pointer_to_raw_data: u32,
}

impl DebugDirectory {
    pub const SIZE: usize = 28;

    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(Error::BufferTooSmall {
                expected: Self::SIZE,
                actual: data.len(),
            });
        }

        Ok(Self {
            characteristics: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            time_date_stamp: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            major_version: u16::from_le_bytes([data[8], data[9]]),
            minor_version: u16::from_le_bytes([data[10], data[11]]),
            debug_type: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
            size_of_data: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
            address_of_raw_data: u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
            pointer_to_raw_data: u32::from_le_bytes([data[24], data[25], data[26], data[27]]),
        })
    }

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..4].copy_from_slice(&self.characteristics.to_le_bytes());
        buf[4..8].copy_from_slice(&self.time_date_stamp.to_le_bytes());
        buf[8..10].copy_from_slice(&self.major_version.to_le_bytes());
        buf[10..12].copy_from_slice(&self.minor_version.to_le_bytes());
        buf[12..16].copy_from_slice(&self.debug_type.to_le_bytes());
        buf[16..20].copy_from_slice(&self.size_of_data.to_le_bytes());
        buf[20..24].copy_from_slice(&self.address_of_raw_data.to_le_bytes());
        buf[24..28].copy_from_slice(&self.pointer_to_raw_data.to_le_bytes());
        buf
    }

    /// Get the debug type as an enum.
    pub fn get_type(&self) -> DebugType {
        DebugType::from_u32(self.debug_type)
    }
}

/// CodeView PDB 7.0 signature (RSDS).
pub const CV_SIGNATURE_RSDS: u32 = 0x53445352; // "RSDS"

/// CodeView PDB 2.0 signature (NB10).
pub const CV_SIGNATURE_NB10: u32 = 0x3031424E; // "NB10"

/// CodeView RSDS (PDB 7.0) debug info.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeViewRsds {
    /// GUID (16 bytes).
    pub guid: [u8; 16],
    /// Age/revision.
    pub age: u32,
    /// Path to PDB file (null-terminated UTF-8).
    pub pdb_path: String,
}

impl CodeViewRsds {
    /// Minimum size: signature (4) + GUID (16) + age (4) + null terminator (1)
    pub const MIN_SIZE: usize = 25;

    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::MIN_SIZE {
            return Err(Error::BufferTooSmall {
                expected: Self::MIN_SIZE,
                actual: data.len(),
            });
        }

        // Verify signature
        let sig = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if sig != CV_SIGNATURE_RSDS {
            return Err(Error::InvalidDataDirectory("Invalid RSDS signature".into()));
        }

        let mut guid = [0u8; 16];
        guid.copy_from_slice(&data[4..20]);
        let age = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);

        // Read null-terminated path
        let path_data = &data[24..];
        let end = path_data.iter().position(|&b| b == 0).unwrap_or(path_data.len());
        let pdb_path = String::from_utf8(path_data[..end].to_vec())
            .map_err(|_| Error::InvalidUtf8)?;

        Ok(Self { guid, age, pdb_path })
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(24 + self.pdb_path.len() + 1);
        buf.extend_from_slice(&CV_SIGNATURE_RSDS.to_le_bytes());
        buf.extend_from_slice(&self.guid);
        buf.extend_from_slice(&self.age.to_le_bytes());
        buf.extend_from_slice(self.pdb_path.as_bytes());
        buf.push(0); // Null terminator
        buf
    }

    /// Format GUID as a string (Microsoft format).
    pub fn guid_string(&self) -> String {
        format!(
            "{:08X}{:04X}{:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            u32::from_le_bytes([self.guid[0], self.guid[1], self.guid[2], self.guid[3]]),
            u16::from_le_bytes([self.guid[4], self.guid[5]]),
            u16::from_le_bytes([self.guid[6], self.guid[7]]),
            self.guid[8], self.guid[9], self.guid[10], self.guid[11],
            self.guid[12], self.guid[13], self.guid[14], self.guid[15]
        )
    }
}

/// Parsed debug information.
#[derive(Debug, Clone, Default)]
pub struct DebugInfo {
    /// List of debug directories.
    pub directories: Vec<DebugDirectory>,
    /// CodeView info (if present).
    pub codeview: Option<CodeViewRsds>,
}

impl DebugInfo {
    /// Parse debug information from a PE.
    pub fn parse<F>(debug_rva: u32, debug_size: u32, read_at_rva: F) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        let mut directories = Vec::new();
        let mut codeview = None;
        let num_entries = debug_size as usize / DebugDirectory::SIZE;

        for i in 0..num_entries {
            let offset = (i * DebugDirectory::SIZE) as u32;
            let data = read_at_rva(debug_rva + offset, DebugDirectory::SIZE)
                .ok_or(Error::InvalidRva(debug_rva + offset))?;

            let dir = DebugDirectory::parse(&data)?;

            // Parse CodeView if present
            if dir.get_type() == DebugType::CodeView && dir.size_of_data > 0 {
                if let Some(cv_data) = read_at_rva(dir.address_of_raw_data, dir.size_of_data as usize) {
                    if cv_data.len() >= 4 {
                        let sig = u32::from_le_bytes([cv_data[0], cv_data[1], cv_data[2], cv_data[3]]);
                        if sig == CV_SIGNATURE_RSDS {
                            if let Ok(rsds) = CodeViewRsds::parse(&cv_data) {
                                codeview = Some(rsds);
                            }
                        }
                    }
                }
            }

            directories.push(dir);
        }

        Ok(Self { directories, codeview })
    }

    /// Get the PDB path if available.
    pub fn pdb_path(&self) -> Option<&str> {
        self.codeview.as_ref().map(|cv| cv.pdb_path.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_directory_size() {
        assert_eq!(DebugDirectory::SIZE, 28);
    }

    #[test]
    fn test_debug_directory_roundtrip() {
        let original = DebugDirectory {
            characteristics: 0,
            time_date_stamp: 0x12345678,
            major_version: 1,
            minor_version: 0,
            debug_type: DebugType::CodeView as u32,
            size_of_data: 100,
            address_of_raw_data: 0x1000,
            pointer_to_raw_data: 0x400,
        };

        let bytes = original.to_bytes();
        let parsed = DebugDirectory::parse(&bytes).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_codeview_rsds_roundtrip() {
        let original = CodeViewRsds {
            guid: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            age: 1,
            pdb_path: "C:\\path\\to\\file.pdb".to_string(),
        };

        let bytes = original.to_bytes();
        let parsed = CodeViewRsds::parse(&bytes).unwrap();
        assert_eq!(original.guid, parsed.guid);
        assert_eq!(original.age, parsed.age);
        assert_eq!(original.pdb_path, parsed.pdb_path);
    }
}

