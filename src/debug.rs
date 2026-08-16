//! Debug directory parsing and building.
//!
//! The debug directory contains debugging information such as PDB paths.
//!
//! # Examples
//!
//! ## Reading debug information from a PE file
//!
//! ```no_run
//! use portex::PeImage;
//!
//! # let file_bytes: &[u8] = &[];
//! let pe = PeImage::parse(file_bytes)?;
//!
//! if let Some(debug_info) = pe.debug_info()? {
//!     for dir in &debug_info.directories {
//!         println!("Debug type: {:?}", dir.debug_type);
//!         println!("  Data RVA: {:#x}", dir.address_of_raw_data);
//!     }
//!     if let Some(ref codeview) = debug_info.codeview {
//!         println!("  PDB path: {}", codeview.pdb_path);
//!         println!("  GUID: {:?}", codeview.guid);
//!         println!("  Age: {}", codeview.age);
//!     }
//! }
//! # Ok::<(), portex::Error>(())
//! ```

use crate::prelude::*;
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
            return Err(Error::buffer_too_small(Self::SIZE, data.len()));
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
            return Err(Error::buffer_too_small(Self::MIN_SIZE, data.len()));
        }

        // Verify signature
        let sig = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if sig != CV_SIGNATURE_RSDS {
            return Err(Error::invalid_data_directory("Invalid RSDS signature"));
        }

        let mut guid = [0u8; 16];
        guid.copy_from_slice(&data[4..20]);
        let age = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);

        // Read null-terminated path
        let path_data = &data[24..];
        let end = path_data
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| Error::invalid_data_directory("RSDS PDB path is not null-terminated"))?;
        let pdb_path =
            String::from_utf8(path_data[..end].to_vec()).map_err(|_| Error::invalid_utf8())?;

        Ok(Self {
            guid,
            age,
            pdb_path,
        })
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.try_to_bytes()
            .expect("CodeView build failed: use try_to_bytes()")
    }

    /// Serialize an RSDS record with checked length and string contents.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>> {
        if self.pdb_path.as_bytes().contains(&0) {
            return Err(Error::invalid_data_directory(
                "CodeView PDB path contains an embedded NUL byte",
            ));
        }
        let capacity = 24usize
            .checked_add(self.pdb_path.len())
            .and_then(|size| size.checked_add(1))
            .ok_or_else(|| Error::invalid_data_directory("CodeView payload size overflow"))?;
        u32::try_from(capacity)
            .map_err(|_| Error::invalid_data_directory("CodeView payload exceeds u32"))?;
        let mut buf = Vec::with_capacity(capacity);
        buf.extend_from_slice(&CV_SIGNATURE_RSDS.to_le_bytes());
        buf.extend_from_slice(&self.guid);
        buf.extend_from_slice(&self.age.to_le_bytes());
        buf.extend_from_slice(self.pdb_path.as_bytes());
        buf.push(0); // Null terminator
        Ok(buf)
    }

    /// Format GUID as a string (Microsoft format).
    pub fn guid_string(&self) -> String {
        format!(
            "{:08X}{:04X}{:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            u32::from_le_bytes([self.guid[0], self.guid[1], self.guid[2], self.guid[3]]),
            u16::from_le_bytes([self.guid[4], self.guid[5]]),
            u16::from_le_bytes([self.guid[6], self.guid[7]]),
            self.guid[8],
            self.guid[9],
            self.guid[10],
            self.guid[11],
            self.guid[12],
            self.guid[13],
            self.guid[14],
            self.guid[15]
        )
    }
}

/// Parsed debug information.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DebugInfo {
    /// List of debug directories.
    pub directories: Vec<DebugDirectory>,
    /// CodeView info (if present).
    pub codeview: Option<CodeViewRsds>,
    /// Raw payload for each directory entry, in the same order as
    /// [`Self::directories`]. `None` means that entry had no readable payload.
    pub data: Vec<Option<Vec<u8>>>,
}

impl DebugInfo {
    /// Parse debug information from a PE.
    pub fn parse<F>(debug_rva: u32, debug_size: u32, read_at_rva: F) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        Self::parse_impl(debug_rva, debug_size, &read_at_rva, |directory| {
            if directory.size_of_data == 0 {
                Some(Vec::new())
            } else if directory.address_of_raw_data != 0 {
                read_at_rva(
                    directory.address_of_raw_data,
                    directory.size_of_data as usize,
                )
            } else {
                None
            }
        })
    }

    /// Parse a raw-file debug directory, falling back to
    /// `PointerToRawData` when an entry has no mapped RVA.
    pub fn parse_with_file<F, G>(
        debug_rva: u32,
        debug_size: u32,
        read_at_rva: F,
        read_at_file_offset: G,
    ) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
        G: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        Self::parse_impl(debug_rva, debug_size, &read_at_rva, |directory| {
            if directory.size_of_data == 0 {
                Some(Vec::new())
            } else {
                (directory.address_of_raw_data != 0)
                    .then(|| {
                        read_at_rva(
                            directory.address_of_raw_data,
                            directory.size_of_data as usize,
                        )
                    })
                    .flatten()
                    .or_else(|| {
                        (directory.pointer_to_raw_data != 0)
                            .then(|| {
                                read_at_file_offset(
                                    directory.pointer_to_raw_data,
                                    directory.size_of_data as usize,
                                )
                            })
                            .flatten()
                    })
            }
        })
    }

    fn parse_impl<F, P>(
        debug_rva: u32,
        debug_size: u32,
        read_at_rva: &F,
        read_payload: P,
    ) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
        P: Fn(&DebugDirectory) -> Option<Vec<u8>>,
    {
        let mut directories = Vec::new();
        let mut codeview = None;
        let mut raw_data = Vec::new();
        if !(debug_size as usize).is_multiple_of(DebugDirectory::SIZE) {
            return Err(Error::invalid_data_directory(format!(
                "debug directory size {} is not a multiple of {}",
                debug_size,
                DebugDirectory::SIZE
            )));
        }
        let num_entries = debug_size as usize / DebugDirectory::SIZE;

        for i in 0..num_entries {
            let offset = i
                .checked_mul(DebugDirectory::SIZE)
                .and_then(|offset| u32::try_from(offset).ok())
                .ok_or_else(|| Error::invalid_data_directory("debug table offset overflow"))?;
            let entry_rva = debug_rva
                .checked_add(offset)
                .ok_or_else(|| Error::invalid_data_directory("debug table RVA overflow"))?;
            let data = read_at_rva(entry_rva, DebugDirectory::SIZE)
                .ok_or(Error::invalid_rva(entry_rva))?;

            let dir = DebugDirectory::parse(&data)?;
            if dir.characteristics != 0 {
                return Err(Error::invalid_data_directory(
                    "debug directory Characteristics must be zero",
                ));
            }
            if dir.size_of_data != 0 && dir.address_of_raw_data == 0 && dir.pointer_to_raw_data == 0
            {
                return Err(Error::invalid_data_directory(
                    "debug payload has a size but neither an RVA nor a file pointer",
                ));
            }

            let payload = read_payload(&dir);
            if let Some(payload) = &payload
                && payload.len() != dir.size_of_data as usize
            {
                return Err(Error::invalid_data_directory(format!(
                    "debug payload has {} bytes but declares {}",
                    payload.len(),
                    dir.size_of_data
                )));
            }

            // Parse CodeView if present
            if dir.get_type() == DebugType::CodeView
                && let Some(cv_data) = payload.as_ref()
                && cv_data.len() >= 4
            {
                let sig = u32::from_le_bytes([cv_data[0], cv_data[1], cv_data[2], cv_data[3]]);
                if sig == CV_SIGNATURE_RSDS {
                    codeview = Some(CodeViewRsds::parse(cv_data)?);
                }
            }

            directories.push(dir);
            raw_data.push(payload);
        }

        Ok(Self {
            directories,
            codeview,
            data: raw_data,
        })
    }

    /// Get the PDB path if available.
    pub fn pdb_path(&self) -> Option<&str> {
        self.codeview.as_ref().map(|cv| cv.pdb_path.as_str())
    }
}

/// Builder for debug directories.
///
/// Debug directories can contain multiple entries (CodeView, POGO, Repro, etc.)
/// but the most common is a single CodeView entry with PDB info.
///
/// # Example
///
/// ```
/// use portex::debug::{DebugBuilder, DebugType, CodeViewRsds};
///
/// // Create a simple CodeView entry
/// let codeview = CodeViewRsds {
///     guid: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
///            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00],
///     age: 1,
///     pdb_path: "C:\\app\\example.pdb".to_string(),
/// };
///
/// let builder = DebugBuilder::new(0x3000);
/// let (data, dir_size, entries) = builder.build_codeview(&codeview);
/// assert_eq!(entries.len(), 1);
/// assert_eq!(entries[0].get_type(), DebugType::CodeView);
/// ```
#[derive(Debug, Clone)]
pub struct DebugBuilder {
    /// Base RVA where the debug section will be placed.
    base_rva: u32,
}

impl DebugBuilder {
    /// Create a new debug builder.
    pub fn new(base_rva: u32) -> Self {
        Self { base_rva }
    }

    /// Build a CodeView-only debug directory.
    ///
    /// Returns (data, directory_size, debug_directories) where:
    /// - `data` is the raw bytes to write to the section
    /// - `directory_size` is the size of the debug directory entries (for data directory)
    /// - `debug_directories` contains the parsed directories for inspection
    pub fn build_codeview(&self, codeview: &CodeViewRsds) -> (Vec<u8>, u32, Vec<DebugDirectory>) {
        self.try_build_codeview(codeview)
            .expect("debug build failed: use try_build_codeview() for fallible serialization")
    }

    /// Build a CodeView entry with checked string length and RVAs.
    pub fn try_build_codeview(
        &self,
        codeview: &CodeViewRsds,
    ) -> Result<(Vec<u8>, u32, Vec<DebugDirectory>)> {
        // Layout: [DebugDirectory (28 bytes)] [CodeView data]
        let cv_data = codeview.try_to_bytes()?;
        let cv_offset = DebugDirectory::SIZE as u32;
        let payload_size = u32::try_from(cv_data.len())
            .map_err(|_| Error::invalid_data_directory("CodeView payload exceeds u32"))?;
        let payload_rva = self
            .base_rva
            .checked_add(cv_offset)
            .ok_or_else(|| Error::invalid_data_directory("CodeView payload RVA overflow"))?;

        let dir = DebugDirectory {
            debug_type: DebugType::CodeView as u32,
            size_of_data: payload_size,
            address_of_raw_data: payload_rva,
            pointer_to_raw_data: 0, // Caller must update after section layout
            ..Default::default()
        };

        let mut data = Vec::with_capacity(DebugDirectory::SIZE + cv_data.len());
        data.extend_from_slice(&dir.to_bytes());
        data.extend_from_slice(&cv_data);

        let dir_size = DebugDirectory::SIZE as u32;
        Ok((data, dir_size, vec![dir]))
    }

    /// Build from an existing DebugInfo structure.
    ///
    /// This rebuilds all directories and every available raw payload.
    pub fn build(&self, debug_info: &DebugInfo) -> (Vec<u8>, u32, Vec<DebugDirectory>) {
        self.try_build(debug_info)
            .expect("debug build failed: use try_build() for fallible serialization")
    }

    /// Rebuild every debug entry and preserved payload with checked offsets.
    pub fn try_build(&self, debug_info: &DebugInfo) -> Result<(Vec<u8>, u32, Vec<DebugDirectory>)> {
        if debug_info.directories.is_empty() {
            return Ok((Vec::new(), 0, Vec::new()));
        }
        if debug_info.data.len() > debug_info.directories.len() {
            return Err(Error::invalid_data_directory(
                "debug payload list is longer than the directory list",
            ));
        }
        let fallback_codeview = debug_info
            .codeview
            .as_ref()
            .map(CodeViewRsds::try_to_bytes)
            .transpose()?;

        let dir_size_usize = debug_info
            .directories
            .len()
            .checked_mul(DebugDirectory::SIZE)
            .ok_or_else(|| Error::invalid_data_directory("debug table size overflow"))?;
        let dir_size = u32::try_from(dir_size_usize)
            .map_err(|_| Error::invalid_data_directory("debug table exceeds u32"))?;
        let payload_size: usize = debug_info.directories.iter().enumerate().try_fold(
            0usize,
            |total, (index, directory)| {
                let size = debug_info
                    .data
                    .get(index)
                    .and_then(Option::as_ref)
                    .map(Vec::len)
                    .or_else(|| {
                        (directory.get_type() == DebugType::CodeView)
                            .then_some(fallback_codeview.as_ref())
                            .flatten()
                            .map(Vec::len)
                    })
                    .unwrap_or(0);
                u32::try_from(size)
                    .map_err(|_| Error::invalid_data_directory("debug payload exceeds u32"))?;
                total
                    .checked_add(size)
                    .ok_or_else(|| Error::invalid_data_directory("debug payload size overflow"))
            },
        )?;
        dir_size_usize
            .checked_add(payload_size)
            .and_then(|size| u32::try_from(size).ok())
            .and_then(|size| self.base_rva.checked_add(size))
            .ok_or_else(|| Error::invalid_data_directory("debug data RVA range overflow"))?;
        let mut data = vec![0u8; dir_size_usize];
        data.try_reserve(payload_size)
            .map_err(|_| Error::invalid_data_directory("debug payload is too large to allocate"))?;
        let mut dirs = Vec::with_capacity(debug_info.directories.len());

        for (index, orig_dir) in debug_info.directories.iter().enumerate() {
            let mut dir = *orig_dir;
            let payload = debug_info
                .data
                .get(index)
                .and_then(Option::as_ref)
                .cloned()
                .or_else(|| {
                    (dir.get_type() == DebugType::CodeView)
                        .then(|| fallback_codeview.clone())
                        .flatten()
                });

            if let Some(payload) = payload {
                dir.address_of_raw_data = self
                    .base_rva
                    .checked_add(u32::try_from(data.len()).map_err(|_| {
                        Error::invalid_data_directory("debug payload offset exceeds u32")
                    })?)
                    .ok_or_else(|| Error::invalid_data_directory("debug payload RVA overflow"))?;
                dir.pointer_to_raw_data = 0;
                dir.size_of_data = u32::try_from(payload.len())
                    .map_err(|_| Error::invalid_data_directory("debug payload exceeds u32"))?;
                data.extend_from_slice(&payload);
            } else {
                dir.address_of_raw_data = 0;
                dir.pointer_to_raw_data = 0;
                dir.size_of_data = 0;
            }
            dirs.push(dir);
        }

        for (index, dir) in dirs.iter().enumerate() {
            let offset = index * DebugDirectory::SIZE;
            data[offset..offset + DebugDirectory::SIZE].copy_from_slice(&dir.to_bytes());
        }

        Ok((data, dir_size, dirs))
    }

    /// Calculate the size needed for a CodeView debug entry.
    pub fn calculate_codeview_size(codeview: &CodeViewRsds) -> usize {
        Self::try_calculate_codeview_size(codeview)
            .expect("CodeView size overflow: use try_calculate_codeview_size()")
    }

    /// Calculate a CodeView entry size with checked string validation.
    pub fn try_calculate_codeview_size(codeview: &CodeViewRsds) -> Result<usize> {
        let payload = codeview.try_to_bytes()?;
        DebugDirectory::SIZE
            .checked_add(payload.len())
            .ok_or_else(|| Error::invalid_data_directory("debug entry size overflow"))
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
