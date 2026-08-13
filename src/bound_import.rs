//! Bound import directory parsing.
//!
//! Bound imports are a legacy optimization where import addresses are pre-resolved
//! at link time. The loader can skip address resolution if the bound DLL hasn't changed.
//!
//! # Examples
//!
//! ```no_run
//! use portex::PeImage;
//!
//! # let file_bytes: &[u8] = &[];
//! let pe = PeImage::parse(file_bytes)?;
//!
//! if let Some(bound) = pe.bound_imports()? {
//!     for desc in &bound.descriptors {
//!         println!("Bound import: {} (timestamp: {:#x})",
//!             desc.module_name, desc.time_date_stamp);
//!         for fwd in &desc.forwarder_refs {
//!             println!("  Forwarder: {} (timestamp: {:#x})",
//!                 fwd.module_name, fwd.time_date_stamp);
//!         }
//!     }
//! }
//! # Ok::<(), portex::Error>(())
//! ```

use crate::prelude::*;
use crate::{Error, Result};

/// IMAGE_BOUND_FORWARDER_REF structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundForwarderRef {
    /// Timestamp of the forwarder DLL.
    pub time_date_stamp: u32,
    /// Offset to module name (from start of bound import data).
    pub offset_module_name: u16,
    /// Reserved.
    pub reserved: u16,
    /// Resolved module name.
    pub module_name: String,
}

impl BoundForwarderRef {
    /// Size of the structure in bytes.
    pub const SIZE: usize = 8;

    /// Parse from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(Error::buffer_too_small(Self::SIZE, data.len()));
        }

        Ok(Self {
            time_date_stamp: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            offset_module_name: u16::from_le_bytes([data[4], data[5]]),
            reserved: u16::from_le_bytes([data[6], data[7]]),
            module_name: String::new(), // Resolved later
        })
    }
}

/// IMAGE_BOUND_IMPORT_DESCRIPTOR structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundImportDescriptor {
    /// Timestamp of the bound DLL.
    pub time_date_stamp: u32,
    /// Offset to module name (from start of bound import data).
    pub offset_module_name: u16,
    /// Number of forwarder references.
    pub number_of_module_forwarder_refs: u16,
    /// Resolved module name.
    pub module_name: String,
    /// Forwarder references.
    pub forwarder_refs: Vec<BoundForwarderRef>,
}

impl BoundImportDescriptor {
    /// Size of the structure in bytes.
    pub const SIZE: usize = 8;

    /// Parse from raw bytes. Returns None if this is the null terminator.
    pub fn parse(data: &[u8]) -> Result<Option<Self>> {
        if data.len() < Self::SIZE {
            return Err(Error::buffer_too_small(Self::SIZE, data.len()));
        }

        let time_date_stamp = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let offset_module_name = u16::from_le_bytes([data[4], data[5]]);
        let number_of_module_forwarder_refs = u16::from_le_bytes([data[6], data[7]]);

        // Null terminator check
        if time_date_stamp == 0 && offset_module_name == 0 && number_of_module_forwarder_refs == 0 {
            return Ok(None);
        }

        Ok(Some(Self {
            time_date_stamp,
            offset_module_name,
            number_of_module_forwarder_refs,
            module_name: String::new(), // Resolved later
            forwarder_refs: Vec::new(), // Parsed later
        }))
    }
}

/// Bound import directory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BoundImportDirectory {
    /// List of bound import descriptors.
    pub descriptors: Vec<BoundImportDescriptor>,
}

impl BoundImportDirectory {
    /// Parse the bound import directory from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut descriptors = Vec::new();
        let mut offset = 0;

        // Parse descriptors and their immediately-following forwarder records.
        while offset < data.len() {
            let descriptor_end = offset
                .checked_add(BoundImportDescriptor::SIZE)
                .ok_or_else(|| Error::invalid_data_directory("bound-import offset overflow"))?;
            if descriptor_end > data.len() {
                return Err(Error::invalid_data_directory(
                    "truncated bound-import descriptor",
                ));
            }
            match BoundImportDescriptor::parse(&data[offset..])? {
                Some(mut desc) => {
                    if desc.offset_module_name == 0 {
                        return Err(Error::invalid_data_directory(
                            "bound-import descriptor has a zero module-name offset",
                        ));
                    }
                    // Resolve module name
                    let name_offset = desc.offset_module_name as usize;
                    desc.module_name = read_cstring(data.get(name_offset..).ok_or_else(|| {
                        Error::invalid_data_directory("bound-import module name is out of range")
                    })?)?;

                    // Parse forwarder refs
                    let fwd_start = descriptor_end;
                    for i in 0..desc.number_of_module_forwarder_refs as usize {
                        let relative = i.checked_mul(BoundForwarderRef::SIZE).ok_or_else(|| {
                            Error::invalid_data_directory("bound-forwarder size overflow")
                        })?;
                        let fwd_offset = fwd_start.checked_add(relative).ok_or_else(|| {
                            Error::invalid_data_directory("bound-forwarder offset overflow")
                        })?;
                        let fwd_end =
                            fwd_offset
                                .checked_add(BoundForwarderRef::SIZE)
                                .ok_or_else(|| {
                                    Error::invalid_data_directory("bound-forwarder range overflow")
                                })?;
                        let mut fwd = BoundForwarderRef::parse(
                            data.get(fwd_offset..fwd_end).ok_or_else(|| {
                                Error::invalid_data_directory("truncated bound-forwarder record")
                            })?,
                        )?;
                        if fwd.reserved != 0 {
                            return Err(Error::invalid_data_directory(
                                "bound-forwarder reserved field must be zero",
                            ));
                        }
                        if fwd.offset_module_name == 0 {
                            return Err(Error::invalid_data_directory(
                                "bound-forwarder has a zero module-name offset",
                            ));
                        }
                        let fwd_name_offset = fwd.offset_module_name as usize;
                        fwd.module_name =
                            read_cstring(data.get(fwd_name_offset..).ok_or_else(|| {
                                Error::invalid_data_directory(
                                    "bound-forwarder module name is out of range",
                                )
                            })?)?;
                        desc.forwarder_refs.push(fwd);
                    }

                    // Skip past descriptor and its forwarder refs
                    offset = fwd_start
                        .checked_add(
                            (desc.number_of_module_forwarder_refs as usize)
                                .checked_mul(BoundForwarderRef::SIZE)
                                .ok_or_else(|| {
                                    Error::invalid_data_directory("bound-forwarder size overflow")
                                })?,
                        )
                        .ok_or_else(|| {
                            Error::invalid_data_directory("bound-import offset overflow")
                        })?;
                    descriptors.push(desc);
                }
                None => return Ok(Self { descriptors }),
            }
        }

        Err(Error::invalid_data_directory(
            "bound-import directory is missing a terminator",
        ))
    }
}

/// Read a null-terminated C string from a byte slice.
fn read_cstring(data: &[u8]) -> Result<String> {
    let end = data
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| Error::invalid_data_directory("bound-import name is not null-terminated"))?;
    String::from_utf8(data[..end].to_vec()).map_err(|_| Error::invalid_utf8())
}

/// Builder for serializing bound import tables.
#[derive(Debug, Default)]
pub struct BoundImportBuilder;

impl BoundImportBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self
    }

    /// Calculate the total size needed for the bound import data.
    pub fn calculate_size(&self, directory: &BoundImportDirectory) -> usize {
        self.try_calculate_size(directory)
            .expect("bound-import size overflow: use try_calculate_size()")
    }

    /// Calculate the size and validate u16-relative name offsets/counts.
    pub fn try_calculate_size(&self, directory: &BoundImportDirectory) -> Result<usize> {
        if directory.descriptors.is_empty() {
            return Ok(0);
        }

        // Descriptors + forwarder refs + null terminator
        let mut desc_size = BoundImportDescriptor::SIZE; // null terminator
        for desc in &directory.descriptors {
            u16::try_from(desc.forwarder_refs.len())
                .map_err(|_| Error::invalid_data_directory("bound-forwarder count exceeds u16"))?;
            if desc
                .forwarder_refs
                .iter()
                .any(|forwarder| forwarder.reserved != 0)
            {
                return Err(Error::invalid_data_directory(
                    "bound-forwarder reserved field must be zero",
                ));
            }
            desc_size = desc_size
                .checked_add(BoundImportDescriptor::SIZE)
                .and_then(|size| {
                    desc.forwarder_refs
                        .len()
                        .checked_mul(BoundForwarderRef::SIZE)
                        .and_then(|forwarders| size.checked_add(forwarders))
                })
                .ok_or_else(|| {
                    Error::invalid_data_directory("bound-import descriptor size overflow")
                })?;
        }

        // Module names (null-terminated strings)
        let mut names_size = 0usize;
        for desc in &directory.descriptors {
            names_size = checked_bound_name_size(names_size, &desc.module_name)?;
            for fwd in &desc.forwarder_refs {
                names_size = checked_bound_name_size(names_size, &fwd.module_name)?;
            }
        }

        let total = desc_size
            .checked_add(names_size)
            .ok_or_else(|| Error::invalid_data_directory("bound-import size overflow"))?;
        if total > usize::from(u16::MAX) {
            return Err(Error::invalid_data_directory(
                "bound-import directory exceeds its u16 name-offset format",
            ));
        }
        Ok(total)
    }

    /// Build the bound import data.
    /// Returns (data, size).
    pub fn build(&self, directory: &BoundImportDirectory) -> (Vec<u8>, u32) {
        self.try_build(directory)
            .expect("bound-import build failed: use try_build() for fallible serialization")
    }

    /// Build a bound-import directory with checked relative offsets.
    pub fn try_build(&self, directory: &BoundImportDirectory) -> Result<(Vec<u8>, u32)> {
        if directory.descriptors.is_empty() {
            return Ok((Vec::new(), 0));
        }

        let total_size = self.try_calculate_size(directory)?;
        let total_size_u32 = u32::try_from(total_size)
            .map_err(|_| Error::invalid_data_directory("bound-import data exceeds u32"))?;
        let mut data = vec![0u8; total_size];

        // Calculate where strings start (after all descriptors + forwarders + null terminator)
        let mut desc_count = 1; // null terminator
        for desc in &directory.descriptors {
            desc_count += 1 + desc.forwarder_refs.len();
        }
        let strings_offset = desc_count * BoundImportDescriptor::SIZE;
        let mut current_string_offset = strings_offset;

        // Write descriptors and collect string offsets
        let mut offset = 0;
        for desc in &directory.descriptors {
            // Write descriptor
            let name_offset = u16::try_from(current_string_offset).map_err(|_| {
                Error::invalid_data_directory("bound-import name offset exceeds u16")
            })?;
            data[offset..offset + 4].copy_from_slice(&desc.time_date_stamp.to_le_bytes());
            data[offset + 4..offset + 6].copy_from_slice(&name_offset.to_le_bytes());
            data[offset + 6..offset + 8].copy_from_slice(
                &u16::try_from(desc.forwarder_refs.len())
                    .map_err(|_| {
                        Error::invalid_data_directory("bound-forwarder count exceeds u16")
                    })?
                    .to_le_bytes(),
            );
            offset += BoundImportDescriptor::SIZE;

            // Write module name
            let name_bytes = desc.module_name.as_bytes();
            data[current_string_offset..current_string_offset + name_bytes.len()]
                .copy_from_slice(name_bytes);
            current_string_offset += name_bytes.len() + 1; // +1 for null

            // Write forwarder refs
            for fwd in &desc.forwarder_refs {
                let fwd_name_offset = u16::try_from(current_string_offset).map_err(|_| {
                    Error::invalid_data_directory("bound-forwarder name offset exceeds u16")
                })?;
                data[offset..offset + 4].copy_from_slice(&fwd.time_date_stamp.to_le_bytes());
                data[offset + 4..offset + 6].copy_from_slice(&fwd_name_offset.to_le_bytes());
                data[offset + 6..offset + 8].copy_from_slice(&fwd.reserved.to_le_bytes());
                offset += BoundForwarderRef::SIZE;

                // Write forwarder module name
                let fwd_name_bytes = fwd.module_name.as_bytes();
                data[current_string_offset..current_string_offset + fwd_name_bytes.len()]
                    .copy_from_slice(fwd_name_bytes);
                current_string_offset += fwd_name_bytes.len() + 1;
            }
        }

        // Null terminator descriptor is already zeros

        Ok((data, total_size_u32))
    }
}

fn checked_bound_name_size(current: usize, name: &str) -> Result<usize> {
    if name.is_empty() || name.as_bytes().contains(&0) {
        return Err(Error::invalid_data_directory(
            "bound-import module names must be nonempty and contain no NUL bytes",
        ));
    }
    current
        .checked_add(
            name.len()
                .checked_add(1)
                .ok_or_else(|| Error::invalid_data_directory("bound-import name size overflow"))?,
        )
        .ok_or_else(|| Error::invalid_data_directory("bound-import names size overflow"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bound_import_descriptor_size() {
        assert_eq!(BoundImportDescriptor::SIZE, 8);
    }

    #[test]
    fn test_bound_forwarder_ref_size() {
        assert_eq!(BoundForwarderRef::SIZE, 8);
    }

    #[test]
    fn test_null_terminator() {
        let data = [0u8; 8];
        let desc = BoundImportDescriptor::parse(&data).unwrap();
        assert!(desc.is_none());
    }

    #[test]
    fn test_buffer_too_small() {
        let data = [0u8; 7];
        assert!(BoundImportDescriptor::parse(&data).is_err());
    }

    #[test]
    fn test_builder_empty() {
        let builder = BoundImportBuilder::new();
        let dir = BoundImportDirectory::default();
        let (data, size) = builder.build(&dir);
        assert!(data.is_empty());
        assert_eq!(size, 0);
    }

    #[test]
    fn test_builder_roundtrip() {
        let dir = BoundImportDirectory {
            descriptors: vec![BoundImportDescriptor {
                time_date_stamp: 0x12345678,
                offset_module_name: 0,
                number_of_module_forwarder_refs: 0,
                module_name: "kernel32.dll".to_string(),
                forwarder_refs: vec![],
            }],
        };

        let builder = BoundImportBuilder::new();
        let (data, _size) = builder.build(&dir);

        // Parse it back
        let parsed = BoundImportDirectory::parse(&data).unwrap();
        assert_eq!(parsed.descriptors.len(), 1);
        assert_eq!(parsed.descriptors[0].module_name, "kernel32.dll");
        assert_eq!(parsed.descriptors[0].time_date_stamp, 0x12345678);
    }
}
