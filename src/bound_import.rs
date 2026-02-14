//! Bound import directory parsing.
//!
//! Bound imports are a legacy optimization where import addresses are pre-resolved
//! at link time. The loader can skip address resolution if the bound DLL hasn't changed.
//!
//! # Examples
//!
//! ```no_run
//! use portex::PE;
//!
//! let pe = PE::from_file("example.exe")?;
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

use crate::{Error, Result};

/// IMAGE_BOUND_FORWARDER_REF structure.
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone, Default)]
pub struct BoundImportDirectory {
    /// List of bound import descriptors.
    pub descriptors: Vec<BoundImportDescriptor>,
}

impl BoundImportDirectory {
    /// Parse the bound import directory from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut descriptors = Vec::new();
        let mut offset = 0;

        // Parse descriptors
        while offset + BoundImportDescriptor::SIZE <= data.len() {
            match BoundImportDescriptor::parse(&data[offset..])? {
                Some(mut desc) => {
                    // Resolve module name
                    let name_offset = desc.offset_module_name as usize;
                    if name_offset < data.len() {
                        desc.module_name = read_cstring(&data[name_offset..]);
                    }

                    // Parse forwarder refs
                    let fwd_start = offset + BoundImportDescriptor::SIZE;
                    for i in 0..desc.number_of_module_forwarder_refs as usize {
                        let fwd_offset = fwd_start + i * BoundForwarderRef::SIZE;
                        if fwd_offset + BoundForwarderRef::SIZE <= data.len() {
                            let mut fwd = BoundForwarderRef::parse(&data[fwd_offset..])?;
                            let fwd_name_offset = fwd.offset_module_name as usize;
                            if fwd_name_offset < data.len() {
                                fwd.module_name = read_cstring(&data[fwd_name_offset..]);
                            }
                            desc.forwarder_refs.push(fwd);
                        }
                    }

                    // Skip past descriptor and its forwarder refs
                    offset = fwd_start
                        + desc.number_of_module_forwarder_refs as usize * BoundForwarderRef::SIZE;
                    descriptors.push(desc);
                }
                None => break,
            }
        }

        Ok(Self { descriptors })
    }
}

/// Read a null-terminated C string from a byte slice.
fn read_cstring(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).into_owned()
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
        if directory.descriptors.is_empty() {
            return 0;
        }

        // Descriptors + forwarder refs + null terminator
        let mut desc_size = BoundImportDescriptor::SIZE; // null terminator
        for desc in &directory.descriptors {
            desc_size += BoundImportDescriptor::SIZE;
            desc_size += desc.forwarder_refs.len() * BoundForwarderRef::SIZE;
        }

        // Module names (null-terminated strings)
        let mut names_size = 0;
        for desc in &directory.descriptors {
            names_size += desc.module_name.len() + 1; // +1 for null terminator
            for fwd in &desc.forwarder_refs {
                names_size += fwd.module_name.len() + 1;
            }
        }

        desc_size + names_size
    }

    /// Build the bound import data.
    /// Returns (data, size).
    pub fn build(&self, directory: &BoundImportDirectory) -> (Vec<u8>, u32) {
        if directory.descriptors.is_empty() {
            return (Vec::new(), 0);
        }

        let total_size = self.calculate_size(directory);
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
            let name_offset = current_string_offset as u16;
            data[offset..offset + 4].copy_from_slice(&desc.time_date_stamp.to_le_bytes());
            data[offset + 4..offset + 6].copy_from_slice(&name_offset.to_le_bytes());
            data[offset + 6..offset + 8]
                .copy_from_slice(&(desc.forwarder_refs.len() as u16).to_le_bytes());
            offset += BoundImportDescriptor::SIZE;

            // Write module name
            let name_bytes = desc.module_name.as_bytes();
            data[current_string_offset..current_string_offset + name_bytes.len()]
                .copy_from_slice(name_bytes);
            current_string_offset += name_bytes.len() + 1; // +1 for null

            // Write forwarder refs
            for fwd in &desc.forwarder_refs {
                let fwd_name_offset = current_string_offset as u16;
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

        (data, total_size as u32)
    }
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
