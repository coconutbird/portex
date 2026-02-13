//! Import table parsing and building.
//!
//! This module provides types for reading and writing PE import tables,
//! including import descriptors, thunks, and the overall import table.

use crate::{Error, Result};

/// IMAGE_IMPORT_DESCRIPTOR - 20 bytes
/// Describes one imported DLL.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ImportDescriptor {
    /// RVA to the Import Lookup Table (or INT - Import Name Table).
    pub original_first_thunk: u32,
    /// Timestamp (0 if not bound).
    pub time_date_stamp: u32,
    /// Forwarder chain index (-1 if no forwarders).
    pub forwarder_chain: u32,
    /// RVA to the DLL name (null-terminated string).
    pub name_rva: u32,
    /// RVA to the Import Address Table (IAT).
    pub first_thunk: u32,
}

impl ImportDescriptor {
    pub const SIZE: usize = 20;

    /// Check if this is a null terminator descriptor.
    pub fn is_null(&self) -> bool {
        self.original_first_thunk == 0
            && self.time_date_stamp == 0
            && self.forwarder_chain == 0
            && self.name_rva == 0
            && self.first_thunk == 0
    }

    /// Parse from bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(Error::BufferTooSmall {
                expected: Self::SIZE,
                actual: data.len(),
            });
        }

        Ok(Self {
            original_first_thunk: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            time_date_stamp: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            forwarder_chain: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            name_rva: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
            first_thunk: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
        })
    }

    /// Write to a buffer.
    pub fn write(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() < Self::SIZE {
            return Err(Error::BufferTooSmall {
                expected: Self::SIZE,
                actual: buf.len(),
            });
        }

        buf[0..4].copy_from_slice(&self.original_first_thunk.to_le_bytes());
        buf[4..8].copy_from_slice(&self.time_date_stamp.to_le_bytes());
        buf[8..12].copy_from_slice(&self.forwarder_chain.to_le_bytes());
        buf[12..16].copy_from_slice(&self.name_rva.to_le_bytes());
        buf[16..20].copy_from_slice(&self.first_thunk.to_le_bytes());

        Ok(())
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0u8; Self::SIZE];
        self.write(&mut buf).expect("buffer size is correct");
        buf
    }
}

/// Import thunk entry - can be either ordinal or name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportThunk {
    /// Import by ordinal number.
    Ordinal(u16),
    /// Import by name (hint, name).
    Name { hint: u16, name: String },
}

impl ImportThunk {
    /// Check if import is by ordinal (high bit set).
    pub fn is_ordinal_entry_32(value: u32) -> bool {
        value & 0x80000000 != 0
    }

    /// Check if import is by ordinal (high bit set) for 64-bit.
    pub fn is_ordinal_entry_64(value: u64) -> bool {
        value & 0x8000000000000000 != 0
    }

    /// Get ordinal from 32-bit thunk entry.
    pub fn ordinal_from_32(value: u32) -> u16 {
        (value & 0xFFFF) as u16
    }

    /// Get ordinal from 64-bit thunk entry.
    pub fn ordinal_from_64(value: u64) -> u16 {
        (value & 0xFFFF) as u16
    }

    /// Get RVA to hint/name from 32-bit thunk entry.
    pub fn hint_name_rva_from_32(value: u32) -> u32 {
        value & 0x7FFFFFFF
    }

    /// Get RVA to hint/name from 64-bit thunk entry.
    pub fn hint_name_rva_from_64(value: u64) -> u32 {
        (value & 0x7FFFFFFF) as u32
    }
}

/// A single imported DLL with its imports.
#[derive(Debug, Clone)]
pub struct ImportedDll {
    /// The DLL name.
    pub name: String,
    /// Import descriptor.
    pub descriptor: ImportDescriptor,
    /// List of imported functions.
    pub imports: Vec<ImportThunk>,
}

/// The complete import table.
#[derive(Debug, Clone, Default)]
pub struct ImportTable {
    /// List of imported DLLs.
    pub dlls: Vec<ImportedDll>,
}

impl ImportTable {
    /// Parse import table from a PE file.
    /// `import_rva` is the RVA from the data directory.
    /// `read_at_rva` is a closure that reads bytes at an RVA.
    pub fn parse<F>(import_rva: u32, is_64bit: bool, read_at_rva: F) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        let mut dlls = Vec::new();
        let mut offset = 0u32;

        loop {
            // Read import descriptor
            let desc_data = read_at_rva(import_rva + offset, ImportDescriptor::SIZE)
                .ok_or(Error::InvalidRva(import_rva + offset))?;
            let descriptor = ImportDescriptor::parse(&desc_data)?;

            if descriptor.is_null() {
                break;
            }

            // Read DLL name
            let name = Self::read_string(&read_at_rva, descriptor.name_rva)?;

            // Read thunks
            let thunk_rva = if descriptor.original_first_thunk != 0 {
                descriptor.original_first_thunk
            } else {
                descriptor.first_thunk
            };

            let imports = Self::read_thunks(&read_at_rva, thunk_rva, is_64bit)?;

            dlls.push(ImportedDll {
                name,
                descriptor,
                imports,
            });

            offset += ImportDescriptor::SIZE as u32;
        }

        Ok(Self { dlls })
    }

    fn read_string<F>(read_at_rva: &F, rva: u32) -> Result<String>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        // Read up to 256 bytes for a DLL name
        let data = read_at_rva(rva, 256).ok_or(Error::InvalidRva(rva))?;
        let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
        String::from_utf8(data[..end].to_vec())
            .map_err(|_| Error::InvalidUtf8)
    }

    fn read_thunks<F>(read_at_rva: &F, thunk_rva: u32, is_64bit: bool) -> Result<Vec<ImportThunk>>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        let mut imports = Vec::new();
        let thunk_size = if is_64bit { 8 } else { 4 };
        let mut offset = 0u32;

        loop {
            let data = read_at_rva(thunk_rva + offset, thunk_size)
                .ok_or(Error::InvalidRva(thunk_rva + offset))?;

            let (is_ordinal, ordinal, hint_rva) = if is_64bit {
                let value = u64::from_le_bytes([
                    data[0], data[1], data[2], data[3],
                    data[4], data[5], data[6], data[7],
                ]);
                if value == 0 {
                    break;
                }
                (
                    ImportThunk::is_ordinal_entry_64(value),
                    ImportThunk::ordinal_from_64(value),
                    ImportThunk::hint_name_rva_from_64(value),
                )
            } else {
                let value = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                if value == 0 {
                    break;
                }
                (
                    ImportThunk::is_ordinal_entry_32(value),
                    ImportThunk::ordinal_from_32(value),
                    ImportThunk::hint_name_rva_from_32(value),
                )
            };

            let thunk = if is_ordinal {
                ImportThunk::Ordinal(ordinal)
            } else {
                // Read hint (2 bytes) + name
                let hint_data = read_at_rva(hint_rva, 2)
                    .ok_or(Error::InvalidRva(hint_rva))?;
                let hint = u16::from_le_bytes([hint_data[0], hint_data[1]]);
                let name = Self::read_string(read_at_rva, hint_rva + 2)?;
                ImportThunk::Name { hint, name }
            };

            imports.push(thunk);
            offset += thunk_size as u32;
        }

        Ok(imports)
    }

    /// Check if the import table is empty.
    pub fn is_empty(&self) -> bool {
        self.dlls.is_empty()
    }

    /// Find a DLL by name (case-insensitive).
    pub fn find_dll(&self, name: &str) -> Option<&ImportedDll> {
        self.dlls.iter().find(|dll| dll.name.eq_ignore_ascii_case(name))
    }

    /// Get total count of imported functions.
    pub fn import_count(&self) -> usize {
        self.dlls.iter().map(|dll| dll.imports.len()).sum()
    }

    /// Add a new DLL with imports.
    pub fn add_dll(&mut self, name: &str, imports: Vec<ImportThunk>) {
        self.dlls.push(ImportedDll {
            name: name.to_string(),
            descriptor: ImportDescriptor::default(),
            imports,
        });
    }

    /// Add an import to an existing DLL, or create the DLL if it doesn't exist.
    pub fn add_import(&mut self, dll_name: &str, import: ImportThunk) {
        if let Some(dll) = self.dlls.iter_mut().find(|d| d.name.eq_ignore_ascii_case(dll_name)) {
            dll.imports.push(import);
        } else {
            self.add_dll(dll_name, vec![import]);
        }
    }

    /// Add a named import (convenience method).
    pub fn add_named_import(&mut self, dll_name: &str, func_name: &str, hint: u16) {
        self.add_import(dll_name, ImportThunk::Name {
            hint,
            name: func_name.to_string(),
        });
    }

    /// Add an ordinal import (convenience method).
    pub fn add_ordinal_import(&mut self, dll_name: &str, ordinal: u16) {
        self.add_import(dll_name, ImportThunk::Ordinal(ordinal));
    }
}

/// Builder for serializing import tables to section data.
#[derive(Debug)]
pub struct ImportTableBuilder {
    /// Whether to build for 64-bit PE.
    pub is_64bit: bool,
    /// Base RVA where the import section will be placed.
    pub base_rva: u32,
}

impl ImportTableBuilder {
    /// Create a new builder.
    pub fn new(is_64bit: bool, base_rva: u32) -> Self {
        Self { is_64bit, base_rva }
    }

    /// Calculate the total size needed for the import section.
    pub fn calculate_size(&self, table: &ImportTable) -> usize {
        if table.dlls.is_empty() {
            return 0;
        }

        let thunk_size = if self.is_64bit { 8 } else { 4 };

        // Import descriptors (one per DLL + null terminator)
        let descriptors_size = (table.dlls.len() + 1) * ImportDescriptor::SIZE;

        // ILT and IAT (both same size: thunks per DLL + null terminator each)
        let mut thunks_count = 0;
        for dll in &table.dlls {
            thunks_count += dll.imports.len() + 1; // +1 for null terminator
        }
        let ilt_size = thunks_count * thunk_size;
        let iat_size = ilt_size; // IAT is same size as ILT

        // Hint/Name entries
        let mut hint_names_size = 0;
        for dll in &table.dlls {
            for import in &dll.imports {
                if let ImportThunk::Name { name, .. } = import {
                    // 2 bytes hint + name + null terminator + padding to even
                    let entry_size = 2 + name.len() + 1;
                    hint_names_size += (entry_size + 1) & !1; // Align to 2
                }
            }
        }

        // DLL names
        let mut dll_names_size = 0;
        for dll in &table.dlls {
            dll_names_size += dll.name.len() + 1; // +1 for null terminator
        }

        descriptors_size + ilt_size + iat_size + hint_names_size + dll_names_size
    }

    /// Build the import section data and return (section_data, iat_rva, iat_size).
    /// The IAT RVA/size can be used to update the IAT data directory.
    pub fn build(&self, table: &ImportTable) -> (Vec<u8>, u32, u32) {
        if table.dlls.is_empty() {
            return (Vec::new(), 0, 0);
        }

        let thunk_size = if self.is_64bit { 8 } else { 4 };
        let total_size = self.calculate_size(table);
        let mut data = vec![0u8; total_size];

        // Calculate offsets
        let descriptors_offset = 0usize;
        let descriptors_size = (table.dlls.len() + 1) * ImportDescriptor::SIZE;

        let ilt_offset = descriptors_size;
        let mut total_thunks = 0usize;
        for dll in &table.dlls {
            total_thunks += dll.imports.len() + 1;
        }
        let ilt_size = total_thunks * thunk_size;

        let iat_offset = ilt_offset + ilt_size;
        let iat_size = ilt_size;

        let hint_names_offset = iat_offset + iat_size;
        let mut hint_names_size = 0usize;
        for dll in &table.dlls {
            for import in &dll.imports {
                if let ImportThunk::Name { name, .. } = import {
                    let entry_size = 2 + name.len() + 1;
                    hint_names_size += (entry_size + 1) & !1;
                }
            }
        }

        let dll_names_offset = hint_names_offset + hint_names_size;

        // Write data
        let mut desc_pos = descriptors_offset;
        let mut ilt_pos = ilt_offset;
        let mut iat_pos = iat_offset;
        let mut hint_name_pos = hint_names_offset;
        let mut dll_name_pos = dll_names_offset;

        for dll in &table.dlls {
            // Write DLL name
            let dll_name_rva = self.base_rva + dll_name_pos as u32;
            let dll_name_bytes = dll.name.as_bytes();
            data[dll_name_pos..dll_name_pos + dll_name_bytes.len()].copy_from_slice(dll_name_bytes);
            dll_name_pos += dll_name_bytes.len() + 1; // +1 for null

            // Write thunks (ILT and IAT)
            let ilt_rva = self.base_rva + ilt_pos as u32;
            let iat_rva = self.base_rva + iat_pos as u32;

            for import in &dll.imports {
                let thunk_value = match import {
                    ImportThunk::Ordinal(ord) => {
                        if self.is_64bit {
                            0x8000000000000000u64 | (*ord as u64)
                        } else {
                            (0x80000000u32 | (*ord as u32)) as u64
                        }
                    }
                    ImportThunk::Name { hint, name } => {
                        // Write hint/name entry
                        let hint_name_rva = self.base_rva + hint_name_pos as u32;
                        data[hint_name_pos..hint_name_pos + 2].copy_from_slice(&hint.to_le_bytes());
                        let name_bytes = name.as_bytes();
                        data[hint_name_pos + 2..hint_name_pos + 2 + name_bytes.len()]
                            .copy_from_slice(name_bytes);
                        let entry_size = 2 + name_bytes.len() + 1;
                        hint_name_pos += (entry_size + 1) & !1; // Align to 2

                        hint_name_rva as u64
                    }
                };

                // Write to ILT
                if self.is_64bit {
                    data[ilt_pos..ilt_pos + 8].copy_from_slice(&thunk_value.to_le_bytes());
                } else {
                    data[ilt_pos..ilt_pos + 4].copy_from_slice(&(thunk_value as u32).to_le_bytes());
                }
                ilt_pos += thunk_size;

                // Write to IAT (same as ILT initially)
                if self.is_64bit {
                    data[iat_pos..iat_pos + 8].copy_from_slice(&thunk_value.to_le_bytes());
                } else {
                    data[iat_pos..iat_pos + 4].copy_from_slice(&(thunk_value as u32).to_le_bytes());
                }
                iat_pos += thunk_size;
            }

            // Null terminator for thunks
            ilt_pos += thunk_size;
            iat_pos += thunk_size;

            // Write import descriptor
            let descriptor = ImportDescriptor {
                original_first_thunk: ilt_rva,
                time_date_stamp: 0,
                forwarder_chain: 0,
                name_rva: dll_name_rva,
                first_thunk: iat_rva,
            };
            descriptor.write(&mut data[desc_pos..desc_pos + ImportDescriptor::SIZE]).ok();
            desc_pos += ImportDescriptor::SIZE;
        }

        // Null terminator descriptor is already zeros

        let iat_rva = self.base_rva + iat_offset as u32;
        (data, iat_rva, iat_size as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_import_descriptor_size() {
        assert_eq!(ImportDescriptor::SIZE, 20);
    }

    #[test]
    fn test_import_descriptor_roundtrip() {
        let original = ImportDescriptor {
            original_first_thunk: 0x1000,
            time_date_stamp: 0,
            forwarder_chain: 0xFFFFFFFF,
            name_rva: 0x2000,
            first_thunk: 0x3000,
        };

        let bytes = original.to_bytes();
        let parsed = ImportDescriptor::parse(&bytes).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_import_descriptor_is_null() {
        let null = ImportDescriptor::default();
        assert!(null.is_null());

        let not_null = ImportDescriptor {
            first_thunk: 0x1000,
            ..Default::default()
        };
        assert!(!not_null.is_null());
    }

    #[test]
    fn test_thunk_ordinal_check() {
        assert!(ImportThunk::is_ordinal_entry_32(0x80000001));
        assert!(!ImportThunk::is_ordinal_entry_32(0x00001000));
        assert!(ImportThunk::is_ordinal_entry_64(0x8000000000000001));
        assert!(!ImportThunk::is_ordinal_entry_64(0x0000000000001000));
    }

    #[test]
    fn test_import_table_builder_roundtrip() {
        // Create an import table
        let mut table = ImportTable::default();
        table.add_named_import("kernel32.dll", "VirtualAlloc", 0);
        table.add_named_import("kernel32.dll", "VirtualFree", 0);
        table.add_ordinal_import("user32.dll", 123);

        assert_eq!(table.dlls.len(), 2);
        assert_eq!(table.dlls[0].imports.len(), 2);
        assert_eq!(table.dlls[1].imports.len(), 1);

        // Build the section (64-bit)
        let base_rva = 0x3000u32;
        let builder = ImportTableBuilder::new(true, base_rva);
        let size = builder.calculate_size(&table);
        assert!(size > 0);

        let (data, iat_rva, iat_size) = builder.build(&table);
        assert!(!data.is_empty());
        assert!(iat_rva >= base_rva);
        assert!(iat_size > 0);

        // Parse the built data back
        let read_fn = |rva: u32, len: usize| -> Option<Vec<u8>> {
            if rva < base_rva {
                return None;
            }
            let offset = (rva - base_rva) as usize;
            if offset >= data.len() {
                return None;
            }
            // Return available data, up to requested length
            let available = (data.len() - offset).min(len);
            Some(data[offset..offset + available].to_vec())
        };

        let parsed = ImportTable::parse(base_rva, true, read_fn).unwrap();
        assert_eq!(parsed.dlls.len(), 2);
        assert_eq!(parsed.dlls[0].name.to_lowercase(), "kernel32.dll");
        assert_eq!(parsed.dlls[0].imports.len(), 2);
        assert_eq!(parsed.dlls[1].name.to_lowercase(), "user32.dll");
        assert_eq!(parsed.dlls[1].imports.len(), 1);

        // Verify import names
        if let ImportThunk::Name { name, .. } = &parsed.dlls[0].imports[0] {
            assert_eq!(name, "VirtualAlloc");
        } else {
            panic!("Expected named import");
        }
        if let ImportThunk::Ordinal(ord) = &parsed.dlls[1].imports[0] {
            assert_eq!(*ord, 123);
        } else {
            panic!("Expected ordinal import");
        }
    }
}

