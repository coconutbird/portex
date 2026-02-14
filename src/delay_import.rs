//! Delay-load import directory parsing.
//!
//! Delay-load imports are loaded on first use rather than at program startup.
//! This is useful for optional dependencies or improving startup time.
//!
//! # Examples
//!
//! ```no_run
//! use portex::PE;
//!
//! let pe = PE::from_file("example.exe")?;
//!
//! let delay_imports = pe.delay_imports()?;
//! for dll in &delay_imports.dlls {
//!     println!("Delay-load DLL: {}", dll.name);
//!     println!("  IAT RVA: {:#x}", dll.descriptor.import_address_table_rva);
//!     println!("  INT RVA: {:#x}", dll.descriptor.import_name_table_rva);
//! }
//! # Ok::<(), portex::Error>(())
//! ```

use crate::{Error, Result};

/// IMAGE_DELAYLOAD_DESCRIPTOR structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct DelayLoadDescriptor {
    /// Attributes (must be 0 for current version).
    pub attributes: u32,
    /// RVA of the DLL name.
    pub dll_name_rva: u32,
    /// RVA of the module handle.
    pub module_handle_rva: u32,
    /// RVA of the delay-load import address table.
    pub import_address_table_rva: u32,
    /// RVA of the delay-load import name table.
    pub import_name_table_rva: u32,
    /// RVA of the bound delay-load import address table.
    pub bound_import_address_table_rva: u32,
    /// RVA of the unload delay-load import address table.
    pub unload_information_table_rva: u32,
    /// Timestamp of the bound DLL (0 if not bound).
    pub time_date_stamp: u32,
}

impl DelayLoadDescriptor {
    /// Size of the structure in bytes.
    pub const SIZE: usize = 32;

    /// Parse from raw bytes. Returns None if this is the null terminator.
    pub fn parse(data: &[u8]) -> Result<Option<Self>> {
        if data.len() < Self::SIZE {
            return Err(Error::buffer_too_small(Self::SIZE, data.len()));
        }

        let read_u32 = |offset: usize| -> u32 {
            u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ])
        };

        let attributes = read_u32(0);
        let dll_name_rva = read_u32(4);
        let module_handle_rva = read_u32(8);
        let import_address_table_rva = read_u32(12);
        let import_name_table_rva = read_u32(16);
        let bound_import_address_table_rva = read_u32(20);
        let unload_information_table_rva = read_u32(24);
        let time_date_stamp = read_u32(28);

        // Null terminator check
        if dll_name_rva == 0 {
            return Ok(None);
        }

        Ok(Some(Self {
            attributes,
            dll_name_rva,
            module_handle_rva,
            import_address_table_rva,
            import_name_table_rva,
            bound_import_address_table_rva,
            unload_information_table_rva,
            time_date_stamp,
        }))
    }
}

/// A delay-load import entry (function to import).
#[derive(Debug, Clone)]
pub enum DelayImportThunk {
    /// Import by ordinal.
    Ordinal(u16),
    /// Import by name with optional hint.
    Name {
        /// Hint (index into export name table).
        hint: u16,
        /// Function name.
        name: String,
    },
}

/// A delay-loaded DLL with its descriptor, name, and imports.
#[derive(Debug, Clone)]
pub struct DelayLoadedDll {
    /// The raw descriptor.
    pub descriptor: DelayLoadDescriptor,
    /// Resolved DLL name.
    pub name: String,
    /// List of imported functions.
    pub imports: Vec<DelayImportThunk>,
}

/// Delay-load import directory.
#[derive(Debug, Clone, Default)]
pub struct DelayImportDirectory {
    /// List of delay-loaded DLLs.
    pub dlls: Vec<DelayLoadedDll>,
}

impl DelayImportDirectory {
    /// Parse the delay import directory.
    ///
    /// # Arguments
    /// * `rva` - RVA of the delay import directory
    /// * `is_64bit` - Whether this is a 64-bit PE
    /// * `read_fn` - Function to read data at an RVA
    pub fn parse<F>(rva: u32, is_64bit: bool, read_fn: F) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        let mut dlls = Vec::new();
        let mut offset = 0u32;
        let thunk_size = if is_64bit { 8 } else { 4 };

        loop {
            let desc_data = read_fn(rva + offset, DelayLoadDescriptor::SIZE)
                .ok_or_else(|| Error::invalid_rva(rva + offset))?;

            match DelayLoadDescriptor::parse(&desc_data)? {
                Some(desc) => {
                    // Resolve DLL name
                    let name = if desc.dll_name_rva != 0 {
                        read_fn(desc.dll_name_rva, 256)
                            .map(|data| read_cstring(&data))
                            .unwrap_or_default()
                    } else {
                        String::new()
                    };

                    // Parse thunks from INT (Import Name Table)
                    let imports = Self::parse_thunks(
                        desc.import_name_table_rva,
                        is_64bit,
                        thunk_size,
                        &read_fn,
                    );

                    dlls.push(DelayLoadedDll {
                        descriptor: desc,
                        name,
                        imports,
                    });
                    offset += DelayLoadDescriptor::SIZE as u32;
                }
                None => break,
            }
        }

        Ok(Self { dlls })
    }

    fn parse_thunks<F>(
        int_rva: u32,
        is_64bit: bool,
        thunk_size: usize,
        read_fn: &F,
    ) -> Vec<DelayImportThunk>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        let mut imports = Vec::new();
        if int_rva == 0 {
            return imports;
        }

        let mut thunk_offset = 0u32;
        let ordinal_flag: u64 = if is_64bit {
            0x8000_0000_0000_0000
        } else {
            0x8000_0000
        };

        while let Some(thunk_data) = read_fn(int_rva + thunk_offset, thunk_size) {
            let thunk_value: u64 = if is_64bit {
                u64::from_le_bytes([
                    thunk_data[0],
                    thunk_data[1],
                    thunk_data[2],
                    thunk_data[3],
                    thunk_data[4],
                    thunk_data[5],
                    thunk_data[6],
                    thunk_data[7],
                ])
            } else {
                u32::from_le_bytes([thunk_data[0], thunk_data[1], thunk_data[2], thunk_data[3]])
                    as u64
            };

            // Null terminator
            if thunk_value == 0 {
                break;
            }

            // Check if import by ordinal
            if thunk_value & ordinal_flag != 0 {
                imports.push(DelayImportThunk::Ordinal((thunk_value & 0xFFFF) as u16));
            } else {
                // Import by name - thunk_value is RVA to hint/name
                let hint_name_rva = thunk_value as u32;
                if let Some(hint_name_data) = read_fn(hint_name_rva, 256) {
                    let hint = u16::from_le_bytes([hint_name_data[0], hint_name_data[1]]);
                    let name = read_cstring(&hint_name_data[2..]);
                    imports.push(DelayImportThunk::Name { hint, name });
                }
            }

            thunk_offset += thunk_size as u32;
        }

        imports
    }
}

/// Read a null-terminated C string from a byte slice.
fn read_cstring(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).into_owned()
}

/// Builder for serializing delay-load import tables.
#[derive(Debug)]
pub struct DelayImportBuilder {
    /// Whether to build for 64-bit PE.
    pub is_64bit: bool,
    /// Base RVA where the delay import section will be placed.
    pub base_rva: u32,
}

impl DelayImportBuilder {
    /// Create a new builder.
    pub fn new(is_64bit: bool, base_rva: u32) -> Self {
        Self { is_64bit, base_rva }
    }

    /// Calculate the total size needed for the delay import data.
    pub fn calculate_size(&self, dlls: &[DelayLoadedDll]) -> usize {
        if dlls.is_empty() {
            return 0;
        }

        let thunk_size = if self.is_64bit { 8 } else { 4 };

        // Descriptors (one per DLL + null terminator)
        let descriptors_size = (dlls.len() + 1) * DelayLoadDescriptor::SIZE;

        // IAT and INT (both same size: thunks per DLL + null terminator each)
        let mut thunks_count = 0;
        for dll in dlls {
            thunks_count += dll.imports.len() + 1; // +1 for null terminator
        }
        let iat_size = thunks_count * thunk_size;
        let int_size = iat_size; // INT is same size as IAT

        // Module handles (one HMODULE pointer per DLL)
        let handles_size = dlls.len() * thunk_size;

        // Hint/Name entries
        let mut hint_names_size = 0;
        for dll in dlls {
            for import in &dll.imports {
                if let DelayImportThunk::Name { name, .. } = import {
                    // 2 bytes hint + name + null terminator + padding to even
                    let entry_size = 2 + name.len() + 1;
                    hint_names_size += (entry_size + 1) & !1;
                }
            }
        }

        // DLL names
        let mut dll_names_size = 0;
        for dll in dlls {
            dll_names_size += dll.name.len() + 1;
        }

        descriptors_size + iat_size + int_size + handles_size + hint_names_size + dll_names_size
    }

    /// Build the delay import data.
    /// Returns (section_data, size).
    pub fn build(&self, dlls: &[DelayLoadedDll]) -> (Vec<u8>, u32) {
        if dlls.is_empty() {
            return (Vec::new(), 0);
        }

        let thunk_size = if self.is_64bit { 8 } else { 4 };
        let total_size = self.calculate_size(dlls);
        let mut data = vec![0u8; total_size];

        // Calculate offsets
        let descriptors_offset = 0usize;
        let descriptors_size = (dlls.len() + 1) * DelayLoadDescriptor::SIZE;

        let iat_offset = descriptors_size;
        let mut total_thunks = 0usize;
        for dll in dlls {
            total_thunks += dll.imports.len() + 1;
        }
        let iat_size = total_thunks * thunk_size;

        let int_offset = iat_offset + iat_size;
        let int_size = iat_size;

        let handles_offset = int_offset + int_size;
        let handles_size = dlls.len() * thunk_size;

        let hint_names_offset = handles_offset + handles_size;
        let mut hint_names_size = 0usize;
        for dll in dlls {
            for import in &dll.imports {
                if let DelayImportThunk::Name { name, .. } = import {
                    let entry_size = 2 + name.len() + 1;
                    hint_names_size += (entry_size + 1) & !1;
                }
            }
        }

        let dll_names_offset = hint_names_offset + hint_names_size;

        // Write data
        let mut desc_offset = descriptors_offset;
        let mut iat_pos = iat_offset;
        let mut int_pos = int_offset;
        let mut handle_pos = handles_offset;
        let mut hint_name_pos = hint_names_offset;
        let mut dll_name_pos = dll_names_offset;

        for dll in dlls {
            let iat_rva = self.base_rva + iat_pos as u32;
            let int_rva = self.base_rva + int_pos as u32;
            let handle_rva = self.base_rva + handle_pos as u32;
            let dll_name_rva = self.base_rva + dll_name_pos as u32;

            // Write descriptor
            // attributes = 1 means use RVA (modern format)
            data[desc_offset..desc_offset + 4].copy_from_slice(&1u32.to_le_bytes());
            data[desc_offset + 4..desc_offset + 8].copy_from_slice(&dll_name_rva.to_le_bytes());
            data[desc_offset + 8..desc_offset + 12].copy_from_slice(&handle_rva.to_le_bytes());
            data[desc_offset + 12..desc_offset + 16].copy_from_slice(&iat_rva.to_le_bytes());
            data[desc_offset + 16..desc_offset + 20].copy_from_slice(&int_rva.to_le_bytes());
            // bound_iat_rva, unload_iat_rva, timestamp = 0
            desc_offset += DelayLoadDescriptor::SIZE;

            // Write DLL name
            let name_bytes = dll.name.as_bytes();
            data[dll_name_pos..dll_name_pos + name_bytes.len()].copy_from_slice(name_bytes);
            dll_name_pos += name_bytes.len() + 1;

            // Write IAT, INT entries and hint/names
            for import in &dll.imports {
                match import {
                    DelayImportThunk::Ordinal(ord) => {
                        let ordinal_flag = if self.is_64bit {
                            0x8000_0000_0000_0000u64
                        } else {
                            0x8000_0000u64
                        };
                        let value = ordinal_flag | (*ord as u64);
                        self.write_thunk(&mut data, iat_pos, value);
                        self.write_thunk(&mut data, int_pos, value);
                    }
                    DelayImportThunk::Name { hint, name } => {
                        let hint_name_rva = self.base_rva + hint_name_pos as u32;
                        self.write_thunk(&mut data, iat_pos, hint_name_rva as u64);
                        self.write_thunk(&mut data, int_pos, hint_name_rva as u64);

                        // Write hint/name
                        data[hint_name_pos..hint_name_pos + 2].copy_from_slice(&hint.to_le_bytes());
                        let name_bytes = name.as_bytes();
                        data[hint_name_pos + 2..hint_name_pos + 2 + name_bytes.len()]
                            .copy_from_slice(name_bytes);
                        let entry_size = 2 + name_bytes.len() + 1;
                        hint_name_pos += (entry_size + 1) & !1;
                    }
                }
                iat_pos += thunk_size;
                int_pos += thunk_size;
            }

            // Null terminator for IAT/INT
            iat_pos += thunk_size;
            int_pos += thunk_size;
            handle_pos += thunk_size;
        }

        // Null terminator descriptor is already zeros

        (data, total_size as u32)
    }

    fn write_thunk(&self, data: &mut [u8], offset: usize, value: u64) {
        if self.is_64bit {
            data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        } else {
            data[offset..offset + 4].copy_from_slice(&(value as u32).to_le_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delay_load_descriptor_size() {
        assert_eq!(DelayLoadDescriptor::SIZE, 32);
    }

    #[test]
    fn test_null_terminator() {
        let data = [0u8; 32];
        let desc = DelayLoadDescriptor::parse(&data).unwrap();
        assert!(desc.is_none());
    }

    #[test]
    fn test_buffer_too_small() {
        let data = [0u8; 31];
        assert!(DelayLoadDescriptor::parse(&data).is_err());
    }

    #[test]
    fn test_builder_empty() {
        let builder = DelayImportBuilder::new(false, 0x1000);
        let (data, size) = builder.build(&[]);
        assert!(data.is_empty());
        assert_eq!(size, 0);
    }

    #[test]
    fn test_builder_calculates_size() {
        let builder = DelayImportBuilder::new(false, 0x1000);
        let dlls = vec![DelayLoadedDll {
            descriptor: DelayLoadDescriptor {
                attributes: 1,
                dll_name_rva: 0,
                module_handle_rva: 0,
                import_address_table_rva: 0,
                import_name_table_rva: 0,
                bound_import_address_table_rva: 0,
                unload_information_table_rva: 0,
                time_date_stamp: 0,
            },
            name: "test.dll".to_string(),
            imports: vec![DelayImportThunk::Name {
                hint: 0,
                name: "TestFunc".to_string(),
            }],
        }];
        let size = builder.calculate_size(&dlls);
        assert!(size > 0);
    }
}
