//! Export table parsing and building.
//!
//! This module provides types for reading and writing PE export tables,
//! including the export directory and exported functions.
//!
//! # Examples
//!
//! ## Listing exports from a DLL
//!
//! ```no_run
//! use portex::PE;
//!
//! let pe = PE::from_file("example.dll")?;
//!
//! let exports = pe.exports()?;
//! println!("DLL name: {}", exports.dll_name);
//! println!("Ordinal base: {}", exports.directory.base);
//!
//! for func in &exports.exports {
//!     let name = func.name.as_deref().unwrap_or("<unnamed>");
//!     let addr = match &func.address {
//!         portex::ExportAddress::Rva(rva) => format!("{:#x}", rva),
//!         portex::ExportAddress::Forwarder(s) => s.clone(),
//!     };
//!     println!("  {} (ordinal {}): {}", name, func.ordinal, addr);
//! }
//! # Ok::<(), portex::Error>(())
//! ```
//!
//! ## Creating a DLL with exports
//!
//! ```no_run
//! use portex::{PE, ExportTable};
//!
//! let mut pe = PE::from_file("input.dll")?;
//!
//! // Build export table
//! let mut exports = ExportTable::default();
//! exports.dll_name = "mylib.dll".to_string();
//! exports.directory.base = 1;
//! exports.add_export(Some("MyFunction1"), 0x1000);
//! exports.add_export(Some("MyFunction2"), 0x2000);
//! exports.add_export(None, 0x3000); // No name, just ordinal
//!
//! // Update PE with new exports
//! pe.update_exports(exports, None)?;
//! pe.write_to_file("output.dll")?;
//! # Ok::<(), portex::Error>(())
//! ```

use crate::{Error, Result};

/// IMAGE_EXPORT_DIRECTORY - 40 bytes
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExportDirectory {
    /// Export flags (reserved, must be 0).
    pub characteristics: u32,
    /// Time/date stamp.
    pub time_date_stamp: u32,
    /// Major version.
    pub major_version: u16,
    /// Minor version.
    pub minor_version: u16,
    /// RVA to the DLL name.
    pub name_rva: u32,
    /// Starting ordinal number.
    pub base: u32,
    /// Number of entries in the Export Address Table.
    pub number_of_functions: u32,
    /// Number of entries in the Name Pointer Table.
    pub number_of_names: u32,
    /// RVA to the Export Address Table (EAT).
    pub address_of_functions: u32,
    /// RVA to the Export Name Pointer Table.
    pub address_of_names: u32,
    /// RVA to the Export Ordinal Table.
    pub address_of_name_ordinals: u32,
}

impl ExportDirectory {
    pub const SIZE: usize = 40;

    /// Parse from bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(Error::buffer_too_small(Self::SIZE, data.len()));
        }

        Ok(Self {
            characteristics: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            time_date_stamp: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            major_version: u16::from_le_bytes([data[8], data[9]]),
            minor_version: u16::from_le_bytes([data[10], data[11]]),
            name_rva: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
            base: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
            number_of_functions: u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
            number_of_names: u32::from_le_bytes([data[24], data[25], data[26], data[27]]),
            address_of_functions: u32::from_le_bytes([data[28], data[29], data[30], data[31]]),
            address_of_names: u32::from_le_bytes([data[32], data[33], data[34], data[35]]),
            address_of_name_ordinals: u32::from_le_bytes([data[36], data[37], data[38], data[39]]),
        })
    }

    /// Write to a buffer.
    pub fn write(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() < Self::SIZE {
            return Err(Error::buffer_too_small(Self::SIZE, buf.len()));
        }

        buf[0..4].copy_from_slice(&self.characteristics.to_le_bytes());
        buf[4..8].copy_from_slice(&self.time_date_stamp.to_le_bytes());
        buf[8..10].copy_from_slice(&self.major_version.to_le_bytes());
        buf[10..12].copy_from_slice(&self.minor_version.to_le_bytes());
        buf[12..16].copy_from_slice(&self.name_rva.to_le_bytes());
        buf[16..20].copy_from_slice(&self.base.to_le_bytes());
        buf[20..24].copy_from_slice(&self.number_of_functions.to_le_bytes());
        buf[24..28].copy_from_slice(&self.number_of_names.to_le_bytes());
        buf[28..32].copy_from_slice(&self.address_of_functions.to_le_bytes());
        buf[32..36].copy_from_slice(&self.address_of_names.to_le_bytes());
        buf[36..40].copy_from_slice(&self.address_of_name_ordinals.to_le_bytes());

        Ok(())
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0u8; Self::SIZE];
        self.write(&mut buf).expect("buffer size is correct");
        buf
    }
}

/// A single exported function.
#[derive(Debug, Clone)]
pub struct ExportedFunction {
    /// Ordinal number.
    pub ordinal: u32,
    /// Function name (if exported by name).
    pub name: Option<String>,
    /// RVA of the function, or forwarded name.
    pub address: ExportAddress,
}

/// The address of an exported function.
#[derive(Debug, Clone)]
pub enum ExportAddress {
    /// RVA to the function.
    Rva(u32),
    /// Forwarded to another DLL (e.g., "NTDLL.RtlAllocateHeap").
    Forwarder(String),
}

/// The complete export table.
#[derive(Debug, Clone, Default)]
pub struct ExportTable {
    /// Export directory header.
    pub directory: ExportDirectory,
    /// DLL name.
    pub dll_name: String,
    /// List of exported functions.
    pub exports: Vec<ExportedFunction>,
}

impl ExportTable {
    /// Parse export table from a PE file.
    /// `export_rva` is the RVA from the data directory.
    /// `export_size` is the size from the data directory (used to detect forwarders).
    /// `read_at_rva` is a closure that reads bytes at an RVA.
    pub fn parse<F>(export_rva: u32, export_size: u32, read_at_rva: F) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        // Read export directory
        let dir_data =
            read_at_rva(export_rva, ExportDirectory::SIZE).ok_or(Error::invalid_rva(export_rva))?;
        let directory = ExportDirectory::parse(&dir_data)?;

        // Read DLL name
        let dll_name = Self::read_string(&read_at_rva, directory.name_rva)?;

        // Read exports
        let exports = Self::read_exports(&read_at_rva, &directory, export_rva, export_size)?;

        Ok(Self {
            directory,
            dll_name,
            exports,
        })
    }

    fn read_string<F>(read_at_rva: &F, rva: u32) -> Result<String>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        let data = read_at_rva(rva, 256).ok_or(Error::invalid_rva(rva))?;
        let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
        String::from_utf8(data[..end].to_vec()).map_err(|_| Error::invalid_utf8())
    }

    fn read_exports<F>(
        read_at_rva: &F,
        dir: &ExportDirectory,
        export_rva: u32,
        export_size: u32,
    ) -> Result<Vec<ExportedFunction>>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        let mut exports = Vec::new();
        let export_end = export_rva + export_size;

        // Read function addresses (EAT)
        for i in 0..dir.number_of_functions {
            let addr_rva = dir.address_of_functions + i * 4;
            let addr_data = read_at_rva(addr_rva, 4).ok_or(Error::invalid_rva(addr_rva))?;
            let func_rva =
                u32::from_le_bytes([addr_data[0], addr_data[1], addr_data[2], addr_data[3]]);

            if func_rva == 0 {
                continue; // Empty slot
            }

            let ordinal = dir.base + i;

            // Check if this is a forwarder (RVA points within export section)
            let address = if func_rva >= export_rva && func_rva < export_end {
                let fwd_name = Self::read_string(read_at_rva, func_rva)?;
                ExportAddress::Forwarder(fwd_name)
            } else {
                ExportAddress::Rva(func_rva)
            };

            exports.push(ExportedFunction {
                ordinal,
                name: None,
                address,
            });
        }

        // Read names and match to ordinals
        for i in 0..dir.number_of_names {
            // Read name RVA
            let name_ptr_rva = dir.address_of_names + i * 4;
            let name_ptr_data =
                read_at_rva(name_ptr_rva, 4).ok_or(Error::invalid_rva(name_ptr_rva))?;
            let name_rva = u32::from_le_bytes([
                name_ptr_data[0],
                name_ptr_data[1],
                name_ptr_data[2],
                name_ptr_data[3],
            ]);

            // Read ordinal index
            let ord_rva = dir.address_of_name_ordinals + i * 2;
            let ord_data = read_at_rva(ord_rva, 2).ok_or(Error::invalid_rva(ord_rva))?;
            let ord_index = u16::from_le_bytes([ord_data[0], ord_data[1]]) as usize;

            // Read name
            let name = Self::read_string(read_at_rva, name_rva)?;

            // Match to export
            if ord_index < exports.len() {
                exports[ord_index].name = Some(name);
            }
        }

        Ok(exports)
    }

    /// Check if the export table is empty.
    pub fn is_empty(&self) -> bool {
        self.exports.is_empty()
    }

    /// Find an export by name.
    pub fn find_by_name(&self, name: &str) -> Option<&ExportedFunction> {
        self.exports
            .iter()
            .find(|e| e.name.as_deref() == Some(name))
    }

    /// Find an export by ordinal.
    pub fn find_by_ordinal(&self, ordinal: u32) -> Option<&ExportedFunction> {
        self.exports.iter().find(|e| e.ordinal == ordinal)
    }

    /// Add an exported function by RVA.
    pub fn add_export(&mut self, name: Option<&str>, rva: u32) {
        let ordinal = if self.exports.is_empty() {
            self.directory.base
        } else {
            self.exports
                .iter()
                .map(|e| e.ordinal)
                .max()
                .unwrap_or(self.directory.base)
                + 1
        };
        self.exports.push(ExportedFunction {
            ordinal,
            name: name.map(|s| s.to_string()),
            address: ExportAddress::Rva(rva),
        });
    }

    /// Add a forwarded export.
    pub fn add_forwarder(&mut self, name: Option<&str>, forward_to: &str) {
        let ordinal = if self.exports.is_empty() {
            self.directory.base
        } else {
            self.exports
                .iter()
                .map(|e| e.ordinal)
                .max()
                .unwrap_or(self.directory.base)
                + 1
        };
        self.exports.push(ExportedFunction {
            ordinal,
            name: name.map(|s| s.to_string()),
            address: ExportAddress::Forwarder(forward_to.to_string()),
        });
    }

    /// Set the DLL name.
    pub fn set_dll_name(&mut self, name: &str) {
        self.dll_name = name.to_string();
    }

    /// Set the ordinal base.
    pub fn set_base(&mut self, base: u32) {
        self.directory.base = base;
    }
}

/// Builder for serializing export tables to section data.
#[derive(Debug)]
pub struct ExportTableBuilder {
    /// Base RVA where the export section will be placed.
    pub base_rva: u32,
}

impl ExportTableBuilder {
    /// Create a new builder.
    pub fn new(base_rva: u32) -> Self {
        Self { base_rva }
    }

    /// Calculate the total size needed for the export section.
    pub fn calculate_size(&self, table: &ExportTable) -> usize {
        if table.exports.is_empty() && table.dll_name.is_empty() {
            return 0;
        }

        // Export directory
        let directory_size = ExportDirectory::SIZE;

        // Export Address Table (4 bytes per function)
        let eat_size = table.exports.len() * 4;

        // Count named exports
        let named_count = table.exports.iter().filter(|e| e.name.is_some()).count();

        // Name Pointer Table (4 bytes per named export)
        let name_ptr_size = named_count * 4;

        // Ordinal Table (2 bytes per named export)
        let ordinal_table_size = named_count * 2;

        // DLL name
        let dll_name_size = table.dll_name.len() + 1;

        // Function names
        let mut names_size = 0;
        for export in &table.exports {
            if let Some(name) = &export.name {
                names_size += name.len() + 1;
            }
        }

        // Forwarder strings
        let mut forwarders_size = 0;
        for export in &table.exports {
            if let ExportAddress::Forwarder(fwd) = &export.address {
                forwarders_size += fwd.len() + 1;
            }
        }

        directory_size
            + eat_size
            + name_ptr_size
            + ordinal_table_size
            + dll_name_size
            + names_size
            + forwarders_size
    }

    /// Build the export section data and return (section_data, export_size).
    pub fn build(&self, table: &ExportTable) -> (Vec<u8>, u32) {
        if table.exports.is_empty() && table.dll_name.is_empty() {
            return (Vec::new(), 0);
        }

        let total_size = self.calculate_size(table);
        let mut data = vec![0u8; total_size];

        // Calculate offsets
        let directory_offset = 0usize;
        let eat_offset = ExportDirectory::SIZE;
        let eat_size = table.exports.len() * 4;

        let named_exports: Vec<_> = table
            .exports
            .iter()
            .enumerate()
            .filter(|(_, e)| e.name.is_some())
            .collect();
        let named_count = named_exports.len();

        let name_ptr_offset = eat_offset + eat_size;
        let name_ptr_size = named_count * 4;

        let ordinal_table_offset = name_ptr_offset + name_ptr_size;
        let ordinal_table_size = named_count * 2;

        let dll_name_offset = ordinal_table_offset + ordinal_table_size;
        let dll_name_size = table.dll_name.len() + 1;

        let strings_offset = dll_name_offset + dll_name_size;

        // Write DLL name
        let dll_name_rva = self.base_rva + dll_name_offset as u32;
        data[dll_name_offset..dll_name_offset + table.dll_name.len()]
            .copy_from_slice(table.dll_name.as_bytes());

        // Write function names and track their RVAs
        let mut string_pos = strings_offset;
        let mut name_rvas: Vec<(usize, u32)> = Vec::new(); // (index_in_exports, rva)

        for (idx, export) in table.exports.iter().enumerate() {
            if let Some(name) = &export.name {
                let name_rva = self.base_rva + string_pos as u32;
                data[string_pos..string_pos + name.len()].copy_from_slice(name.as_bytes());
                string_pos += name.len() + 1;
                name_rvas.push((idx, name_rva));
            }
        }

        // Write forwarder strings and build EAT
        let mut eat_entries: Vec<u32> = Vec::with_capacity(table.exports.len());
        for export in &table.exports {
            match &export.address {
                ExportAddress::Rva(rva) => {
                    eat_entries.push(*rva);
                }
                ExportAddress::Forwarder(fwd) => {
                    let fwd_rva = self.base_rva + string_pos as u32;
                    data[string_pos..string_pos + fwd.len()].copy_from_slice(fwd.as_bytes());
                    string_pos += fwd.len() + 1;
                    eat_entries.push(fwd_rva);
                }
            }
        }

        // Write Export Address Table (EAT)
        for (i, rva) in eat_entries.iter().enumerate() {
            let offset = eat_offset + i * 4;
            data[offset..offset + 4].copy_from_slice(&rva.to_le_bytes());
        }

        // Sort named exports by name for binary search compatibility
        let mut sorted_names: Vec<_> = name_rvas
            .iter()
            .map(|(idx, rva)| {
                let name = table.exports[*idx].name.as_ref().unwrap();
                (name.as_str(), *idx, *rva)
            })
            .collect();
        sorted_names.sort_by(|a, b| a.0.cmp(b.0));

        // Write Name Pointer Table and Ordinal Table
        for (i, (_, export_idx, name_rva)) in sorted_names.iter().enumerate() {
            // Name pointer
            let npt_offset = name_ptr_offset + i * 4;
            data[npt_offset..npt_offset + 4].copy_from_slice(&name_rva.to_le_bytes());

            // Ordinal (index into EAT)
            let ord_offset = ordinal_table_offset + i * 2;
            data[ord_offset..ord_offset + 2].copy_from_slice(&(*export_idx as u16).to_le_bytes());
        }

        // Build and write directory
        let directory = ExportDirectory {
            characteristics: 0,
            time_date_stamp: table.directory.time_date_stamp,
            major_version: table.directory.major_version,
            minor_version: table.directory.minor_version,
            name_rva: dll_name_rva,
            base: table.directory.base,
            number_of_functions: table.exports.len() as u32,
            number_of_names: named_count as u32,
            address_of_functions: self.base_rva + eat_offset as u32,
            address_of_names: if named_count > 0 {
                self.base_rva + name_ptr_offset as u32
            } else {
                0
            },
            address_of_name_ordinals: if named_count > 0 {
                self.base_rva + ordinal_table_offset as u32
            } else {
                0
            },
        };
        directory.write(&mut data[directory_offset..]).ok();

        (data, total_size as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_export_directory_size() {
        assert_eq!(ExportDirectory::SIZE, 40);
    }

    #[test]
    fn test_export_directory_roundtrip() {
        let original = ExportDirectory {
            characteristics: 0,
            time_date_stamp: 0x12345678,
            major_version: 1,
            minor_version: 0,
            name_rva: 0x1000,
            base: 1,
            number_of_functions: 10,
            number_of_names: 8,
            address_of_functions: 0x2000,
            address_of_names: 0x3000,
            address_of_name_ordinals: 0x4000,
        };

        let bytes = original.to_bytes();
        let parsed = ExportDirectory::parse(&bytes).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_export_table_builder_roundtrip() {
        // Create an export table
        let mut table = ExportTable::default();
        table.set_dll_name("test.dll");
        table.set_base(1);
        table.add_export(Some("FunctionA"), 0x1000);
        table.add_export(Some("FunctionB"), 0x2000);
        table.add_export(None, 0x3000); // Export by ordinal only

        assert_eq!(table.exports.len(), 3);
        assert_eq!(table.dll_name, "test.dll");

        // Build the section
        let base_rva = 0x4000u32;
        let builder = ExportTableBuilder::new(base_rva);
        let size = builder.calculate_size(&table);
        assert!(size > 0);

        let (data, export_size) = builder.build(&table);
        assert!(!data.is_empty());
        assert!(export_size > 0);

        // Parse the built data back
        let read_fn = |rva: u32, len: usize| -> Option<Vec<u8>> {
            if rva < base_rva {
                return None;
            }
            let offset = (rva - base_rva) as usize;
            if offset >= data.len() {
                return None;
            }
            let available = (data.len() - offset).min(len);
            Some(data[offset..offset + available].to_vec())
        };

        let parsed = ExportTable::parse(base_rva, export_size, read_fn).unwrap();
        assert_eq!(parsed.dll_name, "test.dll");
        assert_eq!(parsed.exports.len(), 3);

        // Verify named exports
        let func_a = parsed.find_by_name("FunctionA");
        assert!(func_a.is_some());
        if let ExportAddress::Rva(rva) = &func_a.unwrap().address {
            assert_eq!(*rva, 0x1000);
        } else {
            panic!("Expected RVA export");
        }

        let func_b = parsed.find_by_name("FunctionB");
        assert!(func_b.is_some());
    }
}
