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
//! use portex::PeImage;
//!
//! # let file_bytes: &[u8] = &[];
//! let pe = PeImage::parse(file_bytes)?;
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
//! use portex::{ExportTable, PeImage};
//!
//! # let file_bytes: &[u8] = &[];
//! let mut pe = PeImage::parse(file_bytes)?;
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
//! let rebuilt = pe.try_build()?;
//! assert!(!rebuilt.is_empty());
//! # Ok::<(), portex::Error>(())
//! ```

use crate::prelude::*;
use crate::{Error, Result};

/// Maximum length for DLL and function names when reading export tables.
/// This is a reasonable limit that covers all valid Windows symbol names while
/// preventing unbounded reads on malformed PE files.
const MAX_NAME_LEN: usize = 4096;
const MAX_EXPORT_FUNCTIONS: u32 = 1_048_576;

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportedFunction {
    /// Ordinal number.
    pub ordinal: u32,
    /// Function name (if exported by name).
    pub name: Option<String>,
    /// Additional names that resolve to the same ordinal/EAT slot.
    pub aliases: Vec<String>,
    /// RVA of the function, or forwarded name.
    pub address: ExportAddress,
}

/// The address of an exported function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportAddress {
    /// RVA to the function.
    Rva(u32),
    /// Forwarded to another DLL (e.g., "NTDLL.RtlAllocateHeap").
    Forwarder(String),
}

/// The complete export table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
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
        if export_size < ExportDirectory::SIZE as u32 {
            return Err(Error::invalid_data_directory(format!(
                "export directory is {} bytes, expected at least {}",
                export_size,
                ExportDirectory::SIZE
            )));
        }
        // Read export directory
        let dir_data =
            read_at_rva(export_rva, ExportDirectory::SIZE).ok_or(Error::invalid_rva(export_rva))?;
        let directory = ExportDirectory::parse(&dir_data)?;

        if directory.number_of_functions > MAX_EXPORT_FUNCTIONS {
            return Err(Error::invalid_data_directory(format!(
                "export function count {} exceeds the safety limit {}",
                directory.number_of_functions, MAX_EXPORT_FUNCTIONS
            )));
        }
        if directory.name_rva == 0 {
            return Err(Error::invalid_data_directory(
                "export directory has a null DLL name RVA",
            ));
        }

        // Read DLL name
        let dll_name = Self::read_string(
            &read_at_rva,
            directory.name_rva,
            export_rva,
            export_size,
            "export DLL name",
        )?;

        // Read exports
        let exports = Self::read_exports(&read_at_rva, &directory, export_rva, export_size)?;

        Ok(Self {
            directory,
            dll_name,
            exports,
        })
    }

    fn read_string<F>(
        read_at_rva: &F,
        rva: u32,
        export_rva: u32,
        export_size: u32,
        context: &str,
    ) -> Result<String>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        crate::parse_utils::read_c_string_in_range(
            read_at_rva,
            rva,
            export_rva,
            export_size,
            MAX_NAME_LEN,
            context,
        )
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
        let export_end = export_rva
            .checked_add(export_size)
            .ok_or_else(|| Error::invalid_data_directory("export directory RVA overflow"))?;
        if dir.number_of_names > dir.number_of_functions {
            return Err(Error::invalid_data_directory(format!(
                "export name count {} exceeds function count {}",
                dir.number_of_names, dir.number_of_functions
            )));
        }
        crate::parse_utils::bounded_table_range(
            dir.address_of_functions,
            dir.number_of_functions,
            4,
            export_rva,
            export_size,
            "export address table",
        )?;
        crate::parse_utils::bounded_table_range(
            dir.address_of_names,
            dir.number_of_names,
            4,
            export_rva,
            export_size,
            "export name-pointer table",
        )?;
        crate::parse_utils::bounded_table_range(
            dir.address_of_name_ordinals,
            dir.number_of_names,
            2,
            export_rva,
            export_size,
            "export ordinal table",
        )?;

        // Read function addresses (EAT)
        for i in 0..dir.number_of_functions {
            let addr_rva = dir
                .address_of_functions
                .checked_add(i.checked_mul(4).ok_or_else(|| {
                    Error::invalid_data_directory("export address-table offset overflow")
                })?)
                .ok_or_else(|| {
                    Error::invalid_data_directory("export address-table RVA overflow")
                })?;
            let addr_data = crate::parse_utils::read_exact_rva(
                read_at_rva,
                addr_rva,
                4,
                "export address entry",
            )?;
            let func_rva =
                u32::from_le_bytes([addr_data[0], addr_data[1], addr_data[2], addr_data[3]]);

            if func_rva == 0 {
                continue; // Empty slot
            }

            let ordinal = dir
                .base
                .checked_add(i)
                .ok_or_else(|| Error::invalid_data_directory("export ordinal overflow"))?;

            // Check if this is a forwarder (RVA points within export section)
            let address = if func_rva >= export_rva && func_rva < export_end {
                let fwd_name = Self::read_string(
                    read_at_rva,
                    func_rva,
                    export_rva,
                    export_size,
                    "export forwarder",
                )?;
                ExportAddress::Forwarder(fwd_name)
            } else {
                ExportAddress::Rva(func_rva)
            };

            exports.push(ExportedFunction {
                ordinal,
                name: None,
                aliases: Vec::new(),
                address,
            });
        }

        // Read names and match to ordinals
        for i in 0..dir.number_of_names {
            // Read name RVA
            let name_ptr_rva = dir
                .address_of_names
                .checked_add(i.checked_mul(4).ok_or_else(|| {
                    Error::invalid_data_directory("export name-table offset overflow")
                })?)
                .ok_or_else(|| Error::invalid_data_directory("export name-table RVA overflow"))?;
            let name_ptr_data = crate::parse_utils::read_exact_rva(
                read_at_rva,
                name_ptr_rva,
                4,
                "export name pointer",
            )?;
            let name_rva = u32::from_le_bytes([
                name_ptr_data[0],
                name_ptr_data[1],
                name_ptr_data[2],
                name_ptr_data[3],
            ]);

            // Read ordinal index
            let ord_rva = dir
                .address_of_name_ordinals
                .checked_add(i.checked_mul(2).ok_or_else(|| {
                    Error::invalid_data_directory("export ordinal-table offset overflow")
                })?)
                .ok_or_else(|| {
                    Error::invalid_data_directory("export ordinal-table RVA overflow")
                })?;
            let ord_data =
                crate::parse_utils::read_exact_rva(read_at_rva, ord_rva, 2, "export ordinal")?;
            let ord_index = u16::from_le_bytes([ord_data[0], ord_data[1]]) as usize;

            // Read name
            let name = Self::read_string(
                read_at_rva,
                name_rva,
                export_rva,
                export_size,
                "export function name",
            )?;

            // Match to export
            let ordinal = dir
                .base
                .checked_add(ord_index as u32)
                .ok_or_else(|| Error::invalid_data_directory("export ordinal overflow"))?;
            let export = exports
                .iter_mut()
                .find(|export| export.ordinal == ordinal)
                .ok_or_else(|| {
                    Error::invalid_data_directory(format!(
                        "export name references empty function slot {}",
                        ord_index
                    ))
                })?;
            if export.name.is_none() {
                export.name = Some(name);
            } else {
                export.aliases.push(name);
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
        self.exports.iter().find(|export| {
            export.name.as_deref() == Some(name) || export.aliases.iter().any(|alias| alias == name)
        })
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
            aliases: Vec::new(),
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
            aliases: Vec::new(),
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
        self.try_calculate_size(table)
            .expect("export table size overflow: use try_calculate_size()")
    }

    /// Calculate the serialized size while validating sparse ordinals, names,
    /// and all intermediate offsets.
    pub fn try_calculate_size(&self, table: &ExportTable) -> Result<usize> {
        if table.exports.is_empty() && table.dll_name.is_empty() {
            return Ok(0);
        }
        let dimensions = export_dimensions(table)?;
        let eat_size = dimensions
            .function_count
            .checked_mul(4)
            .ok_or_else(|| Error::invalid_data_directory("export address-table size overflow"))?;
        let name_ptr_size = dimensions
            .named_count
            .checked_mul(4)
            .ok_or_else(|| Error::invalid_data_directory("export name-table size overflow"))?;
        let ordinal_size = dimensions
            .named_count
            .checked_mul(2)
            .ok_or_else(|| Error::invalid_data_directory("export ordinal-table size overflow"))?;
        let dll_name_size = checked_string_size(&table.dll_name, "export DLL name")?;

        let mut names_size = 0usize;
        let mut forwarders_size = 0usize;
        for export in &table.exports {
            for name in export.name.iter().chain(export.aliases.iter()) {
                names_size = names_size
                    .checked_add(checked_string_size(name, "export name")?)
                    .ok_or_else(|| Error::invalid_data_directory("export names size overflow"))?;
            }
            if let ExportAddress::Forwarder(forwarder) = &export.address {
                forwarders_size = forwarders_size
                    .checked_add(checked_string_size(forwarder, "export forwarder")?)
                    .ok_or_else(|| {
                        Error::invalid_data_directory("export forwarder size overflow")
                    })?;
            }
        }

        ExportDirectory::SIZE
            .checked_add(eat_size)
            .and_then(|size| size.checked_add(name_ptr_size))
            .and_then(|size| size.checked_add(ordinal_size))
            .and_then(|size| size.checked_add(dll_name_size))
            .and_then(|size| size.checked_add(names_size))
            .and_then(|size| size.checked_add(forwarders_size))
            .ok_or_else(|| Error::invalid_data_directory("export table size overflow"))
    }

    /// Build the export section data and return (section_data, export_size).
    pub fn build(&self, table: &ExportTable) -> (Vec<u8>, u32) {
        self.try_build(table)
            .expect("export table build failed: use try_build() for fallible serialization")
    }

    /// Build an export table while preserving sparse EAT slots and all names
    /// associated with an ordinal.
    pub fn try_build(&self, table: &ExportTable) -> Result<(Vec<u8>, u32)> {
        if table.exports.is_empty() && table.dll_name.is_empty() {
            return Ok((Vec::new(), 0));
        }

        let dimensions = export_dimensions(table)?;
        let total_size = self.try_calculate_size(table)?;
        let total_size_u32 = u32::try_from(total_size)
            .map_err(|_| Error::invalid_data_directory("export table exceeds u32"))?;
        self.base_rva
            .checked_add(total_size_u32)
            .ok_or_else(|| Error::invalid_data_directory("export table RVA range overflow"))?;
        let mut data = vec![0u8; total_size];

        // Calculate offsets
        let eat_offset = ExportDirectory::SIZE;
        let eat_size = dimensions.function_count * 4;
        let name_ptr_offset = eat_offset + eat_size;
        let name_ptr_size = dimensions.named_count * 4;
        let ordinal_table_offset = name_ptr_offset + name_ptr_size;
        let ordinal_table_size = dimensions.named_count * 2;
        let dll_name_offset = ordinal_table_offset + ordinal_table_size;
        let dll_name_size = table.dll_name.len() + 1;
        let strings_offset = dll_name_offset + dll_name_size;

        // Write DLL name
        let dll_name_rva = checked_rva(self.base_rva, dll_name_offset, "export DLL name")?;
        data[dll_name_offset..dll_name_offset + table.dll_name.len()]
            .copy_from_slice(table.dll_name.as_bytes());

        // Write every function name and alias, tracking its EAT index.
        let mut string_pos = strings_offset;
        let mut name_rvas: Vec<(&str, u16, u32)> = Vec::with_capacity(dimensions.named_count);
        for export in &table.exports {
            let eat_index = export
                .ordinal
                .checked_sub(table.directory.base)
                .and_then(|index| u16::try_from(index).ok())
                .ok_or_else(|| {
                    Error::invalid_data_directory(
                        "named export ordinal index does not fit the u16 name table",
                    )
                })?;
            for name in export.name.iter().chain(export.aliases.iter()) {
                let name_rva = checked_rva(self.base_rva, string_pos, "export name")?;
                data[string_pos..string_pos + name.len()].copy_from_slice(name.as_bytes());
                string_pos += name.len() + 1;
                name_rvas.push((name.as_str(), eat_index, name_rva));
            }
        }

        // Write forwarder strings and populate sparse EAT slots.
        let mut eat_entries = vec![0u32; dimensions.function_count];
        for export in &table.exports {
            let index = usize::try_from(export.ordinal - table.directory.base)
                .map_err(|_| Error::invalid_data_directory("export ordinal index overflow"))?;
            eat_entries[index] = match &export.address {
                ExportAddress::Rva(rva) => *rva,
                ExportAddress::Forwarder(fwd) => {
                    let fwd_rva = checked_rva(self.base_rva, string_pos, "export forwarder")?;
                    data[string_pos..string_pos + fwd.len()].copy_from_slice(fwd.as_bytes());
                    string_pos += fwd.len() + 1;
                    fwd_rva
                }
            };
        }

        // Write Export Address Table (EAT)
        for (i, rva) in eat_entries.iter().enumerate() {
            let offset = eat_offset + i * 4;
            data[offset..offset + 4].copy_from_slice(&rva.to_le_bytes());
        }

        // Sort named exports by name for binary search compatibility
        name_rvas.sort_by(|left, right| left.0.cmp(right.0));

        // Write Name Pointer Table and Ordinal Table
        for (i, (_, eat_index, name_rva)) in name_rvas.iter().enumerate() {
            // Name pointer
            let npt_offset = name_ptr_offset + i * 4;
            data[npt_offset..npt_offset + 4].copy_from_slice(&name_rva.to_le_bytes());

            // Ordinal (index into EAT)
            let ord_offset = ordinal_table_offset + i * 2;
            data[ord_offset..ord_offset + 2].copy_from_slice(&eat_index.to_le_bytes());
        }

        // Build and write directory
        let directory = ExportDirectory {
            characteristics: table.directory.characteristics,
            time_date_stamp: table.directory.time_date_stamp,
            major_version: table.directory.major_version,
            minor_version: table.directory.minor_version,
            name_rva: dll_name_rva,
            base: table.directory.base,
            number_of_functions: u32::try_from(dimensions.function_count)
                .map_err(|_| Error::invalid_data_directory("export function count exceeds u32"))?,
            number_of_names: u32::try_from(dimensions.named_count)
                .map_err(|_| Error::invalid_data_directory("export name count exceeds u32"))?,
            address_of_functions: if dimensions.function_count > 0 {
                checked_rva(self.base_rva, eat_offset, "export address table")?
            } else {
                0
            },
            address_of_names: if dimensions.named_count > 0 {
                checked_rva(self.base_rva, name_ptr_offset, "export name table")?
            } else {
                0
            },
            address_of_name_ordinals: if dimensions.named_count > 0 {
                checked_rva(self.base_rva, ordinal_table_offset, "export ordinal table")?
            } else {
                0
            },
        };
        directory.write(&mut data[..ExportDirectory::SIZE])?;

        Ok((data, total_size_u32))
    }
}

#[derive(Debug, Clone, Copy)]
struct ExportDimensions {
    function_count: usize,
    named_count: usize,
}

fn export_dimensions(table: &ExportTable) -> Result<ExportDimensions> {
    let mut ordinals = BTreeMap::new();
    let mut function_count = 0usize;
    let mut named_count = 0usize;
    for export in &table.exports {
        let index = export
            .ordinal
            .checked_sub(table.directory.base)
            .ok_or_else(|| {
                Error::invalid_data_directory(format!(
                    "export ordinal {} is below base {}",
                    export.ordinal, table.directory.base
                ))
            })?;
        if ordinals.insert(export.ordinal, ()).is_some() {
            return Err(Error::invalid_data_directory(format!(
                "duplicate export ordinal {} (use aliases for multiple names)",
                export.ordinal
            )));
        }
        let index_usize = usize::try_from(index)
            .map_err(|_| Error::invalid_data_directory("export ordinal index overflow"))?;
        function_count = function_count.max(
            index_usize
                .checked_add(1)
                .ok_or_else(|| Error::invalid_data_directory("export function count overflow"))?,
        );
        let names_for_export = usize::from(export.name.is_some())
            .checked_add(export.aliases.len())
            .ok_or_else(|| Error::invalid_data_directory("export name count overflow"))?;
        if names_for_export != 0 && index > u32::from(u16::MAX) {
            return Err(Error::invalid_data_directory(format!(
                "named export ordinal {} is too far above base {}",
                export.ordinal, table.directory.base
            )));
        }
        named_count = named_count
            .checked_add(names_for_export)
            .ok_or_else(|| Error::invalid_data_directory("export name count overflow"))?;
    }
    if function_count > MAX_EXPORT_FUNCTIONS as usize {
        return Err(Error::invalid_data_directory(format!(
            "sparse export table needs {} slots, exceeding the safety limit {}",
            function_count, MAX_EXPORT_FUNCTIONS
        )));
    }
    Ok(ExportDimensions {
        function_count,
        named_count,
    })
}

fn checked_string_size(value: &str, context: &str) -> Result<usize> {
    if value.as_bytes().contains(&0) {
        return Err(Error::invalid_data_directory(format!(
            "{context} contains an embedded NUL byte"
        )));
    }
    value
        .len()
        .checked_add(1)
        .ok_or_else(|| Error::invalid_data_directory(format!("{context} size overflow")))
}

fn checked_rva(base: u32, offset: usize, context: &str) -> Result<u32> {
    let offset = u32::try_from(offset)
        .map_err(|_| Error::invalid_data_directory(format!("{context} offset exceeds u32")))?;
    base.checked_add(offset)
        .ok_or_else(|| Error::invalid_data_directory(format!("{context} RVA overflow")))
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
