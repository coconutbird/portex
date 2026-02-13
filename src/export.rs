//! Export table parsing and building.
//!
//! This module provides types for reading and writing PE export tables,
//! including the export directory and exported functions.

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
            return Err(Error::BufferTooSmall {
                expected: Self::SIZE,
                actual: buf.len(),
            });
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
        let dir_data = read_at_rva(export_rva, ExportDirectory::SIZE)
            .ok_or(Error::InvalidRva(export_rva))?;
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
        let data = read_at_rva(rva, 256).ok_or(Error::InvalidRva(rva))?;
        let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
        String::from_utf8(data[..end].to_vec()).map_err(|_| Error::InvalidUtf8)
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
            let addr_data = read_at_rva(addr_rva, 4).ok_or(Error::InvalidRva(addr_rva))?;
            let func_rva = u32::from_le_bytes([addr_data[0], addr_data[1], addr_data[2], addr_data[3]]);

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
            let name_ptr_data = read_at_rva(name_ptr_rva, 4).ok_or(Error::InvalidRva(name_ptr_rva))?;
            let name_rva = u32::from_le_bytes([
                name_ptr_data[0], name_ptr_data[1], name_ptr_data[2], name_ptr_data[3],
            ]);

            // Read ordinal index
            let ord_rva = dir.address_of_name_ordinals + i * 2;
            let ord_data = read_at_rva(ord_rva, 2).ok_or(Error::InvalidRva(ord_rva))?;
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
        self.exports.iter().find(|e| e.name.as_deref() == Some(name))
    }

    /// Find an export by ordinal.
    pub fn find_by_ordinal(&self, ordinal: u32) -> Option<&ExportedFunction> {
        self.exports.iter().find(|e| e.ordinal == ordinal)
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
}

