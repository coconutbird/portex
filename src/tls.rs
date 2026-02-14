//! TLS (Thread Local Storage) directory parsing and building.
//!
//! The TLS directory contains information about thread-local storage,
//! including callbacks that are executed before the entry point.

use crate::{Error, Result};

/// IMAGE_TLS_DIRECTORY32 - 24 bytes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TlsDirectory32 {
    /// Starting address of the TLS template (VA).
    pub start_address_of_raw_data: u32,
    /// Ending address of the TLS template (VA).
    pub end_address_of_raw_data: u32,
    /// Address of the TLS index (VA).
    pub address_of_index: u32,
    /// Address of TLS callback array (VA).
    pub address_of_callbacks: u32,
    /// Size of zero-filled area.
    pub size_of_zero_fill: u32,
    /// Characteristics (reserved, typically 0).
    pub characteristics: u32,
}

impl TlsDirectory32 {
    pub const SIZE: usize = 24;

    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(Error::BufferTooSmall {
                expected: Self::SIZE,
                actual: data.len(),
            });
        }

        Ok(Self {
            start_address_of_raw_data: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            end_address_of_raw_data: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            address_of_index: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            address_of_callbacks: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
            size_of_zero_fill: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
            characteristics: u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
        })
    }

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..4].copy_from_slice(&self.start_address_of_raw_data.to_le_bytes());
        buf[4..8].copy_from_slice(&self.end_address_of_raw_data.to_le_bytes());
        buf[8..12].copy_from_slice(&self.address_of_index.to_le_bytes());
        buf[12..16].copy_from_slice(&self.address_of_callbacks.to_le_bytes());
        buf[16..20].copy_from_slice(&self.size_of_zero_fill.to_le_bytes());
        buf[20..24].copy_from_slice(&self.characteristics.to_le_bytes());
        buf
    }
}

/// IMAGE_TLS_DIRECTORY64 - 40 bytes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TlsDirectory64 {
    /// Starting address of the TLS template (VA).
    pub start_address_of_raw_data: u64,
    /// Ending address of the TLS template (VA).
    pub end_address_of_raw_data: u64,
    /// Address of the TLS index (VA).
    pub address_of_index: u64,
    /// Address of TLS callback array (VA).
    pub address_of_callbacks: u64,
    /// Size of zero-filled area.
    pub size_of_zero_fill: u32,
    /// Characteristics (reserved, typically 0).
    pub characteristics: u32,
}

impl TlsDirectory64 {
    pub const SIZE: usize = 40;

    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(Error::BufferTooSmall {
                expected: Self::SIZE,
                actual: data.len(),
            });
        }

        Ok(Self {
            start_address_of_raw_data: u64::from_le_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ]),
            end_address_of_raw_data: u64::from_le_bytes([
                data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
            ]),
            address_of_index: u64::from_le_bytes([
                data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
            ]),
            address_of_callbacks: u64::from_le_bytes([
                data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
            ]),
            size_of_zero_fill: u32::from_le_bytes([data[32], data[33], data[34], data[35]]),
            characteristics: u32::from_le_bytes([data[36], data[37], data[38], data[39]]),
        })
    }

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..8].copy_from_slice(&self.start_address_of_raw_data.to_le_bytes());
        buf[8..16].copy_from_slice(&self.end_address_of_raw_data.to_le_bytes());
        buf[16..24].copy_from_slice(&self.address_of_index.to_le_bytes());
        buf[24..32].copy_from_slice(&self.address_of_callbacks.to_le_bytes());
        buf[32..36].copy_from_slice(&self.size_of_zero_fill.to_le_bytes());
        buf[36..40].copy_from_slice(&self.characteristics.to_le_bytes());
        buf
    }
}

/// TLS Directory (either 32 or 64-bit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsDirectory {
    Tls32(TlsDirectory32),
    Tls64(TlsDirectory64),
}

impl TlsDirectory {
    /// Parse from bytes, selecting 32 or 64-bit based on flag.
    pub fn parse(data: &[u8], is_64bit: bool) -> Result<Self> {
        if is_64bit {
            Ok(Self::Tls64(TlsDirectory64::parse(data)?))
        } else {
            Ok(Self::Tls32(TlsDirectory32::parse(data)?))
        }
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Tls32(tls) => tls.to_bytes().to_vec(),
            Self::Tls64(tls) => tls.to_bytes().to_vec(),
        }
    }

    /// Get the size of the TLS directory.
    pub fn size(&self) -> usize {
        match self {
            Self::Tls32(_) => TlsDirectory32::SIZE,
            Self::Tls64(_) => TlsDirectory64::SIZE,
        }
    }

    /// Get the callbacks VA (Virtual Address).
    pub fn callbacks_va(&self) -> u64 {
        match self {
            Self::Tls32(tls) => tls.address_of_callbacks as u64,
            Self::Tls64(tls) => tls.address_of_callbacks,
        }
    }

    /// Check if TLS has callbacks (non-zero address).
    pub fn has_callbacks(&self) -> bool {
        self.callbacks_va() != 0
    }
}

/// Parsed TLS information including callbacks.
#[derive(Debug, Clone, Default)]
pub struct TlsInfo {
    /// The TLS directory.
    pub directory: Option<TlsDirectory>,
    /// List of callback RVAs (converted from VAs).
    pub callback_rvas: Vec<u64>,
}

impl TlsInfo {
    /// Parse TLS information from a PE.
    /// `tls_rva` and `tls_size` come from the data directory.
    /// `image_base` is needed to convert VAs to RVAs.
    pub fn parse<F>(
        tls_rva: u32,
        _tls_size: u32,
        image_base: u64,
        is_64bit: bool,
        read_at_rva: F,
    ) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        let dir_size = if is_64bit { TlsDirectory64::SIZE } else { TlsDirectory32::SIZE };
        let data = read_at_rva(tls_rva, dir_size).ok_or(Error::InvalidRva(tls_rva))?;
        let directory = TlsDirectory::parse(&data, is_64bit)?;

        // Parse callbacks if present
        let mut callback_rvas = Vec::new();
        if directory.has_callbacks() {
            let callbacks_va = directory.callbacks_va();
            if callbacks_va > image_base {
                let callbacks_rva = (callbacks_va - image_base) as u32;
                let ptr_size = if is_64bit { 8 } else { 4 };
                let mut offset = 0u32;

                loop {
                    let ptr_data = read_at_rva(callbacks_rva + offset, ptr_size);
                    if ptr_data.is_none() {
                        break;
                    }
                    let ptr_data = ptr_data.unwrap();

                    let callback_va = if is_64bit {
                        u64::from_le_bytes([
                            ptr_data[0], ptr_data[1], ptr_data[2], ptr_data[3],
                            ptr_data[4], ptr_data[5], ptr_data[6], ptr_data[7],
                        ])
                    } else {
                        u32::from_le_bytes([ptr_data[0], ptr_data[1], ptr_data[2], ptr_data[3]]) as u64
                    };

                    // Null terminator
                    if callback_va == 0 {
                        break;
                    }

                    // Convert VA to RVA
                    if callback_va > image_base {
                        callback_rvas.push(callback_va - image_base);
                    }
                    offset += ptr_size as u32;
                }
            }
        }

        Ok(Self {
            directory: Some(directory),
            callback_rvas,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_directory_32_size() {
        assert_eq!(TlsDirectory32::SIZE, 24);
    }

    #[test]
    fn test_tls_directory_64_size() {
        assert_eq!(TlsDirectory64::SIZE, 40);
    }

    #[test]
    fn test_tls_directory_32_roundtrip() {
        let original = TlsDirectory32 {
            start_address_of_raw_data: 0x00401000,
            end_address_of_raw_data: 0x00401100,
            address_of_index: 0x00402000,
            address_of_callbacks: 0x00403000,
            size_of_zero_fill: 256,
            characteristics: 0,
        };

        let bytes = original.to_bytes();
        let parsed = TlsDirectory32::parse(&bytes).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_tls_directory_64_roundtrip() {
        let original = TlsDirectory64 {
            start_address_of_raw_data: 0x0000000140001000,
            end_address_of_raw_data: 0x0000000140001100,
            address_of_index: 0x0000000140002000,
            address_of_callbacks: 0x0000000140003000,
            size_of_zero_fill: 512,
            characteristics: 0,
        };

        let bytes = original.to_bytes();
        let parsed = TlsDirectory64::parse(&bytes).unwrap();
        assert_eq!(original, parsed);
    }
}

