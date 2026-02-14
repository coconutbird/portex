//! TLS (Thread Local Storage) directory parsing and building.
//!
//! The TLS directory contains information about thread-local storage,
//! including callbacks that are executed before the entry point.
//!
//! # Examples
//!
//! ## Reading TLS information from a PE file
//!
//! ```no_run
//! use portex::PE;
//!
//! let pe = PE::from_file("example.exe")?;
//!
//! if let Some(tls) = pe.tls()? {
//!     if let Some(ref dir) = tls.directory {
//!         println!("TLS callbacks VA: {:#x}", dir.callbacks_va());
//!     }
//!     println!("Callback RVAs:");
//!     for &callback in &tls.callback_rvas {
//!         println!("  {:#x}", callback);
//!     }
//! }
//! # Ok::<(), portex::Error>(())
//! ```

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
            return Err(Error::buffer_too_small(Self::SIZE, data.len()));
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
            return Err(Error::buffer_too_small(Self::SIZE, data.len()));
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
        let dir_size = if is_64bit {
            TlsDirectory64::SIZE
        } else {
            TlsDirectory32::SIZE
        };
        let data = read_at_rva(tls_rva, dir_size).ok_or(Error::invalid_rva(tls_rva))?;
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
                            ptr_data[0],
                            ptr_data[1],
                            ptr_data[2],
                            ptr_data[3],
                            ptr_data[4],
                            ptr_data[5],
                            ptr_data[6],
                            ptr_data[7],
                        ])
                    } else {
                        u32::from_le_bytes([ptr_data[0], ptr_data[1], ptr_data[2], ptr_data[3]])
                            as u64
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

/// Builder for TLS directories.
///
/// TLS directories contain thread-local storage initialization data and callbacks.
/// The callbacks are function pointers called before the entry point.
///
/// # Example
///
/// ```
/// use portex::tls::TlsBuilder;
///
/// // Create a TLS builder for 64-bit PE
/// let builder = TlsBuilder::new(0x3000, 0x140000000, true);
///
/// // Build with TLS data region and no callbacks
/// let (data, dir_size) = builder.build(0x1000, 0x1100, &[]);
/// assert!(dir_size > 0);
/// ```
#[derive(Debug, Clone)]
pub struct TlsBuilder {
    /// Base RVA where the TLS section will be placed.
    base_rva: u32,
    /// Image base address (needed to convert RVAs to VAs).
    image_base: u64,
    /// Whether this is a 64-bit PE.
    is_64bit: bool,
}

impl TlsBuilder {
    /// Create a new TLS builder.
    ///
    /// # Arguments
    /// * `base_rva` - RVA where the TLS data will be placed
    /// * `image_base` - Image base address for VA calculations
    /// * `is_64bit` - Whether the target PE is 64-bit
    pub fn new(base_rva: u32, image_base: u64, is_64bit: bool) -> Self {
        Self {
            base_rva,
            image_base,
            is_64bit,
        }
    }

    /// Build the TLS directory data.
    ///
    /// # Arguments
    /// * `raw_data_start_rva` - RVA of the TLS raw data start
    /// * `raw_data_end_rva` - RVA of the TLS raw data end
    /// * `callback_rvas` - List of callback function RVAs
    ///
    /// Returns (data, directory_size) where:
    /// - `data` is the raw bytes to write to the section
    /// - `directory_size` is the size of the TLS directory (for data directory)
    pub fn build(
        &self,
        raw_data_start_rva: u32,
        raw_data_end_rva: u32,
        callback_rvas: &[u64],
    ) -> (Vec<u8>, u32) {
        let ptr_size = if self.is_64bit { 8 } else { 4 };
        let dir_size = if self.is_64bit {
            TlsDirectory64::SIZE
        } else {
            TlsDirectory32::SIZE
        };

        // Layout:
        // [TlsDirectory (24 or 40 bytes)]
        // [TLS Index (4 bytes)]
        // [Callbacks array (ptr_size * (callback_rvas.len() + 1))] - null terminated

        let index_offset = dir_size;
        let callbacks_offset = index_offset + 4; // TLS index is always 4 bytes
        let callbacks_size = ptr_size * (callback_rvas.len() + 1); // +1 for null terminator
        let total_size = callbacks_offset + callbacks_size;

        let mut data = Vec::with_capacity(total_size);

        // Convert RVAs to VAs
        let raw_data_start_va = self.image_base + raw_data_start_rva as u64;
        let raw_data_end_va = self.image_base + raw_data_end_rva as u64;
        let index_va = self.image_base + self.base_rva as u64 + index_offset as u64;
        let callbacks_va = if callback_rvas.is_empty() {
            0 // No callbacks
        } else {
            self.image_base + self.base_rva as u64 + callbacks_offset as u64
        };

        // Write directory
        if self.is_64bit {
            let dir = TlsDirectory64 {
                start_address_of_raw_data: raw_data_start_va,
                end_address_of_raw_data: raw_data_end_va,
                address_of_index: index_va,
                address_of_callbacks: callbacks_va,
                size_of_zero_fill: 0,
                characteristics: 0,
            };
            data.extend_from_slice(&dir.to_bytes());
        } else {
            let dir = TlsDirectory32 {
                start_address_of_raw_data: raw_data_start_va as u32,
                end_address_of_raw_data: raw_data_end_va as u32,
                address_of_index: index_va as u32,
                address_of_callbacks: callbacks_va as u32,
                size_of_zero_fill: 0,
                characteristics: 0,
            };
            data.extend_from_slice(&dir.to_bytes());
        }

        // Write TLS index (initialized to 0)
        data.extend_from_slice(&0u32.to_le_bytes());

        // Write callbacks array
        for &callback_rva in callback_rvas {
            let callback_va = self.image_base + callback_rva;
            if self.is_64bit {
                data.extend_from_slice(&callback_va.to_le_bytes());
            } else {
                data.extend_from_slice(&(callback_va as u32).to_le_bytes());
            }
        }

        // Null terminator for callbacks
        if self.is_64bit {
            data.extend_from_slice(&0u64.to_le_bytes());
        } else {
            data.extend_from_slice(&0u32.to_le_bytes());
        }

        (data, dir_size as u32)
    }

    /// Build from an existing TlsInfo structure.
    ///
    /// This rebuilds the TLS directory from parsed info.
    pub fn build_from_info(&self, tls_info: &TlsInfo) -> (Vec<u8>, u32) {
        let (raw_start, raw_end) = match &tls_info.directory {
            Some(TlsDirectory::Tls32(dir)) => {
                let start = (dir.start_address_of_raw_data as u64)
                    .saturating_sub(self.image_base) as u32;
                let end = (dir.end_address_of_raw_data as u64)
                    .saturating_sub(self.image_base) as u32;
                (start, end)
            }
            Some(TlsDirectory::Tls64(dir)) => {
                let start = dir.start_address_of_raw_data.saturating_sub(self.image_base) as u32;
                let end = dir.end_address_of_raw_data.saturating_sub(self.image_base) as u32;
                (start, end)
            }
            None => (0, 0),
        };

        self.build(raw_start, raw_end, &tls_info.callback_rvas)
    }

    /// Calculate the size needed for TLS data.
    pub fn calculate_size(&self, num_callbacks: usize) -> usize {
        let ptr_size = if self.is_64bit { 8 } else { 4 };
        let dir_size = if self.is_64bit {
            TlsDirectory64::SIZE
        } else {
            TlsDirectory32::SIZE
        };
        dir_size + 4 + ptr_size * (num_callbacks + 1)
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
