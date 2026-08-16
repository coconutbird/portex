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
//! use portex::PeImage;
//!
//! # let file_bytes: &[u8] = &[];
//! let pe = PeImage::parse(file_bytes)?;
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

use crate::prelude::*;
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
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsInfo {
    /// The TLS directory.
    pub directory: Option<TlsDirectory>,
    /// List of callback RVAs (converted from VAs).
    pub callback_rvas: Vec<u64>,
    /// Base used to convert the directory's absolute VAs to RVAs.
    pub image_base: u64,
}

impl TlsInfo {
    /// Parse TLS information from a PE.
    /// `tls_rva` and `tls_size` come from the data directory.
    /// `image_base` is needed to convert VAs to RVAs.
    pub fn parse<F>(
        tls_rva: u32,
        tls_size: u32,
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
        if tls_size < dir_size as u32 {
            return Err(Error::invalid_data_directory(format!(
                "TLS directory size {} is smaller than {}",
                tls_size, dir_size
            )));
        }
        let data = read_at_rva(tls_rva, dir_size).ok_or(Error::invalid_rva(tls_rva))?;
        let directory = TlsDirectory::parse(&data, is_64bit)?;

        let (raw_start, raw_end, index_va) = match &directory {
            TlsDirectory::Tls32(directory) => (
                u64::from(directory.start_address_of_raw_data),
                u64::from(directory.end_address_of_raw_data),
                u64::from(directory.address_of_index),
            ),
            TlsDirectory::Tls64(directory) => (
                directory.start_address_of_raw_data,
                directory.end_address_of_raw_data,
                directory.address_of_index,
            ),
        };
        if (raw_start == 0) != (raw_end == 0) {
            return Err(Error::invalid_data_directory(
                "TLS raw-data start and end must either both be zero or both be VAs",
            ));
        }
        if raw_start != 0 {
            let start_rva = va_to_rva(raw_start, image_base)?;
            let end_rva = va_to_rva(raw_end, image_base)?;
            if end_rva < start_rva {
                return Err(Error::invalid_data_directory(
                    "TLS raw-data end precedes its start",
                ));
            }
        }
        if index_va != 0 {
            va_to_rva(index_va, image_base)?;
        }

        // Parse callbacks if present
        let mut callback_rvas = Vec::new();
        if directory.has_callbacks() {
            let callbacks_va = directory.callbacks_va();
            if callbacks_va >= image_base {
                let callbacks_rva = callbacks_va
                    .checked_sub(image_base)
                    .and_then(|rva| u32::try_from(rva).ok())
                    .ok_or_else(|| {
                        Error::invalid_data_directory(format!(
                            "TLS callback array VA {:#x} is outside image base {:#x}",
                            callbacks_va, image_base
                        ))
                    })?;
                let ptr_size = if is_64bit { 8 } else { 4 };
                let mut offset = 0u32;

                for _ in 0..65_536 {
                    let callback_pointer_rva =
                        callbacks_rva.checked_add(offset).ok_or_else(|| {
                            Error::invalid_data_directory("TLS callback-array RVA overflow")
                        })?;
                    let ptr_data = read_at_rva(callback_pointer_rva, ptr_size)
                        .ok_or(Error::invalid_rva(callback_pointer_rva))?;
                    if ptr_data.len() < ptr_size {
                        return Err(Error::buffer_too_small(ptr_size, ptr_data.len()));
                    }

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
                    let callback_rva = callback_va.checked_sub(image_base).ok_or_else(|| {
                        Error::invalid_data_directory(format!(
                            "TLS callback VA {:#x} is below image base {:#x}",
                            callback_va, image_base
                        ))
                    })?;
                    let callback_rva = u32::try_from(callback_rva).map_err(|_| {
                        Error::invalid_data_directory(format!(
                            "TLS callback VA {:#x} is outside the 32-bit RVA space",
                            callback_va
                        ))
                    })?;
                    callback_rvas.push(u64::from(callback_rva));
                    offset = offset.checked_add(ptr_size as u32).ok_or_else(|| {
                        Error::invalid_data_directory("TLS callback-array size overflow")
                    })?;
                }

                if callback_rvas.len() == 65_536 {
                    return Err(Error::invalid_data_directory(
                        "TLS callback array is missing a terminator",
                    ));
                }
            } else {
                return Err(Error::invalid_data_directory(format!(
                    "TLS callback array VA {:#x} is below image base {:#x}",
                    callbacks_va, image_base
                )));
            }
        }

        Ok(Self {
            directory: Some(directory),
            callback_rvas,
            image_base,
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
        self.try_build(raw_data_start_rva, raw_data_end_rva, callback_rvas)
            .expect("TLS build failed: use try_build() for fallible serialization")
    }

    /// Build TLS data with checked VA/RVA and size arithmetic.
    pub fn try_build(
        &self,
        raw_data_start_rva: u32,
        raw_data_end_rva: u32,
        callback_rvas: &[u64],
    ) -> Result<(Vec<u8>, u32)> {
        if raw_data_end_rva < raw_data_start_rva {
            return Err(Error::invalid_data_directory(
                "TLS raw-data end precedes its start",
            ));
        }
        if (raw_data_start_rva == 0) != (raw_data_end_rva == 0) {
            return Err(Error::invalid_data_directory(
                "TLS raw-data start and end must either both be zero or both be RVAs",
            ));
        }
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
        let after_index = index_offset
            .checked_add(4)
            .ok_or_else(|| Error::invalid_data_directory("TLS index offset overflow"))?;
        let callbacks_offset = after_index
            .checked_add(ptr_size - 1)
            .map(|offset| offset & !(ptr_size - 1))
            .ok_or_else(|| Error::invalid_data_directory("TLS callback alignment overflow"))?;
        let callbacks_size = callback_rvas
            .len()
            .checked_add(1)
            .and_then(|count| count.checked_mul(ptr_size))
            .ok_or_else(|| Error::invalid_data_directory("TLS callback-array size overflow"))?;
        let total_size = callbacks_offset
            .checked_add(callbacks_size)
            .ok_or_else(|| Error::invalid_data_directory("TLS data size overflow"))?;
        let total_size_u32 = u32::try_from(total_size)
            .map_err(|_| Error::invalid_data_directory("TLS data exceeds u32"))?;
        self.base_rva
            .checked_add(total_size_u32)
            .ok_or_else(|| Error::invalid_data_directory("TLS data RVA range overflow"))?;

        let mut data = Vec::with_capacity(total_size);

        // Convert RVAs to VAs
        let (raw_data_start_va, raw_data_end_va) = if raw_data_start_rva == 0 {
            (0, 0)
        } else {
            (
                checked_va(
                    self.image_base,
                    u64::from(raw_data_start_rva),
                    "TLS raw-data start",
                )?,
                checked_va(
                    self.image_base,
                    u64::from(raw_data_end_rva),
                    "TLS raw-data end",
                )?,
            )
        };
        let index_rva = self
            .base_rva
            .checked_add(
                u32::try_from(index_offset)
                    .map_err(|_| Error::invalid_data_directory("TLS index offset exceeds u32"))?,
            )
            .ok_or_else(|| Error::invalid_data_directory("TLS index RVA overflow"))?;
        let index_va = checked_va(self.image_base, u64::from(index_rva), "TLS index")?;
        let callbacks_va = if callback_rvas.is_empty() {
            0 // No callbacks
        } else {
            let callbacks_rva = self
                .base_rva
                .checked_add(u32::try_from(callbacks_offset).map_err(|_| {
                    Error::invalid_data_directory("TLS callback offset exceeds u32")
                })?)
                .ok_or_else(|| Error::invalid_data_directory("TLS callback RVA overflow"))?;
            checked_va(
                self.image_base,
                u64::from(callbacks_rva),
                "TLS callback array",
            )?
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
            let raw_data_start_va = u32::try_from(raw_data_start_va)
                .map_err(|_| Error::invalid_data_directory("PE32 TLS start VA exceeds u32"))?;
            let raw_data_end_va = u32::try_from(raw_data_end_va)
                .map_err(|_| Error::invalid_data_directory("PE32 TLS end VA exceeds u32"))?;
            let index_va = u32::try_from(index_va)
                .map_err(|_| Error::invalid_data_directory("PE32 TLS index VA exceeds u32"))?;
            let callbacks_va = u32::try_from(callbacks_va).map_err(|_| {
                Error::invalid_data_directory("PE32 TLS callback-array VA exceeds u32")
            })?;
            let dir = TlsDirectory32 {
                start_address_of_raw_data: raw_data_start_va,
                end_address_of_raw_data: raw_data_end_va,
                address_of_index: index_va,
                address_of_callbacks: callbacks_va,
                size_of_zero_fill: 0,
                characteristics: 0,
            };
            data.extend_from_slice(&dir.to_bytes());
        }

        // Write TLS index (initialized to 0)
        data.extend_from_slice(&0u32.to_le_bytes());
        data.resize(callbacks_offset, 0);

        // Write callbacks array
        for &callback_rva in callback_rvas {
            let callback_rva = u32::try_from(callback_rva)
                .map_err(|_| Error::invalid_data_directory("TLS callback RVA exceeds u32"))?;
            let callback_va = checked_va(self.image_base, u64::from(callback_rva), "TLS callback")?;
            if self.is_64bit {
                data.extend_from_slice(&callback_va.to_le_bytes());
            } else {
                let callback_va = u32::try_from(callback_va).map_err(|_| {
                    Error::invalid_data_directory("PE32 TLS callback VA exceeds u32")
                })?;
                data.extend_from_slice(&callback_va.to_le_bytes());
            }
        }

        // Null terminator for callbacks
        if self.is_64bit {
            data.extend_from_slice(&0u64.to_le_bytes());
        } else {
            data.extend_from_slice(&0u32.to_le_bytes());
        }

        Ok((data, dir_size as u32))
    }

    /// Build from an existing TlsInfo structure.
    ///
    /// This rebuilds the TLS directory from parsed info.
    pub fn build_from_info(&self, tls_info: &TlsInfo) -> (Vec<u8>, u32) {
        self.try_build_from_info(tls_info)
            .expect("TLS build failed: use try_build_from_info() for fallible serialization")
    }

    /// Rebuild parsed TLS information, rebasing its VA fields to this builder's
    /// image base while preserving zero-fill and characteristics.
    pub fn try_build_from_info(&self, tls_info: &TlsInfo) -> Result<(Vec<u8>, u32)> {
        if matches!(tls_info.directory, Some(TlsDirectory::Tls64(_))) != self.is_64bit
            && tls_info.directory.is_some()
        {
            return Err(Error::invalid_data_directory(
                "TLS directory bitness does not match the target image",
            ));
        }
        let (raw_start, raw_end) = match &tls_info.directory {
            Some(TlsDirectory::Tls32(dir)) => {
                let start = va_to_rva(
                    u64::from(dir.start_address_of_raw_data),
                    tls_info.image_base,
                )?;
                let end = va_to_rva(u64::from(dir.end_address_of_raw_data), tls_info.image_base)?;
                (start, end)
            }
            Some(TlsDirectory::Tls64(dir)) => {
                let start = va_to_rva(dir.start_address_of_raw_data, tls_info.image_base)?;
                let end = va_to_rva(dir.end_address_of_raw_data, tls_info.image_base)?;
                (start, end)
            }
            None => (0, 0),
        };

        let (mut data, size) = self.try_build(raw_start, raw_end, &tls_info.callback_rvas)?;
        match &tls_info.directory {
            Some(TlsDirectory::Tls32(directory)) => {
                data[16..20].copy_from_slice(&directory.size_of_zero_fill.to_le_bytes());
                data[20..24].copy_from_slice(&directory.characteristics.to_le_bytes());
            }
            Some(TlsDirectory::Tls64(directory)) => {
                data[32..36].copy_from_slice(&directory.size_of_zero_fill.to_le_bytes());
                data[36..40].copy_from_slice(&directory.characteristics.to_le_bytes());
            }
            None => {}
        }
        Ok((data, size))
    }

    /// Calculate the size needed for TLS data.
    pub fn calculate_size(&self, num_callbacks: usize) -> usize {
        self.try_calculate_size(num_callbacks)
            .expect("TLS data size overflow: use try_calculate_size()")
    }

    /// Calculate the serialized size using checked pointer-array arithmetic.
    pub fn try_calculate_size(&self, num_callbacks: usize) -> Result<usize> {
        let ptr_size = if self.is_64bit { 8 } else { 4 };
        let dir_size = if self.is_64bit {
            TlsDirectory64::SIZE
        } else {
            TlsDirectory32::SIZE
        };
        let callbacks_offset = dir_size
            .checked_add(4)
            .and_then(|size| size.checked_add(ptr_size - 1))
            .map(|size| size & !(ptr_size - 1))
            .ok_or_else(|| Error::invalid_data_directory("TLS callback alignment overflow"))?;
        let callback_bytes = num_callbacks
            .checked_add(1)
            .and_then(|count| count.checked_mul(ptr_size))
            .ok_or_else(|| Error::invalid_data_directory("TLS callback-array size overflow"))?;
        let size = callbacks_offset
            .checked_add(callback_bytes)
            .ok_or_else(|| Error::invalid_data_directory("TLS data size overflow"))?;
        u32::try_from(size).map_err(|_| Error::invalid_data_directory("TLS data exceeds u32"))?;
        Ok(size)
    }
}

fn checked_va(image_base: u64, rva: u64, context: &str) -> Result<u64> {
    image_base
        .checked_add(rva)
        .ok_or_else(|| Error::invalid_data_directory(format!("{context} VA overflow")))
}

fn va_to_rva(va: u64, image_base: u64) -> Result<u32> {
    if va == 0 {
        return Ok(0);
    }
    va.checked_sub(image_base)
        .and_then(|rva| u32::try_from(rva).ok())
        .ok_or_else(|| {
            Error::invalid_data_directory(format!(
                "TLS VA {:#x} is outside image base {:#x}",
                va, image_base
            ))
        })
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
