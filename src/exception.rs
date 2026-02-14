//! Exception directory (.pdata) parsing and building.
//!
//! The exception directory contains runtime function entries used for
//! structured exception handling (SEH) and stack unwinding on x64.

use crate::{Error, Result};

/// RUNTIME_FUNCTION entry for x64 (12 bytes).
/// Used in .pdata section for exception handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RuntimeFunction {
    /// RVA of the start of the function.
    pub begin_address: u32,
    /// RVA of the end of the function.
    pub end_address: u32,
    /// RVA of the unwind information.
    pub unwind_info_address: u32,
}

impl RuntimeFunction {
    pub const SIZE: usize = 12;

    /// Parse from bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(Error::BufferTooSmall {
                expected: Self::SIZE,
                actual: data.len(),
            });
        }

        Ok(Self {
            begin_address: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            end_address: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            unwind_info_address: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
        })
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..4].copy_from_slice(&self.begin_address.to_le_bytes());
        buf[4..8].copy_from_slice(&self.end_address.to_le_bytes());
        buf[8..12].copy_from_slice(&self.unwind_info_address.to_le_bytes());
        buf
    }

    /// Get the function size in bytes.
    pub fn size(&self) -> u32 {
        self.end_address.saturating_sub(self.begin_address)
    }

    /// Check if an RVA is within this function.
    pub fn contains_rva(&self, rva: u32) -> bool {
        rva >= self.begin_address && rva < self.end_address
    }
}

/// Unwind operation codes for x64.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UnwindOpCode {
    /// Push a nonvolatile integer register.
    PushNonVol = 0,
    /// Allocate a large-sized area on the stack.
    AllocLarge = 1,
    /// Allocate a small-sized area on the stack.
    AllocSmall = 2,
    /// Establish the frame pointer register.
    SetFpReg = 3,
    /// Save a nonvolatile integer register on the stack using MOV.
    SaveNonVol = 4,
    /// Save a nonvolatile integer register on the stack with a far offset.
    SaveNonVolFar = 5,
    /// Describes the function epilog.
    Epilog = 6,
    /// Reserved.
    SpareCode = 7,
    /// Save an XMM(128) register on the stack.
    SaveXmm128 = 8,
    /// Save an XMM(128) register on the stack with a far offset.
    SaveXmm128Far = 9,
    /// Push a machine frame.
    PushMachFrame = 10,
}

impl UnwindOpCode {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::PushNonVol),
            1 => Some(Self::AllocLarge),
            2 => Some(Self::AllocSmall),
            3 => Some(Self::SetFpReg),
            4 => Some(Self::SaveNonVol),
            5 => Some(Self::SaveNonVolFar),
            6 => Some(Self::Epilog),
            7 => Some(Self::SpareCode),
            8 => Some(Self::SaveXmm128),
            9 => Some(Self::SaveXmm128Far),
            10 => Some(Self::PushMachFrame),
            _ => None,
        }
    }
}

/// A single unwind code entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnwindCode {
    /// Offset in prolog where this operation occurs.
    pub code_offset: u8,
    /// Operation code (4 bits) and operation info (4 bits).
    pub op_and_info: u8,
}

impl UnwindCode {
    /// Get the operation code.
    pub fn op_code(&self) -> Option<UnwindOpCode> {
        UnwindOpCode::from_u8(self.op_and_info & 0x0F)
    }

    /// Get the operation info (interpretation depends on op_code).
    pub fn op_info(&self) -> u8 {
        self.op_and_info >> 4
    }
}

/// Unwind flags.
pub const UNW_FLAG_NHANDLER: u8 = 0;
pub const UNW_FLAG_EHANDLER: u8 = 1;
pub const UNW_FLAG_UHANDLER: u8 = 2;
pub const UNW_FLAG_CHAININFO: u8 = 4;

/// UNWIND_INFO header for x64.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UnwindInfo {
    /// Version (3 bits) and flags (5 bits).
    pub version_flags: u8,
    /// Size of the prolog in bytes.
    pub size_of_prolog: u8,
    /// Number of unwind codes.
    pub count_of_codes: u8,
    /// Frame register (4 bits) and frame register offset (4 bits).
    pub frame_reg_and_offset: u8,
    /// Array of unwind codes.
    pub unwind_codes: Vec<UnwindCode>,
    /// Exception handler RVA (if UNW_FLAG_EHANDLER or UNW_FLAG_UHANDLER).
    pub exception_handler: Option<u32>,
    /// Chained unwind info RVA (if UNW_FLAG_CHAININFO).
    pub chained_info: Option<u32>,
}

impl UnwindInfo {
    /// Minimum size: version_flags + size_of_prolog + count_of_codes + frame_reg_and_offset.
    pub const MIN_SIZE: usize = 4;

    /// Get the version (bits 0-2).
    pub fn version(&self) -> u8 {
        self.version_flags & 0x07
    }

    /// Get the flags (bits 3-7).
    pub fn flags(&self) -> u8 {
        self.version_flags >> 3
    }

    /// Check if this has an exception handler.
    pub fn has_exception_handler(&self) -> bool {
        let flags = self.flags();
        (flags & UNW_FLAG_EHANDLER) != 0 || (flags & UNW_FLAG_UHANDLER) != 0
    }

    /// Check if this is chained to another unwind info.
    pub fn is_chained(&self) -> bool {
        (self.flags() & UNW_FLAG_CHAININFO) != 0
    }

    /// Get the frame register (0 = no frame register).
    pub fn frame_register(&self) -> u8 {
        self.frame_reg_and_offset & 0x0F
    }

    /// Get the frame register offset (scaled by 16).
    pub fn frame_offset(&self) -> u8 {
        self.frame_reg_and_offset >> 4
    }

    /// Parse from bytes at an RVA.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::MIN_SIZE {
            return Err(Error::BufferTooSmall {
                expected: Self::MIN_SIZE,
                actual: data.len(),
            });
        }

        let version_flags = data[0];
        let size_of_prolog = data[1];
        let count_of_codes = data[2];
        let frame_reg_and_offset = data[3];

        // Parse unwind codes (2 bytes each)
        let codes_size = count_of_codes as usize * 2;
        if data.len() < Self::MIN_SIZE + codes_size {
            return Err(Error::BufferTooSmall {
                expected: Self::MIN_SIZE + codes_size,
                actual: data.len(),
            });
        }

        let mut unwind_codes = Vec::with_capacity(count_of_codes as usize);
        for i in 0..count_of_codes as usize {
            let offset = Self::MIN_SIZE + i * 2;
            unwind_codes.push(UnwindCode {
                code_offset: data[offset],
                op_and_info: data[offset + 1],
            });
        }

        // After unwind codes, there may be handler/chained info
        // Align to 4-byte boundary
        let aligned_offset = Self::MIN_SIZE + ((codes_size + 3) & !3);
        let flags = version_flags >> 3;

        let mut exception_handler = None;
        let mut chained_info = None;

        if data.len() >= aligned_offset + 4 {
            let extra = u32::from_le_bytes([
                data[aligned_offset],
                data[aligned_offset + 1],
                data[aligned_offset + 2],
                data[aligned_offset + 3],
            ]);

            if (flags & UNW_FLAG_CHAININFO) != 0 {
                chained_info = Some(extra);
            } else if (flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) != 0 {
                exception_handler = Some(extra);
            }
        }

        Ok(Self {
            version_flags,
            size_of_prolog,
            count_of_codes,
            frame_reg_and_offset,
            unwind_codes,
            exception_handler,
            chained_info,
        })
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let codes_size = self.unwind_codes.len() * 2;
        let aligned_codes_size = (codes_size + 3) & !3;
        let has_extra = self.exception_handler.is_some() || self.chained_info.is_some();
        let total_size = Self::MIN_SIZE + aligned_codes_size + if has_extra { 4 } else { 0 };

        let mut buf = vec![0u8; total_size];
        buf[0] = self.version_flags;
        buf[1] = self.size_of_prolog;
        buf[2] = self.count_of_codes;
        buf[3] = self.frame_reg_and_offset;

        for (i, code) in self.unwind_codes.iter().enumerate() {
            let offset = Self::MIN_SIZE + i * 2;
            buf[offset] = code.code_offset;
            buf[offset + 1] = code.op_and_info;
        }

        if let Some(handler) = self.exception_handler {
            let offset = Self::MIN_SIZE + aligned_codes_size;
            buf[offset..offset + 4].copy_from_slice(&handler.to_le_bytes());
        } else if let Some(chained) = self.chained_info {
            let offset = Self::MIN_SIZE + aligned_codes_size;
            buf[offset..offset + 4].copy_from_slice(&chained.to_le_bytes());
        }

        buf
    }
}

/// The complete exception directory (.pdata).
#[derive(Debug, Clone, Default)]
pub struct ExceptionDirectory {
    /// List of runtime function entries.
    pub functions: Vec<RuntimeFunction>,
}

impl ExceptionDirectory {
    /// Parse exception directory from a PE.
    pub fn parse<F>(pdata_rva: u32, pdata_size: u32, read_at_rva: F) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        let num_entries = pdata_size as usize / RuntimeFunction::SIZE;
        let mut functions = Vec::with_capacity(num_entries);

        for i in 0..num_entries {
            let offset = (i * RuntimeFunction::SIZE) as u32;
            let data = read_at_rva(pdata_rva + offset, RuntimeFunction::SIZE)
                .ok_or(Error::InvalidRva(pdata_rva + offset))?;

            let func = RuntimeFunction::parse(&data)?;
            // Skip null entries
            if func.begin_address != 0 || func.end_address != 0 {
                functions.push(func);
            }
        }

        Ok(Self { functions })
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.functions.len() * RuntimeFunction::SIZE);
        for func in &self.functions {
            buf.extend_from_slice(&func.to_bytes());
        }
        buf
    }

    /// Find the runtime function containing an RVA.
    pub fn find_function(&self, rva: u32) -> Option<&RuntimeFunction> {
        self.functions.iter().find(|f| f.contains_rva(rva))
    }

    /// Get the number of functions.
    pub fn len(&self) -> usize {
        self.functions.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }

    /// Add a runtime function entry.
    pub fn add_function(&mut self, begin: u32, end: u32, unwind_info: u32) {
        self.functions.push(RuntimeFunction {
            begin_address: begin,
            end_address: end,
            unwind_info_address: unwind_info,
        });
    }

    /// Sort functions by begin address.
    pub fn sort(&mut self) {
        self.functions.sort_by_key(|f| f.begin_address);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtime_function_size() {
        assert_eq!(RuntimeFunction::SIZE, 12);
    }

    #[test]
    fn test_runtime_function_roundtrip() {
        let original = RuntimeFunction {
            begin_address: 0x1000,
            end_address: 0x1100,
            unwind_info_address: 0x2000,
        };

        let bytes = original.to_bytes();
        let parsed = RuntimeFunction::parse(&bytes).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_runtime_function_contains_rva() {
        let func = RuntimeFunction {
            begin_address: 0x1000,
            end_address: 0x1100,
            unwind_info_address: 0x2000,
        };

        assert!(func.contains_rva(0x1000));
        assert!(func.contains_rva(0x1050));
        assert!(!func.contains_rva(0x1100)); // End is exclusive
        assert!(!func.contains_rva(0x0FFF));
    }

    #[test]
    fn test_exception_directory_roundtrip() {
        let mut dir = ExceptionDirectory::default();
        dir.add_function(0x1000, 0x1100, 0x2000);
        dir.add_function(0x1200, 0x1300, 0x2100);

        let bytes = dir.to_bytes();

        let read_fn = |rva: u32, len: usize| -> Option<Vec<u8>> {
            let offset = rva as usize;
            if offset >= bytes.len() {
                return None;
            }
            let available = (bytes.len() - offset).min(len);
            Some(bytes[offset..offset + available].to_vec())
        };

        let parsed = ExceptionDirectory::parse(0, bytes.len() as u32, read_fn).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed.functions[0].begin_address, 0x1000);
        assert_eq!(parsed.functions[1].begin_address, 0x1200);
    }
}
