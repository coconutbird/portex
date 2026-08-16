//! Exception directory (.pdata) parsing and building.
//!
//! The exception directory contains runtime function entries used for
//! structured exception handling (SEH) and stack unwinding on x64.

use crate::coff::MachineType;
use crate::prelude::*;
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

/// ARM/ARM64 `.pdata` record (8 bytes).
///
/// The low two bits of `unwind_data` select packed versus unpacked unwind
/// information. Keeping the complete word makes this type usable for both ARM
/// encodings without losing architecture-specific packed fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PackedRuntimeFunction {
    /// RVA of the first instruction in the function or fragment.
    pub begin_address: u32,
    /// Architecture-specific packed unwind word or exception-data RVA + flags.
    pub unwind_data: u32,
}

impl PackedRuntimeFunction {
    pub const SIZE: usize = 8;

    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(Error::buffer_too_small(Self::SIZE, data.len()));
        }
        Ok(Self {
            begin_address: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            unwind_data: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
        })
    }

    pub fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut bytes = [0; Self::SIZE];
        bytes[..4].copy_from_slice(&self.begin_address.to_le_bytes());
        bytes[4..].copy_from_slice(&self.unwind_data.to_le_bytes());
        bytes
    }

    /// Low-bit discriminator defined by the ARM exception ABI.
    pub const fn flag(self) -> u8 {
        (self.unwind_data & 0b11) as u8
    }

    /// RVA of the external exception-data record when [`Self::flag`] is zero.
    pub const fn exception_data_rva(self) -> Option<u32> {
        if self.flag() == 0 {
            Some(self.unwind_data & !0b11)
        } else {
            None
        }
    }

    /// Whether the unwind description is encoded directly in this record.
    pub const fn is_packed(self) -> bool {
        self.flag() != 0
    }
}

impl RuntimeFunction {
    pub const SIZE: usize = 12;

    /// Parse from bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(Error::buffer_too_small(Self::SIZE, data.len()));
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
    /// Complete chained runtime-function entry (if `UNW_FLAG_CHAININFO`).
    pub chained_function: Option<RuntimeFunction>,
    /// Language-specific bytes following an exception-handler RVA.
    pub handler_data: Vec<u8>,
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
            return Err(Error::buffer_too_small(Self::MIN_SIZE, data.len()));
        }

        let version_flags = data[0];
        let size_of_prolog = data[1];
        let count_of_codes = data[2];
        let frame_reg_and_offset = data[3];

        Self::validate_header(version_flags)?;

        // Parse unwind codes (2 bytes each)
        let codes_size = count_of_codes as usize * 2;
        if data.len() < Self::MIN_SIZE + codes_size {
            return Err(Error::buffer_too_small(
                Self::MIN_SIZE + codes_size,
                data.len(),
            ));
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
        let mut chained_function = None;
        let mut handler_data = Vec::new();

        if (flags & UNW_FLAG_CHAININFO) != 0 {
            let end = aligned_offset
                .checked_add(RuntimeFunction::SIZE)
                .ok_or_else(|| Error::invalid_data_directory("chained unwind offset overflow"))?;
            if data.len() < end {
                return Err(Error::buffer_too_small(end, data.len()));
            }
            let function = RuntimeFunction::parse(&data[aligned_offset..end])?;
            chained_info = Some(function.begin_address);
            chained_function = Some(function);
        } else if (flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) != 0 {
            let end = aligned_offset
                .checked_add(4)
                .ok_or_else(|| Error::invalid_data_directory("unwind handler offset overflow"))?;
            if data.len() < end {
                return Err(Error::buffer_too_small(end, data.len()));
            }
            exception_handler = Some(u32::from_le_bytes([
                data[aligned_offset],
                data[aligned_offset + 1],
                data[aligned_offset + 2],
                data[aligned_offset + 3],
            ]));
            handler_data.extend_from_slice(&data[end..]);
        }

        let info = Self {
            version_flags,
            size_of_prolog,
            count_of_codes,
            frame_reg_and_offset,
            unwind_codes,
            exception_handler,
            chained_info,
            chained_function,
            handler_data,
        };
        info.validate()?;
        Ok(info)
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.try_to_bytes()
            .expect("unwind-info build failed: use try_to_bytes()")
    }

    /// Serialize a complete, internally consistent x64 unwind record.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let codes_size = self
            .unwind_codes
            .len()
            .checked_mul(2)
            .ok_or_else(|| Error::invalid_data_directory("unwind-code size overflow"))?;
        let aligned_codes_size = codes_size
            .checked_add(3)
            .map(|size| size & !3)
            .ok_or_else(|| Error::invalid_data_directory("unwind-code alignment overflow"))?;
        let chained_size = self
            .chained_function
            .map(|_| RuntimeFunction::SIZE)
            .unwrap_or(0);
        let handler_size = self
            .exception_handler
            .map(|_| {
                4usize
                    .checked_add(self.handler_data.len())
                    .ok_or_else(|| Error::invalid_data_directory("unwind handler size overflow"))
            })
            .transpose()?
            .unwrap_or(0);
        let total_size = Self::MIN_SIZE
            .checked_add(aligned_codes_size)
            .and_then(|size| size.checked_add(chained_size.max(handler_size)))
            .ok_or_else(|| Error::invalid_data_directory("unwind-info size overflow"))?;

        let mut buf = vec![0u8; total_size];
        buf[0] = self.version_flags;
        buf[1] = self.size_of_prolog;
        buf[2] = u8::try_from(self.unwind_codes.len())
            .map_err(|_| Error::invalid_data_directory("more than 255 unwind-code slots"))?;
        buf[3] = self.frame_reg_and_offset;

        for (i, code) in self.unwind_codes.iter().enumerate() {
            let offset = Self::MIN_SIZE + i * 2;
            buf[offset] = code.code_offset;
            buf[offset + 1] = code.op_and_info;
        }

        if let Some(chained) = self.chained_function {
            let offset = Self::MIN_SIZE + aligned_codes_size;
            buf[offset..offset + RuntimeFunction::SIZE].copy_from_slice(&chained.to_bytes());
        } else if let Some(handler) = self.exception_handler {
            let offset = Self::MIN_SIZE + aligned_codes_size;
            buf[offset..offset + 4].copy_from_slice(&handler.to_le_bytes());
            buf[offset + 4..].copy_from_slice(&self.handler_data);
        }

        Ok(buf)
    }

    /// Check the flag combination and associated trailing payload.
    pub fn validate(&self) -> Result<()> {
        Self::validate_header(self.version_flags)?;
        if self.unwind_codes.len() > u8::MAX as usize {
            return Err(Error::invalid_data_directory(
                "more than 255 unwind-code slots",
            ));
        }

        let chained = self.is_chained();
        let handled = self.has_exception_handler();
        if chained {
            if self.chained_function.is_none() {
                return Err(Error::invalid_data_directory(
                    "UNW_FLAG_CHAININFO requires a complete RUNTIME_FUNCTION record",
                ));
            }
            if self.exception_handler.is_some() || !self.handler_data.is_empty() {
                return Err(Error::invalid_data_directory(
                    "chained unwind info cannot contain exception-handler data",
                ));
            }
        } else if self.chained_function.is_some() || self.chained_info.is_some() {
            return Err(Error::invalid_data_directory(
                "chained runtime function present without UNW_FLAG_CHAININFO",
            ));
        }

        if handled {
            if self.exception_handler.is_none() {
                return Err(Error::invalid_data_directory(
                    "unwind handler flag requires an exception-handler RVA",
                ));
            }
        } else if self.exception_handler.is_some() || !self.handler_data.is_empty() {
            return Err(Error::invalid_data_directory(
                "exception-handler data present without a handler flag",
            ));
        }
        Ok(())
    }

    fn validate_header(version_flags: u8) -> Result<()> {
        let version = version_flags & 0x07;
        if !(1..=2).contains(&version) {
            return Err(Error::invalid_data_directory(format!(
                "unsupported x64 unwind version {version}"
            )));
        }
        let flags = version_flags >> 3;
        let supported = UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER | UNW_FLAG_CHAININFO;
        if flags & !supported != 0 {
            return Err(Error::invalid_data_directory(format!(
                "unsupported x64 unwind flags {flags:#x}"
            )));
        }
        if flags & UNW_FLAG_CHAININFO != 0 && flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0 {
            return Err(Error::invalid_data_directory(
                "UNW_FLAG_CHAININFO cannot be combined with handler flags",
            ));
        }
        Ok(())
    }
}

/// The complete exception directory (.pdata).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
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
        if !(pdata_size as usize).is_multiple_of(RuntimeFunction::SIZE) {
            return Err(Error::invalid_data_directory(format!(
                "x64 exception directory size {} is not a multiple of {}",
                pdata_size,
                RuntimeFunction::SIZE
            )));
        }
        let num_entries = pdata_size as usize / RuntimeFunction::SIZE;
        let mut functions = Vec::with_capacity(num_entries);

        for i in 0..num_entries {
            let offset = u32::try_from(i * RuntimeFunction::SIZE)
                .map_err(|_| Error::invalid_data_directory("exception table offset overflow"))?;
            let entry_rva = pdata_rva
                .checked_add(offset)
                .ok_or_else(|| Error::invalid_data_directory("exception table RVA overflow"))?;
            let data = read_at_rva(entry_rva, RuntimeFunction::SIZE)
                .ok_or(Error::invalid_rva(entry_rva))?;

            let func = RuntimeFunction::parse(&data)?;
            // Skip null entries
            if func.begin_address != 0 || func.end_address != 0 {
                functions.push(func);
            }
        }

        let directory = Self { functions };
        directory.validate()?;
        Ok(directory)
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.try_to_bytes()
            .expect("exception-directory build failed: use try_to_bytes()")
    }

    pub fn try_to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut buf = Vec::with_capacity(self.functions.len() * RuntimeFunction::SIZE);
        for func in &self.functions {
            buf.extend_from_slice(&func.to_bytes());
        }
        Ok(buf)
    }

    pub fn validate(&self) -> Result<()> {
        let byte_size = self
            .functions
            .len()
            .checked_mul(RuntimeFunction::SIZE)
            .ok_or_else(|| Error::invalid_data_directory("exception table size overflow"))?;
        u32::try_from(byte_size)
            .map_err(|_| Error::invalid_data_directory("exception table size exceeds u32"))?;

        let mut previous_end = 0u32;
        for (index, function) in self.functions.iter().enumerate() {
            if function.begin_address >= function.end_address {
                return Err(Error::invalid_data_directory(format!(
                    "exception function {index} has an empty or reversed range"
                )));
            }
            if index != 0 && function.begin_address < previous_end {
                return Err(Error::invalid_data_directory(format!(
                    "exception function {index} is unsorted or overlaps its predecessor"
                )));
            }
            previous_end = function.end_address;
        }
        Ok(())
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

/// ARM-family exception directory using fixed-width packed records.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PackedExceptionDirectory {
    pub functions: Vec<PackedRuntimeFunction>,
}

impl PackedExceptionDirectory {
    pub fn parse<F>(pdata_rva: u32, pdata_size: u32, read_at_rva: F) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        if !(pdata_size as usize).is_multiple_of(PackedRuntimeFunction::SIZE) {
            return Err(Error::invalid_data_directory(format!(
                "ARM exception directory size {} is not a multiple of {}",
                pdata_size,
                PackedRuntimeFunction::SIZE
            )));
        }
        let count = pdata_size as usize / PackedRuntimeFunction::SIZE;
        let mut functions = Vec::with_capacity(count);
        for index in 0..count {
            let relative = u32::try_from(index * PackedRuntimeFunction::SIZE)
                .map_err(|_| Error::invalid_data_directory("exception table offset overflow"))?;
            let rva = pdata_rva
                .checked_add(relative)
                .ok_or_else(|| Error::invalid_data_directory("exception table RVA overflow"))?;
            let bytes = read_at_rva(rva, PackedRuntimeFunction::SIZE)
                .ok_or_else(|| Error::invalid_rva(rva))?;
            let function = PackedRuntimeFunction::parse(&bytes)?;
            if function.begin_address != 0 || function.unwind_data != 0 {
                functions.push(function);
            }
        }
        Ok(Self { functions })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.try_to_bytes()
            .expect("packed exception-directory build failed: use try_to_bytes()")
    }

    pub fn try_to_bytes(&self) -> Result<Vec<u8>> {
        let byte_size = self
            .functions
            .len()
            .checked_mul(PackedRuntimeFunction::SIZE)
            .ok_or_else(|| Error::invalid_data_directory("exception table size overflow"))?;
        u32::try_from(byte_size)
            .map_err(|_| Error::invalid_data_directory("exception table size exceeds u32"))?;
        let mut bytes = Vec::with_capacity(self.functions.len() * PackedRuntimeFunction::SIZE);
        for function in &self.functions {
            bytes.extend_from_slice(&function.to_bytes());
        }
        Ok(bytes)
    }

    pub fn len(&self) -> usize {
        self.functions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }
}

/// Architecture-aware representation of the PE exception directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExceptionTable {
    /// AMD64 `RUNTIME_FUNCTION` records.
    X64(ExceptionDirectory),
    /// ARM/Thumb packed `.pdata` records.
    Arm(PackedExceptionDirectory),
    /// ARM64, ARM64EC, or ARM64X packed `.pdata` records.
    Arm64(PackedExceptionDirectory),
    /// Bytes for machines whose exception ABI is not modelled by this crate.
    Raw { machine: u16, data: Vec<u8> },
}

impl ExceptionTable {
    pub fn parse<F>(machine: u16, pdata_rva: u32, pdata_size: u32, read_at_rva: F) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        match MachineType::from_u16(machine) {
            Some(MachineType::Amd64) => {
                ExceptionDirectory::parse(pdata_rva, pdata_size, read_at_rva).map(Self::X64)
            }
            Some(MachineType::Arm | MachineType::ArmNt | MachineType::Thumb) => {
                let directory =
                    PackedExceptionDirectory::parse(pdata_rva, pdata_size, read_at_rva)?;
                if directory
                    .functions
                    .iter()
                    .any(|function| !function.begin_address.is_multiple_of(2))
                {
                    return Err(Error::invalid_data_directory(
                        "ARM runtime-function address is not instruction-aligned",
                    ));
                }
                Ok(Self::Arm(directory))
            }
            Some(MachineType::Arm64 | MachineType::Arm64Ec | MachineType::Arm64X) => {
                let directory =
                    PackedExceptionDirectory::parse(pdata_rva, pdata_size, read_at_rva)?;
                if directory.functions.iter().any(|function| {
                    !function.begin_address.is_multiple_of(4) || function.flag() == 3
                }) {
                    return Err(Error::invalid_data_directory(
                        "ARM64 runtime-function record is misaligned or uses reserved flag 3",
                    ));
                }
                Ok(Self::Arm64(directory))
            }
            _ => crate::parse_utils::read_exact_rva(
                &read_at_rva,
                pdata_rva,
                pdata_size as usize,
                "raw exception table",
            )
            .map(|data| Self::Raw { machine, data }),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.try_to_bytes()
            .expect("exception-table build failed: use try_to_bytes()")
    }

    pub fn try_to_bytes(&self) -> Result<Vec<u8>> {
        match self {
            Self::X64(directory) => directory.try_to_bytes(),
            Self::Arm(directory) | Self::Arm64(directory) => directory.try_to_bytes(),
            Self::Raw { data, .. } => {
                u32::try_from(data.len()).map_err(|_| {
                    Error::invalid_data_directory("exception table size exceeds u32")
                })?;
                Ok(data.clone())
            }
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::X64(directory) => directory.len(),
            Self::Arm(directory) | Self::Arm64(directory) => directory.len(),
            Self::Raw { data, .. } => data.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Self::X64(directory) => directory.is_empty(),
            Self::Arm(directory) | Self::Arm64(directory) => directory.is_empty(),
            Self::Raw { data, .. } => data.is_empty(),
        }
    }
}

/// Builder for exception directories (.pdata).
///
/// Exception directories contain runtime function entries for x64 SEH.
/// This builder helps create and manage these entries.
///
/// # Example
///
/// ```
/// use portex::exception::ExceptionBuilder;
///
/// let mut builder = ExceptionBuilder::new();
///
/// // Add functions with their unwind info RVAs
/// builder.add_function(0x1000, 0x1100, 0x3000);
/// builder.add_function(0x1200, 0x1400, 0x3100);
///
/// let (data, size) = builder.build();
/// assert_eq!(size, 24); // 2 functions * 12 bytes each
/// ```
#[derive(Debug, Clone, Default)]
pub struct ExceptionBuilder {
    /// The exception directory being built.
    directory: ExceptionDirectory,
}

impl ExceptionBuilder {
    /// Create a new exception builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create from an existing exception directory.
    pub fn from_directory(directory: ExceptionDirectory) -> Self {
        Self { directory }
    }

    /// Add a runtime function entry.
    ///
    /// # Arguments
    /// * `begin_rva` - RVA of the function start
    /// * `end_rva` - RVA of the function end
    /// * `unwind_info_rva` - RVA of the unwind information
    pub fn add_function(
        &mut self,
        begin_rva: u32,
        end_rva: u32,
        unwind_info_rva: u32,
    ) -> &mut Self {
        self.directory
            .add_function(begin_rva, end_rva, unwind_info_rva);
        self
    }

    /// Build the exception directory.
    ///
    /// Returns (data, size) where:
    /// - `data` is the raw bytes to write to the section
    /// - `size` is the total size of the exception directory
    pub fn build(&mut self) -> (Vec<u8>, u32) {
        self.try_build()
            .expect("exception-directory build failed: use try_build()")
    }

    pub fn try_build(&mut self) -> Result<(Vec<u8>, u32)> {
        // Sort by begin address (required for binary search)
        self.directory.sort();
        let data = self.directory.try_to_bytes()?;
        let size = u32::try_from(data.len())
            .map_err(|_| Error::invalid_data_directory("exception table size exceeds u32"))?;
        Ok((data, size))
    }

    /// Build from the existing directory without modification.
    pub fn build_from(directory: &ExceptionDirectory) -> (Vec<u8>, u32) {
        Self::try_build_from(directory)
            .expect("exception-directory build failed: use try_build_from()")
    }

    pub fn try_build_from(directory: &ExceptionDirectory) -> Result<(Vec<u8>, u32)> {
        let mut dir = directory.clone();
        dir.sort();
        let data = dir.try_to_bytes()?;
        let size = u32::try_from(data.len())
            .map_err(|_| Error::invalid_data_directory("exception table size exceeds u32"))?;
        Ok((data, size))
    }

    /// Get the number of functions.
    pub fn len(&self) -> usize {
        self.directory.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.directory.is_empty()
    }

    /// Calculate the size needed for the exception directory.
    pub fn calculate_size(num_functions: usize) -> usize {
        Self::try_calculate_size(num_functions)
            .expect("exception-directory size overflow: use try_calculate_size()")
    }

    pub fn try_calculate_size(num_functions: usize) -> Result<usize> {
        let size = num_functions
            .checked_mul(RuntimeFunction::SIZE)
            .ok_or_else(|| Error::invalid_data_directory("exception table size overflow"))?;
        u32::try_from(size)
            .map_err(|_| Error::invalid_data_directory("exception table size exceeds u32"))?;
        Ok(size)
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
