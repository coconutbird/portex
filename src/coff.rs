//! COFF File Header structures and parsing.

use crate::reader::Reader;
use crate::{Error, Result};

/// PE signature "PE\0\0".
pub const PE_SIGNATURE: u32 = 0x00004550;

/// Machine type constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
#[non_exhaustive]
pub enum MachineType {
    /// Unknown machine type.
    Unknown = 0x0000,
    /// Intel 386 or later.
    I386 = 0x014C,
    /// x64 (AMD64).
    Amd64 = 0x8664,
    /// ARM little endian.
    Arm = 0x01C0,
    /// ARM64 little endian.
    Arm64 = 0xAA64,
    /// ARM Thumb-2 little endian.
    ArmNt = 0x01C4,
    /// EFI byte code.
    Ebc = 0x0EBC,
    /// Intel Itanium.
    Ia64 = 0x0200,
    /// RISC-V 32-bit.
    RiscV32 = 0x5032,
    /// RISC-V 64-bit.
    RiscV64 = 0x5064,
}

impl MachineType {
    /// Convert from raw u16 value.
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0000 => Some(Self::Unknown),
            0x014C => Some(Self::I386),
            0x8664 => Some(Self::Amd64),
            0x01C0 => Some(Self::Arm),
            0xAA64 => Some(Self::Arm64),
            0x01C4 => Some(Self::ArmNt),
            0x0EBC => Some(Self::Ebc),
            0x0200 => Some(Self::Ia64),
            0x5032 => Some(Self::RiscV32),
            0x5064 => Some(Self::RiscV64),
            _ => None,
        }
    }
}

/// Characteristics flags for the COFF header.
pub mod characteristics {
    /// Relocation info stripped from file.
    pub const RELOCS_STRIPPED: u16 = 0x0001;
    /// File is executable.
    pub const EXECUTABLE_IMAGE: u16 = 0x0002;
    /// Line numbers stripped from file.
    pub const LINE_NUMS_STRIPPED: u16 = 0x0004;
    /// Local symbols stripped from file.
    pub const LOCAL_SYMS_STRIPPED: u16 = 0x0008;
    /// Aggressively trim working set.
    pub const AGGRESSIVE_WS_TRIM: u16 = 0x0010;
    /// App can handle >2GB addresses.
    pub const LARGE_ADDRESS_AWARE: u16 = 0x0020;
    /// Bytes of machine word are reversed (obsolete).
    pub const BYTES_REVERSED_LO: u16 = 0x0080;
    /// 32-bit word machine.
    pub const MACHINE_32BIT: u16 = 0x0100;
    /// Debugging info stripped from file.
    pub const DEBUG_STRIPPED: u16 = 0x0200;
    /// Copy to swap file if on removable media.
    pub const REMOVABLE_RUN_FROM_SWAP: u16 = 0x0400;
    /// Copy to swap file if on network media.
    pub const NET_RUN_FROM_SWAP: u16 = 0x0800;
    /// File is a system file.
    pub const SYSTEM: u16 = 0x1000;
    /// File is a DLL.
    pub const DLL: u16 = 0x2000;
    /// File should only be run on a uniprocessor machine.
    pub const UP_SYSTEM_ONLY: u16 = 0x4000;
    /// Bytes of machine word are reversed (obsolete).
    pub const BYTES_REVERSED_HI: u16 = 0x8000;
}

/// COFF File Header (IMAGE_FILE_HEADER).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct CoffHeader {
    /// Target machine type.
    pub machine: u16,
    /// Number of sections.
    pub number_of_sections: u16,
    /// Timestamp (seconds since epoch).
    pub time_date_stamp: u32,
    /// File offset of COFF symbol table.
    pub pointer_to_symbol_table: u32,
    /// Number of entries in symbol table.
    pub number_of_symbols: u32,
    /// Size of optional header.
    pub size_of_optional_header: u16,
    /// Characteristics flags.
    pub characteristics: u16,
}

impl CoffHeader {
    /// Size of the COFF header in bytes.
    pub const SIZE: usize = 20;

    /// Parse a COFF header from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(Error::buffer_too_small(Self::SIZE, data.len()));
        }

        Ok(Self {
            machine: u16::from_le_bytes([data[0], data[1]]),
            number_of_sections: u16::from_le_bytes([data[2], data[3]]),
            time_date_stamp: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            pointer_to_symbol_table: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            number_of_symbols: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
            size_of_optional_header: u16::from_le_bytes([data[16], data[17]]),
            characteristics: u16::from_le_bytes([data[18], data[19]]),
        })
    }

    /// Write the COFF header to a byte buffer.
    pub fn write(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() < Self::SIZE {
            return Err(Error::buffer_too_small(Self::SIZE, buf.len()));
        }

        buf[0..2].copy_from_slice(&self.machine.to_le_bytes());
        buf[2..4].copy_from_slice(&self.number_of_sections.to_le_bytes());
        buf[4..8].copy_from_slice(&self.time_date_stamp.to_le_bytes());
        buf[8..12].copy_from_slice(&self.pointer_to_symbol_table.to_le_bytes());
        buf[12..16].copy_from_slice(&self.number_of_symbols.to_le_bytes());
        buf[16..18].copy_from_slice(&self.size_of_optional_header.to_le_bytes());
        buf[18..20].copy_from_slice(&self.characteristics.to_le_bytes());

        Ok(())
    }

    /// Get the machine type as an enum.
    pub fn machine_type(&self) -> Option<MachineType> {
        MachineType::from_u16(self.machine)
    }

    /// Check if the file is a DLL.
    pub fn is_dll(&self) -> bool {
        self.characteristics & characteristics::DLL != 0
    }

    /// Check if the file is executable.
    pub fn is_executable(&self) -> bool {
        self.characteristics & characteristics::EXECUTABLE_IMAGE != 0
    }

    /// Parse a COFF header from a Reader at the given offset.
    pub fn read_from<R: Reader>(reader: &R, offset: u64) -> Result<Self> {
        let mut buf = [0u8; Self::SIZE];
        reader.read_exact_at(offset, &mut buf)?;
        Self::parse(&buf)
    }

    /// Serialize to a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0u8; Self::SIZE];
        self.write(&mut buf).expect("buffer size is correct");
        buf
    }
}

/// Verify PE signature at the given offset.
pub fn verify_pe_signature<R: Reader>(reader: &R, offset: u64) -> Result<()> {
    let sig = reader.read_u32_at(offset)?;
    if sig != PE_SIGNATURE {
        return Err(Error::invalid_pe_signature());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coff_header_size() {
        assert_eq!(CoffHeader::SIZE, 20);
    }

    #[test]
    fn test_machine_type_from_u16() {
        assert_eq!(MachineType::from_u16(0x8664), Some(MachineType::Amd64));
        assert_eq!(MachineType::from_u16(0x014C), Some(MachineType::I386));
        assert_eq!(MachineType::from_u16(0xFFFF), None);
    }

    #[test]
    fn test_coff_header_roundtrip() {
        let header = CoffHeader {
            machine: MachineType::Amd64 as u16,
            number_of_sections: 5,
            time_date_stamp: 0x12345678,
            pointer_to_symbol_table: 0,
            number_of_symbols: 0,
            size_of_optional_header: 240,
            characteristics: characteristics::EXECUTABLE_IMAGE
                | characteristics::LARGE_ADDRESS_AWARE,
        };

        let mut buf = [0u8; 20];
        header.write(&mut buf).unwrap();

        let parsed = CoffHeader::parse(&buf).unwrap();
        assert_eq!(header, parsed);
        assert!(parsed.is_executable());
        assert!(!parsed.is_dll());
    }
}
