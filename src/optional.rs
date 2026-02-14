//! Optional Header structures and parsing.

use crate::data_dir::DataDirectory;
use crate::reader::Reader;
use crate::{Error, Result};

/// PE32 magic number.
pub const PE32_MAGIC: u16 = 0x10B;
/// PE32+ (64-bit) magic number.
pub const PE32PLUS_MAGIC: u16 = 0x20B;

/// Windows subsystem values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Subsystem {
    Unknown = 0,
    Native = 1,
    WindowsGui = 2,
    WindowsCui = 3,
    Os2Cui = 5,
    PosixCui = 7,
    NativeWindows = 8,
    WindowsCeGui = 9,
    EfiApplication = 10,
    EfiBootServiceDriver = 11,
    EfiRuntimeDriver = 12,
    EfiRom = 13,
    Xbox = 14,
    WindowsBootApplication = 16,
}

impl Subsystem {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(Self::Unknown),
            1 => Some(Self::Native),
            2 => Some(Self::WindowsGui),
            3 => Some(Self::WindowsCui),
            5 => Some(Self::Os2Cui),
            7 => Some(Self::PosixCui),
            8 => Some(Self::NativeWindows),
            9 => Some(Self::WindowsCeGui),
            10 => Some(Self::EfiApplication),
            11 => Some(Self::EfiBootServiceDriver),
            12 => Some(Self::EfiRuntimeDriver),
            13 => Some(Self::EfiRom),
            14 => Some(Self::Xbox),
            16 => Some(Self::WindowsBootApplication),
            _ => None,
        }
    }
}

/// DLL characteristics flags.
pub mod dll_characteristics {
    pub const HIGH_ENTROPY_VA: u16 = 0x0020;
    pub const DYNAMIC_BASE: u16 = 0x0040;
    pub const FORCE_INTEGRITY: u16 = 0x0080;
    pub const NX_COMPAT: u16 = 0x0100;
    pub const NO_ISOLATION: u16 = 0x0200;
    pub const NO_SEH: u16 = 0x0400;
    pub const NO_BIND: u16 = 0x0800;
    pub const APPCONTAINER: u16 = 0x1000;
    pub const WDM_DRIVER: u16 = 0x2000;
    pub const GUARD_CF: u16 = 0x4000;
    pub const TERMINAL_SERVER_AWARE: u16 = 0x8000;
}

/// PE32 Optional Header (32-bit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionalHeader32 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: u32,
    pub image_base: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directories: Vec<DataDirectory>,
}

/// PE32+ Optional Header (64-bit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionalHeader64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directories: Vec<DataDirectory>,
}

/// Combined optional header enum for PE32 and PE32+.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OptionalHeader {
    Pe32(OptionalHeader32),
    Pe32Plus(OptionalHeader64),
}

impl OptionalHeader32 {
    pub const BASE_SIZE: usize = 96;

    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::BASE_SIZE {
            return Err(Error::BufferTooSmall {
                expected: Self::BASE_SIZE,
                actual: data.len(),
            });
        }

        let number_of_rva_and_sizes = u32::from_le_bytes([data[92], data[93], data[94], data[95]]);
        let dirs_count = number_of_rva_and_sizes as usize;
        let total_size = Self::BASE_SIZE + dirs_count * DataDirectory::SIZE;

        if data.len() < total_size {
            return Err(Error::BufferTooSmall {
                expected: total_size,
                actual: data.len(),
            });
        }

        let mut data_directories = Vec::with_capacity(dirs_count);
        for i in 0..dirs_count {
            let offset = Self::BASE_SIZE + i * DataDirectory::SIZE;
            data_directories.push(DataDirectory::parse(&data[offset..])?);
        }

        Ok(Self {
            magic: u16::from_le_bytes([data[0], data[1]]),
            major_linker_version: data[2],
            minor_linker_version: data[3],
            size_of_code: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            size_of_initialized_data: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            size_of_uninitialized_data: u32::from_le_bytes([
                data[12], data[13], data[14], data[15],
            ]),
            address_of_entry_point: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
            base_of_code: u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
            base_of_data: u32::from_le_bytes([data[24], data[25], data[26], data[27]]),
            image_base: u32::from_le_bytes([data[28], data[29], data[30], data[31]]),
            section_alignment: u32::from_le_bytes([data[32], data[33], data[34], data[35]]),
            file_alignment: u32::from_le_bytes([data[36], data[37], data[38], data[39]]),
            major_operating_system_version: u16::from_le_bytes([data[40], data[41]]),
            minor_operating_system_version: u16::from_le_bytes([data[42], data[43]]),
            major_image_version: u16::from_le_bytes([data[44], data[45]]),
            minor_image_version: u16::from_le_bytes([data[46], data[47]]),
            major_subsystem_version: u16::from_le_bytes([data[48], data[49]]),
            minor_subsystem_version: u16::from_le_bytes([data[50], data[51]]),
            win32_version_value: u32::from_le_bytes([data[52], data[53], data[54], data[55]]),
            size_of_image: u32::from_le_bytes([data[56], data[57], data[58], data[59]]),
            size_of_headers: u32::from_le_bytes([data[60], data[61], data[62], data[63]]),
            check_sum: u32::from_le_bytes([data[64], data[65], data[66], data[67]]),
            subsystem: u16::from_le_bytes([data[68], data[69]]),
            dll_characteristics: u16::from_le_bytes([data[70], data[71]]),
            size_of_stack_reserve: u32::from_le_bytes([data[72], data[73], data[74], data[75]]),
            size_of_stack_commit: u32::from_le_bytes([data[76], data[77], data[78], data[79]]),
            size_of_heap_reserve: u32::from_le_bytes([data[80], data[81], data[82], data[83]]),
            size_of_heap_commit: u32::from_le_bytes([data[84], data[85], data[86], data[87]]),
            loader_flags: u32::from_le_bytes([data[88], data[89], data[90], data[91]]),
            number_of_rva_and_sizes,
            data_directories,
        })
    }

    pub fn size(&self) -> usize {
        Self::BASE_SIZE + self.data_directories.len() * DataDirectory::SIZE
    }

    /// Write the PE32 optional header to a buffer.
    pub fn write(&self, buf: &mut [u8]) -> Result<()> {
        let total_size = self.size();
        if buf.len() < total_size {
            return Err(Error::BufferTooSmall {
                expected: total_size,
                actual: buf.len(),
            });
        }

        buf[0..2].copy_from_slice(&self.magic.to_le_bytes());
        buf[2] = self.major_linker_version;
        buf[3] = self.minor_linker_version;
        buf[4..8].copy_from_slice(&self.size_of_code.to_le_bytes());
        buf[8..12].copy_from_slice(&self.size_of_initialized_data.to_le_bytes());
        buf[12..16].copy_from_slice(&self.size_of_uninitialized_data.to_le_bytes());
        buf[16..20].copy_from_slice(&self.address_of_entry_point.to_le_bytes());
        buf[20..24].copy_from_slice(&self.base_of_code.to_le_bytes());
        buf[24..28].copy_from_slice(&self.base_of_data.to_le_bytes());
        buf[28..32].copy_from_slice(&self.image_base.to_le_bytes());
        buf[32..36].copy_from_slice(&self.section_alignment.to_le_bytes());
        buf[36..40].copy_from_slice(&self.file_alignment.to_le_bytes());
        buf[40..42].copy_from_slice(&self.major_operating_system_version.to_le_bytes());
        buf[42..44].copy_from_slice(&self.minor_operating_system_version.to_le_bytes());
        buf[44..46].copy_from_slice(&self.major_image_version.to_le_bytes());
        buf[46..48].copy_from_slice(&self.minor_image_version.to_le_bytes());
        buf[48..50].copy_from_slice(&self.major_subsystem_version.to_le_bytes());
        buf[50..52].copy_from_slice(&self.minor_subsystem_version.to_le_bytes());
        buf[52..56].copy_from_slice(&self.win32_version_value.to_le_bytes());
        buf[56..60].copy_from_slice(&self.size_of_image.to_le_bytes());
        buf[60..64].copy_from_slice(&self.size_of_headers.to_le_bytes());
        buf[64..68].copy_from_slice(&self.check_sum.to_le_bytes());
        buf[68..70].copy_from_slice(&self.subsystem.to_le_bytes());
        buf[70..72].copy_from_slice(&self.dll_characteristics.to_le_bytes());
        buf[72..76].copy_from_slice(&self.size_of_stack_reserve.to_le_bytes());
        buf[76..80].copy_from_slice(&self.size_of_stack_commit.to_le_bytes());
        buf[80..84].copy_from_slice(&self.size_of_heap_reserve.to_le_bytes());
        buf[84..88].copy_from_slice(&self.size_of_heap_commit.to_le_bytes());
        buf[88..92].copy_from_slice(&self.loader_flags.to_le_bytes());
        buf[92..96].copy_from_slice(&self.number_of_rva_and_sizes.to_le_bytes());

        // Write data directories
        let mut offset = Self::BASE_SIZE;
        for dir in &self.data_directories {
            dir.write(&mut buf[offset..offset + DataDirectory::SIZE])?;
            offset += DataDirectory::SIZE;
        }

        Ok(())
    }

    /// Serialize to a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0u8; self.size()];
        self.write(&mut buf).expect("buffer size is correct");
        buf
    }
}

impl OptionalHeader64 {
    pub const BASE_SIZE: usize = 112;

    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::BASE_SIZE {
            return Err(Error::BufferTooSmall {
                expected: Self::BASE_SIZE,
                actual: data.len(),
            });
        }

        let number_of_rva_and_sizes =
            u32::from_le_bytes([data[108], data[109], data[110], data[111]]);
        let dirs_count = number_of_rva_and_sizes as usize;
        let total_size = Self::BASE_SIZE + dirs_count * DataDirectory::SIZE;

        if data.len() < total_size {
            return Err(Error::BufferTooSmall {
                expected: total_size,
                actual: data.len(),
            });
        }

        let mut data_directories = Vec::with_capacity(dirs_count);
        for i in 0..dirs_count {
            let offset = Self::BASE_SIZE + i * DataDirectory::SIZE;
            data_directories.push(DataDirectory::parse(&data[offset..])?);
        }

        Ok(Self {
            magic: u16::from_le_bytes([data[0], data[1]]),
            major_linker_version: data[2],
            minor_linker_version: data[3],
            size_of_code: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            size_of_initialized_data: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            size_of_uninitialized_data: u32::from_le_bytes([
                data[12], data[13], data[14], data[15],
            ]),
            address_of_entry_point: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
            base_of_code: u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
            image_base: u64::from_le_bytes([
                data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
            ]),
            section_alignment: u32::from_le_bytes([data[32], data[33], data[34], data[35]]),
            file_alignment: u32::from_le_bytes([data[36], data[37], data[38], data[39]]),
            major_operating_system_version: u16::from_le_bytes([data[40], data[41]]),
            minor_operating_system_version: u16::from_le_bytes([data[42], data[43]]),
            major_image_version: u16::from_le_bytes([data[44], data[45]]),
            minor_image_version: u16::from_le_bytes([data[46], data[47]]),
            major_subsystem_version: u16::from_le_bytes([data[48], data[49]]),
            minor_subsystem_version: u16::from_le_bytes([data[50], data[51]]),
            win32_version_value: u32::from_le_bytes([data[52], data[53], data[54], data[55]]),
            size_of_image: u32::from_le_bytes([data[56], data[57], data[58], data[59]]),
            size_of_headers: u32::from_le_bytes([data[60], data[61], data[62], data[63]]),
            check_sum: u32::from_le_bytes([data[64], data[65], data[66], data[67]]),
            subsystem: u16::from_le_bytes([data[68], data[69]]),
            dll_characteristics: u16::from_le_bytes([data[70], data[71]]),
            size_of_stack_reserve: u64::from_le_bytes([
                data[72], data[73], data[74], data[75], data[76], data[77], data[78], data[79],
            ]),
            size_of_stack_commit: u64::from_le_bytes([
                data[80], data[81], data[82], data[83], data[84], data[85], data[86], data[87],
            ]),
            size_of_heap_reserve: u64::from_le_bytes([
                data[88], data[89], data[90], data[91], data[92], data[93], data[94], data[95],
            ]),
            size_of_heap_commit: u64::from_le_bytes([
                data[96], data[97], data[98], data[99], data[100], data[101], data[102], data[103],
            ]),
            loader_flags: u32::from_le_bytes([data[104], data[105], data[106], data[107]]),
            number_of_rva_and_sizes,
            data_directories,
        })
    }

    pub fn size(&self) -> usize {
        Self::BASE_SIZE + self.data_directories.len() * DataDirectory::SIZE
    }

    /// Write the PE32+ optional header to a buffer.
    pub fn write(&self, buf: &mut [u8]) -> Result<()> {
        let total_size = self.size();
        if buf.len() < total_size {
            return Err(Error::BufferTooSmall {
                expected: total_size,
                actual: buf.len(),
            });
        }

        buf[0..2].copy_from_slice(&self.magic.to_le_bytes());
        buf[2] = self.major_linker_version;
        buf[3] = self.minor_linker_version;
        buf[4..8].copy_from_slice(&self.size_of_code.to_le_bytes());
        buf[8..12].copy_from_slice(&self.size_of_initialized_data.to_le_bytes());
        buf[12..16].copy_from_slice(&self.size_of_uninitialized_data.to_le_bytes());
        buf[16..20].copy_from_slice(&self.address_of_entry_point.to_le_bytes());
        buf[20..24].copy_from_slice(&self.base_of_code.to_le_bytes());
        buf[24..32].copy_from_slice(&self.image_base.to_le_bytes());
        buf[32..36].copy_from_slice(&self.section_alignment.to_le_bytes());
        buf[36..40].copy_from_slice(&self.file_alignment.to_le_bytes());
        buf[40..42].copy_from_slice(&self.major_operating_system_version.to_le_bytes());
        buf[42..44].copy_from_slice(&self.minor_operating_system_version.to_le_bytes());
        buf[44..46].copy_from_slice(&self.major_image_version.to_le_bytes());
        buf[46..48].copy_from_slice(&self.minor_image_version.to_le_bytes());
        buf[48..50].copy_from_slice(&self.major_subsystem_version.to_le_bytes());
        buf[50..52].copy_from_slice(&self.minor_subsystem_version.to_le_bytes());
        buf[52..56].copy_from_slice(&self.win32_version_value.to_le_bytes());
        buf[56..60].copy_from_slice(&self.size_of_image.to_le_bytes());
        buf[60..64].copy_from_slice(&self.size_of_headers.to_le_bytes());
        buf[64..68].copy_from_slice(&self.check_sum.to_le_bytes());
        buf[68..70].copy_from_slice(&self.subsystem.to_le_bytes());
        buf[70..72].copy_from_slice(&self.dll_characteristics.to_le_bytes());
        buf[72..80].copy_from_slice(&self.size_of_stack_reserve.to_le_bytes());
        buf[80..88].copy_from_slice(&self.size_of_stack_commit.to_le_bytes());
        buf[88..96].copy_from_slice(&self.size_of_heap_reserve.to_le_bytes());
        buf[96..104].copy_from_slice(&self.size_of_heap_commit.to_le_bytes());
        buf[104..108].copy_from_slice(&self.loader_flags.to_le_bytes());
        buf[108..112].copy_from_slice(&self.number_of_rva_and_sizes.to_le_bytes());

        // Write data directories
        let mut offset = Self::BASE_SIZE;
        for dir in &self.data_directories {
            dir.write(&mut buf[offset..offset + DataDirectory::SIZE])?;
            offset += DataDirectory::SIZE;
        }

        Ok(())
    }

    /// Serialize to a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0u8; self.size()];
        self.write(&mut buf).expect("buffer size is correct");
        buf
    }
}

impl OptionalHeader {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 2 {
            return Err(Error::BufferTooSmall {
                expected: 2,
                actual: data.len(),
            });
        }

        let magic = u16::from_le_bytes([data[0], data[1]]);
        match magic {
            PE32_MAGIC => Ok(Self::Pe32(OptionalHeader32::parse(data)?)),
            PE32PLUS_MAGIC => Ok(Self::Pe32Plus(OptionalHeader64::parse(data)?)),
            _ => Err(Error::InvalidOptionalHeaderMagic(magic)),
        }
    }

    pub fn is_pe32(&self) -> bool {
        matches!(self, Self::Pe32(_))
    }

    pub fn is_pe32plus(&self) -> bool {
        matches!(self, Self::Pe32Plus(_))
    }

    pub fn size(&self) -> usize {
        match self {
            Self::Pe32(h) => h.size(),
            Self::Pe32Plus(h) => h.size(),
        }
    }

    pub fn data_directories(&self) -> &[DataDirectory] {
        match self {
            Self::Pe32(h) => &h.data_directories,
            Self::Pe32Plus(h) => &h.data_directories,
        }
    }

    /// Get mutable reference to data directories.
    pub fn data_directories_mut(&mut self) -> &mut Vec<DataDirectory> {
        match self {
            Self::Pe32(h) => &mut h.data_directories,
            Self::Pe32Plus(h) => &mut h.data_directories,
        }
    }

    /// Write the optional header to a buffer.
    pub fn write(&self, buf: &mut [u8]) -> Result<()> {
        match self {
            Self::Pe32(h) => h.write(buf),
            Self::Pe32Plus(h) => h.write(buf),
        }
    }

    /// Serialize to a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Pe32(h) => h.to_bytes(),
            Self::Pe32Plus(h) => h.to_bytes(),
        }
    }

    /// Parse an optional header from a Reader at the given offset.
    pub fn read_from<R: Reader>(reader: &R, offset: u64) -> Result<Self> {
        // First read the magic to determine type
        let magic = reader.read_u16_at(offset)?;

        // Determine size needed
        let base_size = match magic {
            PE32_MAGIC => OptionalHeader32::BASE_SIZE,
            PE32PLUS_MAGIC => OptionalHeader64::BASE_SIZE,
            _ => return Err(Error::InvalidOptionalHeaderMagic(magic)),
        };

        // Read the base header to get number of data directories
        let num_dirs_offset = match magic {
            PE32_MAGIC => offset + 92, // Offset of number_of_rva_and_sizes in PE32
            PE32PLUS_MAGIC => offset + 108, // Offset in PE32+
            _ => unreachable!(),
        };
        let num_dirs = reader.read_u32_at(num_dirs_offset)? as usize;

        let total_size = base_size + num_dirs * DataDirectory::SIZE;
        let data = reader.read_bytes_at(offset, total_size)?;
        Self::parse(&data)
    }

    /// Get the entry point RVA.
    pub fn address_of_entry_point(&self) -> u32 {
        match self {
            Self::Pe32(h) => h.address_of_entry_point,
            Self::Pe32Plus(h) => h.address_of_entry_point,
        }
    }

    /// Get the image base address.
    pub fn image_base(&self) -> u64 {
        match self {
            Self::Pe32(h) => h.image_base as u64,
            Self::Pe32Plus(h) => h.image_base,
        }
    }

    /// Get section alignment.
    pub fn section_alignment(&self) -> u32 {
        match self {
            Self::Pe32(h) => h.section_alignment,
            Self::Pe32Plus(h) => h.section_alignment,
        }
    }

    /// Get file alignment.
    pub fn file_alignment(&self) -> u32 {
        match self {
            Self::Pe32(h) => h.file_alignment,
            Self::Pe32Plus(h) => h.file_alignment,
        }
    }

    /// Get size of image.
    pub fn size_of_image(&self) -> u32 {
        match self {
            Self::Pe32(h) => h.size_of_image,
            Self::Pe32Plus(h) => h.size_of_image,
        }
    }

    /// Get size of headers.
    pub fn size_of_headers(&self) -> u32 {
        match self {
            Self::Pe32(h) => h.size_of_headers,
            Self::Pe32Plus(h) => h.size_of_headers,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_optional_header_sizes() {
        assert_eq!(OptionalHeader32::BASE_SIZE, 96);
        assert_eq!(OptionalHeader64::BASE_SIZE, 112);
    }

    #[test]
    fn test_subsystem_from_u16() {
        assert_eq!(Subsystem::from_u16(2), Some(Subsystem::WindowsGui));
        assert_eq!(Subsystem::from_u16(3), Some(Subsystem::WindowsCui));
        assert_eq!(Subsystem::from_u16(255), None);
    }
}
