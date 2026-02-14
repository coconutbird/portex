//! CLR (Common Language Runtime) header parsing.
//!
//! This module provides minimal CLR header parsing for .NET assemblies.
//! The CLI header (IMAGE_COR20_HEADER) is located via DataDirectory index 14 (ClrRuntime).
//!
//! For full metadata parsing (BSJB, streams, tables), see the `clrmeta` crate.
//!
//! # Examples
//!
//! ```no_run
//! use portex::PE;
//!
//! let pe = PE::from_file("managed.exe")?;
//!
//! if let Some(cli) = pe.cli_header()? {
//!     println!("CLR runtime: {}.{}", cli.major_runtime_version, cli.minor_runtime_version);
//!     println!("Metadata RVA: {:#x}, size: {}", cli.metadata_rva, cli.metadata_size);
//!     println!("Entry point token: {:#x}", cli.entry_point_token_or_rva);
//!     if cli.is_il_only() {
//!         println!("IL-only assembly");
//!     }
//! }
//! # Ok::<(), portex::Error>(())
//! ```

use crate::{Error, Result};

/// CLI header (IMAGE_COR20_HEADER).
///
/// This 72-byte structure is the entry point for .NET metadata.
/// Located via `DataDirectoryType::ClrRuntime` (index 14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct CliHeader {
    /// Size of the header (always 72).
    pub cb: u32,
    /// Major runtime version required.
    pub major_runtime_version: u16,
    /// Minor runtime version required.
    pub minor_runtime_version: u16,
    /// RVA of metadata (BSJB).
    pub metadata_rva: u32,
    /// Size of metadata.
    pub metadata_size: u32,
    /// Flags (COMIMAGE_FLAGS_*).
    pub flags: u32,
    /// Entry point token (MethodDef/File) or native entry point RVA.
    pub entry_point_token_or_rva: u32,
    /// RVA of resources.
    pub resources_rva: u32,
    /// Size of resources.
    pub resources_size: u32,
    /// RVA of strong name signature.
    pub strong_name_signature_rva: u32,
    /// Size of strong name signature.
    pub strong_name_signature_size: u32,
    /// RVA of code manager table (reserved).
    pub code_manager_table_rva: u32,
    /// Size of code manager table.
    pub code_manager_table_size: u32,
    /// RVA of VTable fixups.
    pub vtable_fixups_rva: u32,
    /// Size of VTable fixups.
    pub vtable_fixups_size: u32,
    /// RVA of export address table jumps.
    pub export_address_table_jumps_rva: u32,
    /// Size of export address table jumps.
    pub export_address_table_jumps_size: u32,
    /// RVA of managed native header (reserved).
    pub managed_native_header_rva: u32,
    /// Size of managed native header.
    pub managed_native_header_size: u32,
}

impl CliHeader {
    /// Size of the CLI header in bytes.
    pub const SIZE: usize = 72;

    /// COMIMAGE_FLAGS_ILONLY - Contains only IL code.
    pub const FLAG_ILONLY: u32 = 0x0000_0001;
    /// COMIMAGE_FLAGS_32BITREQUIRED - Requires 32-bit platform.
    pub const FLAG_32BITREQUIRED: u32 = 0x0000_0002;
    /// COMIMAGE_FLAGS_IL_LIBRARY - IL library (not executable).
    pub const FLAG_IL_LIBRARY: u32 = 0x0000_0004;
    /// COMIMAGE_FLAGS_STRONGNAMESIGNED - Strong-name signed.
    pub const FLAG_STRONGNAMESIGNED: u32 = 0x0000_0008;
    /// COMIMAGE_FLAGS_NATIVE_ENTRYPOINT - Entry point is native RVA (not token).
    pub const FLAG_NATIVE_ENTRYPOINT: u32 = 0x0000_0010;
    /// COMIMAGE_FLAGS_TRACKDEBUGDATA - Track debug data.
    pub const FLAG_TRACKDEBUGDATA: u32 = 0x0001_0000;
    /// COMIMAGE_FLAGS_32BITPREFERRED - Prefers 32-bit platform.
    pub const FLAG_32BITPREFERRED: u32 = 0x0002_0000;

    /// Parse CLI header from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(Error::buffer_too_small(Self::SIZE, data.len()));
        }

        let read_u32 = |offset: usize| -> u32 {
            u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ])
        };
        let read_u16 =
            |offset: usize| -> u16 { u16::from_le_bytes([data[offset], data[offset + 1]]) };

        Ok(Self {
            cb: read_u32(0),
            major_runtime_version: read_u16(4),
            minor_runtime_version: read_u16(6),
            metadata_rva: read_u32(8),
            metadata_size: read_u32(12),
            flags: read_u32(16),
            entry_point_token_or_rva: read_u32(20),
            resources_rva: read_u32(24),
            resources_size: read_u32(28),
            strong_name_signature_rva: read_u32(32),
            strong_name_signature_size: read_u32(36),
            code_manager_table_rva: read_u32(40),
            code_manager_table_size: read_u32(44),
            vtable_fixups_rva: read_u32(48),
            vtable_fixups_size: read_u32(52),
            export_address_table_jumps_rva: read_u32(56),
            export_address_table_jumps_size: read_u32(60),
            managed_native_header_rva: read_u32(64),
            managed_native_header_size: read_u32(68),
        })
    }

    /// Check if the assembly contains only IL code.
    pub fn is_il_only(&self) -> bool {
        self.flags & Self::FLAG_ILONLY != 0
    }

    /// Check if the assembly requires 32-bit platform.
    pub fn is_32bit_required(&self) -> bool {
        self.flags & Self::FLAG_32BITREQUIRED != 0
    }

    /// Check if the assembly prefers 32-bit platform.
    pub fn is_32bit_preferred(&self) -> bool {
        self.flags & Self::FLAG_32BITPREFERRED != 0
    }

    /// Check if the assembly is strong-name signed.
    pub fn is_strong_name_signed(&self) -> bool {
        self.flags & Self::FLAG_STRONGNAMESIGNED != 0
    }

    /// Check if the entry point is a native RVA (vs metadata token).
    pub fn has_native_entry_point(&self) -> bool {
        self.flags & Self::FLAG_NATIVE_ENTRYPOINT != 0
    }

    /// Serialize the CLI header to a 72-byte array.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut data = [0u8; Self::SIZE];

        data[0..4].copy_from_slice(&self.cb.to_le_bytes());
        data[4..6].copy_from_slice(&self.major_runtime_version.to_le_bytes());
        data[6..8].copy_from_slice(&self.minor_runtime_version.to_le_bytes());
        data[8..12].copy_from_slice(&self.metadata_rva.to_le_bytes());
        data[12..16].copy_from_slice(&self.metadata_size.to_le_bytes());
        data[16..20].copy_from_slice(&self.flags.to_le_bytes());
        data[20..24].copy_from_slice(&self.entry_point_token_or_rva.to_le_bytes());
        data[24..28].copy_from_slice(&self.resources_rva.to_le_bytes());
        data[28..32].copy_from_slice(&self.resources_size.to_le_bytes());
        data[32..36].copy_from_slice(&self.strong_name_signature_rva.to_le_bytes());
        data[36..40].copy_from_slice(&self.strong_name_signature_size.to_le_bytes());
        data[40..44].copy_from_slice(&self.code_manager_table_rva.to_le_bytes());
        data[44..48].copy_from_slice(&self.code_manager_table_size.to_le_bytes());
        data[48..52].copy_from_slice(&self.vtable_fixups_rva.to_le_bytes());
        data[52..56].copy_from_slice(&self.vtable_fixups_size.to_le_bytes());
        data[56..60].copy_from_slice(&self.export_address_table_jumps_rva.to_le_bytes());
        data[60..64].copy_from_slice(&self.export_address_table_jumps_size.to_le_bytes());
        data[64..68].copy_from_slice(&self.managed_native_header_rva.to_le_bytes());
        data[68..72].copy_from_slice(&self.managed_native_header_size.to_le_bytes());

        data
    }
}

impl Default for CliHeader {
    fn default() -> Self {
        Self {
            cb: Self::SIZE as u32,
            major_runtime_version: 2,
            minor_runtime_version: 5,
            metadata_rva: 0,
            metadata_size: 0,
            flags: 0,
            entry_point_token_or_rva: 0,
            resources_rva: 0,
            resources_size: 0,
            strong_name_signature_rva: 0,
            strong_name_signature_size: 0,
            code_manager_table_rva: 0,
            code_manager_table_size: 0,
            vtable_fixups_rva: 0,
            vtable_fixups_size: 0,
            export_address_table_jumps_rva: 0,
            export_address_table_jumps_size: 0,
            managed_native_header_rva: 0,
            managed_native_header_size: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_header_size() {
        assert_eq!(CliHeader::SIZE, 72);
    }

    #[test]
    fn test_cli_header_buffer_too_small() {
        let data = [0u8; 71];
        assert!(CliHeader::parse(&data).is_err());
    }

    #[test]
    fn test_cli_header_roundtrip() {
        let header = CliHeader {
            cb: 72,
            major_runtime_version: 2,
            minor_runtime_version: 5,
            metadata_rva: 0x2000,
            metadata_size: 0x1234,
            flags: CliHeader::FLAG_ILONLY | CliHeader::FLAG_STRONGNAMESIGNED,
            entry_point_token_or_rva: 0x0600_0001,
            resources_rva: 0x3000,
            resources_size: 0x100,
            strong_name_signature_rva: 0,
            strong_name_signature_size: 0,
            code_manager_table_rva: 0,
            code_manager_table_size: 0,
            vtable_fixups_rva: 0,
            vtable_fixups_size: 0,
            export_address_table_jumps_rva: 0,
            export_address_table_jumps_size: 0,
            managed_native_header_rva: 0,
            managed_native_header_size: 0,
        };

        let bytes = header.to_bytes();
        let parsed = CliHeader::parse(&bytes).unwrap();

        assert_eq!(header, parsed);
    }

    #[test]
    fn test_cli_header_default() {
        let header = CliHeader::default();
        assert_eq!(header.cb, 72);
        assert_eq!(header.major_runtime_version, 2);
        assert_eq!(header.minor_runtime_version, 5);
    }
}
