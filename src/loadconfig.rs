//! Load Configuration Directory parsing and building.
//!
//! The Load Configuration Directory contains security features like
//! SafeSEH, CFG (Control Flow Guard), and other runtime configuration.

use crate::{Error, Result};

/// IMAGE_LOAD_CONFIG_DIRECTORY32 (Windows 10+) - 192 bytes
/// Note: Size varies by Windows version; we parse what's available.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LoadConfigDirectory32 {
    /// Size of this structure.
    pub size: u32,
    /// Time/date stamp.
    pub time_date_stamp: u32,
    /// Major version.
    pub major_version: u16,
    /// Minor version.
    pub minor_version: u16,
    /// Global flags to clear.
    pub global_flags_clear: u32,
    /// Global flags to set.
    pub global_flags_set: u32,
    /// Default timeout for critical sections.
    pub critical_section_default_timeout: u32,
    /// Size of minimum memory to de-commit.
    pub de_commit_free_block_threshold: u32,
    /// Size of minimum total memory to de-commit.
    pub de_commit_total_free_threshold: u32,
    /// VA of lock prefix table (x86 only).
    pub lock_prefix_table: u32,
    /// Maximum allocation size.
    pub maximum_allocation_size: u32,
    /// Maximum virtual memory size.
    pub virtual_memory_threshold: u32,
    /// Process affinity mask.
    pub process_affinity_mask: u32,
    /// Process heap flags.
    pub process_heap_flags: u32,
    /// Service pack version.
    pub csd_version: u16,
    /// Dependent load flags.
    pub dependent_load_flags: u16,
    /// VA of edit list (reserved).
    pub edit_list: u32,
    /// VA of security cookie.
    pub security_cookie: u32,
    /// VA of SEH handler table.
    pub se_handler_table: u32,
    /// Number of SEH handlers.
    pub se_handler_count: u32,
    /// VA of CFG check function pointer.
    pub guard_cf_check_function_pointer: u32,
    /// VA of CFG dispatch function pointer.
    pub guard_cf_dispatch_function_pointer: u32,
    /// VA of CFG function table.
    pub guard_cf_function_table: u32,
    /// Number of entries in CFG function table.
    pub guard_cf_function_count: u32,
    /// CFG flags.
    pub guard_flags: u32,
}

impl LoadConfigDirectory32 {
    /// Minimum size for basic parsing.
    pub const MIN_SIZE: usize = 64;
    /// Size with CFG fields.
    pub const SIZE_WITH_CFG: usize = 104;

    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::MIN_SIZE {
            return Err(Error::BufferTooSmall {
                expected: Self::MIN_SIZE,
                actual: data.len(),
            });
        }

        let size = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let mut config = Self {
            size,
            time_date_stamp: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            major_version: u16::from_le_bytes([data[8], data[9]]),
            minor_version: u16::from_le_bytes([data[10], data[11]]),
            global_flags_clear: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
            global_flags_set: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
            critical_section_default_timeout: u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
            de_commit_free_block_threshold: u32::from_le_bytes([data[24], data[25], data[26], data[27]]),
            de_commit_total_free_threshold: u32::from_le_bytes([data[28], data[29], data[30], data[31]]),
            lock_prefix_table: u32::from_le_bytes([data[32], data[33], data[34], data[35]]),
            maximum_allocation_size: u32::from_le_bytes([data[36], data[37], data[38], data[39]]),
            virtual_memory_threshold: u32::from_le_bytes([data[40], data[41], data[42], data[43]]),
            process_affinity_mask: u32::from_le_bytes([data[44], data[45], data[46], data[47]]),
            process_heap_flags: u32::from_le_bytes([data[48], data[49], data[50], data[51]]),
            csd_version: u16::from_le_bytes([data[52], data[53]]),
            dependent_load_flags: u16::from_le_bytes([data[54], data[55]]),
            edit_list: u32::from_le_bytes([data[56], data[57], data[58], data[59]]),
            security_cookie: u32::from_le_bytes([data[60], data[61], data[62], data[63]]),
            ..Default::default()
        };

        // Parse SEH fields if present (offset 64-71)
        if data.len() >= 72 {
            config.se_handler_table = u32::from_le_bytes([data[64], data[65], data[66], data[67]]);
            config.se_handler_count = u32::from_le_bytes([data[68], data[69], data[70], data[71]]);
        }

        // Parse CFG fields if present (offset 72-103)
        if data.len() >= Self::SIZE_WITH_CFG {
            config.guard_cf_check_function_pointer = u32::from_le_bytes([data[72], data[73], data[74], data[75]]);
            config.guard_cf_dispatch_function_pointer = u32::from_le_bytes([data[76], data[77], data[78], data[79]]);
            config.guard_cf_function_table = u32::from_le_bytes([data[80], data[81], data[82], data[83]]);
            config.guard_cf_function_count = u32::from_le_bytes([data[84], data[85], data[86], data[87]]);
            config.guard_flags = u32::from_le_bytes([data[88], data[89], data[90], data[91]]);
        }

        Ok(config)
    }

    /// Serialize to bytes (up to the size field value).
    pub fn to_bytes(&self) -> Vec<u8> {
        let output_size = (self.size as usize).max(Self::MIN_SIZE);
        let mut buf = vec![0u8; output_size];

        buf[0..4].copy_from_slice(&self.size.to_le_bytes());
        buf[4..8].copy_from_slice(&self.time_date_stamp.to_le_bytes());
        buf[8..10].copy_from_slice(&self.major_version.to_le_bytes());
        buf[10..12].copy_from_slice(&self.minor_version.to_le_bytes());
        buf[12..16].copy_from_slice(&self.global_flags_clear.to_le_bytes());
        buf[16..20].copy_from_slice(&self.global_flags_set.to_le_bytes());
        buf[20..24].copy_from_slice(&self.critical_section_default_timeout.to_le_bytes());
        buf[24..28].copy_from_slice(&self.de_commit_free_block_threshold.to_le_bytes());
        buf[28..32].copy_from_slice(&self.de_commit_total_free_threshold.to_le_bytes());
        buf[32..36].copy_from_slice(&self.lock_prefix_table.to_le_bytes());
        buf[36..40].copy_from_slice(&self.maximum_allocation_size.to_le_bytes());
        buf[40..44].copy_from_slice(&self.virtual_memory_threshold.to_le_bytes());
        buf[44..48].copy_from_slice(&self.process_affinity_mask.to_le_bytes());
        buf[48..52].copy_from_slice(&self.process_heap_flags.to_le_bytes());
        buf[52..54].copy_from_slice(&self.csd_version.to_le_bytes());
        buf[54..56].copy_from_slice(&self.dependent_load_flags.to_le_bytes());
        buf[56..60].copy_from_slice(&self.edit_list.to_le_bytes());
        buf[60..64].copy_from_slice(&self.security_cookie.to_le_bytes());

        if output_size >= 72 {
            buf[64..68].copy_from_slice(&self.se_handler_table.to_le_bytes());
            buf[68..72].copy_from_slice(&self.se_handler_count.to_le_bytes());
        }

        if output_size >= Self::SIZE_WITH_CFG {
            buf[72..76].copy_from_slice(&self.guard_cf_check_function_pointer.to_le_bytes());
            buf[76..80].copy_from_slice(&self.guard_cf_dispatch_function_pointer.to_le_bytes());
            buf[80..84].copy_from_slice(&self.guard_cf_function_table.to_le_bytes());
            buf[84..88].copy_from_slice(&self.guard_cf_function_count.to_le_bytes());
            buf[88..92].copy_from_slice(&self.guard_flags.to_le_bytes());
        }

        buf
    }

    /// Check if CFG is enabled.
    pub fn has_cfg(&self) -> bool {
        self.guard_cf_function_table != 0 || self.guard_flags != 0
    }

    /// Check if SafeSEH is present.
    pub fn has_safe_seh(&self) -> bool {
        self.se_handler_table != 0
    }
}

/// IMAGE_LOAD_CONFIG_DIRECTORY64 (Windows 10+)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LoadConfigDirectory64 {
    pub size: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub global_flags_clear: u32,
    pub global_flags_set: u32,
    pub critical_section_default_timeout: u32,
    pub de_commit_free_block_threshold: u64,
    pub de_commit_total_free_threshold: u64,
    pub lock_prefix_table: u64,
    pub maximum_allocation_size: u64,
    pub virtual_memory_threshold: u64,
    pub process_affinity_mask: u64,
    pub process_heap_flags: u32,
    pub csd_version: u16,
    pub dependent_load_flags: u16,
    pub edit_list: u64,
    pub security_cookie: u64,
    pub se_handler_table: u64,
    pub se_handler_count: u64,
    pub guard_cf_check_function_pointer: u64,
    pub guard_cf_dispatch_function_pointer: u64,
    pub guard_cf_function_table: u64,
    pub guard_cf_function_count: u64,
    pub guard_flags: u32,
}

impl LoadConfigDirectory64 {
    pub const MIN_SIZE: usize = 112;
    pub const SIZE_WITH_CFG: usize = 148;

    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::MIN_SIZE {
            return Err(Error::BufferTooSmall {
                expected: Self::MIN_SIZE,
                actual: data.len(),
            });
        }

        let mut config = Self {
            size: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            time_date_stamp: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            major_version: u16::from_le_bytes([data[8], data[9]]),
            minor_version: u16::from_le_bytes([data[10], data[11]]),
            global_flags_clear: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
            global_flags_set: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
            critical_section_default_timeout: u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
            de_commit_free_block_threshold: u64::from_le_bytes([
                data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
            ]),
            de_commit_total_free_threshold: u64::from_le_bytes([
                data[32], data[33], data[34], data[35], data[36], data[37], data[38], data[39],
            ]),
            lock_prefix_table: u64::from_le_bytes([
                data[40], data[41], data[42], data[43], data[44], data[45], data[46], data[47],
            ]),
            maximum_allocation_size: u64::from_le_bytes([
                data[48], data[49], data[50], data[51], data[52], data[53], data[54], data[55],
            ]),
            virtual_memory_threshold: u64::from_le_bytes([
                data[56], data[57], data[58], data[59], data[60], data[61], data[62], data[63],
            ]),
            process_affinity_mask: u64::from_le_bytes([
                data[64], data[65], data[66], data[67], data[68], data[69], data[70], data[71],
            ]),
            process_heap_flags: u32::from_le_bytes([data[72], data[73], data[74], data[75]]),
            csd_version: u16::from_le_bytes([data[76], data[77]]),
            dependent_load_flags: u16::from_le_bytes([data[78], data[79]]),
            edit_list: u64::from_le_bytes([
                data[80], data[81], data[82], data[83], data[84], data[85], data[86], data[87],
            ]),
            security_cookie: u64::from_le_bytes([
                data[88], data[89], data[90], data[91], data[92], data[93], data[94], data[95],
            ]),
            se_handler_table: u64::from_le_bytes([
                data[96], data[97], data[98], data[99], data[100], data[101], data[102], data[103],
            ]),
            se_handler_count: u64::from_le_bytes([
                data[104], data[105], data[106], data[107], data[108], data[109], data[110], data[111],
            ]),
            ..Default::default()
        };

        // Parse CFG fields if present
        if data.len() >= Self::SIZE_WITH_CFG {
            config.guard_cf_check_function_pointer = u64::from_le_bytes([
                data[112], data[113], data[114], data[115], data[116], data[117], data[118], data[119],
            ]);
            config.guard_cf_dispatch_function_pointer = u64::from_le_bytes([
                data[120], data[121], data[122], data[123], data[124], data[125], data[126], data[127],
            ]);
            config.guard_cf_function_table = u64::from_le_bytes([
                data[128], data[129], data[130], data[131], data[132], data[133], data[134], data[135],
            ]);
            config.guard_cf_function_count = u64::from_le_bytes([
                data[136], data[137], data[138], data[139], data[140], data[141], data[142], data[143],
            ]);
            config.guard_flags = u32::from_le_bytes([data[144], data[145], data[146], data[147]]);
        }

        Ok(config)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let output_size = (self.size as usize).max(Self::MIN_SIZE);
        let mut buf = vec![0u8; output_size];

        buf[0..4].copy_from_slice(&self.size.to_le_bytes());
        buf[4..8].copy_from_slice(&self.time_date_stamp.to_le_bytes());
        buf[8..10].copy_from_slice(&self.major_version.to_le_bytes());
        buf[10..12].copy_from_slice(&self.minor_version.to_le_bytes());
        buf[12..16].copy_from_slice(&self.global_flags_clear.to_le_bytes());
        buf[16..20].copy_from_slice(&self.global_flags_set.to_le_bytes());
        buf[20..24].copy_from_slice(&self.critical_section_default_timeout.to_le_bytes());
        buf[24..32].copy_from_slice(&self.de_commit_free_block_threshold.to_le_bytes());
        buf[32..40].copy_from_slice(&self.de_commit_total_free_threshold.to_le_bytes());
        buf[40..48].copy_from_slice(&self.lock_prefix_table.to_le_bytes());
        buf[48..56].copy_from_slice(&self.maximum_allocation_size.to_le_bytes());
        buf[56..64].copy_from_slice(&self.virtual_memory_threshold.to_le_bytes());
        buf[64..72].copy_from_slice(&self.process_affinity_mask.to_le_bytes());
        buf[72..76].copy_from_slice(&self.process_heap_flags.to_le_bytes());
        buf[76..78].copy_from_slice(&self.csd_version.to_le_bytes());
        buf[78..80].copy_from_slice(&self.dependent_load_flags.to_le_bytes());
        buf[80..88].copy_from_slice(&self.edit_list.to_le_bytes());
        buf[88..96].copy_from_slice(&self.security_cookie.to_le_bytes());
        buf[96..104].copy_from_slice(&self.se_handler_table.to_le_bytes());
        buf[104..112].copy_from_slice(&self.se_handler_count.to_le_bytes());

        if output_size >= Self::SIZE_WITH_CFG {
            buf[112..120].copy_from_slice(&self.guard_cf_check_function_pointer.to_le_bytes());
            buf[120..128].copy_from_slice(&self.guard_cf_dispatch_function_pointer.to_le_bytes());
            buf[128..136].copy_from_slice(&self.guard_cf_function_table.to_le_bytes());
            buf[136..144].copy_from_slice(&self.guard_cf_function_count.to_le_bytes());
            buf[144..148].copy_from_slice(&self.guard_flags.to_le_bytes());
        }

        buf
    }

    pub fn has_cfg(&self) -> bool {
        self.guard_cf_function_table != 0 || self.guard_flags != 0
    }
}

/// Load Config Directory (either 32 or 64-bit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadConfigDirectory {
    Config32(LoadConfigDirectory32),
    Config64(LoadConfigDirectory64),
}

impl LoadConfigDirectory {
    pub fn parse(data: &[u8], is_64bit: bool) -> Result<Self> {
        if is_64bit {
            Ok(Self::Config64(LoadConfigDirectory64::parse(data)?))
        } else {
            Ok(Self::Config32(LoadConfigDirectory32::parse(data)?))
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Config32(c) => c.to_bytes(),
            Self::Config64(c) => c.to_bytes(),
        }
    }

    pub fn security_cookie_va(&self) -> u64 {
        match self {
            Self::Config32(c) => c.security_cookie as u64,
            Self::Config64(c) => c.security_cookie,
        }
    }

    pub fn has_cfg(&self) -> bool {
        match self {
            Self::Config32(c) => c.has_cfg(),
            Self::Config64(c) => c.has_cfg(),
        }
    }
}

/// CFG Guard flags.
pub mod guard_flags {
    pub const CF_INSTRUMENTED: u32 = 0x00000100;
    pub const CFW_INSTRUMENTED: u32 = 0x00000200;
    pub const CF_FUNCTION_TABLE_PRESENT: u32 = 0x00000400;
    pub const SECURITY_COOKIE_UNUSED: u32 = 0x00000800;
    pub const PROTECT_DELAYLOAD_IAT: u32 = 0x00001000;
    pub const DELAYLOAD_IAT_IN_ITS_OWN_SECTION: u32 = 0x00002000;
    pub const CF_EXPORT_SUPPRESSION_INFO_PRESENT: u32 = 0x00004000;
    pub const CF_ENABLE_EXPORT_SUPPRESSION: u32 = 0x00008000;
    pub const CF_LONGJUMP_TABLE_PRESENT: u32 = 0x00010000;
    pub const RF_INSTRUMENTED: u32 = 0x00020000;
    pub const RF_ENABLE: u32 = 0x00040000;
    pub const RF_STRICT: u32 = 0x00080000;
    pub const RETPOLINE_PRESENT: u32 = 0x00100000;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_config_32_min_size() {
        assert_eq!(LoadConfigDirectory32::MIN_SIZE, 64);
    }

    #[test]
    fn test_load_config_64_min_size() {
        assert_eq!(LoadConfigDirectory64::MIN_SIZE, 112);
    }

    #[test]
    fn test_load_config_32_roundtrip() {
        let original = LoadConfigDirectory32 {
            size: 104,
            time_date_stamp: 0x12345678,
            major_version: 1,
            minor_version: 0,
            security_cookie: 0x00401000,
            se_handler_table: 0x00402000,
            se_handler_count: 5,
            guard_cf_function_table: 0x00403000,
            guard_cf_function_count: 10,
            guard_flags: guard_flags::CF_INSTRUMENTED,
            ..Default::default()
        };

        let bytes = original.to_bytes();
        let parsed = LoadConfigDirectory32::parse(&bytes).unwrap();
        assert_eq!(original.size, parsed.size);
        assert_eq!(original.security_cookie, parsed.security_cookie);
        assert_eq!(original.guard_flags, parsed.guard_flags);
    }

    #[test]
    fn test_load_config_64_roundtrip() {
        let original = LoadConfigDirectory64 {
            size: 148,
            security_cookie: 0x0000000140001000,
            guard_cf_function_table: 0x0000000140002000,
            guard_cf_function_count: 20,
            guard_flags: guard_flags::CF_INSTRUMENTED | guard_flags::CF_FUNCTION_TABLE_PRESENT,
            ..Default::default()
        };

        let bytes = original.to_bytes();
        let parsed = LoadConfigDirectory64::parse(&bytes).unwrap();
        assert_eq!(original.size, parsed.size);
        assert_eq!(original.security_cookie, parsed.security_cookie);
        assert_eq!(original.guard_flags, parsed.guard_flags);
    }
}

