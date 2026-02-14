//! Resource directory parsing and building.
//!
//! The resource directory contains embedded resources like icons, version info,
//! manifests, dialogs, and other application data.

use crate::{Error, Result};

/// Standard resource types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ResourceType {
    Cursor = 1,
    Bitmap = 2,
    Icon = 3,
    Menu = 4,
    Dialog = 5,
    String = 6,
    FontDir = 7,
    Font = 8,
    Accelerator = 9,
    RcData = 10,
    MessageTable = 11,
    GroupCursor = 12,
    GroupIcon = 14,
    Version = 16,
    DlgInclude = 17,
    PlugPlay = 19,
    Vxd = 20,
    AniCursor = 21,
    AniIcon = 22,
    Html = 23,
    Manifest = 24,
}

impl ResourceType {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::Cursor),
            2 => Some(Self::Bitmap),
            3 => Some(Self::Icon),
            4 => Some(Self::Menu),
            5 => Some(Self::Dialog),
            6 => Some(Self::String),
            7 => Some(Self::FontDir),
            8 => Some(Self::Font),
            9 => Some(Self::Accelerator),
            10 => Some(Self::RcData),
            11 => Some(Self::MessageTable),
            12 => Some(Self::GroupCursor),
            14 => Some(Self::GroupIcon),
            16 => Some(Self::Version),
            17 => Some(Self::DlgInclude),
            19 => Some(Self::PlugPlay),
            20 => Some(Self::Vxd),
            21 => Some(Self::AniCursor),
            22 => Some(Self::AniIcon),
            23 => Some(Self::Html),
            24 => Some(Self::Manifest),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Cursor => "CURSOR",
            Self::Bitmap => "BITMAP",
            Self::Icon => "ICON",
            Self::Menu => "MENU",
            Self::Dialog => "DIALOG",
            Self::String => "STRING",
            Self::FontDir => "FONTDIR",
            Self::Font => "FONT",
            Self::Accelerator => "ACCELERATOR",
            Self::RcData => "RCDATA",
            Self::MessageTable => "MESSAGETABLE",
            Self::GroupCursor => "GROUP_CURSOR",
            Self::GroupIcon => "GROUP_ICON",
            Self::Version => "VERSION",
            Self::DlgInclude => "DLGINCLUDE",
            Self::PlugPlay => "PLUGPLAY",
            Self::Vxd => "VXD",
            Self::AniCursor => "ANICURSOR",
            Self::AniIcon => "ANIICON",
            Self::Html => "HTML",
            Self::Manifest => "MANIFEST",
        }
    }
}

/// Resource name/ID - can be numeric or string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceId {
    /// Numeric ID.
    Id(u16),
    /// String name.
    Name(String),
}

impl ResourceId {
    /// Check if this is a standard resource type ID.
    pub fn as_resource_type(&self) -> Option<ResourceType> {
        match self {
            Self::Id(id) => ResourceType::from_u16(*id),
            Self::Name(_) => None,
        }
    }
}

/// IMAGE_RESOURCE_DIRECTORY - 16 bytes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResourceDirectoryHeader {
    /// Resource flags (reserved, usually 0).
    pub characteristics: u32,
    /// Time/date stamp.
    pub time_date_stamp: u32,
    /// Major version.
    pub major_version: u16,
    /// Minor version.
    pub minor_version: u16,
    /// Number of named entries.
    pub number_of_named_entries: u16,
    /// Number of ID entries.
    pub number_of_id_entries: u16,
}

impl ResourceDirectoryHeader {
    pub const SIZE: usize = 16;

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
            number_of_named_entries: u16::from_le_bytes([data[12], data[13]]),
            number_of_id_entries: u16::from_le_bytes([data[14], data[15]]),
        })
    }

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..4].copy_from_slice(&self.characteristics.to_le_bytes());
        buf[4..8].copy_from_slice(&self.time_date_stamp.to_le_bytes());
        buf[8..10].copy_from_slice(&self.major_version.to_le_bytes());
        buf[10..12].copy_from_slice(&self.minor_version.to_le_bytes());
        buf[12..14].copy_from_slice(&self.number_of_named_entries.to_le_bytes());
        buf[14..16].copy_from_slice(&self.number_of_id_entries.to_le_bytes());
        buf
    }

    pub fn total_entries(&self) -> usize {
        self.number_of_named_entries as usize + self.number_of_id_entries as usize
    }
}

/// IMAGE_RESOURCE_DIRECTORY_ENTRY - 8 bytes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResourceDirectoryEntry {
    /// Name offset (high bit set) or ID.
    pub name_or_id: u32,
    /// Offset to data or subdirectory (high bit set = subdirectory).
    pub offset_to_data: u32,
}

impl ResourceDirectoryEntry {
    pub const SIZE: usize = 8;

    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(Error::BufferTooSmall {
                expected: Self::SIZE,
                actual: data.len(),
            });
        }

        Ok(Self {
            name_or_id: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            offset_to_data: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
        })
    }

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..4].copy_from_slice(&self.name_or_id.to_le_bytes());
        buf[4..8].copy_from_slice(&self.offset_to_data.to_le_bytes());
        buf
    }

    /// Check if this entry has a string name (vs numeric ID).
    pub fn is_named(&self) -> bool {
        (self.name_or_id & 0x80000000) != 0
    }

    /// Get the name offset (only valid if is_named() is true).
    pub fn name_offset(&self) -> u32 {
        self.name_or_id & 0x7FFFFFFF
    }

    /// Get the ID (only valid if is_named() is false).
    pub fn id(&self) -> u16 {
        self.name_or_id as u16
    }

    /// Check if this points to a subdirectory (vs data entry).
    pub fn is_directory(&self) -> bool {
        (self.offset_to_data & 0x80000000) != 0
    }

    /// Get the offset to subdirectory or data entry.
    pub fn data_offset(&self) -> u32 {
        self.offset_to_data & 0x7FFFFFFF
    }
}

/// IMAGE_RESOURCE_DATA_ENTRY - 16 bytes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResourceDataEntry {
    /// RVA of the resource data.
    pub offset_to_data: u32,
    /// Size of the resource data.
    pub size: u32,
    /// Code page.
    pub code_page: u32,
    /// Reserved.
    pub reserved: u32,
}

impl ResourceDataEntry {
    pub const SIZE: usize = 16;

    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(Error::BufferTooSmall {
                expected: Self::SIZE,
                actual: data.len(),
            });
        }

        Ok(Self {
            offset_to_data: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            size: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            code_page: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            reserved: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
        })
    }

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..4].copy_from_slice(&self.offset_to_data.to_le_bytes());
        buf[4..8].copy_from_slice(&self.size.to_le_bytes());
        buf[8..12].copy_from_slice(&self.code_page.to_le_bytes());
        buf[12..16].copy_from_slice(&self.reserved.to_le_bytes());
        buf
    }
}

/// A parsed resource entry with data.
#[derive(Debug, Clone)]
pub struct Resource {
    /// Resource type (level 1).
    pub resource_type: ResourceId,
    /// Resource name/ID (level 2).
    pub name: ResourceId,
    /// Language ID (level 3).
    pub language: u16,
    /// RVA of the resource data.
    pub data_rva: u32,
    /// Size of the resource data.
    pub size: u32,
    /// Code page.
    pub code_page: u32,
}

impl Resource {
    /// Check if this is a specific resource type.
    pub fn is_type(&self, rt: ResourceType) -> bool {
        matches!(&self.resource_type, ResourceId::Id(id) if *id == rt as u16)
    }

    /// Get as standard resource type.
    pub fn get_type(&self) -> Option<ResourceType> {
        self.resource_type.as_resource_type()
    }
}

/// Parsed resource directory.
#[derive(Debug, Clone, Default)]
pub struct ResourceDirectory {
    /// All resources in the directory.
    pub resources: Vec<Resource>,
}

impl ResourceDirectory {
    /// Parse resource directory from PE data.
    pub fn parse<F>(rsrc_rva: u32, _rsrc_size: u32, read_at_rva: F) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        let mut resources = Vec::new();

        // Read the root directory
        let root_data = read_at_rva(rsrc_rva, ResourceDirectoryHeader::SIZE)
            .ok_or(Error::InvalidRva(rsrc_rva))?;
        let root_header = ResourceDirectoryHeader::parse(&root_data)?;

        // Parse type entries (level 1)
        for i in 0..root_header.total_entries() {
            let entry_offset = rsrc_rva + ResourceDirectoryHeader::SIZE as u32 +
                (i * ResourceDirectoryEntry::SIZE) as u32;
            let entry_data = read_at_rva(entry_offset, ResourceDirectoryEntry::SIZE)
                .ok_or(Error::InvalidRva(entry_offset))?;
            let type_entry = ResourceDirectoryEntry::parse(&entry_data)?;

            let type_id = Self::parse_resource_id(&type_entry, rsrc_rva, &read_at_rva)?;

            if !type_entry.is_directory() {
                continue;
            }

            // Parse name entries (level 2)
            let name_dir_offset = rsrc_rva + type_entry.data_offset();
            let name_dir_data = read_at_rva(name_dir_offset, ResourceDirectoryHeader::SIZE)
                .ok_or(Error::InvalidRva(name_dir_offset))?;
            let name_header = ResourceDirectoryHeader::parse(&name_dir_data)?;

            for j in 0..name_header.total_entries() {
                let name_entry_offset = name_dir_offset + ResourceDirectoryHeader::SIZE as u32 +
                    (j * ResourceDirectoryEntry::SIZE) as u32;
                let name_entry_data = read_at_rva(name_entry_offset, ResourceDirectoryEntry::SIZE)
                    .ok_or(Error::InvalidRva(name_entry_offset))?;
                let name_entry = ResourceDirectoryEntry::parse(&name_entry_data)?;

                let name_id = Self::parse_resource_id(&name_entry, rsrc_rva, &read_at_rva)?;

                if !name_entry.is_directory() {
                    continue;
                }

                // Parse language entries (level 3)
                let lang_dir_offset = rsrc_rva + name_entry.data_offset();
                let lang_dir_data = read_at_rva(lang_dir_offset, ResourceDirectoryHeader::SIZE)
                    .ok_or(Error::InvalidRva(lang_dir_offset))?;
                let lang_header = ResourceDirectoryHeader::parse(&lang_dir_data)?;

                for k in 0..lang_header.total_entries() {
                    let lang_entry_offset = lang_dir_offset + ResourceDirectoryHeader::SIZE as u32 +
                        (k * ResourceDirectoryEntry::SIZE) as u32;
                    let lang_entry_data = read_at_rva(lang_entry_offset, ResourceDirectoryEntry::SIZE)
                        .ok_or(Error::InvalidRva(lang_entry_offset))?;
                    let lang_entry = ResourceDirectoryEntry::parse(&lang_entry_data)?;

                    let language = lang_entry.id();

                    if lang_entry.is_directory() {
                        continue; // Should be a data entry at this level
                    }

                    // Parse data entry
                    let data_entry_offset = rsrc_rva + lang_entry.data_offset();
                    let data_entry_data = read_at_rva(data_entry_offset, ResourceDataEntry::SIZE)
                        .ok_or(Error::InvalidRva(data_entry_offset))?;
                    let data_entry = ResourceDataEntry::parse(&data_entry_data)?;

                    resources.push(Resource {
                        resource_type: type_id.clone(),
                        name: name_id.clone(),
                        language,
                        data_rva: data_entry.offset_to_data,
                        size: data_entry.size,
                        code_page: data_entry.code_page,
                    });
                }
            }
        }

        Ok(Self { resources })
    }

    fn parse_resource_id<F>(entry: &ResourceDirectoryEntry, rsrc_rva: u32, read_at_rva: &F) -> Result<ResourceId>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        if entry.is_named() {
            let name_offset = rsrc_rva + entry.name_offset();
            // Resource names are length-prefixed Unicode strings
            let len_data = read_at_rva(name_offset, 2).ok_or(Error::InvalidRva(name_offset))?;
            let len = u16::from_le_bytes([len_data[0], len_data[1]]) as usize;
            let name_data = read_at_rva(name_offset + 2, len * 2).ok_or(Error::InvalidRva(name_offset + 2))?;

            // Convert UTF-16LE to String
            let mut chars = Vec::with_capacity(len);
            for i in 0..len {
                let ch = u16::from_le_bytes([name_data[i * 2], name_data[i * 2 + 1]]);
                chars.push(ch);
            }
            let name = String::from_utf16_lossy(&chars);
            Ok(ResourceId::Name(name))
        } else {
            Ok(ResourceId::Id(entry.id()))
        }
    }

    /// Find resources by type.
    pub fn find_by_type(&self, rt: ResourceType) -> Vec<&Resource> {
        self.resources.iter().filter(|r| r.is_type(rt)).collect()
    }

    /// Get the manifest resource (if any).
    pub fn manifest(&self) -> Option<&Resource> {
        self.find_by_type(ResourceType::Manifest).first().copied()
    }

    /// Get version info resource (if any).
    pub fn version_info(&self) -> Option<&Resource> {
        self.find_by_type(ResourceType::Version).first().copied()
    }

    /// Get all icon resources.
    pub fn icons(&self) -> Vec<&Resource> {
        self.find_by_type(ResourceType::Icon)
    }

    /// Get icon group resources.
    pub fn icon_groups(&self) -> Vec<&Resource> {
        self.find_by_type(ResourceType::GroupIcon)
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.resources.is_empty()
    }

    /// Get the number of resources.
    pub fn len(&self) -> usize {
        self.resources.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_directory_header_size() {
        assert_eq!(ResourceDirectoryHeader::SIZE, 16);
    }

    #[test]
    fn test_resource_directory_entry_size() {
        assert_eq!(ResourceDirectoryEntry::SIZE, 8);
    }

    #[test]
    fn test_resource_data_entry_size() {
        assert_eq!(ResourceDataEntry::SIZE, 16);
    }

    #[test]
    fn test_resource_directory_header_roundtrip() {
        let original = ResourceDirectoryHeader {
            characteristics: 0,
            time_date_stamp: 0x12345678,
            major_version: 1,
            minor_version: 0,
            number_of_named_entries: 2,
            number_of_id_entries: 5,
        };

        let bytes = original.to_bytes();
        let parsed = ResourceDirectoryHeader::parse(&bytes).unwrap();
        assert_eq!(original, parsed);
        assert_eq!(parsed.total_entries(), 7);
    }

    #[test]
    fn test_resource_entry_flags() {
        // Test directory entry with name
        let entry = ResourceDirectoryEntry {
            name_or_id: 0x80001000, // High bit set = named
            offset_to_data: 0x80002000, // High bit set = directory
        };
        assert!(entry.is_named());
        assert!(entry.is_directory());
        assert_eq!(entry.name_offset(), 0x1000);
        assert_eq!(entry.data_offset(), 0x2000);

        // Test ID entry pointing to data
        let entry2 = ResourceDirectoryEntry {
            name_or_id: 16, // RT_VERSION
            offset_to_data: 0x3000,
        };
        assert!(!entry2.is_named());
        assert!(!entry2.is_directory());
        assert_eq!(entry2.id(), 16);
    }

    #[test]
    fn test_resource_type_names() {
        assert_eq!(ResourceType::Manifest.name(), "MANIFEST");
        assert_eq!(ResourceType::Version.name(), "VERSION");
        assert_eq!(ResourceType::Icon.name(), "ICON");
    }
}

