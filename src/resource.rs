//! Resource directory parsing and building.
//!
//! The resource directory contains embedded resources like icons, version info,
//! manifests, dialogs, and other application data.
//!
//! # Examples
//!
//! ## Listing resources from a PE file
//!
//! ```no_run
//! use portex::PE;
//!
//! let pe = PE::from_file("example.exe")?;
//!
//! let resources = pe.resources()?;
//! for resource in &resources.resources {
//!     println!("Type: {:?}, Name: {:?}, Language: {}, Size: {}",
//!         resource.resource_type,
//!         resource.name,
//!         resource.language,
//!         resource.size);
//! }
//! # Ok::<(), portex::Error>(())
//! ```
//!
//! ## Adding resources to a PE file
//!
//! ```no_run
//! use portex::{PE, ResourceBuilder, ResourceType};
//!
//! let mut pe = PE::from_file("input.exe")?;
//!
//! // Build resources
//! let mut builder = ResourceBuilder::new();
//!
//! // Add a manifest (RT_MANIFEST = 24)
//! let manifest = b"<?xml version=\"1.0\"?>...";
//! builder.add_resource(ResourceType::Manifest, 1, 0x0409, manifest.to_vec());
//!
//! // Add an icon
//! let icon_data = std::fs::read("icon.ico")?;
//! builder.add_resource(ResourceType::Icon, 1, 0x0409, icon_data);
//!
//! // Update PE with new resources
//! pe.update_resources(&builder, None)?;
//! pe.write_to_file("output.exe")?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

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
            return Err(Error::buffer_too_small(Self::SIZE, data.len()));
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
            return Err(Error::buffer_too_small(Self::SIZE, data.len()));
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
            return Err(Error::buffer_too_small(Self::SIZE, data.len()));
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

/// A parsed resource entry with optional data.
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
    /// The actual resource data (only populated if parsed with `parse_with_data`).
    pub data: Option<Vec<u8>>,
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

    /// Check if the resource data is loaded.
    pub fn has_data(&self) -> bool {
        self.data.is_some()
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
            .ok_or(Error::invalid_rva(rsrc_rva))?;
        let root_header = ResourceDirectoryHeader::parse(&root_data)?;

        // Parse type entries (level 1)
        for i in 0..root_header.total_entries() {
            let entry_offset = rsrc_rva
                + ResourceDirectoryHeader::SIZE as u32
                + (i * ResourceDirectoryEntry::SIZE) as u32;
            let entry_data = read_at_rva(entry_offset, ResourceDirectoryEntry::SIZE)
                .ok_or(Error::invalid_rva(entry_offset))?;
            let type_entry = ResourceDirectoryEntry::parse(&entry_data)?;

            let type_id = Self::parse_resource_id(&type_entry, rsrc_rva, &read_at_rva)?;

            if !type_entry.is_directory() {
                continue;
            }

            // Parse name entries (level 2)
            let name_dir_offset = rsrc_rva + type_entry.data_offset();
            let name_dir_data = read_at_rva(name_dir_offset, ResourceDirectoryHeader::SIZE)
                .ok_or(Error::invalid_rva(name_dir_offset))?;
            let name_header = ResourceDirectoryHeader::parse(&name_dir_data)?;

            for j in 0..name_header.total_entries() {
                let name_entry_offset = name_dir_offset
                    + ResourceDirectoryHeader::SIZE as u32
                    + (j * ResourceDirectoryEntry::SIZE) as u32;
                let name_entry_data = read_at_rva(name_entry_offset, ResourceDirectoryEntry::SIZE)
                    .ok_or(Error::invalid_rva(name_entry_offset))?;
                let name_entry = ResourceDirectoryEntry::parse(&name_entry_data)?;

                let name_id = Self::parse_resource_id(&name_entry, rsrc_rva, &read_at_rva)?;

                if !name_entry.is_directory() {
                    continue;
                }

                // Parse language entries (level 3)
                let lang_dir_offset = rsrc_rva + name_entry.data_offset();
                let lang_dir_data = read_at_rva(lang_dir_offset, ResourceDirectoryHeader::SIZE)
                    .ok_or(Error::invalid_rva(lang_dir_offset))?;
                let lang_header = ResourceDirectoryHeader::parse(&lang_dir_data)?;

                for k in 0..lang_header.total_entries() {
                    let lang_entry_offset = lang_dir_offset
                        + ResourceDirectoryHeader::SIZE as u32
                        + (k * ResourceDirectoryEntry::SIZE) as u32;
                    let lang_entry_data =
                        read_at_rva(lang_entry_offset, ResourceDirectoryEntry::SIZE)
                            .ok_or(Error::invalid_rva(lang_entry_offset))?;
                    let lang_entry = ResourceDirectoryEntry::parse(&lang_entry_data)?;

                    let language = lang_entry.id();

                    if lang_entry.is_directory() {
                        continue; // Should be a data entry at this level
                    }

                    // Parse data entry
                    let data_entry_offset = rsrc_rva + lang_entry.data_offset();
                    let data_entry_data = read_at_rva(data_entry_offset, ResourceDataEntry::SIZE)
                        .ok_or(Error::invalid_rva(data_entry_offset))?;
                    let data_entry = ResourceDataEntry::parse(&data_entry_data)?;

                    resources.push(Resource {
                        resource_type: type_id.clone(),
                        name: name_id.clone(),
                        language,
                        data_rva: data_entry.offset_to_data,
                        size: data_entry.size,
                        code_page: data_entry.code_page,
                        data: None,
                    });
                }
            }
        }

        Ok(Self { resources })
    }

    fn parse_resource_id<F>(
        entry: &ResourceDirectoryEntry,
        rsrc_rva: u32,
        read_at_rva: &F,
    ) -> Result<ResourceId>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        if entry.is_named() {
            let name_offset = rsrc_rva + entry.name_offset();
            // Resource names are length-prefixed Unicode strings
            let len_data = read_at_rva(name_offset, 2).ok_or(Error::invalid_rva(name_offset))?;
            let len = u16::from_le_bytes([len_data[0], len_data[1]]) as usize;
            let name_data =
                read_at_rva(name_offset + 2, len * 2).ok_or(Error::invalid_rva(name_offset + 2))?;

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

    /// Parse resource directory from PE data, including resource data.
    ///
    /// Unlike `parse()`, this method also loads the actual resource data into each `Resource`.
    pub fn parse_with_data<F>(rsrc_rva: u32, rsrc_size: u32, read_at_rva: F) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        let mut dir = Self::parse(rsrc_rva, rsrc_size, &read_at_rva)?;
        dir.load_data(&read_at_rva);
        Ok(dir)
    }

    /// Load the actual data for all resources that don't have it yet.
    ///
    /// This is useful if you parsed with `parse()` and later want to load specific resource data.
    pub fn load_data<F>(&mut self, read_at_rva: F)
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        for resource in &mut self.resources {
            if resource.data.is_none() && resource.size > 0 {
                resource.data = read_at_rva(resource.data_rva, resource.size as usize);
            }
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

/// A resource entry with owned data for building.
#[derive(Debug, Clone)]
pub struct ResourceEntry {
    /// Resource type (level 1).
    pub resource_type: ResourceId,
    /// Resource name/ID (level 2).
    pub name: ResourceId,
    /// Language ID (level 3).
    pub language: u16,
    /// Code page.
    pub code_page: u32,
    /// Resource data.
    pub data: Vec<u8>,
}

impl ResourceEntry {
    /// Create a new resource entry with numeric type and ID.
    pub fn new(resource_type: u16, id: u16, language: u16, data: Vec<u8>) -> Self {
        Self {
            resource_type: ResourceId::Id(resource_type),
            name: ResourceId::Id(id),
            language,
            code_page: 0,
            data,
        }
    }

    /// Create a new resource entry with a standard type.
    pub fn with_type(rt: ResourceType, id: u16, language: u16, data: Vec<u8>) -> Self {
        Self::new(rt as u16, id, language, data)
    }

    /// Create a manifest resource.
    pub fn manifest(data: Vec<u8>) -> Self {
        Self::with_type(ResourceType::Manifest, 1, 0x0409, data)
    }

    /// Create a version info resource.
    pub fn version_info(data: Vec<u8>) -> Self {
        Self::with_type(ResourceType::Version, 1, 0x0409, data)
    }
}

/// Builder for constructing a resource directory.
///
/// The PE resource directory is a 3-level tree:
/// - Level 1: Resource Type (e.g., RT_ICON, RT_MANIFEST)
/// - Level 2: Resource Name/ID
/// - Level 3: Language ID
///
/// # Example
/// ```ignore
/// let mut builder = ResourceBuilder::new();
/// builder.add(ResourceEntry::manifest(manifest_xml.into_bytes()));
/// let (data, size) = builder.build(rsrc_rva);
/// ```
#[derive(Debug, Clone, Default)]
pub struct ResourceBuilder {
    /// Resources to include.
    entries: Vec<ResourceEntry>,
}

impl ResourceBuilder {
    /// Create a new resource builder.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add a resource entry.
    pub fn add(&mut self, entry: ResourceEntry) -> &mut Self {
        self.entries.push(entry);
        self
    }

    /// Add a resource with standard type.
    pub fn add_resource(
        &mut self,
        rt: ResourceType,
        id: u16,
        language: u16,
        data: Vec<u8>,
    ) -> &mut Self {
        self.add(ResourceEntry::with_type(rt, id, language, data))
    }

    /// Add a manifest resource.
    pub fn add_manifest(&mut self, data: Vec<u8>) -> &mut Self {
        self.add(ResourceEntry::manifest(data))
    }

    /// Add a version info resource.
    pub fn add_version_info(&mut self, data: Vec<u8>) -> &mut Self {
        self.add(ResourceEntry::version_info(data))
    }

    /// Calculate the total size needed for the resource section.
    pub fn calculate_size(&self) -> usize {
        if self.entries.is_empty() {
            return 0;
        }

        let layout = self.compute_layout();
        layout.total_size
    }

    /// Build the resource directory data.
    /// Returns (data, total_size).
    pub fn build(&self, base_rva: u32) -> (Vec<u8>, u32) {
        if self.entries.is_empty() {
            return (Vec::new(), 0);
        }

        let layout = self.compute_layout();
        let mut data = vec![0u8; layout.total_size];

        // Write root directory (Level 1 - Types)
        self.write_directory_header(&mut data, 0, &layout.types);

        let mut entry_offset = ResourceDirectoryHeader::SIZE;
        for (type_idx, (type_id, names)) in layout.types.iter().enumerate() {
            // Write type entry
            let name_or_id = match type_id {
                ResourceId::Id(id) => *id as u32,
                ResourceId::Name(_) => 0x80000000 | layout.type_name_offsets[type_idx],
            };
            let offset_to_data = 0x80000000 | layout.type_dir_offsets[type_idx];
            self.write_entry(&mut data, entry_offset, name_or_id, offset_to_data);
            entry_offset += ResourceDirectoryEntry::SIZE;

            // Write name directory (Level 2)
            let name_dir_offset = layout.type_dir_offsets[type_idx] as usize;
            self.write_directory_header(&mut data, name_dir_offset, names);

            let mut name_entry_offset = name_dir_offset + ResourceDirectoryHeader::SIZE;
            let mut lang_idx_base = 0;
            for (name_idx, (name_id, langs)) in names.iter().enumerate() {
                // Write name entry
                let name_or_id = match name_id {
                    ResourceId::Id(id) => *id as u32,
                    ResourceId::Name(_) => {
                        0x80000000 | layout.name_name_offsets[type_idx][name_idx]
                    }
                };
                let offset_to_data = 0x80000000 | layout.name_dir_offsets[type_idx][name_idx];
                self.write_entry(&mut data, name_entry_offset, name_or_id, offset_to_data);
                name_entry_offset += ResourceDirectoryEntry::SIZE;

                // Write language directory (Level 3)
                let lang_dir_offset = layout.name_dir_offsets[type_idx][name_idx] as usize;
                self.write_lang_directory_header(&mut data, lang_dir_offset, langs.len());

                let mut lang_entry_offset = lang_dir_offset + ResourceDirectoryHeader::SIZE;
                for (lang_local_idx, &lang_id) in langs.iter().enumerate() {
                    let lang_idx = lang_idx_base + lang_local_idx;
                    // Write language entry (points to data entry, not directory)
                    let data_entry_offset = layout.data_entry_offsets[type_idx][lang_idx];
                    self.write_entry(
                        &mut data,
                        lang_entry_offset,
                        lang_id as u32,
                        data_entry_offset,
                    );
                    lang_entry_offset += ResourceDirectoryEntry::SIZE;

                    // Write data entry
                    let entry_info = &layout.entry_info[type_idx][lang_idx];
                    let data_rva = base_rva + layout.data_offsets[type_idx][lang_idx];
                    self.write_data_entry(
                        &mut data,
                        data_entry_offset as usize,
                        data_rva,
                        entry_info.data_size,
                        entry_info.code_page,
                    );

                    // Write actual resource data
                    let data_offset = layout.data_offsets[type_idx][lang_idx] as usize;
                    data[data_offset..data_offset + entry_info.data_size as usize]
                        .copy_from_slice(&self.entries[entry_info.entry_idx].data);
                }
                lang_idx_base += langs.len();
            }
        }

        // Write string names
        for (type_idx, (type_id, _)) in layout.types.iter().enumerate() {
            if let ResourceId::Name(name) = type_id {
                let offset = layout.type_name_offsets[type_idx] as usize;
                self.write_string_name(&mut data, offset, name);
            }
        }

        for (type_idx, (_, names)) in layout.types.iter().enumerate() {
            for (name_idx, (name_id, _)) in names.iter().enumerate() {
                if let ResourceId::Name(name) = name_id {
                    let offset = layout.name_name_offsets[type_idx][name_idx] as usize;
                    self.write_string_name(&mut data, offset, name);
                }
            }
        }

        (data, layout.total_size as u32)
    }

    fn write_directory_header<T>(
        &self,
        data: &mut [u8],
        offset: usize,
        entries: &[(ResourceId, T)],
    ) {
        let (named, id): (Vec<_>, Vec<_>) = entries
            .iter()
            .partition(|(id, _)| matches!(id, ResourceId::Name(_)));
        let header = ResourceDirectoryHeader {
            characteristics: 0,
            time_date_stamp: 0,
            major_version: 0,
            minor_version: 0,
            number_of_named_entries: named.len() as u16,
            number_of_id_entries: id.len() as u16,
        };
        data[offset..offset + ResourceDirectoryHeader::SIZE].copy_from_slice(&header.to_bytes());
    }

    fn write_lang_directory_header(&self, data: &mut [u8], offset: usize, count: usize) {
        let header = ResourceDirectoryHeader {
            characteristics: 0,
            time_date_stamp: 0,
            major_version: 0,
            minor_version: 0,
            number_of_named_entries: 0,
            number_of_id_entries: count as u16,
        };
        data[offset..offset + ResourceDirectoryHeader::SIZE].copy_from_slice(&header.to_bytes());
    }

    fn write_entry(&self, data: &mut [u8], offset: usize, name_or_id: u32, offset_to_data: u32) {
        let entry = ResourceDirectoryEntry {
            name_or_id,
            offset_to_data,
        };
        data[offset..offset + ResourceDirectoryEntry::SIZE].copy_from_slice(&entry.to_bytes());
    }

    fn write_data_entry(
        &self,
        data: &mut [u8],
        offset: usize,
        rva: u32,
        size: u32,
        code_page: u32,
    ) {
        let entry = ResourceDataEntry {
            offset_to_data: rva,
            size,
            code_page,
            reserved: 0,
        };
        data[offset..offset + ResourceDataEntry::SIZE].copy_from_slice(&entry.to_bytes());
    }

    fn write_string_name(&self, data: &mut [u8], offset: usize, name: &str) {
        let utf16: Vec<u16> = name.encode_utf16().collect();
        let len = utf16.len() as u16;
        data[offset..offset + 2].copy_from_slice(&len.to_le_bytes());
        for (i, ch) in utf16.iter().enumerate() {
            data[offset + 2 + i * 2..offset + 2 + i * 2 + 2].copy_from_slice(&ch.to_le_bytes());
        }
    }

    fn compute_layout(&self) -> ResourceLayout {
        // Group entries by type -> name -> language
        use std::collections::BTreeMap;

        // Type -> Name -> Vec<(language, entry_idx)>
        let mut grouped: BTreeMap<ResourceIdKey, BTreeMap<ResourceIdKey, Vec<(u16, usize)>>> =
            BTreeMap::new();

        for (idx, entry) in self.entries.iter().enumerate() {
            let type_key = ResourceIdKey::from(&entry.resource_type);
            let name_key = ResourceIdKey::from(&entry.name);

            grouped
                .entry(type_key)
                .or_default()
                .entry(name_key)
                .or_default()
                .push((entry.language, idx));
        }

        // Build layout
        let num_types = grouped.len();
        let mut offset = ResourceDirectoryHeader::SIZE + num_types * ResourceDirectoryEntry::SIZE;

        // Type directories
        let mut type_dir_offsets = Vec::new();
        let mut type_name_offsets = Vec::new();
        let mut name_dir_offsets: Vec<Vec<u32>> = Vec::new();
        let mut name_name_offsets: Vec<Vec<u32>> = Vec::new();
        let mut data_entry_offsets: Vec<Vec<u32>> = Vec::new();
        let mut entry_info: Vec<Vec<EntryInfo>> = Vec::new();

        let mut types: ResourceTree = Vec::new();

        for (type_key, names_map) in &grouped {
            type_dir_offsets.push(offset as u32);
            type_name_offsets.push(0); // Placeholder

            let num_names = names_map.len();
            offset += ResourceDirectoryHeader::SIZE + num_names * ResourceDirectoryEntry::SIZE;

            let mut names_vec = Vec::new();
            let mut this_name_dir_offsets = Vec::new();
            let mut this_name_name_offsets = Vec::new();
            let mut this_data_entry_offsets = Vec::new();
            let mut this_entry_info = Vec::new();

            for (name_key, langs) in names_map {
                this_name_dir_offsets.push(offset as u32);
                this_name_name_offsets.push(0); // Placeholder

                let num_langs = langs.len();
                offset += ResourceDirectoryHeader::SIZE + num_langs * ResourceDirectoryEntry::SIZE;

                let mut lang_ids = Vec::new();
                for &(lang_id, entry_idx) in langs {
                    this_data_entry_offsets.push(offset as u32);
                    offset += ResourceDataEntry::SIZE;
                    lang_ids.push(lang_id);
                    this_entry_info.push(EntryInfo {
                        entry_idx,
                        data_size: self.entries[entry_idx].data.len() as u32,
                        code_page: self.entries[entry_idx].code_page,
                    });
                }

                names_vec.push((name_key.to_resource_id(), lang_ids));
            }

            name_dir_offsets.push(this_name_dir_offsets);
            name_name_offsets.push(this_name_name_offsets);
            data_entry_offsets.push(this_data_entry_offsets);
            entry_info.push(this_entry_info);
            types.push((type_key.to_resource_id(), names_vec));
        }

        // String table for names
        let mut string_offset = offset;
        for (type_idx, (type_id, _)) in types.iter().enumerate() {
            if let ResourceId::Name(name) = type_id {
                type_name_offsets[type_idx] = string_offset as u32;
                string_offset += 2 + name.encode_utf16().count() * 2;
            }
        }

        for (type_idx, (_, names)) in types.iter().enumerate() {
            for (name_idx, (name_id, _)) in names.iter().enumerate() {
                if let ResourceId::Name(name) = name_id {
                    name_name_offsets[type_idx][name_idx] = string_offset as u32;
                    string_offset += 2 + name.encode_utf16().count() * 2;
                }
            }
        }

        // Calculate data offsets (8-byte aligned)
        let mut data_offset = (string_offset + 7) & !7;
        let mut data_offsets: Vec<Vec<u32>> = Vec::new();

        for type_entries in &entry_info {
            let mut type_data_offsets = Vec::new();
            for info in type_entries {
                type_data_offsets.push(data_offset as u32);
                data_offset += (info.data_size as usize + 7) & !7;
            }
            data_offsets.push(type_data_offsets);
        }

        let total_size = data_offset;

        ResourceLayout {
            types,
            type_dir_offsets,
            type_name_offsets,
            name_dir_offsets,
            name_name_offsets,
            data_entry_offsets,
            data_offsets,
            entry_info,
            total_size,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum ResourceIdKey {
    Id(u16),
    Name(String),
}

impl ResourceIdKey {
    fn from(id: &ResourceId) -> Self {
        match id {
            ResourceId::Id(n) => Self::Id(*n),
            ResourceId::Name(s) => Self::Name(s.clone()),
        }
    }

    fn to_resource_id(&self) -> ResourceId {
        match self {
            Self::Id(n) => ResourceId::Id(*n),
            Self::Name(s) => ResourceId::Name(s.clone()),
        }
    }
}

#[derive(Debug)]
struct EntryInfo {
    entry_idx: usize,
    data_size: u32,
    code_page: u32,
}

/// Type alias for the resource tree structure: Type -> Name -> Languages
type ResourceTree = Vec<(ResourceId, Vec<(ResourceId, Vec<u16>)>)>;

#[derive(Debug)]
struct ResourceLayout {
    types: ResourceTree,
    type_dir_offsets: Vec<u32>,
    type_name_offsets: Vec<u32>,
    name_dir_offsets: Vec<Vec<u32>>,
    name_name_offsets: Vec<Vec<u32>>,
    data_entry_offsets: Vec<Vec<u32>>,
    data_offsets: Vec<Vec<u32>>,
    entry_info: Vec<Vec<EntryInfo>>,
    total_size: usize,
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
            name_or_id: 0x80001000,     // High bit set = named
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

    #[test]
    fn test_resource_builder_single_resource() {
        let mut builder = ResourceBuilder::new();
        builder.add_manifest(b"<xml>test</xml>".to_vec());

        let (data, size) = builder.build(0x3000);
        assert!(size > 0);
        assert!(!data.is_empty());

        // Verify we can parse the built data
        let read_fn = |rva: u32, len: usize| -> Option<Vec<u8>> {
            let offset = (rva - 0x3000) as usize;
            if offset + len <= data.len() {
                Some(data[offset..offset + len].to_vec())
            } else {
                None
            }
        };

        let parsed = ResourceDirectory::parse(0x3000, size, read_fn).unwrap();
        assert_eq!(parsed.len(), 1);
        assert!(parsed.manifest().is_some());
    }

    #[test]
    fn test_resource_builder_multiple_resources() {
        let mut builder = ResourceBuilder::new();
        builder
            .add_manifest(b"manifest data".to_vec())
            .add_version_info(b"version data".to_vec())
            .add_resource(ResourceType::RcData, 100, 0x0409, b"custom data".to_vec());

        let (data, size) = builder.build(0x4000);
        assert!(size > 0);

        let read_fn = |rva: u32, len: usize| -> Option<Vec<u8>> {
            let offset = (rva - 0x4000) as usize;
            if offset + len <= data.len() {
                Some(data[offset..offset + len].to_vec())
            } else {
                None
            }
        };

        let parsed = ResourceDirectory::parse(0x4000, size, read_fn).unwrap();
        assert_eq!(parsed.len(), 3);
        assert!(parsed.manifest().is_some());
        assert!(parsed.version_info().is_some());
    }
}
