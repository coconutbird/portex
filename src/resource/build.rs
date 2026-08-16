use super::*;

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

    /// Create a builder from a parsed ResourceDirectory.
    ///
    /// The directory must have been parsed with `resources_with_data()` so that
    /// the `Resource::data` field is populated.
    ///
    /// Returns `None` if any resource is missing its data.
    pub fn from_directory(directory: &ResourceDirectory) -> Option<Self> {
        let mut builder = Self::new();
        for resource in &directory.resources {
            let data = resource.data.as_ref()?.clone();
            builder.add(ResourceEntry {
                resource_type: resource.resource_type.clone(),
                name: resource.name.clone(),
                language: resource.language,
                code_page: resource.code_page,
                data,
            });
        }
        Some(builder)
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
        self.try_calculate_size()
            .expect("resource size overflow: use try_calculate_size()")
    }

    /// Calculate the resource size with checked tree counts, UTF-16 lengths,
    /// data lengths, and relative offsets.
    pub fn try_calculate_size(&self) -> Result<usize> {
        if self.entries.is_empty() {
            return Ok(0);
        }

        Ok(self.try_compute_layout()?.total_size)
    }

    /// Build the resource directory data.
    /// Returns (data, total_size).
    pub fn build(&self, base_rva: u32) -> (Vec<u8>, u32) {
        self.try_build(base_rva)
            .expect("resource build failed: use try_build() for fallible serialization")
    }

    /// Build the resource tree with checked relative offsets and data RVAs.
    pub fn try_build(&self, base_rva: u32) -> Result<(Vec<u8>, u32)> {
        if self.entries.is_empty() {
            return Ok((Vec::new(), 0));
        }

        let layout = self.try_compute_layout()?;
        let total_size = u32::try_from(layout.total_size)
            .map_err(|_| Error::invalid_data_directory("resource directory exceeds u32"))?;
        base_rva
            .checked_add(total_size)
            .ok_or_else(|| Error::invalid_data_directory("resource data RVA range overflow"))?;
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
                    let data_rva = base_rva
                        .checked_add(layout.data_offsets[type_idx][lang_idx])
                        .ok_or_else(|| {
                            Error::invalid_data_directory("resource data RVA overflow")
                        })?;
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

        Ok((data, total_size))
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
        // Group entries by type -> name -> language.
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
        for names in grouped.values_mut() {
            for languages in names.values_mut() {
                languages.sort_by_key(|(language, _)| *language);
            }
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

    fn try_compute_layout(&self) -> Result<ResourceLayout> {
        self.validate_entries()?;
        Ok(self.compute_layout())
    }

    fn validate_entries(&self) -> Result<()> {
        const MAX_RESOURCE_ENTRIES: usize = 262_144;
        const MAX_RELATIVE_OFFSET: u64 = 0x7fff_ffff;
        if self.entries.len() > MAX_RESOURCE_ENTRIES {
            return Err(Error::invalid_data_directory(format!(
                "resource count {} exceeds the safety limit {}",
                self.entries.len(),
                MAX_RESOURCE_ENTRIES
            )));
        }

        let mut grouped: BTreeMap<ResourceIdKey, BTreeMap<ResourceIdKey, Vec<u16>>> =
            BTreeMap::new();
        let mut seen = BTreeMap::new();
        for entry in &self.entries {
            validate_resource_id(&entry.resource_type, "resource type")?;
            validate_resource_id(&entry.name, "resource name")?;
            u32::try_from(entry.data.len())
                .map_err(|_| Error::invalid_data_directory("resource data exceeds u32"))?;
            let type_key = ResourceIdKey::from(&entry.resource_type);
            let name_key = ResourceIdKey::from(&entry.name);
            if seen
                .insert((type_key.clone(), name_key.clone(), entry.language), ())
                .is_some()
            {
                return Err(Error::invalid_data_directory(format!(
                    "duplicate resource type/name/language entry ({:?}, {:?}, {})",
                    entry.resource_type, entry.name, entry.language
                )));
            }
            grouped
                .entry(type_key)
                .or_default()
                .entry(name_key)
                .or_default()
                .push(entry.language);
        }
        ensure_u16_count(grouped.len(), "resource type")?;

        let mut total = checked_u64_add(
            ResourceDirectoryHeader::SIZE as u64,
            checked_u64_mul(grouped.len(), ResourceDirectoryEntry::SIZE, "resource root")?,
            "resource root",
        )?;
        for (resource_type, names) in &grouped {
            ensure_u16_count(names.len(), "resource name")?;
            total = checked_u64_add(
                total,
                checked_u64_add(
                    ResourceDirectoryHeader::SIZE as u64,
                    checked_u64_mul(names.len(), ResourceDirectoryEntry::SIZE, "resource names")?,
                    "resource names",
                )?,
                "resource directory",
            )?;
            if let ResourceIdKey::Name(name) = resource_type {
                total = checked_u64_add(total, resource_name_size(name)?, "resource strings")?;
            }
            for (name, languages) in names {
                ensure_u16_count(languages.len(), "resource language")?;
                total = checked_u64_add(
                    total,
                    checked_u64_add(
                        ResourceDirectoryHeader::SIZE as u64,
                        checked_u64_mul(
                            languages.len(),
                            ResourceDirectoryEntry::SIZE,
                            "resource languages",
                        )?,
                        "resource languages",
                    )?,
                    "resource directory",
                )?;
                total = checked_u64_add(
                    total,
                    checked_u64_mul(
                        languages.len(),
                        ResourceDataEntry::SIZE,
                        "resource data entries",
                    )?,
                    "resource data entries",
                )?;
                if let ResourceIdKey::Name(name) = name {
                    total = checked_u64_add(total, resource_name_size(name)?, "resource strings")?;
                }
            }
        }

        total = total
            .checked_add(7)
            .map(|size| size & !7)
            .ok_or_else(|| Error::invalid_data_directory("resource alignment overflow"))?;
        for entry in &self.entries {
            let aligned = (entry.data.len() as u64)
                .checked_add(7)
                .map(|size| size & !7)
                .ok_or_else(|| Error::invalid_data_directory("resource data size overflow"))?;
            total = checked_u64_add(total, aligned, "resource data")?;
        }
        if total > MAX_RELATIVE_OFFSET {
            return Err(Error::invalid_data_directory(format!(
                "resource directory size {:#x} exceeds the 31-bit relative-offset format",
                total
            )));
        }
        Ok(())
    }
}

fn validate_resource_id(id: &ResourceId, context: &str) -> Result<()> {
    if let ResourceId::Name(name) = id {
        let units = name.encode_utf16().count();
        if units > usize::from(u16::MAX) {
            return Err(Error::invalid_data_directory(format!(
                "{context} is {} UTF-16 units, exceeding u16",
                units
            )));
        }
    }
    Ok(())
}

fn ensure_u16_count(count: usize, context: &str) -> Result<()> {
    u16::try_from(count)
        .map(|_| ())
        .map_err(|_| Error::invalid_data_directory(format!("{context} count exceeds u16")))
}

fn resource_name_size(name: &str) -> Result<u64> {
    let units = name.encode_utf16().count();
    ensure_u16_count(units, "resource-name UTF-16 unit")?;
    (units as u64)
        .checked_mul(2)
        .and_then(|size| size.checked_add(2))
        .ok_or_else(|| Error::invalid_data_directory("resource-name size overflow"))
}

fn checked_u64_mul(count: usize, width: usize, context: &str) -> Result<u64> {
    (count as u64)
        .checked_mul(width as u64)
        .ok_or_else(|| Error::invalid_data_directory(format!("{context} size overflow")))
}

fn checked_u64_add(left: u64, right: u64, context: &str) -> Result<u64> {
    left.checked_add(right)
        .ok_or_else(|| Error::invalid_data_directory(format!("{context} size overflow")))
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum ResourceIdKey {
    // Named entries must precede numeric IDs in every resource directory.
    Name(String),
    Id(u16),
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
