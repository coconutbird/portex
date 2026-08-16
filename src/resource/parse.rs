use super::*;

impl ResourceDirectory {
    /// Parse resource directory from PE data.
    pub fn parse<F>(rsrc_rva: u32, rsrc_size: u32, read_at_rva: F) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        const MAX_VISITED_ENTRIES: usize = 262_144;
        if rsrc_size < ResourceDirectoryHeader::SIZE as u32 {
            return Err(Error::invalid_data_directory(format!(
                "resource directory is {} bytes, expected at least {}",
                rsrc_size,
                ResourceDirectoryHeader::SIZE
            )));
        }
        let mut resources = Vec::new();
        let mut visited_entries = 0usize;
        let mut seen_resources = BTreeMap::new();

        // Read the root directory
        let root_data = read_at_rva(rsrc_rva, ResourceDirectoryHeader::SIZE)
            .ok_or(Error::invalid_rva(rsrc_rva))?;
        let root_header = ResourceDirectoryHeader::parse(&root_data)?;

        // Parse type entries (level 1)
        for i in 0..root_header.total_entries() {
            visited_entries += 1;
            if visited_entries > MAX_VISITED_ENTRIES {
                return Err(Error::invalid_data_directory(
                    "resource tree exceeds the entry limit",
                ));
            }
            let relative = ResourceDirectoryHeader::SIZE
                .checked_add(i.checked_mul(ResourceDirectoryEntry::SIZE).ok_or_else(|| {
                    Error::invalid_data_directory("resource entry offset overflow")
                })?)
                .ok_or_else(|| Error::invalid_data_directory("resource entry offset overflow"))?;
            let entry_offset = checked_resource_rva(
                rsrc_rva,
                rsrc_size,
                relative as u32,
                ResourceDirectoryEntry::SIZE,
                "resource type entry",
            )?;
            let entry_data = read_at_rva(entry_offset, ResourceDirectoryEntry::SIZE)
                .ok_or(Error::invalid_rva(entry_offset))?;
            let type_entry = ResourceDirectoryEntry::parse(&entry_data)?;
            validate_resource_entry_order(i, &root_header, &type_entry, "resource type")?;

            let type_id = Self::parse_resource_id(&type_entry, rsrc_rva, rsrc_size, &read_at_rva)?;

            if !type_entry.is_directory() {
                return Err(Error::invalid_data_directory(
                    "resource type entry must point to a subdirectory",
                ));
            }

            // Parse name entries (level 2)
            let name_dir_offset = checked_resource_rva(
                rsrc_rva,
                rsrc_size,
                type_entry.data_offset(),
                ResourceDirectoryHeader::SIZE,
                "resource name directory",
            )?;
            let name_dir_data = read_at_rva(name_dir_offset, ResourceDirectoryHeader::SIZE)
                .ok_or(Error::invalid_rva(name_dir_offset))?;
            let name_header = ResourceDirectoryHeader::parse(&name_dir_data)?;

            for j in 0..name_header.total_entries() {
                visited_entries += 1;
                if visited_entries > MAX_VISITED_ENTRIES {
                    return Err(Error::invalid_data_directory(
                        "resource tree exceeds the entry limit",
                    ));
                }
                let directory_relative =
                    name_dir_offset.checked_sub(rsrc_rva).ok_or_else(|| {
                        Error::invalid_data_directory("resource directory precedes its base")
                    })?;
                let entry_relative = ResourceDirectoryHeader::SIZE
                    .checked_add(j.checked_mul(ResourceDirectoryEntry::SIZE).ok_or_else(|| {
                        Error::invalid_data_directory("resource entry offset overflow")
                    })?)
                    .and_then(|offset| u32::try_from(offset).ok())
                    .and_then(|offset| directory_relative.checked_add(offset))
                    .ok_or_else(|| {
                        Error::invalid_data_directory("resource entry offset overflow")
                    })?;
                let name_entry_offset = checked_resource_rva(
                    rsrc_rva,
                    rsrc_size,
                    entry_relative,
                    ResourceDirectoryEntry::SIZE,
                    "resource name entry",
                )?;
                let name_entry_data = read_at_rva(name_entry_offset, ResourceDirectoryEntry::SIZE)
                    .ok_or(Error::invalid_rva(name_entry_offset))?;
                let name_entry = ResourceDirectoryEntry::parse(&name_entry_data)?;
                validate_resource_entry_order(j, &name_header, &name_entry, "resource name")?;

                let name_id =
                    Self::parse_resource_id(&name_entry, rsrc_rva, rsrc_size, &read_at_rva)?;

                if !name_entry.is_directory() {
                    return Err(Error::invalid_data_directory(
                        "resource name entry must point to a subdirectory",
                    ));
                }

                // Parse language entries (level 3)
                let lang_dir_offset = checked_resource_rva(
                    rsrc_rva,
                    rsrc_size,
                    name_entry.data_offset(),
                    ResourceDirectoryHeader::SIZE,
                    "resource language directory",
                )?;
                let lang_dir_data = read_at_rva(lang_dir_offset, ResourceDirectoryHeader::SIZE)
                    .ok_or(Error::invalid_rva(lang_dir_offset))?;
                let lang_header = ResourceDirectoryHeader::parse(&lang_dir_data)?;

                for k in 0..lang_header.total_entries() {
                    visited_entries += 1;
                    if visited_entries > MAX_VISITED_ENTRIES {
                        return Err(Error::invalid_data_directory(
                            "resource tree exceeds the entry limit",
                        ));
                    }
                    let directory_relative =
                        lang_dir_offset.checked_sub(rsrc_rva).ok_or_else(|| {
                            Error::invalid_data_directory("resource directory precedes its base")
                        })?;
                    let entry_relative = ResourceDirectoryHeader::SIZE
                        .checked_add(k.checked_mul(ResourceDirectoryEntry::SIZE).ok_or_else(
                            || Error::invalid_data_directory("resource entry offset overflow"),
                        )?)
                        .and_then(|offset| u32::try_from(offset).ok())
                        .and_then(|offset| directory_relative.checked_add(offset))
                        .ok_or_else(|| {
                            Error::invalid_data_directory("resource entry offset overflow")
                        })?;
                    let lang_entry_offset = checked_resource_rva(
                        rsrc_rva,
                        rsrc_size,
                        entry_relative,
                        ResourceDirectoryEntry::SIZE,
                        "resource language entry",
                    )?;
                    let lang_entry_data =
                        read_at_rva(lang_entry_offset, ResourceDirectoryEntry::SIZE)
                            .ok_or(Error::invalid_rva(lang_entry_offset))?;
                    let lang_entry = ResourceDirectoryEntry::parse(&lang_entry_data)?;
                    validate_resource_entry_order(
                        k,
                        &lang_header,
                        &lang_entry,
                        "resource language",
                    )?;

                    if lang_entry.is_named() {
                        return Err(Error::invalid_data_directory(
                            "resource language entry must use an integer identifier",
                        ));
                    }
                    let language = lang_entry.id();

                    if lang_entry.is_directory() {
                        return Err(Error::invalid_data_directory(
                            "resource language entry must point to a data entry",
                        ));
                    }

                    // Parse data entry
                    let data_entry_offset = checked_resource_rva(
                        rsrc_rva,
                        rsrc_size,
                        lang_entry.data_offset(),
                        ResourceDataEntry::SIZE,
                        "resource data entry",
                    )?;
                    let data_entry_data = read_at_rva(data_entry_offset, ResourceDataEntry::SIZE)
                        .ok_or(Error::invalid_rva(data_entry_offset))?;
                    let data_entry = ResourceDataEntry::parse(&data_entry_data)?;
                    if data_entry.reserved != 0 {
                        return Err(Error::invalid_data_directory(
                            "resource data-entry reserved field must be zero",
                        ));
                    }
                    if seen_resources
                        .insert((type_id.clone(), name_id.clone(), language), ())
                        .is_some()
                    {
                        return Err(Error::invalid_data_directory(
                            "duplicate resource type/name/language entry",
                        ));
                    }

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
        rsrc_size: u32,
        read_at_rva: &F,
    ) -> Result<ResourceId>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        if entry.is_named() {
            let name_offset = checked_resource_rva(
                rsrc_rva,
                rsrc_size,
                entry.name_offset(),
                2,
                "resource name length",
            )?;
            // Resource names are length-prefixed Unicode strings
            let len_data = crate::parse_utils::read_exact_rva(
                read_at_rva,
                name_offset,
                2,
                "resource name length",
            )?;
            let len = u16::from_le_bytes([len_data[0], len_data[1]]) as usize;
            let byte_len = len
                .checked_mul(2)
                .ok_or_else(|| Error::invalid_data_directory("resource name length overflow"))?;
            let string_relative = entry
                .name_offset()
                .checked_add(2)
                .ok_or_else(|| Error::invalid_data_directory("resource name offset overflow"))?;
            let string_rva = checked_resource_rva(
                rsrc_rva,
                rsrc_size,
                string_relative,
                byte_len,
                "resource name",
            )?;
            let name_data = crate::parse_utils::read_exact_rva(
                read_at_rva,
                string_rva,
                byte_len,
                "resource name",
            )?;

            // Convert UTF-16LE to String
            let mut chars = Vec::with_capacity(len);
            for i in 0..len {
                let ch = u16::from_le_bytes([name_data[i * 2], name_data[i * 2 + 1]]);
                chars.push(ch);
            }
            let name = String::from_utf16(&chars).map_err(|_| {
                Error::invalid_data_directory("resource name contains invalid UTF-16")
            })?;
            Ok(ResourceId::Name(name))
        } else {
            if entry.name_or_id & 0xffff_0000 != 0 {
                return Err(Error::invalid_data_directory(
                    "numeric resource identifier has nonzero reserved bits",
                ));
            }
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
        dir.try_load_data(&read_at_rva)?;
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

    /// Strictly load all resource payloads, returning an error for the first
    /// unreadable range.
    pub fn try_load_data<F>(&mut self, read_at_rva: F) -> Result<()>
    where
        F: Fn(u32, usize) -> Option<Vec<u8>>,
    {
        for resource in &mut self.resources {
            if resource.data.is_none() && resource.size > 0 {
                resource.data = Some(crate::parse_utils::read_exact_rva(
                    &read_at_rva,
                    resource.data_rva,
                    resource.size as usize,
                    "resource payload",
                )?);
            }
        }
        Ok(())
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

fn validate_resource_entry_order(
    index: usize,
    header: &ResourceDirectoryHeader,
    entry: &ResourceDirectoryEntry,
    context: &str,
) -> Result<()> {
    let should_be_named = index < usize::from(header.number_of_named_entries);
    if entry.is_named() != should_be_named {
        return Err(Error::invalid_data_directory(format!(
            "{context} entries are not ordered with named entries first"
        )));
    }
    Ok(())
}
