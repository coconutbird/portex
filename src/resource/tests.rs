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
