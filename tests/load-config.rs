//! Tests for the bytes that `PeImage::load_config` reads.
//!
//! The `Size` field of the load config structure bounds the read, as it does
//! in the Windows loader. The size of the data directory can differ from it.
//! MSVC linkers write `0x40` as the directory size of a PE32 image whose
//! structure has a `Size` of `0xC0`.

use portex::directories::{LoadConfigDirectory, LoadConfigDirectory32, LoadConfigDirectory64};
use portex::error::ErrorKind;
use portex::headers::{DataDirectoryType, MachineType};
use portex::image::{PeBuilder, PeImage};
use portex::section::characteristics;

/// The size of the raw data of each section. It equals the file alignment, so
/// the builder adds no padding after the data.
const SECTION_BYTES: usize = 0x200;

/// Builds a PE32 structure of `size` bytes. The fields that a directory size
/// of `0x40` cuts off hold values, and so does the versioned tail.
fn config32(size: u32) -> LoadConfigDirectory32 {
    let tail = (size as usize).saturating_sub(LoadConfigDirectory32::SIZE_WITH_CFG);
    LoadConfigDirectory32 {
        size,
        security_cookie: 0x0040_3000,
        se_handler_table: 0x0040_2100,
        se_handler_count: 1,
        guard_cf_check_function_pointer: 0x0040_2008,
        trailing_data: vec![0x5a; tail],
        ..Default::default()
    }
}

/// Builds a PE32+ structure of `size` bytes. The fields after the first `0x60`
/// bytes hold values, and so does the versioned tail.
fn config64(size: u32) -> LoadConfigDirectory64 {
    let tail = (size as usize).saturating_sub(LoadConfigDirectory64::SIZE_WITH_CFG);
    LoadConfigDirectory64 {
        size,
        security_cookie: 0x1_4000_3000,
        guard_cf_check_function_pointer: 0x1_4000_2008,
        guard_cf_function_table: 0x1_4000_2100,
        guard_cf_function_count: 3,
        trailing_data: vec![0x5a; tail],
        ..Default::default()
    }
}

/// Builds the image that holds `bytes` at `offset` in its last section and
/// declares a load config directory of `directory_size` bytes there.
///
/// The test reads the image after it passes through the raw file format, as a
/// user of the crate does.
fn image_with_load_config(
    machine: MachineType,
    bytes: &[u8],
    offset: usize,
    directory_size: u32,
) -> PeImage {
    let mut section = vec![0; offset];
    section.extend_from_slice(bytes);
    section.resize(section.len().max(SECTION_BYTES), 0);
    let mut image = PeBuilder::new()
        .machine(machine)
        .add_section(
            ".text",
            vec![0xcc; SECTION_BYTES],
            characteristics::CODE | characteristics::EXECUTE | characteristics::READ,
        )
        .add_section(
            ".rdata",
            section,
            characteristics::INITIALIZED_DATA | characteristics::READ,
        )
        .try_build()
        .unwrap();
    let start = image
        .section_by_name(".rdata")
        .unwrap()
        .header
        .virtual_address;
    image.set_data_directory(
        DataDirectoryType::LoadConfig,
        start + u32::try_from(offset).unwrap(),
        directory_size,
    );
    PeImage::parse(&image.try_build().unwrap()).unwrap()
}

/// Returns the PE32 structure that the image holds.
fn read32(image: &PeImage) -> LoadConfigDirectory32 {
    match image.load_config().unwrap().unwrap() {
        LoadConfigDirectory::Config32(config) => config,
        LoadConfigDirectory::Config64(_) => panic!("a PE32 image holds a PE32 structure"),
    }
}

/// Returns the PE32+ structure that the image holds.
fn read64(image: &PeImage) -> LoadConfigDirectory64 {
    match image.load_config().unwrap().unwrap() {
        LoadConfigDirectory::Config64(config) => config,
        LoadConfigDirectory::Config32(_) => panic!("a PE32+ image holds a PE32+ structure"),
    }
}

#[test]
fn a_pe32_directory_size_below_the_structure_size_reads_the_whole_structure() {
    let config = config32(0xc0);
    let image = image_with_load_config(
        MachineType::I386,
        &config.try_to_bytes().unwrap(),
        0x10,
        0x40,
    );
    let directory = image.data_directory(DataDirectoryType::LoadConfig).unwrap();
    assert_eq!(directory.size, 0x40);

    // `se_handler_table` starts at offset 0x40, after the end of the directory.
    assert_eq!(read32(&image), config);
}

#[test]
fn a_pe32_plus_directory_size_below_the_structure_size_reads_the_whole_structure() {
    let config = config64(0x100);
    let image = image_with_load_config(
        MachineType::Amd64,
        &config.try_to_bytes().unwrap(),
        0x10,
        0x60,
    );
    let directory = image.data_directory(DataDirectoryType::LoadConfig).unwrap();
    assert_eq!(directory.size, 0x60);

    // `guard_cf_function_table` starts at offset 0x80, after the directory.
    assert_eq!(read64(&image), config);
}

#[test]
fn a_directory_size_above_the_structure_size_does_not_widen_the_structure() {
    let mut bytes = config32(0xc0).try_to_bytes().unwrap();
    bytes[..4].copy_from_slice(&0x40_u32.to_le_bytes());
    let image = image_with_load_config(MachineType::I386, &bytes, 0x10, 0xc0);

    // The structure ends at offset 0x40: the fields after it are absent.
    let config = read32(&image);
    assert_eq!(config.size, 0x40);
    assert_eq!(config.security_cookie, 0x0040_3000);
    assert_eq!(config.se_handler_table, 0);
    assert_eq!(config.se_handler_count, 0);
    assert!(config.trailing_data.is_empty());
}

#[test]
fn a_structure_size_of_zero_uses_the_directory_size() {
    let config = LoadConfigDirectory32 {
        se_handler_table: 0x0040_2100,
        se_handler_count: 1,
        ..Default::default()
    };
    let mut bytes = config.try_to_bytes().unwrap();
    assert_eq!(bytes.len(), 72);
    bytes[..4].copy_from_slice(&0_u32.to_le_bytes());
    let image = image_with_load_config(MachineType::I386, &bytes, 0x10, 72);

    let config = read32(&image);
    assert_eq!(config.size, 0);
    assert_eq!(config.se_handler_table, 0x0040_2100);
    assert_eq!(config.se_handler_count, 1);

    // The directory size bounds the read, so a shorter directory cuts the
    // structure before `se_handler_count`.
    let cut = image_with_load_config(MachineType::I386, &bytes, 0x10, 68);
    let config = read32(&cut);
    assert_eq!(config.se_handler_table, 0x0040_2100);
    assert_eq!(config.se_handler_count, 0);
}

#[test]
fn a_structure_size_past_the_mapped_bytes_is_rejected() {
    // The structure starts 0x40 bytes before the end of the last section and
    // states a `Size` of 0xc0. The directory size of 0x40 stays in bounds.
    let bytes = config32(0xc0).try_to_bytes().unwrap();
    let offset = SECTION_BYTES - 0x40;
    let image = image_with_load_config(MachineType::I386, &bytes[..0x40], offset, 0x40);

    let error = image.load_config().unwrap_err();
    assert!(
        matches!(error.kind(), ErrorKind::InvalidDataDirectory(message)
            if message.contains("load-config size 192")),
        "{error}"
    );
}

#[test]
fn a_structure_size_beyond_the_image_is_rejected() {
    let mut bytes = config32(0xc0).try_to_bytes().unwrap();
    bytes[..4].copy_from_slice(&u32::MAX.to_le_bytes());
    let image = image_with_load_config(MachineType::I386, &bytes, 0x10, 0x40);

    let error = image.load_config().unwrap_err();
    assert!(
        matches!(error.kind(), ErrorKind::InvalidDataDirectory(_)),
        "{error}"
    );
}

#[test]
fn a_directory_that_starts_outside_the_image_is_rejected() {
    let bytes = config32(0xc0).try_to_bytes().unwrap();
    let mut image = image_with_load_config(MachineType::I386, &bytes, 0x10, 0x40);
    image.set_data_directory(DataDirectoryType::LoadConfig, 0x10_0000, 0x40);

    let error = image.load_config().unwrap_err();
    assert!(
        matches!(error.kind(), ErrorKind::InvalidRva(0x10_0000)),
        "{error}"
    );
}

#[test]
fn an_absent_directory_is_not_an_error() {
    let bytes = config32(0xc0).try_to_bytes().unwrap();
    let mut image = image_with_load_config(MachineType::I386, &bytes, 0x10, 0x40);
    image.set_data_directory(DataDirectoryType::LoadConfig, 0, 0);

    assert!(image.load_config().unwrap().is_none());
}
