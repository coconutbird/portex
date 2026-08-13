//! Raw and loader-mapped image-layout integration tests.

use portex::{
    BaseAddressReader, CoffHeader, ImportTable, ImportThunk, MachineType, PeBuilder, PeHeaders,
    PeImage, SectionHeader, SliceReader, SourceLayout, Subsystem, section::characteristics,
};

fn build_test_pe() -> PeImage {
    PeBuilder::new()
        .machine(MachineType::Amd64)
        .subsystem(Subsystem::WindowsCui)
        .entry_point(0x1000)
        .add_section(
            ".text",
            vec![0xCC; 0x180],
            characteristics::CODE | characteristics::EXECUTE | characteristics::READ,
        )
        .add_section(
            ".data",
            vec![0x5A; 0x80],
            characteristics::INITIALIZED_DATA | characteristics::READ | characteristics::WRITE,
        )
        .build()
}

fn map_file_image(file: &[u8]) -> Vec<u8> {
    let headers = PeHeaders::from_slice(file).expect("test PE headers should parse");
    let mut mapped = vec![0u8; headers.optional_header.size_of_image() as usize];

    let headers_size = headers.optional_header.size_of_headers() as usize;
    let headers_to_copy = headers_size.min(file.len()).min(mapped.len());
    mapped[..headers_to_copy].copy_from_slice(&file[..headers_to_copy]);

    for section in &headers.section_headers {
        if section.pointer_to_raw_data == 0 || section.size_of_raw_data == 0 {
            continue;
        }

        let source_start = section.pointer_to_raw_data as usize;
        let source_end = source_start + section.size_of_raw_data as usize;
        let mapped_start = section.virtual_address as usize;
        let mapped_end = mapped_start + section.size_of_raw_data as usize;
        mapped[mapped_start..mapped_end].copy_from_slice(&file[source_start..source_end]);
    }

    mapped
}

#[test]
fn raw_and_mapped_images_produce_the_same_section_data() {
    let source = build_test_pe();
    let raw = source.build();
    let mapped = map_file_image(&raw);

    let from_file_layout = PeImage::parse(&raw).expect("raw PE should parse");
    let from_explicit_file_layout =
        PeImage::parse_with_layout(&raw, SourceLayout::File).expect("raw PE should parse");
    let from_mapped_layout = PeImage::parse_mapped(&mapped).expect("mapped PE should parse");

    assert_eq!(
        from_file_layout.section_by_name(".text").unwrap().data,
        from_explicit_file_layout
            .section_by_name(".text")
            .unwrap()
            .data
    );
    assert_eq!(
        from_file_layout.section_by_name(".text").unwrap().data,
        from_mapped_layout.section_by_name(".text").unwrap().data
    );
    assert_eq!(
        from_mapped_layout.read_at_rva(0x1000, 0x180),
        Some(&[0xCC; 0x180][..])
    );
}

#[test]
fn mapped_image_convenience_apis_parse_directories() {
    let mut source = PeBuilder::new()
        .machine(MachineType::Amd64)
        .subsystem(Subsystem::WindowsCui)
        .entry_point(0x1000)
        .add_section(".text", vec![0xCC; 0x200], 0x60000020)
        .add_section(".rdata", vec![0; 0x1000], 0x40000040)
        .build();

    let mut imports = ImportTable::default();
    imports.add_dll(
        "KERNEL32.dll",
        vec![ImportThunk::Name {
            hint: 0,
            name: "ExitProcess".to_string(),
        }],
    );
    source
        .update_imports(imports, None)
        .expect("imports should be written");

    let raw = source.build();
    let mapped = map_file_image(&raw);
    let parsed = PeImage::parse_mapped(&mapped).expect("mapped PE should parse");
    let parsed_imports = parsed.imports().expect("mapped imports should parse");

    assert_eq!(parsed_imports.dlls.len(), 1);
    assert_eq!(parsed_imports.dlls[0].name, "KERNEL32.dll");
}

#[test]
fn mapped_images_include_virtual_zero_fill() {
    let mut raw = build_test_pe().build();
    let headers = PeHeaders::from_slice(&raw).expect("raw headers should parse");
    let data_index = headers
        .section_headers
        .iter()
        .position(|section| section.name_str() == ".data")
        .unwrap();
    let section_table_offset = headers.pe_offset as usize
        + 4
        + CoffHeader::SIZE
        + headers.coff_header.size_of_optional_header as usize;
    let data_header_offset = section_table_offset + data_index * SectionHeader::SIZE;

    // Make the in-memory extent larger than the initialized bytes in the file.
    raw[data_header_offset + 8..data_header_offset + 12].copy_from_slice(&0x300u32.to_le_bytes());

    let mapped = map_file_image(&raw);
    let from_file = PeImage::parse(&raw).expect("raw PE should parse");
    let from_mapped = PeImage::parse_mapped(&mapped).expect("mapped PE should parse");
    let data_rva = from_mapped
        .section_by_name(".data")
        .unwrap()
        .header
        .virtual_address;

    assert_eq!(from_file.read_at_rva(data_rva + 0x280, 1), None);
    assert_eq!(from_mapped.read_at_rva(data_rva + 0x280, 1), Some(&[0][..]));
}

#[test]
fn readers_and_rva_resolution_honor_the_selected_layout() {
    let source = build_test_pe();
    let raw = source.build();
    let mapped = map_file_image(&raw);
    let headers = PeHeaders::from_slice(&raw).expect("raw headers should parse");
    let text = headers.section_by_name(".text").unwrap();
    let text_rva = text.virtual_address + 0x20;

    assert_eq!(
        headers.rva_to_source_offset(text_rva, SourceLayout::File),
        Some(text.pointer_to_raw_data + 0x20)
    );
    assert_eq!(
        headers.rva_to_source_offset(text_rva, SourceLayout::Mapped),
        Some(text_rva)
    );
    assert_eq!(headers.rva_to_offset(0x40), Some(0x40));

    let mut prefixed_image = vec![0xA5; 0x80];
    prefixed_image.extend_from_slice(&mapped);
    let reader = SliceReader::new(&prefixed_image);
    let from_offset = PeImage::read_from(&reader, 0x80, SourceLayout::Mapped)
        .expect("mapped PE at a reader offset should parse");
    assert_eq!(from_offset.read_at_rva(0x1000, 1), Some(&[0xCC][..]));

    // SAFETY: `mapped` remains alive and unchanged for the reader's entire use.
    let base_reader = unsafe { BaseAddressReader::new(mapped.as_ptr(), Some(mapped.len())) };
    let from_base = PeImage::read_from(&base_reader, 0, SourceLayout::Mapped)
        .expect("mapped PE at a base address should parse");
    assert_eq!(from_base.read_at_rva(0x1000, 1), Some(&[0xCC][..]));
}
