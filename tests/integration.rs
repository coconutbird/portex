//! Integration tests for portex PE library.
//!
//! These tests perform roundtrip operations: create/parse → modify → rebuild → re-parse.

use portex::{
    debug::CodeViewRsds,
    loadconfig::{LoadConfigDirectory, LoadConfigDirectory64},
    section::characteristics,
    tls::TlsInfo,
    ExceptionDirectory, ExportTable, ImportTable, ImportThunk, MachineType, PEBuilder,
    RelocationTable, RelocationType, Subsystem, PE,
};

/// Test that PEBuilder creates a valid PE that can be parsed back.
#[test]
fn test_pe_builder_roundtrip() {
    // Create a minimal 64-bit PE
    let pe = PEBuilder::new()
        .machine(MachineType::Amd64)
        .subsystem(Subsystem::WindowsCui)
        .entry_point(0x1000)
        .add_section(
            ".text",
            vec![0xCC; 0x200],
            characteristics::CODE | characteristics::EXECUTE | characteristics::READ,
        ) // CODE | EXECUTE | READ
        .add_section(
            ".data",
            vec![0x00; 0x100],
            characteristics::INITIALIZED_DATA | characteristics::READ | characteristics::WRITE,
        ) // INITIALIZED_DATA | READ | WRITE
        .build();

    // Re-parse the built PE
    let bytes = pe.build();
    let parsed = PE::parse(&bytes).expect("Failed to parse built PE");

    // Verify structure
    assert!(parsed.is_64bit());
    assert_eq!(parsed.coff_header.machine, MachineType::Amd64 as u16);
    assert_eq!(parsed.sections.len(), 2);
    assert_eq!(parsed.sections[0].name(), ".text");
    assert_eq!(parsed.sections[1].name(), ".data");
}

/// Test that PEBuilder creates a valid 32-bit PE.
#[test]
fn test_pe_builder_32bit_roundtrip() {
    let pe = PEBuilder::new()
        .machine(MachineType::I386)
        .subsystem(Subsystem::WindowsGui)
        .entry_point(0x1000)
        .add_section(".text", vec![0x90; 0x100], 0x60000020)
        .build();

    let bytes = pe.build();
    let parsed = PE::parse(&bytes).expect("Failed to parse 32-bit PE");

    assert!(!parsed.is_64bit());
    assert_eq!(parsed.coff_header.machine, MachineType::I386 as u16);
}

/// Test import table roundtrip.
#[test]
fn test_import_table_roundtrip() {
    // Create PE with a section for imports
    let mut pe = PEBuilder::new()
        .machine(MachineType::Amd64)
        .subsystem(Subsystem::WindowsCui)
        .entry_point(0x1000)
        .add_section(".text", vec![0xCC; 0x200], 0x60000020)
        .add_section(".rdata", vec![0x00; 0x1000], 0x40000040) // INITIALIZED_DATA | READ
        .build();

    // Create import table with proper ImportThunk types
    let mut imports = ImportTable::default();
    imports.add_dll(
        "KERNEL32.dll",
        vec![
            ImportThunk::Name {
                hint: 0,
                name: "GetLastError".to_string(),
            },
            ImportThunk::Name {
                hint: 0,
                name: "ExitProcess".to_string(),
            },
        ],
    );
    imports.add_dll(
        "USER32.dll",
        vec![ImportThunk::Name {
            hint: 0,
            name: "MessageBoxA".to_string(),
        }],
    );

    // Update imports
    pe.update_imports(imports.clone(), None)
        .expect("Failed to update imports");

    // Rebuild and re-parse
    let bytes = pe.build();
    let parsed = PE::parse(&bytes).expect("Failed to parse PE with imports");

    // Verify imports
    let parsed_imports = parsed.imports().expect("Failed to get imports");
    assert_eq!(parsed_imports.dlls.len(), 2);
}

/// Test export table roundtrip.
#[test]
fn test_export_table_roundtrip() {
    let mut pe = PEBuilder::new()
        .machine(MachineType::Amd64)
        .subsystem(Subsystem::WindowsCui)
        .entry_point(0x1000)
        .add_section(".text", vec![0xCC; 0x200], 0x60000020)
        .add_section(".rdata", vec![0x00; 0x1000], 0x40000040)
        .build();

    // Create export table
    let mut exports = ExportTable::default();
    exports.set_dll_name("TestModule.dll");
    exports.add_export(Some("TestFunction1"), 0x1000);
    exports.add_export(Some("TestFunction2"), 0x1010);

    pe.update_exports(exports, None)
        .expect("Failed to update exports");

    let bytes = pe.build();
    let parsed = PE::parse(&bytes).expect("Failed to parse PE with exports");

    let parsed_exports = parsed.exports().expect("Failed to get exports");
    assert_eq!(parsed_exports.exports.len(), 2);
}

/// Test relocation table roundtrip.
#[test]
fn test_relocation_roundtrip() {
    let mut pe = PEBuilder::new()
        .machine(MachineType::Amd64)
        .subsystem(Subsystem::WindowsCui)
        .entry_point(0x1000)
        .add_section(".text", vec![0xCC; 0x200], 0x60000020)
        .add_section(".reloc", vec![0x00; 0x1000], 0x42000040) // DISCARDABLE | INITIALIZED_DATA | READ
        .build();

    // Create relocation table
    let mut relocs = RelocationTable::default();
    relocs.add_relocation(0x1000, RelocationType::Dir64);
    relocs.add_relocation(0x1008, RelocationType::Dir64);
    relocs.add_relocation(0x2000, RelocationType::HighLow);

    pe.update_relocations(relocs, None)
        .expect("Failed to update relocations");

    let bytes = pe.build();
    let parsed = PE::parse(&bytes).expect("Failed to parse PE with relocations");

    let parsed_relocs = parsed.relocations().expect("Failed to get relocations");
    assert!(!parsed_relocs.blocks.is_empty());
}

/// Test exception directory roundtrip.
#[test]
fn test_exception_roundtrip() {
    let mut pe = PEBuilder::new()
        .machine(MachineType::Amd64)
        .subsystem(Subsystem::WindowsCui)
        .entry_point(0x1000)
        .add_section(".text", vec![0xCC; 0x400], 0x60000020)
        .add_section(".pdata", vec![0x00; 0x1000], 0x40000040)
        .build();

    // Create exception directory
    let mut exceptions = ExceptionDirectory::default();
    exceptions.add_function(0x1000, 0x1100, 0x3000);
    exceptions.add_function(0x1200, 0x1300, 0x3100);

    pe.update_exception(&exceptions, None)
        .expect("Failed to update exceptions");

    let bytes = pe.build();
    let parsed = PE::parse(&bytes).expect("Failed to parse PE with exceptions");

    let parsed_exceptions = parsed
        .exception_directory()
        .expect("Failed to get exceptions");
    assert_eq!(parsed_exceptions.functions.len(), 2);
}

/// Test TLS directory roundtrip.
#[test]
fn test_tls_roundtrip() {
    let mut pe = PEBuilder::new()
        .machine(MachineType::Amd64)
        .subsystem(Subsystem::WindowsCui)
        .entry_point(0x1000)
        .add_section(".text", vec![0xCC; 0x200], 0x60000020)
        .add_section(".tls", vec![0x00; 0x1000], 0xC0000040) // INITIALIZED_DATA | READ | WRITE
        .build();

    // Create TLS info with default (no callbacks)
    let tls_info = TlsInfo::default();

    pe.update_tls(&tls_info, None)
        .expect("Failed to update TLS");

    let bytes = pe.build();
    let parsed = PE::parse(&bytes).expect("Failed to parse PE with TLS");

    // Verify TLS directory is present
    let tls = parsed.tls().expect("Failed to get TLS");
    assert!(tls.is_some());
}

/// Test debug directory roundtrip.
#[test]
fn test_debug_roundtrip() {
    let mut pe = PEBuilder::new()
        .machine(MachineType::Amd64)
        .subsystem(Subsystem::WindowsCui)
        .entry_point(0x1000)
        .add_section(".text", vec![0xCC; 0x200], 0x60000020)
        .add_section(".rdata", vec![0x00; 0x1000], 0x40000040)
        .build();

    // Add CodeView debug info using update_debug_codeview
    let codeview = CodeViewRsds {
        guid: [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ],
        age: 1,
        pdb_path: "C:\\test.pdb".to_string(),
    };
    pe.update_debug_codeview(&codeview, None)
        .expect("Failed to update debug");

    let bytes = pe.build();
    let parsed = PE::parse(&bytes).expect("Failed to parse PE with debug");

    // Verify debug directory is present
    let debug_info = parsed.debug_info().expect("Failed to get debug info");
    assert!(debug_info.is_some());
}

/// Test LoadConfig roundtrip.
#[test]
fn test_loadconfig_roundtrip() {
    let mut pe = PEBuilder::new()
        .machine(MachineType::Amd64)
        .subsystem(Subsystem::WindowsCui)
        .entry_point(0x1000)
        .add_section(".text", vec![0xCC; 0x200], 0x60000020)
        .add_section(".rdata", vec![0x00; 0x2000], 0x40000040)
        .build();

    // Create LoadConfig with security cookie
    let config64 = LoadConfigDirectory64 {
        size: LoadConfigDirectory64::MIN_SIZE as u32,
        security_cookie: 0x140002000, // VA of security cookie
        ..Default::default()
    };
    let loadconfig = LoadConfigDirectory::Config64(config64);

    pe.update_load_config(&loadconfig, None)
        .expect("Failed to update LoadConfig");

    let bytes = pe.build();
    let parsed = PE::parse(&bytes).expect("Failed to parse PE with LoadConfig");

    // Verify LoadConfig is present
    let config = parsed.load_config().expect("Failed to get LoadConfig");
    assert!(config.is_some());
}

/// Test section management.
#[test]
fn test_section_management() {
    let mut pe = PEBuilder::new()
        .machine(MachineType::Amd64)
        .subsystem(Subsystem::WindowsCui)
        .entry_point(0x1000)
        .add_section(".text", vec![0xCC; 0x100], 0x60000020)
        .build();

    assert_eq!(pe.sections.len(), 1);

    // Add a new section (note: returns () not Result)
    pe.add_section_with_data(".data", vec![0x00; 0x100], 0xC0000040);

    assert_eq!(pe.sections.len(), 2);
    assert!(pe.find_section(".data").is_some());

    // Rebuild and re-parse
    let bytes = pe.build();
    let parsed = PE::parse(&bytes).expect("Failed to parse PE with added section");

    assert_eq!(parsed.sections.len(), 2);
}

/// Test that multiple update methods can be called on a PE.
/// Note: This test verifies the update methods don't panic or error,
/// but doesn't verify full roundtrip since section appending behavior
/// varies based on implementation.
#[test]
fn test_multiple_updates_succeed() {
    let mut pe = PEBuilder::new()
        .machine(MachineType::Amd64)
        .subsystem(Subsystem::WindowsCui)
        .entry_point(0x1000)
        .add_section(".text", vec![0xCC; 0x1000], 0x60000020)
        .add_section(".rdata", vec![0x00; 0x2000], 0x40000040)
        .build();

    // Add imports
    let mut imports = ImportTable::default();
    imports.add_dll(
        "KERNEL32.dll",
        vec![ImportThunk::Name {
            hint: 0,
            name: "GetLastError".to_string(),
        }],
    );
    pe.update_imports(imports, None)
        .expect("Failed to add imports");

    // Add exports
    let mut exports = ExportTable::default();
    exports.set_dll_name("test.dll");
    exports.add_export(Some("TestFunc"), 0x1000);
    pe.update_exports(exports, None)
        .expect("Failed to add exports");

    // Rebuild
    let bytes = pe.build();
    let parsed = PE::parse(&bytes).expect("Failed to parse modified PE");

    // Verify imports were written
    assert!(!parsed.imports().expect("imports").dlls.is_empty());
    // Verify exports were written
    assert!(!parsed.exports().expect("exports").exports.is_empty());
}

/// Test that we can parse and validate the built PE.
#[test]
fn test_pe_validation() {
    let pe = PEBuilder::new()
        .machine(MachineType::Amd64)
        .subsystem(Subsystem::WindowsCui)
        .entry_point(0x1000)
        .add_section(".text", vec![0xCC; 0x200], 0x60000020)
        .add_section(".data", vec![0x00; 0x100], 0xC0000040)
        .build();

    let bytes = pe.build();
    let parsed = PE::parse(&bytes).expect("Failed to parse PE");

    // Validate the parsed PE
    let issues = parsed.validate();

    // A freshly built PE should have no critical issues
    // (there may be warnings for things like missing characteristics)
    for issue in &issues {
        // Just check we don't panic when validating
        let _ = format!("{:?}", issue);
    }
}
