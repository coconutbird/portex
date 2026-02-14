# Portex

A self-contained PE (Portable Executable) file reader/writer library for Rust.

[![CI](https://github.com/coconutbird/portex/actions/workflows/ci.yml/badge.svg)](https://github.com/coconutbird/portex/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **Zero dependencies** - All PE structures defined from scratch, no Windows SDK required
- **Multiple loading modes** - Load from files, memory slices, or custom sources via the `Reader` trait
- **Partial loading** - Use `PEHeaders` for lightweight header-only parsing
- **Full PE support** - Imports, exports, resources, relocations, TLS, debug info, exceptions, and more
- **Builder pattern** - Construct new PE structures programmatically
- **Validation** - Built-in PE validation with detailed error reporting

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
portex = "0.1"
```

## Quick Start

```rust
use portex::{PE, PEHeaders};

// Load and parse a full PE file
let pe = PE::from_file("example.exe")?;
println!("64-bit: {}", pe.is_64bit());
println!("Is DLL: {}", pe.is_dll());

// Access imports
if let Some(imports) = pe.imports() {
    for dll in imports.dlls() {
        println!("Imports from: {}", dll.name);
    }
}

// Or just load headers (efficient for large files)
let headers = PEHeaders::from_file("example.dll")?;
println!("Entry point: {:#x}", headers.entry_point());
```

## Modules

| Module | Description |
|--------|-------------|
| `pe` | Main `PE` and `PEHeaders` types |
| `import` | Import table parsing and building |
| `export` | Export table parsing and building |
| `resource` | Resource directory parsing and building |
| `reloc` | Base relocations |
| `tls` | Thread Local Storage |
| `debug` | Debug directory and CodeView info |
| `exception` | Exception handling (x64 unwind info) |
| `section` | Section headers and data |
| `validation` | PE validation utilities |

## Building PEs

```rust
use portex::{PE, MachineType, Subsystem};
use portex::section::characteristics;

let pe = PE::builder()
    .machine(MachineType::Amd64)
    .subsystem(Subsystem::WindowsCui)
    .add_section(".text", code, characteristics::CODE | characteristics::EXECUTE | characteristics::READ)
    .add_section(".data", data, characteristics::INITIALIZED_DATA | characteristics::READ | characteristics::WRITE)
    .build()?;
```

## Fuzzing

Fuzz testing is set up using `cargo-fuzz` (requires Linux/macOS or WSL):

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Run fuzzer
cargo +nightly fuzz run fuzz_pe_parse
```

## License

MIT

