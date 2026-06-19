# Portex

A self-contained PE (Portable Executable) file reader/writer library for Rust.

[![CI](https://github.com/coconutbird/portex/actions/workflows/ci.yml/badge.svg)](https://github.com/coconutbird/portex/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **Zero dependencies** - All PE structures defined from scratch, no Windows SDK required
- **`no_std` support** - Disable the default `std` feature to build `no_std + alloc`; bare-metal targets (UEFI loaders, kernels, embedded reverse-engineering tools) keep the full parser/builder/validation API
- **Multiple loading modes** - Load from files, memory slices, or custom sources via the `Reader` trait
- **Partial loading** - Use `PEHeaders` for lightweight header-only parsing
- **Full PE support** - Imports, exports, resources, relocations, TLS, debug info, exceptions, and more
- **Builder pattern** - Construct new PE structures programmatically
- **Validation** - Built-in PE validation with detailed error reporting

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
portex = "0.2"
```

For `no_std + alloc` consumers (UEFI loaders, kernels, etc.), disable the default `std` feature:

```toml
[dependencies]
portex = { version = "0.2", default-features = false }
```

### Feature flags

- **`std`** _(default on)_ — file-IO and `std::io` interop. Disable to build `no_std + alloc`. Gated items:
  - `PE::from_file`, `PE::write_to_file`
  - `PEHeaders::from_file`
  - `FileReader` (struct + `Reader` impl)
  - `ErrorKind::Io(io::Error)` variant
  - `From<io::Error>` and `std::error::Error` impls on `Error`

Without `std`, the crate is `no_std + alloc`. Parsers, builders, validation, in-memory `Reader` implementations (`SliceReader`, `VecReader`, `BaseAddressReader`), `RelocationTable::apply`, and the rest of the PE API stay available — bring your own bytes via `&[u8]`, a custom `Reader`, or an RVA-resolving closure passed to the directory parsers.

## Quick Start

```rust
use portex::{PE, PEHeaders};

// Load and parse a full PE file
let pe = PE::from_file("example.exe")?;
println!("64-bit: {}", pe.is_64bit());
println!("Is DLL: {}", pe.is_dll());

// Access imports
let imports = pe.imports()?;
for dll in &imports.dlls {
    println!("Imports from: {}", dll.name);
}

// Or just load headers (efficient for large files)
let headers = PEHeaders::from_file("example.dll")?;
println!("Entry point: {:#x}", headers.entry_point());
```

### `no_std` quick start

When `std` is disabled, you bring the bytes yourself — either as a `&[u8]` you already have in memory, or via a closure that reads at an RVA. Headers parse from a slice; directory walkers (relocations, imports, exports, resources, …) take an RVA-resolving closure so you can bridge whatever "where the image lives" abstraction you have (a remote-process handle, a hypervisor view of guest memory, a UEFI-loaded image).

```rust
use portex::{DataDirectoryType, PEHeaders, RelocationTable};

// `image` points at a PE laid out in memory (sections at their RVAs).
let headers = PEHeaders::from_slice(image)?;
let dir = headers
    .optional_header
    .data_directories()
    .get(DataDirectoryType::BaseReloc.as_index())
    .copied()
    .filter(|d| d.virtual_address != 0 && d.size != 0);

if let Some(dir) = dir {
    // For an in-memory image, RVA == offset from `image_base`.
    let read_at_rva = |rva: u32, len: usize| -> Option<Vec<u8>> {
        let r = rva as usize;
        let end = r.checked_add(len)?;
        (end <= image.len()).then(|| image[r..end].to_vec())
    };
    let table = RelocationTable::parse(dir.virtual_address, dir.size, read_at_rva)?;
    table.apply(image_mut, delta, /* is_64bit */ true);
}
```

## Modules

| Module         | Description                             |
| -------------- | --------------------------------------- |
| `pe`           | Main `PE` and `PEHeaders` types         |
| `import`       | Import table parsing and building       |
| `export`       | Export table parsing and building       |
| `resource`     | Resource directory parsing and building |
| `reloc`        | Base relocations                        |
| `tls`          | Thread Local Storage                    |
| `debug`        | Debug directory and CodeView info       |
| `exception`    | Exception handling (x64 unwind info)    |
| `section`      | Section headers and data                |
| `validation`   | PE validation utilities                 |
| `bound_import` | Bound import directory                  |
| `delay_import` | Delay-load import directory             |
| `security`     | Authenticode certificate directory      |
| `clr`          | CLR/.NET runtime header                 |
| `loadconfig`   | Load configuration directory            |

## Building PEs from Scratch

```rust
use portex::{PE, MachineType, Subsystem};
use portex::section::characteristics;

let code = vec![0xCC; 256]; // Your code here

let pe = PE::builder()
    .machine(MachineType::Amd64)
    .subsystem(Subsystem::WindowsCui)
    .entry_point(0x1000)
    .add_section(".text", code, characteristics::CODE | characteristics::EXECUTE | characteristics::READ)
    .build();

std::fs::write("output.exe", pe.build())?;
```

## Modifying PEs

```rust
use portex::PE;

// Parse, modify, and rebuild
let mut pe = PE::from_file("example.exe")?;

// Modify imports, exports, resources, etc.
let imports = pe.imports()?;
pe.update_imports(imports, None)?;

// Write back to disk
std::fs::write("modified.exe", pe.build())?;
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
