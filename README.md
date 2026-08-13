# Portex

A self-contained PE (Portable Executable) file reader/writer library for Rust.

[![CI](https://github.com/coconutbird/portex/actions/workflows/ci.yml/badge.svg)](https://github.com/coconutbird/portex/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **Zero dependencies** - All PE structures defined from scratch, no Windows SDK required
- **`no_std` support** - Disable the default `std` feature to build `no_std + alloc`; bare-metal targets (UEFI loaders, kernels, embedded reverse-engineering tools) keep the full parser/builder/validation API
- **Multiple loading modes** - Load raw files, loader-mapped images, memory slices, or custom sources via the `Reader` trait
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

### Raw files and mapped images

Portex distinguishes raw file bytes from images already laid out by a PE loader:

```rust
use portex::{ImageLayout, PE};

// Raw file bytes: section data is at PointerToRawData.
let raw_pe = PE::parse(raw_file_bytes)?;

// Loader-mapped image: section data is at its RVA/VirtualAddress.
let mapped_pe = PE::parse_mapped(mapped_image)?;

// The explicit form is useful when the layout is selected dynamically.
let mapped_pe = PE::parse_with_layout(mapped_image, ImageLayout::Mapped)?;
```

For custom or remote-process sources, use
`PE::read_from(&reader, image_base_offset, ImageLayout::Mapped)`. Both layouts
are normalized into the same owned `PE` representation, so convenience methods
such as `imports()`, `exports()`, and `relocations()` work identically afterward.
`PEHeaders::rva_to_source_offset` provides the corresponding layout-aware,
image-relative RVA conversion when only headers are being loaded.

### `no_std` quick start

When `std` is disabled, you bring the bytes yourself — either as a `&[u8]` you already have in memory or through a custom `Reader`. The full `PE` API supports both raw and mapped layouts; individual directory parsers still accept an RVA-resolving closure for zero-copy or specialized access patterns.

```rust
use portex::PE;

// `image` points at a PE laid out in memory (sections at their RVAs).
let pe = PE::parse_mapped(image)?;
let relocations = pe.relocations()?;
relocations.apply(image_mut, delta, pe.is_64bit());
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

## Development

Toolchain and pre-commit hooks are managed via [mise](https://mise.jdx.dev/). After cloning:

```bash
mise install               # installs the pinned Rust toolchain + prek
mise run precommit-install # wires up .git/hooks (one-time)
mise run precommit         # runs all hooks across the whole tree
```

The pre-commit config (`.pre-commit-config.yaml`) runs `cargo fmt`, `cargo check`, `cargo clippy` for both the default and `--no-default-features` feature sets, plus the usual whitespace/EOF/TOML/YAML hygiene hooks. Hooks are executed by [`prek`](https://github.com/j178/prek), a fast Rust reimplementation of the `pre-commit` framework — `mise install` brings it in automatically.

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
