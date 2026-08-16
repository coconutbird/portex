# Portex

Portex is a `no_std`-friendly parser, editor, and builder for PE executable
images. It deliberately distinguishes byte-for-byte files from images already
mapped by a loader, because their RVA-to-source translations are different.

[![CI](https://github.com/coconutbird/portex/actions/workflows/ci.yml/badge.svg)](https://github.com/coconutbird/portex/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## What it supports

- Raw PE files, loader-mapped images, and mapped images relocated to a runtime
  base.
- PE32 and PE32+ headers, checked RVA/VA conversion, section layout, zero-filled
  virtual tails, overlays, Authenticode certificate tables, and checksums.
- Imports, delay imports, bound imports, sparse/aliased exports, resources, base
  relocations, TLS, debug records, load configuration, and x64/ARM/ARM64
  exception tables.
- Rich headers plus the PE-level CLR/CLI header and raw metadata blob.
- Lossless raw-file round trips through `PeFile`, including noncanonical gaps,
  certificate bytes, and arbitrary overlays when the layout is unchanged.
- Strict malformed-input checks, fallible builders, structural validation, and
  both sequential and positional I/O.
- `no_std + alloc` support. Sequential I/O uses
  [`nostdio`](https://github.com/coconutbird/nostdio); positional `ReadAt`
  access remains available for mapped and remote images.

Portex targets PE executable images such as executables, DLLs, drivers, and
UEFI-style images. Standalone COFF object files and COFF symbol tables are out
of scope. CLR metadata streams and tables are also intentionally out of scope;
pass `PeImage::clr_metadata()` to a metadata crate such as `clrmeta`.

## Installation

```toml
[dependencies]
portex = "0.3"
```

For `no_std + alloc`:

```toml
[dependencies]
portex = { version = "0.3", default-features = false }
```

Portex 0.3 requires Rust 1.88 or newer.

The default `std` feature adds filesystem helpers, `FileReader`, standard
I/O error conversion, and `nostdio`'s standard-library integration. Parsing,
building, mapped-image handling, validation, in-memory readers, and stream APIs
remain available without it.

## Core types

| Type | Use it for |
| --- | --- |
| `PeFile` | A complete raw file whose certificates, gaps, and overlay must be preserved |
| `PeImage` | A normalized executable image parsed from raw or loader-mapped bytes |
| `PeHeaders` | Header-only inspection without loading section payloads |
| `PeBuilder` | Constructing a new executable image |

## Quick start

```rust,no_run
use portex::PeFile;

let mut file = PeFile::from_file("example.exe")?;
let image = file.image();

println!("64-bit: {}", image.is_64bit());
println!("entry point RVA: {:#x}", image.entry_point());

for dll in &image.imports()?.dlls {
    println!("imports from {}", dll.name);
}

// Edits go through the normalized image while PeFile retains raw-only state.
let imports = file.image().imports()?;
file.image_mut().update_imports(imports, None)?;
file.write_to_file("modified.exe")?;
# Ok::<(), portex::Error>(())
```

Use `PeImage::parse(raw_bytes)` when overlays and certificates do not need to
survive rebuilding, or `PeFile::parse(raw_bytes)` when they do.

## Raw files versus mapped images

```rust,no_run
use portex::{ParseOptions, PeImage, SourceLayout};

# let raw_file_bytes: &[u8] = &[];
# let mapped_image: &[u8] = &[];
// Raw file: section payloads are addressed by PointerToRawData.
let raw = PeImage::parse(raw_file_bytes)?;

// Loader-mapped image: section payloads are addressed by RVA.
let mapped = PeImage::parse_mapped(mapped_image)?;

// Preserve the actual load base for VA-bearing directories such as TLS.
let relocated = PeImage::parse_mapped_at(mapped_image, 0x0000_7ff6_0000_0000)?;

// Explicit options also support missing/discarded mapped section pages.
let partial = PeImage::parse_with_options(
    mapped_image,
    ParseOptions::mapped().allow_missing_section_data(),
)?;

assert_eq!(raw.source_layout(), SourceLayout::File);
assert_eq!(mapped.source_layout(), SourceLayout::Mapped);
assert_eq!(relocated.runtime_image_base(), Some(0x0000_7ff6_0000_0000));
# Ok::<(), portex::Error>(())
```

`PeImage::to_mapped_image()` creates loader-style bytes at the preferred image
base. `to_mapped_image_at(base)` also applies supported base relocations for a
different runtime base.

For a remote process or another random-access source, implement `ReadAt` and
use:

```text
PeImage::read_from(&reader, source_offset, SourceLayout::Mapped)
PeImage::read_mapped_from(&reader, source_offset, runtime_image_base)
```

`PeHeaders::rva_to_source_offset` exposes the same layout-aware translation
without reading all sections.

## Sequential and positional I/O

`nostdio` supplies cursor-based `Read`, `Write`, and `Seek` traits:

```rust,no_run
use portex::PeFile;
use portex::io::Cursor;

# let raw_file_bytes: &[u8] = &[];
let mut input = Cursor::new(raw_file_bytes);
let file = PeFile::from_stream(&mut input)?;

let mut output = Cursor::new(Vec::new());
file.write_to(&mut output)?;
# Ok::<(), portex::Error>(())
```

Portex also keeps a positional `ReadAt` abstraction because it is a better fit
for process memory, sparse address spaces, concurrent callers, and sources that
must not share cursor state. `SeekReader` adapts a `nostdio::Read + Seek`
source to `ReadAt`.

## Building an image

```rust,no_run
use portex::section::characteristics;
use portex::{MachineType, PeBuilder, Subsystem};

let image = PeBuilder::new()
    .machine(MachineType::Amd64)
    .subsystem(Subsystem::WindowsCui)
    .entry_point(0x1000)
    .add_section(
        ".text",
        vec![0xcc; 256],
        characteristics::CODE | characteristics::EXECUTE | characteristics::READ,
    )
    .try_build()?;

let raw_file = image.try_build()?;
assert!(!raw_file.is_empty());
# Ok::<(), portex::Error>(())
```

Directory builders and image update methods are fallible. Prefer the `try_*`
variants when input or edits are not fully trusted.

## Module layout

The ergonomic facades cover the common entry points:

| Module | Contents |
| --- | --- |
| `image` | `PeImage`, `PeFile`, `PeHeaders`, parsing options, and `PeBuilder` |
| `headers` | DOS, COFF image, optional, section, and data-directory header types |
| `directories` | Imports, exports, resources, relocations, TLS, exceptions, debug, security, CLR hand-off, and related builders |
| `io` | `nostdio` traits/types plus positional `ReadAt` readers |

Specialized modules such as `import`, `resource`, `reloc`, `security`, and
`validation` remain public for focused imports.

Nested implementation modules use Rust's modern `module.rs` plus
`module/child.rs` layout; the older `module/mod.rs` form is intentionally not
used.

## Development

Toolchain and pre-commit hooks are managed with
[`mise`](https://mise.jdx.dev/):

```bash
mise install
mise run precommit-install
mise run precommit
```

The hooks run rustfmt and Clippy over every crate target with both the full
feature set and `no_std + alloc`, and lint the separate fuzz package. CI runs
the same matrix plus both test and rustdoc feature modes. Warnings are denied
by each package manifest, so the policy also applies to direct Cargo commands.

Fuzz targets live under `fuzz/` and can be run with `cargo-fuzz` on
Linux/macOS or WSL:

```bash
cargo +nightly fuzz run fuzz-pe-headers
cargo +nightly fuzz run fuzz-pe-parse
```

## License

Licensed under the [MIT License](LICENSE).
