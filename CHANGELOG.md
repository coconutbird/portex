# Changelog

This project follows [Semantic Versioning](https://semver.org/).

## 0.3.0 - 2026-08-15

### Breaking changes

- Replaced the legacy `PE`, `PEFile`, `PEHeaders`, `PEBuilder`, `ImageLayout`,
  and `Reader` names with `PeImage`, `PeFile`, `PeHeaders`, `PeBuilder`,
  `SourceLayout`, and `ReadAt`.
- Removed the deprecated `rebuild_all`, `cli_header`, `PeImage::security`,
  `security_from_bytes`, `prepare_security_update`,
  `try_prepare_security_update`, and `into_pe` compatibility helpers.
- Moved byte-for-byte certificate and overlay operations to `PeFile`; `PeImage`
  now represents a normalized executable image.
- Made the source layout explicit when parsing loader-mapped or relocated
  in-memory images.

### Added

- Parsing for raw PE files, loader-mapped images, and mapped images relocated
  to a runtime base, with layout-correct RVA translation.
- Lossless `PeFile` support for headers, section gaps, certificate data, and
  overlays.
- Core PE directory support including imports, delay and bound imports,
  exports, resources, relocations, exceptions, TLS, load configuration,
  debug data, security certificates, and the CLR header/blob handoff.
- `no_std + alloc` support through `nostdio`, plus fuzz targets for header and
  full-image parsing.

### Changed

- Reorganized the public facade and implementation modules around the
  `PeImage`, `PeFile`, and `PeBuilder` workflows.
- Split implementation files into focused modules of at most 1,000 lines.
- Strengthened linting, documentation, architecture coverage, malformed-input
  tests, layout tests, round-trip tests, and CI validation.
- Set Rust 1.88 as the minimum supported Rust version.

### Migration from 0.2

| 0.2 name | 0.3 replacement |
| --- | --- |
| `PE` | `PeImage` for normalized images, or `PeFile` for lossless raw files |
| `PEFile` | `PeFile` |
| `PEHeaders` | `PeHeaders` |
| `PEBuilder` | `PeBuilder` |
| `ImageLayout` | `SourceLayout` |
| `Reader` | `ReadAt` |

Portex handles PE executable images, not standalone COFF object files. CLR
metadata stream and table parsing remains the responsibility of a dedicated
metadata crate; Portex exposes the CLR header and metadata blob needed for that
handoff.
