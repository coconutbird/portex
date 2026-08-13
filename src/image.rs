//! Whole-image parsing, editing, and building APIs.
//!
//! Use [`PeImage`] when bytes are already normalized as either a raw file or a
//! loader-mapped image. Use [`PeFile`] when raw-only state such as overlay bytes,
//! Authenticode certificates, and file gaps must survive a round trip.

pub use crate::builder::PeBuilder;
pub use crate::pe::{MissingSectionData, ParseOptions, PeHeaders, PeImage, SourceLayout};
pub use crate::pe_file::PeFile;
