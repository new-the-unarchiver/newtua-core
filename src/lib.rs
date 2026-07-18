//! newtua-core — archive extraction engine.

pub mod error;
pub use error::{Error, Result};

pub mod archive;
pub use archive::{
    ArchiveReader, Confidence, Entry, EntryKind, FormatHandler, FormatId, OpenOptions, ReadSeek,
    Source,
};

pub mod encoding;
pub use encoding::decode_names;

pub mod path_safety;
pub use path_safety::{safe_join, safe_symlink_target};

pub mod decompress;
pub use decompress::{Compressor, decompressor};

mod datetime;

pub mod format;

pub mod volume;
pub use volume::{ConcatReader, volume_members};

pub mod detect;
pub use detect::{detect_compressor, open, registry};

pub mod extract;
pub use extract::{
    ExtractOptions, ExtractReport, Flow, ProgressEvent, ProgressFn, common_root, extract_all,
    wrapper_name,
};

pub mod macos;
pub use macos::is_macos_metadata;

#[cfg(test)]
mod smoke {
    #[test]
    fn workspace_builds() {
        assert_eq!(2 + 2, 4);
    }
}
