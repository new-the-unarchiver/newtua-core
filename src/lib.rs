//! newtua-core — archive extraction engine.

pub mod error;
pub use error::{Error, Result};

pub mod archive;
pub use archive::{
    ArchiveReader, Confidence, Entry, EntryKind, EntrySink, FormatHandler, FormatId, OpenOptions,
    ReadSeek, SinkStep, SinkWriter, Source,
};

pub mod encoding;
pub use encoding::{decode_names, detect_encoding};

pub mod path_safety;
pub use path_safety::{safe_join, safe_symlink_target};

pub mod decompress;
pub use decompress::{Compressor, decompressor};

mod datetime;

/// Third-party code carried inside this crate rather than depended on.
///
/// See `src/vendor/<name>/VENDORED.md` for what each one is, why it is not a
/// dependency, and how to compare it against its upstream.
///
/// The `unsafe` ban sits here rather than on any one module: neither vendored
/// reader has a line of it today, and a rule that holds for the whole shelf
/// keeps holding for whatever lands on it next. The crate as a whole cannot
/// carry the ban — `datetime.rs` and `format/hfsplus.rs` need it.
#[forbid(unsafe_code)]
mod vendor;

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
