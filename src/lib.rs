//! newtua-core — движок распаковки архивов.

pub mod error;
pub use error::{Error, Result};

pub mod archive;
pub use archive::{
    ArchiveReader, Confidence, Entry, FormatHandler, FormatId, OpenOptions, ReadSeek, Source,
};

pub mod encoding;
pub use encoding::decode_names;

pub mod path_safety;
pub use path_safety::safe_join;

pub mod decompress;
pub use decompress::{decompressor, Compressor};

pub mod format;

pub mod volume;
pub use volume::{volume_members, ConcatReader};

pub mod detect;
pub use detect::{detect_compressor, open, registry};

pub mod extract;
pub use extract::{common_root, extract_all, ExtractOptions, ExtractReport};

#[cfg(test)]
mod smoke {
    #[test]
    fn workspace_builds() {
        assert_eq!(2 + 2, 4);
    }
}
