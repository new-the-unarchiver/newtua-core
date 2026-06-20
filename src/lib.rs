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

#[cfg(test)]
mod smoke {
    #[test]
    fn workspace_builds() {
        assert_eq!(2 + 2, 4);
    }
}
