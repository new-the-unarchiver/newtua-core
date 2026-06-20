//! newtua-core — движок распаковки архивов.

pub mod error;
pub use error::{Error, Result};

pub mod archive;
pub use archive::{
    ArchiveReader, Confidence, Entry, FormatHandler, FormatId, OpenOptions, Source,
};

#[cfg(test)]
mod smoke {
    #[test]
    fn workspace_builds() {
        assert_eq!(2 + 2, 4);
    }
}
