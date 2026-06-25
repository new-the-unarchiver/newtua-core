use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("unknown or unsupported archive format")]
    UnknownFormat,

    #[error("format {format}: feature not supported: {feature}")]
    Unsupported { format: String, feature: String },

    #[error("archive is encrypted; a password is required")]
    Encrypted,

    #[error("incorrect password")]
    WrongPassword,

    #[error("archive is corrupt: {0}")]
    Corrupt(String),

    #[error("unsafe path in archive (path traversal): {0}")]
    PathTraversal(String),

    #[error("missing volume for multi-part archive: {0}")]
    MissingVolume(String),

    #[error("internal: entry index out of range: {0}")]
    InvalidIndex(usize),
}

/// Map a third-party crate's `io::Error` onto our error model: structural
/// problems (`InvalidData` / `UnexpectedEof`) become `Corrupt`, everything else
/// stays `Io`. Shared by the format handlers (cab, ar, cpio, deb, xar) so the
/// classification lives in one place.
pub(crate) fn io_err_to_corrupt(e: std::io::Error) -> Error {
    match e.kind() {
        std::io::ErrorKind::InvalidData | std::io::ErrorKind::UnexpectedEof => {
            Error::Corrupt(e.to_string())
        }
        _ => Error::Io(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_err_to_corrupt_classifies_kinds() {
        let corrupt = io_err_to_corrupt(std::io::Error::from(std::io::ErrorKind::InvalidData));
        assert!(matches!(corrupt, Error::Corrupt(_)));
        let eof = io_err_to_corrupt(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        assert!(matches!(eof, Error::Corrupt(_)));
        let io = io_err_to_corrupt(std::io::Error::from(std::io::ErrorKind::NotFound));
        assert!(matches!(io, Error::Io(_)));
    }

    #[test]
    fn display_messages_are_human_readable() {
        let e = Error::WrongPassword;
        assert!(e.to_string().to_lowercase().contains("password"));

        let e = Error::Unsupported {
            format: "rar".into(),
            feature: "solid".into(),
        };
        let msg = e.to_string();
        assert!(msg.contains("rar") && msg.contains("solid"));
    }

    #[test]
    fn io_error_converts() {
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "x");
        let e: Error = io.into();
        assert!(matches!(e, Error::Io(_)));
    }
}

#[cfg(test)]
mod edge {
    use super::*;

    #[test]
    fn corrupt_carries_context() {
        let e = Error::Corrupt("bad central directory".into());
        assert!(e.to_string().contains("bad central directory"));
    }

    #[test]
    fn path_traversal_carries_offending_path() {
        let e = Error::PathTraversal("../../etc/passwd".into());
        assert!(e.to_string().contains("../../etc/passwd"));
    }

    #[test]
    fn invalid_index_display_contains_index_and_number() {
        let e = Error::InvalidIndex(7);
        let msg = e.to_string();
        assert!(msg.contains("7"), "expected '7' in: {msg}");
        assert!(msg.contains("index"), "expected 'index' in: {msg}");
    }
}
