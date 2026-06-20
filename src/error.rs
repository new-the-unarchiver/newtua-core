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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_messages_are_human_readable() {
        let e = Error::WrongPassword;
        assert!(e.to_string().to_lowercase().contains("password"));

        let e = Error::Unsupported { format: "rar".into(), feature: "solid".into() };
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
}
