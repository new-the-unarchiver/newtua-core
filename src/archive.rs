use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatId { Zip, Tar, Gzip, Bzip2, Xz, SevenZ, Rar }

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Confidence(pub u8);

impl Confidence {
    pub const NONE: Confidence = Confidence(0);
    pub const MAGIC: Confidence = Confidence(100);
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub path_raw: Vec<u8>,
    pub path: PathBuf,
    pub size: u64,
    pub is_dir: bool,
    pub is_encrypted: bool,
    pub modified: Option<SystemTime>,
}

#[derive(Debug, Clone, Default)]
pub struct OpenOptions {
    pub password: Option<String>,
    pub encoding_override: Option<String>,
}

/// Источник архива: либо seekable-файл, либо чистый поток.
pub enum Source {
    Seekable { inner: Box<dyn ReadSeek>, path: Option<PathBuf> },
    Stream { inner: Box<dyn Read>, path: Option<PathBuf> },
}

pub trait ReadSeek: Read + Seek {}
impl<T: Read + Seek> ReadSeek for T {}

impl Source {
    pub fn path(p: &Path) -> Result<Source> {
        let f = std::fs::File::open(p)?;
        Ok(Source::Seekable { inner: Box::new(f), path: Some(p.to_path_buf()) })
    }

    pub fn file_path(&self) -> Option<&Path> {
        match self {
            Source::Seekable { path, .. } | Source::Stream { path, .. } => path.as_deref(),
        }
    }

    /// Прочитать первые `n` байт, не нарушая последующее чтение (для seekable —
    /// откат в начало; для stream — буфер не возвращается, поэтому header
    /// читается только из seekable-источников).
    pub fn peek_header(&mut self, n: usize) -> Result<Vec<u8>> {
        match self {
            Source::Seekable { inner, .. } => {
                let mut buf = vec![0u8; n];
                let read = read_up_to(inner, &mut buf)?;
                buf.truncate(read);
                inner.seek(SeekFrom::Start(0))?;
                Ok(buf)
            }
            Source::Stream { .. } => Err(Error::UnknownFormat),
        }
    }
}

fn read_up_to(r: &mut dyn Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

pub trait FormatHandler {
    fn id(&self) -> FormatId;
    fn probe(&self, header: &[u8], name: Option<&str>) -> Confidence;
    fn open(&self, src: Source, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>>;
}

pub trait ArchiveReader {
    fn format(&self) -> FormatId;
    fn entries(&mut self) -> Result<&[Entry]>;
    fn read_entry(&mut self, idx: usize, out: &mut dyn Write) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confidence_ordering() {
        assert!(Confidence::MAGIC > Confidence::NONE);
        assert_eq!(Confidence::NONE, Confidence(0));
    }

    #[test]
    fn open_options_default_is_empty() {
        let o = OpenOptions::default();
        assert!(o.password.is_none());
        assert!(o.encoding_override.is_none());
    }

    #[test]
    fn entry_construction() {
        let e = Entry {
            path_raw: b"a.txt".to_vec(),
            path: std::path::PathBuf::from("a.txt"),
            size: 5,
            is_dir: false,
            is_encrypted: false,
            modified: None,
        };
        assert_eq!(e.size, 5);
        assert!(!e.is_dir);
    }
}
