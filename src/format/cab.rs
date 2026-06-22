use std::io::Write;
use std::time::{Duration, SystemTime};

use crate::archive::{
    ArchiveReader, Confidence, Entry, EntryKind, FormatHandler, FormatId, OpenOptions, ReadSeek,
    Source,
};
use crate::error::{Error, Result};

pub struct CabHandler;

impl FormatHandler for CabHandler {
    fn id(&self) -> FormatId {
        FormatId::Cab
    }

    fn probe(&self, header: &[u8], _name: Option<&str>) -> Confidence {
        if header.starts_with(b"MSCF") {
            Confidence::MAGIC
        } else {
            Confidence::NONE
        }
    }

    fn open(&self, src: Source, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        open_cab(src, opts)
    }
}

/// Convert a unix timestamp (seconds since the epoch) to `SystemTime`.
/// Returns `None` for pre-1970 timestamps (we only model non-negative times).
fn unix_secs_to_systime(secs: i64) -> Option<SystemTime> {
    if secs < 0 {
        None
    } else {
        Some(SystemTime::UNIX_EPOCH + Duration::from_secs(secs as u64))
    }
}

/// Map a `cab`-crate `io::Error` onto our error model.
fn map_cab_err(e: std::io::Error) -> Error {
    match e.kind() {
        std::io::ErrorKind::InvalidData | std::io::ErrorKind::UnexpectedEof => {
            Error::Corrupt(e.to_string())
        }
        _ => Error::Io(e),
    }
}

fn open_cab(src: Source, _opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
    let inner: Box<dyn ReadSeek> = match src {
        Source::Seekable { inner, .. } => inner,
        Source::Stream { .. } => {
            return Err(Error::Unsupported {
                format: "cab".into(),
                feature: "streaming (cab requires seek)".into(),
            });
        }
    };
    let cab = cab::Cabinet::new(inner).map_err(map_cab_err)?;

    let mut entries: Vec<Entry> = Vec::new();
    let mut names: Vec<String> = Vec::new();
    let mut quantum: Vec<bool> = Vec::new();
    for folder in cab.folder_entries() {
        let is_quantum = matches!(
            folder.compression_type(),
            cab::CompressionType::Quantum(_, _)
        );
        for file in folder.file_entries() {
            let raw = file.name();
            let path = std::path::PathBuf::from(raw.replace('\\', "/"));
            let modified = file
                .datetime()
                .map(|dt| dt.assume_utc().unix_timestamp())
                .and_then(unix_secs_to_systime);
            entries.push(Entry {
                path_raw: raw.as_bytes().to_vec(),
                path,
                kind: EntryKind::File,
                size: file.uncompressed_size() as u64,
                mode: None,
                is_encrypted: false,
                modified,
            });
            names.push(raw.to_string());
            quantum.push(is_quantum);
        }
    }

    Ok(Box::new(CabReader {
        cab,
        entries,
        names,
        quantum,
    }))
}

struct CabReader {
    cab: cab::Cabinet<Box<dyn ReadSeek>>,
    entries: Vec<Entry>,
    /// Original CAB names (with `\`), passed verbatim to `read_file`.
    names: Vec<String>,
    /// True when entry `i`'s folder uses Quantum compression (unreadable).
    quantum: Vec<bool>,
}

impl ArchiveReader for CabReader {
    fn format(&self) -> FormatId {
        FormatId::Cab
    }

    fn entries(&mut self) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn read_entry(&mut self, idx: usize, out: &mut dyn Write) -> Result<()> {
        if idx >= self.entries.len() {
            return Err(Error::InvalidIndex(idx));
        }
        if self.quantum[idx] {
            return Err(Error::Unsupported {
                format: "cab".into(),
                feature: "Quantum compression".into(),
            });
        }
        let name = self.names[idx].clone();
        let mut reader = self.cab.read_file(&name).map_err(map_cab_err)?;
        std::io::copy(&mut reader, out)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_detects_mscf_magic() {
        assert_eq!(CabHandler.probe(b"MSCF\0\0\0\0", None), Confidence::MAGIC);
    }

    #[test]
    fn probe_rejects_other() {
        assert_eq!(CabHandler.probe(b"PK\x03\x04", None), Confidence::NONE);
    }

    #[test]
    fn probe_rejects_empty() {
        assert_eq!(CabHandler.probe(b"", None), Confidence::NONE);
    }

    #[test]
    fn cab_handler_id_is_cab() {
        assert_eq!(CabHandler.id(), FormatId::Cab);
    }

    #[test]
    fn unix_secs_to_systime_epoch_and_negative() {
        assert_eq!(unix_secs_to_systime(0), Some(SystemTime::UNIX_EPOCH));
        assert_eq!(
            unix_secs_to_systime(60),
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(60))
        );
        assert_eq!(unix_secs_to_systime(-1), None);
    }
}
