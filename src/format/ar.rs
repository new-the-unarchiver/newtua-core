use std::io::Write;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::archive::{
    ArchiveReader, Confidence, Entry, EntryKind, FormatHandler, FormatId, OpenOptions, ReadSeek,
    Source,
};
use crate::encoding::decode_names;
use crate::error::{Error, Result};

pub struct ArHandler;

impl FormatHandler for ArHandler {
    fn id(&self) -> FormatId {
        FormatId::Ar
    }

    fn probe(&self, header: &[u8], _name: Option<&str>) -> Confidence {
        if header.starts_with(b"!<arch>\n") {
            Confidence::MAGIC
        } else {
            Confidence::NONE
        }
    }

    fn open(&self, src: Source, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        let inner: Box<dyn ReadSeek> = match src {
            Source::Seekable { inner, .. } => inner,
            Source::Stream { .. } => {
                return Err(Error::Unsupported {
                    format: "ar".into(),
                    feature: "streaming (ar requires seek)".into(),
                });
            }
        };
        let mut archive = ar::Archive::new(inner);

        // First pass: read every member header. No member data is read here —
        // `read_entry` pulls it lazily via `jump_to_entry`. The `ar` crate skips
        // special members (the GNU `//` name table and the symbol table), so
        // every entry we see is a real file.
        let mut raw_names: Vec<Vec<u8>> = Vec::new();
        let mut metas: Vec<(u64, Option<u32>, Option<SystemTime>)> = Vec::new();
        while let Some(entry) = archive.next_entry() {
            let entry = entry.map_err(map_ar_err)?;
            let header = entry.header();
            raw_names.push(header.identifier().to_vec());
            // ar stores unix permissions; keep only the permission bits.
            let mode = Some(header.mode() & 0o7777);
            let modified = Some(unix_secs_to_systime(header.mtime()));
            metas.push((header.size(), mode, modified));
        }

        // ar member names are raw bytes (Unix paths, no `\`); decode like
        // zip/tar so the `--encoding` override applies uniformly.
        let names = decode_names(&raw_names, opts.encoding_override.as_deref());
        let mut entries = Vec::with_capacity(metas.len());
        for (i, (size, mode, modified)) in metas.into_iter().enumerate() {
            entries.push(Entry {
                path_raw: raw_names[i].clone(),
                path: std::path::PathBuf::from(&names[i]),
                kind: EntryKind::File,
                size,
                mode,
                is_encrypted: false,
                modified,
            });
        }

        Ok(Box::new(ArReader { archive, entries }))
    }
}

/// Convert an `ar` mtime (unix seconds, always non-negative) to `SystemTime`.
fn unix_secs_to_systime(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

/// Map an `ar`-crate `io::Error` onto our error model.
fn map_ar_err(e: std::io::Error) -> Error {
    match e.kind() {
        std::io::ErrorKind::InvalidData | std::io::ErrorKind::UnexpectedEof => {
            Error::Corrupt(e.to_string())
        }
        _ => Error::Io(e),
    }
}

struct ArReader {
    archive: ar::Archive<Box<dyn ReadSeek>>,
    entries: Vec<Entry>,
}

impl ArchiveReader for ArReader {
    fn format(&self) -> FormatId {
        FormatId::Ar
    }

    fn entries(&mut self) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn read_entry(&mut self, idx: usize, out: &mut dyn Write) -> Result<()> {
        if idx >= self.entries.len() {
            return Err(Error::InvalidIndex(idx));
        }
        // `jump_to_entry` indexes real members in the same order as `next_entry`
        // (special members skipped), so `idx` matches our `entries` order.
        let mut entry = self.archive.jump_to_entry(idx).map_err(map_ar_err)?;
        std::io::copy(&mut entry, out)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_detects_ar_magic() {
        assert_eq!(ArHandler.probe(b"!<arch>\n", None), Confidence::MAGIC);
    }

    #[test]
    fn probe_rejects_other() {
        assert_eq!(ArHandler.probe(b"PK\x03\x04", None), Confidence::NONE);
    }

    #[test]
    fn probe_rejects_empty() {
        assert_eq!(ArHandler.probe(b"", None), Confidence::NONE);
    }

    #[test]
    fn probe_rejects_short_prefix() {
        // The magic is 8 bytes; a 7-byte prefix must not match.
        assert_eq!(ArHandler.probe(b"!<arch>", None), Confidence::NONE);
    }

    #[test]
    fn ar_handler_id_is_ar() {
        assert_eq!(ArHandler.id(), FormatId::Ar);
    }

    #[test]
    fn unix_secs_to_systime_epoch_and_value() {
        assert_eq!(unix_secs_to_systime(0), UNIX_EPOCH);
        assert_eq!(
            unix_secs_to_systime(60),
            UNIX_EPOCH + Duration::from_secs(60)
        );
    }

    #[test]
    fn map_ar_err_invalid_data_is_corrupt() {
        let e = std::io::Error::from(std::io::ErrorKind::InvalidData);
        assert!(matches!(map_ar_err(e), Error::Corrupt(_)));
    }

    #[test]
    fn map_ar_err_not_found_is_io() {
        let e = std::io::Error::from(std::io::ErrorKind::NotFound);
        assert!(matches!(map_ar_err(e), Error::Io(_)));
    }
}
