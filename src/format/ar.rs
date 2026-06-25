use std::io::Write;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::archive::{
    ArchiveReader, Confidence, Entry, EntryKind, FormatHandler, FormatId, OpenOptions, ReadSeek,
    Source,
};
use crate::encoding::decode_names;
use crate::error::{Error, Result, io_err_to_corrupt};

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
            let entry = entry.map_err(io_err_to_corrupt)?;
            let header = entry.header();
            raw_names.push(header.identifier().to_vec());
            // ar stores unix permissions; keep only the permission bits.
            let mode = Some(header.mode() & 0o7777);
            let modified = Some(unix_secs_to_systime(header.mtime()));
            metas.push((header.size(), mode, modified));
        }

        // ar member names are raw bytes (Unix paths, no `\`); decode the whole
        // batch at once (single charset detection) like zip/tar so the
        // `--encoding` override applies uniformly. `raw_names` is not needed
        // afterwards, so consume both vectors instead of cloning.
        let names = decode_names(&raw_names, opts.encoding_override.as_deref());
        let mut entries = Vec::with_capacity(metas.len());
        for ((path_raw, name), (size, mode, modified)) in
            raw_names.into_iter().zip(names).zip(metas)
        {
            entries.push(Entry {
                path_raw,
                path: std::path::PathBuf::from(name),
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
        let mut entry = self.archive.jump_to_entry(idx).map_err(io_err_to_corrupt)?;
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
}
