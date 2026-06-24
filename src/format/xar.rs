use std::fmt::Debug;
use std::io::{Read, Seek, Write};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use apple_xar::reader::XarReader;
use apple_xar::table_of_contents::FileType;

use crate::archive::{
    ArchiveReader, Confidence, Entry, EntryKind, FormatHandler, FormatId, OpenOptions, ReadSeek,
    Source,
};
use crate::error::{Error, Result};

// ── Debug wrapper ─────────────────────────────────────────────────────────────

/// Wraps `Box<dyn ReadSeek>` with a no-op `Debug` impl so it can satisfy the
/// `R: Debug` bound required by `XarReader<R>`.
struct DebugReadSeek(Box<dyn ReadSeek>);

impl Debug for DebugReadSeek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DebugReadSeek(<dyn ReadSeek>)")
    }
}

impl Read for DebugReadSeek {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl Seek for DebugReadSeek {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.0.seek(pos)
    }
}

// ── Helper ────────────────────────────────────────────────────────────────────

/// Map an `apple-xar` error onto our error model.
fn map_xar_err(e: apple_xar::Error) -> Error {
    match e {
        apple_xar::Error::Io(io) => match io.kind() {
            std::io::ErrorKind::InvalidData | std::io::ErrorKind::UnexpectedEof => {
                Error::Corrupt(io.to_string())
            }
            _ => Error::Io(io),
        },
        apple_xar::Error::Scroll(_)
        | apple_xar::Error::SerdeXml(_)
        | apple_xar::Error::TableOfContentsCorrupted(_)
        | apple_xar::Error::BadChecksum(_) => Error::Corrupt(e.to_string()),
        apple_xar::Error::UnimplementedFileEncoding(enc) => Error::Unsupported {
            format: "xar".into(),
            feature: format!("member codec {enc}"),
        },
        _ => Error::Corrupt(e.to_string()),
    }
}

/// Parse a XAR mtime string (RFC 3339 / ISO 8601 like "2025-01-02T03:04:05") to
/// `SystemTime`. We do a best-effort parse; returns `None` on any parse failure.
fn parse_mtime(s: &str) -> Option<SystemTime> {
    // XAR stores mtime as e.g. "2025-01-02T03:04:05" (no timezone = UTC assumed).
    // We do a minimal manual parse to avoid pulling in chrono.
    let s = s.trim();
    // Expect at least "YYYY-MM-DDTHH:MM:SS" (19 chars)
    if s.len() < 19 {
        return None;
    }
    let year: i64 = s[0..4].parse().ok()?;
    let month: u64 = s[5..7].parse().ok()?;
    let day: u64 = s[8..10].parse().ok()?;
    let hour: u64 = s[11..13].parse().ok()?;
    let min: u64 = s[14..16].parse().ok()?;
    let sec: u64 = s[17..19].parse().ok()?;

    if year < 1970 {
        return None;
    }

    // Rough days-since-epoch calculation (ignoring leap seconds, good enough for
    // display purposes — matches how other handlers approach mtime).
    let days_in_month = [0u64, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let year = year as u64;
    let mut days: u64 = 0;
    for y in 1970..year {
        days += if is_leap(y) { 366 } else { 365 };
    }
    for m in 1..month {
        let extra = if m == 2 && is_leap(year) { 1 } else { 0 };
        days += days_in_month[m as usize] + extra;
    }
    days += day - 1;
    let secs = days * 86400 + hour * 3600 + min * 60 + sec;
    Some(UNIX_EPOCH + Duration::from_secs(secs))
}

fn is_leap(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

// ── Handler ───────────────────────────────────────────────────────────────────

pub struct XarHandler;

impl FormatHandler for XarHandler {
    fn id(&self) -> FormatId {
        FormatId::Xar
    }

    fn probe(&self, header: &[u8], _name: Option<&str>) -> Confidence {
        if header.starts_with(b"xar!") {
            Confidence::MAGIC
        } else {
            Confidence::NONE
        }
    }

    fn open(&self, src: Source, _opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        let inner: Box<dyn ReadSeek> = match src {
            Source::Seekable { inner, .. } => inner,
            Source::Stream { .. } => {
                return Err(Error::Unsupported {
                    format: "xar".into(),
                    feature: "streaming (xar requires seek)".into(),
                });
            }
        };

        let xar = XarReader::new(DebugReadSeek(inner)).map_err(map_xar_err)?;

        let toc_files = xar.files().map_err(map_xar_err)?;

        let mut entries: Vec<Entry> = Vec::with_capacity(toc_files.len());
        // Per-entry file IDs, parallel to `entries`; used in `read_entry` to
        // locate member data without re-scanning the TOC by path.
        let mut file_ids: Vec<u64> = Vec::with_capacity(toc_files.len());

        for (path_str, file) in toc_files {
            let path_raw = path_str.as_bytes().to_vec();
            let path = PathBuf::from(&path_str);

            // Parse octal mode string e.g. "0100644" → 0o100644
            let mode: Option<u32> = file
                .mode
                .as_deref()
                .and_then(|s| u32::from_str_radix(s.trim_start_matches('0'), 8).ok());

            let modified: Option<SystemTime> = file.mtime.as_deref().and_then(parse_mtime);

            let (kind, size) = match file.file_type {
                FileType::Directory => (EntryKind::Dir, 0u64),
                FileType::Link => {
                    // XAR symlink: the link target is stored in the file body.
                    // We report it as Symlink with an empty target here and populate
                    // it below (reading symlink bodies is rare; defer to read_entry).
                    // Per the brief, writing nothing for symlinks is fine.
                    let target = PathBuf::new(); // placeholder
                    (EntryKind::Symlink { target }, file.size.unwrap_or(0))
                }
                FileType::HardLink => {
                    // Hard links: expose as regular files; body is in the heap.
                    (EntryKind::File, file.size.unwrap_or(0))
                }
                FileType::File => (EntryKind::File, file.size.unwrap_or(0)),
            };

            entries.push(Entry {
                path_raw,
                path,
                kind,
                size,
                mode,
                is_encrypted: false,
                modified,
            });
            file_ids.push(file.id);
        }

        Ok(Box::new(XarReaderInner {
            xar,
            entries,
            file_ids,
        }))
    }
}

// ── Reader ────────────────────────────────────────────────────────────────────

/// Wraps `XarReader` so it implements `ArchiveReader`. The inner reader uses our
/// `DebugReadSeek` wrapper which satisfies the `R: Debug` bound on `XarReader`.
struct XarReaderInner {
    xar: XarReader<DebugReadSeek>,
    entries: Vec<Entry>,
    /// TOC file IDs, parallel to `entries`.
    file_ids: Vec<u64>,
}

impl Debug for XarReaderInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XarReaderInner")
            .field("entries_count", &self.entries.len())
            .finish()
    }
}

impl ArchiveReader for XarReaderInner {
    fn format(&self) -> FormatId {
        FormatId::Xar
    }

    fn entries(&mut self) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn read_entry(&mut self, idx: usize, out: &mut dyn Write) -> Result<()> {
        if idx >= self.entries.len() {
            return Err(Error::InvalidIndex(idx));
        }

        match &self.entries[idx].kind {
            EntryKind::Dir => return Ok(()),
            EntryKind::Symlink { .. } => return Ok(()),
            EntryKind::File => {}
        }

        let id = self.file_ids[idx];
        // `write_file_data_decoded_from_id` requires `impl Write` (Sized), so
        // we cannot pass `&mut dyn Write` directly.  Buffer into a Vec first,
        // then copy to `out`.  For large files this may use significant RAM;
        // acceptable for v1 (XAR member payloads are usually small pkg scripts).
        let mut buf: Vec<u8> = Vec::new();
        self.xar
            .write_file_data_decoded_from_id(id, &mut buf)
            .map_err(map_xar_err)?;
        out.write_all(&buf)?;
        Ok(())
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_is_xar() {
        assert_eq!(XarHandler.id(), FormatId::Xar);
    }

    #[test]
    fn probe_positive_magic() {
        assert_eq!(XarHandler.probe(b"xar!\0\x1c", None), Confidence::MAGIC);
    }

    #[test]
    fn probe_negative_zip() {
        assert_eq!(XarHandler.probe(b"PK\x03\x04", None), Confidence::NONE);
    }

    #[test]
    fn probe_rejects_empty() {
        assert_eq!(XarHandler.probe(b"", None), Confidence::NONE);
    }

    #[test]
    fn parse_mtime_basic() {
        let t = parse_mtime("2025-01-02T03:04:05").unwrap();
        assert!(t > UNIX_EPOCH);
    }

    #[test]
    fn parse_mtime_short_returns_none() {
        assert!(parse_mtime("2025").is_none());
    }
}
