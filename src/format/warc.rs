use std::collections::HashMap;
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::time::SystemTime;

use flate2::read::MultiGzDecoder;
use warc::{RecordType, WarcHeader, WarcReader};

use crate::archive::{
    ArchiveReader, Confidence, Entry, EntryKind, FormatHandler, FormatId, OpenOptions, Source,
};
use crate::error::{Error, Result};

// ── Handler ───────────────────────────────────────────────────────────────────

pub struct WarcHandler;

impl FormatHandler for WarcHandler {
    fn id(&self) -> FormatId {
        FormatId::Warc
    }

    fn probe(&self, header: &[u8], name: Option<&str>) -> Confidence {
        // Plain WARC content magic: every WARC file starts with "WARC/1."
        if header.starts_with(b"WARC/1.") {
            return Confidence::MAGIC;
        }
        // Extension-based detection for .warc and .warc.gz (the latter hides
        // its WARC magic behind per-record gzip, so content probing won't work).
        if let Some(n) = name {
            let lower = n.to_ascii_lowercase();
            if lower.ends_with(".warc") || lower.ends_with(".warc.gz") {
                return Confidence::MAGIC;
            }
        }
        Confidence::NONE
    }

    fn open(&self, src: Source, _opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        // Determine whether this source is gzip-compressed.
        // Two signals: (1) file name ends with .warc.gz, (2) first two bytes
        // are the gzip magic 0x1f 0x8b.
        let path_is_gz = src
            .file_path()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.to_ascii_lowercase().ends_with(".warc.gz"));

        // Extract the underlying reader from Source.
        let reader: Box<dyn Read> = match src {
            Source::Seekable { mut inner, .. } => {
                inner.seek(SeekFrom::Start(0))?;
                inner
            }
            Source::Stream { inner, .. } => inner,
        };

        // If gzip, wrap in MultiGzDecoder which transparently handles
        // concatenated gzip members (one per WARC record in .warc.gz).
        // This is approach (B) from the spec — it keeps a single generic type
        // (WarcReader<BufReader<Box<dyn Read>>>) for both gzip and plain paths.
        let plain_reader: Box<dyn Read> = if path_is_gz {
            Box::new(MultiGzDecoder::new(reader))
        } else {
            // For plain .warc files, check gzip magic (first 2 bytes).
            // We cannot peek without consuming from a non-seekable stream, but
            // our Sources from open_single are always seekable; for safety,
            // rely on the path check above and fall through to plain WARC.
            reader
        };

        let warc_reader = WarcReader::new(BufReader::new(plain_reader));

        // Single-pass: iterate all records, keep response + resource records,
        // copy their (HTTP-header-stripped) bodies into one shared temp file.
        let mut temp = tempfile::NamedTempFile::new()?;
        let mut entries: Vec<Entry> = Vec::new();
        let mut offsets: Vec<(u64, u64)> = Vec::new();

        // Used for deduplication of derived path names.
        let mut seen_paths: HashMap<String, usize> = HashMap::new();

        for result in warc_reader.iter_records() {
            let record = result.map_err(|e| Error::Corrupt(e.to_string()))?;

            let rec_type = record.warc_type();
            if !matches!(rec_type, RecordType::Response | RecordType::Resource) {
                continue;
            }

            // Derive a safe relative path from the WARC-Target-URI. Records with
            // no URI fall back to their position among the emitted entries.
            let uri_opt = record.header(WarcHeader::TargetURI);
            let base_name = match &uri_opt {
                Some(uri) => uri_to_path(uri),
                None => format!("record-{}", entries.len()),
            };

            // Deduplicate: if the same base_name appeared before, append -1, -2, …
            let entry_name = dedup_path(&base_name, &mut seen_paths);

            // Timestamp from WARC-Date (RFC 3339; parse the common subset).
            let modified: Option<SystemTime> = record
                .header(WarcHeader::Date)
                .as_deref()
                .and_then(parse_warc_date);

            // Body: for `response` records, strip the HTTP response headers
            // (everything up to and including the first \r\n\r\n).
            let body_bytes = record.body();
            let payload: &[u8] = if matches!(rec_type, RecordType::Response) {
                strip_http_headers(body_bytes)
            } else {
                body_bytes
            };

            let offset = temp.seek(SeekFrom::End(0))?;
            temp.write_all(payload)?;
            let size = payload.len() as u64;

            let path = PathBuf::from(&entry_name);
            entries.push(Entry {
                path_raw: entry_name.into_bytes(),
                path,
                kind: EntryKind::File,
                size,
                mode: None,
                is_encrypted: false,
                modified,
            });
            offsets.push((offset, size));
        }

        let data = temp.into_temp_path();
        Ok(Box::new(WarcReader_ {
            entries,
            offsets,
            _data: data,
        }))
    }
}

// ── URI → safe relative path ──────────────────────────────────────────────────

/// Convert a WARC-Target-URI to a safe relative filesystem path.
///
/// Strategy:
/// 1. Strip the scheme and `://` prefix (e.g. `http://`).
/// 2. Drop query (`?…`) and fragment (`#…`).
/// 3. Remove any leading `/` from the resulting string.
/// 4. Collapse empty path segments and `.` components; reject `..` by
///    replacing each `..` segment with `_` (defensive, not abort).
///
/// Examples:
/// - `http://example.com/page.html` → `example.com/page.html`
/// - `https://example.com/` → `example.com`
/// - `http://example.com` → `example.com`
pub(crate) fn uri_to_path(uri: &str) -> String {
    // Strip scheme, then drop query (`?…`) and fragment (`#…`).
    let without_scheme = uri.split_once("://").map_or(uri, |(_, rest)| rest);
    let without_query = without_scheme
        .split_once('?')
        .map_or(without_scheme, |(left, _)| left);
    let without_qs = without_query
        .split_once('#')
        .map_or(without_query, |(left, _)| left);

    // Normalize slashes and filter out empty segments, `.`, and `..`.
    let segments: Vec<&str> = without_qs
        .split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .map(|s| if s == ".." { "_" } else { s })
        .collect();

    if segments.is_empty() {
        "index".to_string()
    } else {
        segments.join("/")
    }
}

/// Ensure `base` is unique in `seen`. Returns the (possibly suffixed) name and
/// updates the map.
fn dedup_path(base: &str, seen: &mut HashMap<String, usize>) -> String {
    let count = seen.entry(base.to_owned()).or_insert(0);
    let n = *count;
    *count += 1;
    if n == 0 {
        base.to_owned()
    } else {
        format!("{base}-{n}")
    }
}

// ── HTTP header stripping ─────────────────────────────────────────────────────

/// Strip HTTP response headers from a WARC response body.
///
/// WARC `response` records contain the raw HTTP response, including status
/// line and headers, separated from the payload by `\r\n\r\n`.  We return
/// everything after the first `\r\n\r\n`; if the separator is not found
/// (malformed or very short record), the whole body is returned as-is.
pub(crate) fn strip_http_headers(body: &[u8]) -> &[u8] {
    // The separator is b"\r\n\r\n" (4 bytes).
    let sep = b"\r\n\r\n";
    if let Some(pos) = body.windows(sep.len()).position(|w| w == sep) {
        &body[pos + sep.len()..]
    } else {
        body
    }
}

// ── WARC-Date parsing ─────────────────────────────────────────────────────────

/// Parse a WARC-Date string (ISO 8601 / RFC 3339 subset: `YYYY-MM-DDTHH:MM:SSZ`)
/// into a `SystemTime`.  Returns `None` on any parse failure.
fn parse_warc_date(date_str: &str) -> Option<SystemTime> {
    // Expected format: "2006-01-02T15:04:05Z" (20 chars, UTC only)
    let s = date_str.trim();
    if s.len() < 20 {
        return None;
    }
    let year: i32 = s[0..4].parse().ok()?;
    let month: u32 = s[5..7].parse().ok()?;
    let day: u32 = s[8..10].parse().ok()?;
    let hour: u64 = s[11..13].parse().ok()?;
    let min: u64 = s[14..16].parse().ok()?;
    let sec: u64 = s[17..19].parse().ok()?;

    // Range validation + the UTC conversion (including rejecting month > 12 etc.)
    // live in the shared helper, so a crafted date yields None, never a panic.
    crate::datetime::civil_to_systime(year, month, day, hour, min, sec)
}

// ── Reader ────────────────────────────────────────────────────────────────────

/// Internal name avoids clash with the `warc::WarcReader` type we import above.
struct WarcReader_ {
    entries: Vec<Entry>,
    /// Per-entry `(offset_in_temp, byte_count)`.
    offsets: Vec<(u64, u64)>,
    /// Temp file holding all payload bytes, concatenated.
    _data: tempfile::TempPath,
}

impl ArchiveReader for WarcReader_ {
    fn format(&self) -> FormatId {
        FormatId::Warc
    }

    fn entries(&mut self) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn read_entry(&mut self, idx: usize, out: &mut dyn Write) -> Result<()> {
        if idx >= self.entries.len() {
            return Err(Error::InvalidIndex(idx));
        }
        let (offset, size) = self.offsets[idx];
        crate::detect::read_temp_slice(&self._data, offset, size, out)
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::Confidence;

    // ── probe tests ──────────────────────────────────────────────────────────

    #[test]
    fn id_is_warc() {
        assert_eq!(WarcHandler.id(), FormatId::Warc);
    }

    #[test]
    fn parse_warc_date_valid_and_out_of_range() {
        // A well-formed UTC date parses.
        assert!(parse_warc_date("1970-01-01T00:00:00Z") == Some(SystemTime::UNIX_EPOCH));
        assert!(parse_warc_date("2020-06-15T12:30:00Z").is_some());
        // A crafted month > 12 must return None, NOT panic on days_in_month[13].
        assert_eq!(parse_warc_date("2020-13-01T00:00:00Z"), None);
        assert_eq!(parse_warc_date("2020-00-01T00:00:00Z"), None);
        assert_eq!(parse_warc_date("1969-12-31T23:59:59Z"), None); // pre-epoch
    }

    #[test]
    fn probe_positive_magic() {
        let header = b"WARC/1.0\r\nWARC-Type: warcinfo\r\n";
        assert_eq!(WarcHandler.probe(header, None), Confidence::MAGIC);
    }

    #[test]
    fn probe_positive_warc_gz_name() {
        // The content starts with gzip magic, not WARC — extension triggers detection.
        let header = &[0x1f_u8, 0x8b, 0x08, 0x00];
        assert_eq!(
            WarcHandler.probe(header, Some("archive.warc.gz")),
            Confidence::MAGIC
        );
    }

    #[test]
    fn probe_positive_warc_extension() {
        // .warc with WARC content magic.
        let header = b"WARC/1.0\r\n";
        assert_eq!(
            WarcHandler.probe(header, Some("site.warc")),
            Confidence::MAGIC
        );
    }

    #[test]
    fn probe_negative_zip() {
        assert_eq!(WarcHandler.probe(b"PK\x03\x04", None), Confidence::NONE);
    }

    // ── uri_to_path tests ────────────────────────────────────────────────────

    #[test]
    fn uri_to_path_http() {
        assert_eq!(
            uri_to_path("http://example.com/page.html"),
            "example.com/page.html"
        );
    }

    #[test]
    fn uri_to_path_root() {
        assert_eq!(uri_to_path("https://example.com/"), "example.com");
    }

    #[test]
    fn uri_to_path_no_scheme() {
        assert_eq!(uri_to_path("example.com/data"), "example.com/data");
    }

    #[test]
    fn uri_to_path_query_stripped() {
        assert_eq!(
            uri_to_path("http://example.com/search?q=foo&bar=1"),
            "example.com/search"
        );
    }

    #[test]
    fn uri_to_path_dotdot_sanitized() {
        assert_eq!(
            uri_to_path("http://example.com/../etc/passwd"),
            "example.com/_/etc/passwd"
        );
    }

    // ── strip_http_headers tests ─────────────────────────────────────────────

    #[test]
    fn strip_http_headers_basic() {
        let body = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>body</html>";
        assert_eq!(strip_http_headers(body), b"<html>body</html>");
    }

    #[test]
    fn strip_http_headers_no_separator_returns_full() {
        let body = b"no-separator-here";
        assert_eq!(strip_http_headers(body), body.as_ref());
    }

    #[test]
    fn strip_http_headers_empty_payload() {
        let body = b"HTTP/1.1 200 OK\r\n\r\n";
        assert_eq!(strip_http_headers(body), b"");
    }
}
