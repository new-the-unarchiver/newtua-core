//! In-house XAR (`.xar` / `.pkg`) reader — decode only.
//!
//! XAR layout: a 28-byte big-endian header, a zlib-compressed XML table of
//! contents (TOC), then the heap holding each file's (optionally compressed)
//! bytes. We parse the header and TOC ourselves and read heap slices on demand,
//! so we depend only on `flate2`/`bzip2`/`xz2` (already in the workspace) plus a
//! tiny XML DOM (`roxmltree`) — no `apple-xar`, no `ring`.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use bzip2::read::BzDecoder;
use flate2::read::ZlibDecoder;
use xz2::read::XzDecoder;

use crate::archive::{
    ArchiveReader, Confidence, Entry, EntryKind, FormatHandler, FormatId, OpenOptions, ReadSeek,
    Source,
};
use crate::error::{Error, Result, io_err_to_corrupt};

/// Reject absurd TOC sizes early (defends against a crafted header forcing a
/// huge allocation). Real XAR TOCs are kilobytes to a few megabytes.
const MAX_TOC_COMPRESSED: u64 = 128 * 1024 * 1024;

// ── Heap codec ──────────────────────────────────────────────────────────────

/// Compression codec of a member's bytes in the heap, from `<encoding style>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Codec {
    /// `application/x-gzip` or `application/zlib` — a raw zlib stream (NOT gzip).
    Zlib,
    Bzip2,
    Xz,
    /// `application/octet-stream` or absent — stored verbatim.
    Stored,
}

/// Map a `<encoding style="…">` value to a codec. Unknown styles are rejected so
/// we never silently mis-decode a member.
fn codec_from_style(style: Option<&str>) -> Result<Codec> {
    Ok(match style {
        Some("application/x-gzip") | Some("application/zlib") => Codec::Zlib,
        Some("application/x-bzip2") => Codec::Bzip2,
        Some("application/x-xz") => Codec::Xz,
        Some("application/octet-stream") | None => Codec::Stored,
        Some(other) => {
            return Err(Error::Unsupported {
                format: "xar".into(),
                feature: format!("member codec {other}"),
            });
        }
    })
}

/// Where a file's bytes live in the heap, parallel to an `Entry`.
#[derive(Debug, Clone, Copy)]
struct HeapItem {
    /// Offset relative to the heap (i.e. to `heap_offset`).
    offset: u64,
    /// Compressed byte count in the heap.
    length: u64,
    codec: Codec,
}

// ── TOC helpers ───────────────────────────────────────────────────────────────

/// Text of the first direct-child element named `tag`, owned to avoid borrowing
/// the parsed document.
fn child_text(node: roxmltree::Node, tag: &str) -> Option<String> {
    node.children()
        .find(|c| c.is_element() && c.has_tag_name(tag))
        .and_then(|c| c.text())
        .map(str::to_string)
}

/// Parse a XAR mtime string (ISO 8601 like "2025-01-02T03:04:05" or
/// "…Z") to `SystemTime`. Best-effort; returns `None` on any parse failure.
fn parse_mtime(s: &str) -> Option<SystemTime> {
    let s = s.trim();
    // Expect at least "YYYY-MM-DDTHH:MM:SS" (19 chars); ignore any trailing zone.
    if s.len() < 19 {
        return None;
    }
    let year: i32 = s[0..4].parse().ok()?;
    let month: u32 = s[5..7].parse().ok()?;
    let day: u32 = s[8..10].parse().ok()?;
    let hour: u64 = s[11..13].parse().ok()?;
    let min: u64 = s[14..16].parse().ok()?;
    let sec: u64 = s[17..19].parse().ok()?;
    crate::datetime::civil_to_systime(year, month, day, hour, min, sec)
}

/// Recursively collect `<file>` nodes under `node`, joining `parent/name` into
/// full paths. Appends to `entries` and the parallel `items` (one slot per
/// entry; `None` for entries with no heap body).
fn collect(
    node: roxmltree::Node,
    parent: &Path,
    entries: &mut Vec<Entry>,
    items: &mut Vec<Option<HeapItem>>,
) -> Result<()> {
    for file in node
        .children()
        .filter(|c| c.is_element() && c.has_tag_name("file"))
    {
        let name = match child_text(file, "name") {
            Some(n) => n,
            // A `<file>` without a `<name>` is malformed; skip it.
            None => continue,
        };
        let path = parent.join(&name);
        let kind_str = child_text(file, "type").unwrap_or_else(|| "file".to_string());
        let mode = child_text(file, "mode").and_then(|s| u32::from_str_radix(s.trim(), 8).ok());
        let modified = child_text(file, "mtime").as_deref().and_then(parse_mtime);

        // The member body is the DIRECT-child `<data>` — never `<ea>` (extended
        // attribute streams), which carry their own `<encoding>`/`<offset>`.
        let data = file
            .children()
            .find(|c| c.is_element() && c.has_tag_name("data"));

        let (kind, size, item) = match kind_str.as_str() {
            "directory" => (EntryKind::Dir, 0u64, None),
            "symlink" => {
                let target = file
                    .children()
                    .find(|c| c.is_element() && c.has_tag_name("link"))
                    .and_then(|l| l.text())
                    .unwrap_or_default();
                (
                    EntryKind::Symlink {
                        target: PathBuf::from(target),
                    },
                    0u64,
                    None,
                )
            }
            // "file", "hardlink", or anything else → a regular file. A hardlink
            // reference without `<data>` reads as empty.
            _ => match data {
                Some(d) => {
                    let offset = child_text(d, "offset")
                        .and_then(|s| s.trim().parse().ok())
                        .unwrap_or(0);
                    let length = child_text(d, "length")
                        .and_then(|s| s.trim().parse().ok())
                        .unwrap_or(0);
                    let size = child_text(d, "size")
                        .and_then(|s| s.trim().parse().ok())
                        .unwrap_or(0);
                    let style = d
                        .children()
                        .find(|c| c.is_element() && c.has_tag_name("encoding"))
                        .and_then(|e| e.attribute("style"));
                    let codec = codec_from_style(style)?;
                    (
                        EntryKind::File,
                        size,
                        Some(HeapItem {
                            offset,
                            length,
                            codec,
                        }),
                    )
                }
                None => (EntryKind::File, 0u64, None),
            },
        };

        entries.push(Entry {
            path_raw: path.to_string_lossy().as_bytes().to_vec(),
            path: path.clone(),
            kind,
            size,
            mode,
            is_encrypted: false,
            modified,
        });
        items.push(item);

        // Recurse into directory contents (only directories carry `<file>`
        // children; recursing other nodes is harmless).
        collect(file, &path, entries, items)?;
    }
    Ok(())
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

    fn open(&self, mut src: Source, _opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        if matches!(src, Source::Stream { .. }) {
            return Err(Error::Unsupported {
                format: "xar".into(),
                feature: "streaming (xar requires seek)".into(),
            });
        }

        // Validate the 28-byte header up front (peek rewinds the source).
        let hdr = src.peek_header(28)?;
        if hdr.len() < 28 {
            return Err(Error::Corrupt("xar: file too short (< 28 bytes)".into()));
        }
        if &hdr[0..4] != b"xar!" {
            return Err(Error::Corrupt("xar: bad magic (expected 'xar!')".into()));
        }
        let header_len = u16::from_be_bytes([hdr[4], hdr[5]]) as u64;
        if header_len < 28 {
            return Err(Error::Corrupt(format!(
                "xar: header size field {header_len} < 28 (malformed)"
            )));
        }
        let toc_len_compressed = u64::from_be_bytes(hdr[8..16].try_into().unwrap());
        if toc_len_compressed == 0 || toc_len_compressed > MAX_TOC_COMPRESSED {
            return Err(Error::Corrupt(format!(
                "xar: implausible TOC length {toc_len_compressed}"
            )));
        }

        let mut inner: Box<dyn ReadSeek> = match src {
            Source::Seekable { inner, .. } => inner,
            Source::Stream { .. } => unreachable!("stream rejected above"),
        };

        // Skip the (possibly larger-than-28) header and read the compressed TOC.
        inner
            .seek(SeekFrom::Start(header_len))
            .map_err(io_err_to_corrupt)?;
        let mut toc_compressed = vec![0u8; toc_len_compressed as usize];
        inner
            .read_exact(&mut toc_compressed)
            .map_err(io_err_to_corrupt)?;
        let heap_offset = header_len + toc_len_compressed;

        // Inflate the zlib TOC, then parse the XML.
        let mut xml = String::new();
        ZlibDecoder::new(&toc_compressed[..])
            .read_to_string(&mut xml)
            .map_err(|e| Error::Corrupt(format!("xar: TOC inflate: {e}")))?;
        let doc = roxmltree::Document::parse(&xml)
            .map_err(|e| Error::Corrupt(format!("xar: TOC XML: {e}")))?;
        let toc = doc
            .descendants()
            .find(|n| n.has_tag_name("toc"))
            .ok_or_else(|| Error::Corrupt("xar: TOC has no <toc> element".into()))?;

        let mut entries: Vec<Entry> = Vec::new();
        let mut items: Vec<Option<HeapItem>> = Vec::new();
        collect(toc, Path::new(""), &mut entries, &mut items)?;

        Ok(Box::new(XarReaderInner {
            inner,
            heap_offset,
            entries,
            items,
        }))
    }
}

// ── Reader ────────────────────────────────────────────────────────────────────

struct XarReaderInner {
    inner: Box<dyn ReadSeek>,
    heap_offset: u64,
    entries: Vec<Entry>,
    /// Heap location per entry, parallel to `entries`; `None` for dirs, symlinks,
    /// and empty/bodyless files.
    items: Vec<Option<HeapItem>>,
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
            EntryKind::Dir | EntryKind::Symlink { .. } => return Ok(()),
            EntryKind::File => {}
        }
        // No heap body (empty file or hardlink reference) → nothing to write.
        let Some(item) = self.items[idx] else {
            return Ok(());
        };

        self.inner
            .seek(SeekFrom::Start(self.heap_offset + item.offset))
            .map_err(io_err_to_corrupt)?;
        let limited = (&mut self.inner).take(item.length);
        match item.codec {
            Codec::Stored => {
                let mut r = limited;
                std::io::copy(&mut r, out).map_err(io_err_to_corrupt)?;
            }
            Codec::Zlib => {
                std::io::copy(&mut ZlibDecoder::new(limited), out).map_err(io_err_to_corrupt)?;
            }
            Codec::Bzip2 => {
                std::io::copy(&mut BzDecoder::new(limited), out).map_err(io_err_to_corrupt)?;
            }
            Codec::Xz => {
                std::io::copy(&mut XzDecoder::new(limited), out).map_err(io_err_to_corrupt)?;
            }
        }
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
        assert!(t > SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn parse_mtime_with_zone_suffix() {
        // The trailing 'Z' (and anything past second 19) is ignored.
        assert!(parse_mtime("2026-06-25T08:50:04Z").is_some());
    }

    #[test]
    fn parse_mtime_short_returns_none() {
        assert!(parse_mtime("2025").is_none());
    }

    #[test]
    fn codec_from_style_mapping() {
        assert_eq!(
            codec_from_style(Some("application/x-gzip")).unwrap(),
            Codec::Zlib
        );
        assert_eq!(
            codec_from_style(Some("application/zlib")).unwrap(),
            Codec::Zlib
        );
        assert_eq!(
            codec_from_style(Some("application/x-bzip2")).unwrap(),
            Codec::Bzip2
        );
        assert_eq!(
            codec_from_style(Some("application/x-xz")).unwrap(),
            Codec::Xz
        );
        assert_eq!(
            codec_from_style(Some("application/octet-stream")).unwrap(),
            Codec::Stored
        );
        assert_eq!(codec_from_style(None).unwrap(), Codec::Stored);
        assert!(matches!(
            codec_from_style(Some("application/x-lzfse")),
            Err(Error::Unsupported { .. })
        ));
    }

    /// Regression: a XAR header with `size` field < 28 must return
    /// `Err(Error::Corrupt)` rather than panicking.
    #[test]
    fn header_size_below_28_returns_corrupt_not_panic() {
        use crate::archive::Source;
        use std::io::Cursor;

        let mut buf = [0u8; 28];
        buf[0..4].copy_from_slice(b"xar!");
        buf[4..6].copy_from_slice(&16u16.to_be_bytes()); // size = 16 < 28
        buf[6..8].copy_from_slice(&1u16.to_be_bytes());

        let src = Source::Seekable {
            inner: Box::new(Cursor::new(buf.to_vec())),
            path: None,
        };

        let result = XarHandler.open(src, &OpenOptions::default());
        assert!(matches!(result, Err(Error::Corrupt(_))));
    }
}
