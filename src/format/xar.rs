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

/// Cap the *decompressed* TOC to bound a zlib-bomb (a tiny compressed TOC that
/// inflates to gigabytes). Past this the XML is truncated and parsing fails →
/// `Corrupt`, a safe fail-closed path.
const MAX_TOC_UNCOMPRESSED: u64 = 256 * 1024 * 1024;

/// Cap XML element nesting. `roxmltree`'s parser recurses once per nesting level
/// and overflows the stack on a deeply-nested document (~100–150 levels on a
/// 2 MiB stack — an uncatchable process abort). We reject deeper TOCs *before*
/// parsing. Real XAR trees nest only a handful of levels, so 64 is generous.
const MAX_TOC_DEPTH: usize = 64;

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

/// First index of `needle` in `b[from..]`.
fn memchr_from(b: &[u8], from: usize, needle: u8) -> Option<usize> {
    b.get(from..)?
        .iter()
        .position(|&c| c == needle)
        .map(|p| from + p)
}

/// First index of `pat` in `b[from..]`.
fn find_from(b: &[u8], from: usize, pat: &[u8]) -> Option<usize> {
    if pat.is_empty() || from > b.len() || b.len() - from < pat.len() {
        return None;
    }
    b[from..]
        .windows(pat.len())
        .position(|w| w == pat)
        .map(|p| from + p)
}

/// Conservatively report whether XML element nesting ever exceeds `limit`.
///
/// Robust against comments, CDATA, processing instructions/declarations, and
/// `>` inside quoted attribute values, so a crafted TOC cannot hide nesting
/// from this guard. Runs before `roxmltree::parse` (which would otherwise
/// recurse per level and overflow the stack on a deeply-nested document). On
/// any malformed/unterminated construct it returns `false` and lets the real
/// parser produce the error.
fn exceeds_nesting_depth(xml: &str, limit: usize) -> bool {
    let b = xml.as_bytes();
    let n = b.len();
    let mut i = 0;
    let mut depth: usize = 0;
    while i < n {
        if b[i] != b'<' {
            i += 1;
            continue;
        }
        if b[i..].starts_with(b"<!--") {
            match find_from(b, i + 4, b"-->") {
                Some(p) => i = p + 3,
                None => return false,
            }
        } else if b[i..].starts_with(b"<![CDATA[") {
            match find_from(b, i + 9, b"]]>") {
                Some(p) => i = p + 3,
                None => return false,
            }
        } else if i + 1 < n && (b[i + 1] == b'?' || b[i + 1] == b'!') {
            // PI or declaration — not element nesting; skip to '>'.
            match memchr_from(b, i + 2, b'>') {
                Some(p) => i = p + 1,
                None => return false,
            }
        } else if i + 1 < n && b[i + 1] == b'/' {
            depth = depth.saturating_sub(1);
            match memchr_from(b, i + 2, b'>') {
                Some(p) => i = p + 1,
                None => return false,
            }
        } else {
            // Opening tag: scan to the unquoted '>', tracking self-closing.
            let mut j = i + 1;
            let mut quote = 0u8;
            let mut prev = 0u8;
            let mut end = None;
            while j < n {
                let c = b[j];
                if quote != 0 {
                    if c == quote {
                        quote = 0;
                    }
                } else if c == b'"' || c == b'\'' {
                    quote = c;
                } else if c == b'>' {
                    end = Some(j);
                    break;
                }
                prev = c;
                j += 1;
            }
            match end {
                Some(e) => {
                    if prev != b'/' {
                        depth += 1;
                        if depth > limit {
                            return true;
                        }
                    }
                    i = e + 1;
                }
                None => return false,
            }
        }
    }
    false
}

/// Collect every `<file>` node under the `<toc>`, joining `parent/name` into
/// full paths, into a flat `entries` list plus the parallel `items` (one slot
/// per entry; `None` for entries with no heap body).
///
/// Iterative DFS (explicit stack of `(node, parent path)`) so a crafted
/// deeply-nested TOC cannot overflow the stack. Children are pushed reversed so
/// siblings emerge in document order (pre-order).
fn collect(
    toc: roxmltree::Node,
    entries: &mut Vec<Entry>,
    items: &mut Vec<Option<HeapItem>>,
) -> Result<()> {
    let mut stack: Vec<(roxmltree::Node, PathBuf)> = Vec::new();
    let seed: Vec<roxmltree::Node> = toc
        .children()
        .filter(|c| c.is_element() && c.has_tag_name("file"))
        .collect();
    for f in seed.into_iter().rev() {
        stack.push((f, PathBuf::new()));
    }

    while let Some((file, parent)) = stack.pop() {
        let name = match child_text(file, "name") {
            Some(n) => n,
            // A `<file>` without a `<name>` is malformed; skip it.
            None => continue,
        };
        // Reject names that cannot map to a safe relative path. Extraction is
        // already guarded by `safe_join`, but skipping these keeps the listing
        // metadata honest (no `../` or absolute paths shown). Descendants of a
        // rejected directory are skipped with it.
        let np = Path::new(&name);
        if np.is_absolute()
            || np
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            continue;
        }
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

        // Queue this node's `<file>` children (reversed → document order).
        let kids: Vec<roxmltree::Node> = file
            .children()
            .filter(|c| c.is_element() && c.has_tag_name("file"))
            .collect();
        for c in kids.into_iter().rev() {
            stack.push((c, path.clone()));
        }
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
            .take(MAX_TOC_UNCOMPRESSED)
            .read_to_string(&mut xml)
            .map_err(|e| Error::Corrupt(format!("xar: TOC inflate: {e}")))?;
        // Guard before parsing: roxmltree recurses per nesting level and would
        // overflow the stack (uncatchable abort) on a deeply-nested TOC.
        if exceeds_nesting_depth(&xml, MAX_TOC_DEPTH) {
            return Err(Error::Corrupt("xar: TOC nesting too deep".into()));
        }
        let doc = roxmltree::Document::parse(&xml)
            .map_err(|e| Error::Corrupt(format!("xar: TOC XML: {e}")))?;
        let toc = doc
            .descendants()
            .find(|n| n.has_tag_name("toc"))
            .ok_or_else(|| Error::Corrupt("xar: TOC has no <toc> element".into()))?;

        let mut entries: Vec<Entry> = Vec::new();
        let mut items: Vec<Option<HeapItem>> = Vec::new();
        collect(toc, &mut entries, &mut items)?;

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

        // `item.offset` is attacker-controlled; guard the sum against overflow
        // (a debug-build panic / release-build wrong seek).
        let abs_offset = self
            .heap_offset
            .checked_add(item.offset)
            .ok_or_else(|| Error::Corrupt("xar: heap offset overflow".into()))?;
        self.inner
            .seek(SeekFrom::Start(abs_offset))
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

    // ── Crafted-input safety regressions ──────────────────────────────────────

    /// Build a XAR (header + zlib-compressed TOC, empty heap) from a TOC XML.
    fn build_xar(toc_xml: &str) -> Vec<u8> {
        use flate2::Compression;
        use flate2::write::ZlibEncoder;
        use std::io::Write as _;

        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(toc_xml.as_bytes()).unwrap();
        let toc_comp = enc.finish().unwrap();

        let mut buf = Vec::new();
        buf.extend_from_slice(b"xar!");
        buf.extend_from_slice(&28u16.to_be_bytes()); // header_len
        buf.extend_from_slice(&1u16.to_be_bytes()); // version
        buf.extend_from_slice(&(toc_comp.len() as u64).to_be_bytes());
        buf.extend_from_slice(&(toc_xml.len() as u64).to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes()); // checksum = sha1
        buf.extend_from_slice(&toc_comp);
        buf
    }

    fn open_bytes(buf: Vec<u8>) -> Result<Box<dyn ArchiveReader>> {
        use crate::archive::Source;
        use std::io::Cursor;
        XarHandler.open(
            Source::Seekable {
                inner: Box::new(Cursor::new(buf)),
                path: None,
            },
            &OpenOptions::default(),
        )
    }

    /// A deeply-nested TOC is rejected as `Corrupt` by the depth guard *before*
    /// roxmltree parses it — so a crafted file cannot overflow the stack.
    #[test]
    fn deeply_nested_toc_is_rejected_before_parse() {
        let levels = 200; // > MAX_TOC_DEPTH (64)
        let mut xml = String::from("<xar><toc>");
        for _ in 0..levels {
            xml.push_str("<file><name>d</name><type>directory</type>");
        }
        for _ in 0..levels {
            xml.push_str("</file>");
        }
        xml.push_str("</toc></xar>");
        assert!(matches!(
            open_bytes(build_xar(&xml)),
            Err(Error::Corrupt(_))
        ));
    }

    #[test]
    fn nesting_depth_scanner_basics() {
        assert!(!exceeds_nesting_depth("<a><b><c/></b></a>", 64));
        assert!(exceeds_nesting_depth("<a><b><c></c></b></a>", 2));
        assert!(!exceeds_nesting_depth("<a><b><c></c></b></a>", 3));
        // Self-closing tags do not add depth.
        assert!(!exceeds_nesting_depth("<a><b/><b/><b/></a>", 2));
    }

    #[test]
    fn nesting_depth_scanner_resists_evasion() {
        // `<a>` is depth 1; the `<x><y><z>` hidden in a comment must NOT count,
        // so a limit of 3 is not exceeded (a broken scanner would reach 4).
        assert!(!exceeds_nesting_depth("<a><!-- <x><y><z> --></a>", 3));
        // Same, hidden inside CDATA.
        assert!(!exceeds_nesting_depth("<a><![CDATA[<x><y><z>]]></a>", 3));
        // A '>' inside a quoted attribute must not end the tag early (which
        // would desync the depth count).
        assert!(exceeds_nesting_depth(
            "<a attr=\"b>c\"><d><e></e></d></a>",
            2
        ));
        assert!(!exceeds_nesting_depth(
            "<a attr=\"b>c\"><d><e></e></d></a>",
            3
        ));
    }

    /// A `<data>` offset that overflows `heap_offset + offset` must yield
    /// `Corrupt` on read, never a panic or a wrong seek.
    #[test]
    fn heap_offset_overflow_is_corrupt_not_panic() {
        let xml = format!(
            "<xar><toc><file id=\"1\"><name>f</name><type>file</type>\
             <data><offset>{}</offset><length>1</length><size>1</size>\
             <encoding style=\"application/octet-stream\"/></data></file></toc></xar>",
            u64::MAX
        );
        let mut ar = open_bytes(build_xar(&xml)).expect("open should succeed");
        let mut out = Vec::new();
        assert!(matches!(ar.read_entry(0, &mut out), Err(Error::Corrupt(_))));
    }

    /// Names with `..` or absolute paths are skipped from the listing.
    #[test]
    fn traversal_names_are_skipped() {
        let xml = "<xar><toc>\
            <file id=\"1\"><name>../evil</name><type>file</type></file>\
            <file id=\"2\"><name>/etc/passwd</name><type>file</type></file>\
            <file id=\"3\"><name>ok.txt</name><type>file</type></file>\
            </toc></xar>";
        let mut ar = open_bytes(build_xar(xml)).expect("open should succeed");
        let entries = ar.entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path.to_str(), Some("ok.txt"));
    }
}
