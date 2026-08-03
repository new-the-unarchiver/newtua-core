//! WPRESS (`.wpress`) — the site dump written by the WordPress plugin
//! *All-in-One WP Migration*.
//!
//! Shape: a flat sequence of records, each a fixed-length header followed by the
//! file's bytes **stored raw** (no compression, no alignment, no per-entry
//! trailer). The archive ends with a header block of all zeros; a file that
//! simply stops after the last body is accepted too (the reference unpacker
//! does the same).
//!
//! # Header layout
//!
//! Every field is text, NUL-padded on the right; the numbers are plain ASCII
//! decimal.
//!
//! ```text
//!  off   len  field
//!    0   255  name    file name, no directory part
//!  255    14  size    body length in bytes
//!  269    12  mtime   modification time, Unix seconds
//!  281  4096  prefix  directory path the file sits in ("." or "" = root)
//!            ────────
//!         4377  total
//! ```
//!
//! The spans were **not** taken from a format description: they were pinned
//! empirically against the wpress unpacker Keka ships (`kwet`), the way the
//! project pins every layout it did not write itself.
//!
//! * A file built with these spans, holding three files in nested directories,
//!   is read by `kwet` into exactly those paths with byte-identical contents —
//!   which pins the total stride at 4377, since any other prefix width would
//!   desynchronise the second and third records.
//! * A file whose name/size/mtime fields are filled to their last byte (255
//!   characters, 14 digits, 12 digits — no NUL padding anywhere) is also read
//!   correctly, which pins the three scalar widths individually: one byte less
//!   and the next field would start inside the previous one.
//! * `kwet` prints `Unable to parse the header as wpress` on random bytes and
//!   on a non-numeric size field — the same two cases this handler answers with
//!   `Error::UnknownFormat`.
//!
//! There is no magic number anywhere in the format, so detection is by the
//! `.wpress` extension and confirmed by parsing the first header — the same
//! shape as ISO and HFS+.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::archive::{
    ArchiveReader, Confidence, Entry, EntryKind, FormatHandler, FormatId, OpenOptions, ReadSeek,
    Source,
};
use crate::datetime::unix_secs_to_systime;
use crate::encoding::decode_names;
use crate::error::{Error, Result};
use crate::path_safety::raw_path_escapes;

// ── Header geometry ──────────────────────────────────────────────────────────

const NAME_LEN: usize = 255;
const SIZE_LEN: usize = 14;
const MTIME_LEN: usize = 12;
const PREFIX_LEN: usize = 4096;
const HEADER_LEN: usize = NAME_LEN + SIZE_LEN + MTIME_LEN + PREFIX_LEN; // 4377

const NAME_OFF: usize = 0;
const SIZE_OFF: usize = NAME_OFF + NAME_LEN; // 255
const MTIME_OFF: usize = SIZE_OFF + SIZE_LEN; // 269
const PREFIX_OFF: usize = MTIME_OFF + MTIME_LEN; // 281

// ── Handler ──────────────────────────────────────────────────────────────────

pub struct WpressHandler;

impl FormatHandler for WpressHandler {
    fn id(&self) -> FormatId {
        FormatId::Wpress
    }

    /// Detect by the `.wpress` extension only: the format carries no signature
    /// at all, so there is nothing in the header peek to match on. Reported at
    /// `EXTENSION` confidence (below `MAGIC`) so a genuine other-format file
    /// that happens to be named `.wpress` still wins on content. The guess is
    /// confirmed in `open`, which parses the first header and answers
    /// `UnknownFormat` when it does not hold up.
    fn probe(&self, _header: &[u8], name: Option<&str>) -> Confidence {
        let is_wpress = name.is_some_and(|n| {
            Path::new(n)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("wpress"))
        });
        if is_wpress {
            Confidence::EXTENSION
        } else {
            Confidence::NONE
        }
    }

    fn open(&self, src: Source, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        let mut inner: Box<dyn ReadSeek> = match src {
            Source::Seekable { inner, .. } => inner,
            Source::Stream { .. } => {
                return Err(Error::Unsupported {
                    format: "wpress".into(),
                    feature: "streaming (wpress bodies are read by offset)".into(),
                });
            }
        };

        let file_len = inner.seek(SeekFrom::End(0))?;
        inner.seek(SeekFrom::Start(0))?;
        let (raw_paths, records) = scan(inner.as_mut(), file_len)?;
        Ok(Box::new(build_reader(inner, raw_paths, records, opts)))
    }
}

// ── Parsing ──────────────────────────────────────────────────────────────────

/// One record's header, still as raw bytes (names are decoded later, once for
/// the whole archive).
///
/// The two text fields borrow the caller's header block: they are only needed
/// until the record's path has been joined, well before the block is refilled.
struct RawHeader<'a> {
    name: &'a [u8],
    prefix: &'a [u8],
    size: u64,
    mtime: Option<u64>,
}

/// Split a text field at its first NUL and require every byte after it to be
/// NUL too. Returns `None` when the padding holds anything else — the cheapest
/// structural check the format offers, and the one that makes random bytes fail
/// immediately instead of being read as a plausible name.
fn text_field(field: &[u8]) -> Option<&[u8]> {
    match field.iter().position(|&b| b == 0) {
        None => Some(field), // filled to the last byte, no padding at all
        Some(end) => {
            if field[end..].iter().all(|&b| b == 0) {
                Some(&field[..end])
            } else {
                None
            }
        }
    }
}

/// Parse a NUL-padded ASCII decimal field. Trailing spaces are tolerated (some
/// writers pad with them); anything else is a parse failure, not a silent zero.
/// An empty field yields `None`, which callers read as "unset".
fn decimal_field(field: &[u8]) -> Option<Option<u64>> {
    let digits = text_field(field)?.trim_ascii_end();
    if digits.is_empty() {
        return Some(None);
    }
    if !digits.iter().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // 14 digits max by construction, so this cannot overflow u64; `parse`
    // still rejects anything that would.
    std::str::from_utf8(digits)
        .ok()?
        .parse::<u64>()
        .ok()
        .map(Some)
}

/// Parse a whole header block. `None` means "this is not a wpress header".
fn parse_header(block: &[u8]) -> Option<RawHeader<'_>> {
    debug_assert_eq!(block.len(), HEADER_LEN);
    let name = text_field(&block[NAME_OFF..NAME_OFF + NAME_LEN])?;
    if name.is_empty() || name.contains(&b'/') || name.contains(&b'\\') {
        // The name field holds a bare file name; a separator there means we are
        // not aligned on a real header.
        return None;
    }
    let size = decimal_field(&block[SIZE_OFF..SIZE_OFF + SIZE_LEN])?.unwrap_or(0);
    let mtime = decimal_field(&block[MTIME_OFF..MTIME_OFF + MTIME_LEN])?;
    let prefix = text_field(&block[PREFIX_OFF..PREFIX_OFF + PREFIX_LEN])?;
    Some(RawHeader {
        name,
        prefix,
        size,
        mtime,
    })
}

/// Per-entry data collected by the scan: where the body lives in the file.
///
/// The entry's raw path is collected alongside, in its own `Vec`, so it can be
/// handed to `decode_names` by reference and then moved straight into
/// `Entry::path_raw` without ever being cloned.
struct Record {
    offset: u64,
    size: u64,
    mtime: Option<u64>,
}

/// Walk the record chain from byte 0 to the end marker, returning the entries'
/// raw paths and, parallel to them, where each body lives.
///
/// Every length in this loop comes straight out of the file and is therefore
/// untrusted: the declared body size is checked against the real file length
/// **before** it is recorded, and every offset is advanced with `checked_add`.
/// Nothing here is allocated to the declared size — bodies are never read at
/// open time, only located.
fn scan(src: &mut dyn ReadSeek, file_len: u64) -> Result<(Vec<Vec<u8>>, Vec<Record>)> {
    let mut raw_paths: Vec<Vec<u8>> = Vec::new();
    let mut records: Vec<Record> = Vec::new();
    let mut pos: u64 = 0;
    let mut block = vec![0u8; HEADER_LEN];

    loop {
        let remaining = file_len.saturating_sub(pos);
        if remaining == 0 {
            // Clean end: the archive stopped right after the last body. The
            // reference unpacker accepts this, so we do too.
            break;
        }
        if remaining < HEADER_LEN as u64 {
            // A partial tail is only acceptable as a short all-zero end marker.
            let n = usize::try_from(remaining).unwrap_or(usize::MAX);
            let tail = &mut block[..n];
            src.read_exact(tail)?;
            if tail.iter().all(|&b| b == 0) {
                break;
            }
            return corrupt_or_unknown(
                records.is_empty(),
                format!("wpress: truncated header at offset {pos} ({remaining} bytes left)"),
            );
        }

        src.read_exact(&mut block)?;
        if block.iter().all(|&b| b == 0) {
            break; // end-of-archive marker
        }

        let Some(header) = parse_header(&block) else {
            return corrupt_or_unknown(
                records.is_empty(),
                format!("wpress: unparsable record header at offset {pos}"),
            );
        };

        let body_off = pos
            .checked_add(HEADER_LEN as u64)
            .ok_or_else(|| Error::Corrupt("wpress: header offset overflow".into()))?;
        let next = body_off.checked_add(header.size).ok_or_else(|| {
            Error::Corrupt(format!(
                "wpress: body size {} overflows the offset at {pos}",
                header.size
            ))
        })?;
        if next > file_len {
            // The declared length does not fit the file: truncated archive, or
            // a crafted size field. Either way it is refused here, before it can
            // size a read.
            return corrupt_or_unknown(
                records.is_empty(),
                format!(
                    "wpress: body of {} claims {} bytes but only {} remain",
                    String::from_utf8_lossy(header.name),
                    header.size,
                    file_len.saturating_sub(body_off)
                ),
            );
        }

        raw_paths.push(join_raw(header.prefix, header.name));
        records.push(Record {
            offset: body_off,
            size: header.size,
            mtime: header.mtime,
        });

        src.seek(SeekFrom::Start(next))?;
        pos = next;
    }

    if records.is_empty() {
        // Nothing at all was parsed (empty file, or a lone end marker): with no
        // magic to lean on there is no evidence this is a wpress archive.
        return Err(Error::UnknownFormat);
    }
    Ok((raw_paths, records))
}

/// A failure on the very first record means the `.wpress` guess did not hold up
/// — that is `UnknownFormat`, the same answer the extension-detected ISO and
/// HFS+ handlers give. Once a record has parsed, the file *is* a wpress archive
/// and a later failure is a corrupt one.
fn corrupt_or_unknown<T>(first_record: bool, message: String) -> Result<T> {
    if first_record {
        Err(Error::UnknownFormat)
    } else {
        Err(Error::Corrupt(message))
    }
}

/// Join the directory field and the file name into the entry's full path,
/// working on the archive's raw bytes (never on a decoded string).
///
/// The prefix is a relative path; `.` and the empty string both mean the root,
/// and a leading `./` or a trailing `/` is dropped — all three verified against
/// the reference unpacker.
fn join_raw(prefix: &[u8], name: &[u8]) -> Vec<u8> {
    let mut p = prefix;
    while let Some(rest) = p.strip_prefix(b"./".as_slice()) {
        p = rest;
    }
    if p == b"." {
        p = b"";
    }
    while let Some(rest) = p.strip_suffix(b"/".as_slice()) {
        p = rest;
    }
    if p.is_empty() {
        name.to_vec()
    } else {
        [p, b"/", name].concat()
    }
}

/// Turn the scan into a reader: decode all names in one pass (one encoding for
/// the whole archive, as everywhere else in the crate), then build the entries.
fn build_reader(
    inner: Box<dyn ReadSeek>,
    raw_names: Vec<Vec<u8>>,
    records: Vec<Record>,
    opts: &OpenOptions,
) -> WpressReader {
    let names = decode_names(&raw_names, opts.encoding_override.as_deref());

    let mut entries = Vec::with_capacity(records.len());
    let mut bodies = Vec::with_capacity(records.len());
    for (i, (raw_path, rec)) in raw_names.into_iter().zip(records).enumerate() {
        // For an escaping path we do not trust the decoded form: the path is
        // rendered straight from the raw bytes so the `..` components reach
        // `safe_join` verbatim and the entry is refused at extraction time.
        let path = if raw_path_escapes(&raw_path) {
            PathBuf::from(String::from_utf8_lossy(&raw_path).into_owned())
        } else {
            PathBuf::from(&names[i])
        };
        entries.push(Entry {
            path_raw: raw_path,
            path,
            kind: EntryKind::File,
            size: rec.size,
            mode: None,
            is_encrypted: false,
            modified: rec.mtime.and_then(unix_secs_to_systime),
            is_resource_fork: false,
        });
        bodies.push((rec.offset, rec.size));
    }

    WpressReader {
        src: inner,
        entries,
        bodies,
    }
}

// ── Reader ───────────────────────────────────────────────────────────────────

pub struct WpressReader {
    src: Box<dyn ReadSeek>,
    entries: Vec<Entry>,
    /// Parallel to `entries`: `(offset, size)` of the body inside the archive.
    bodies: Vec<(u64, u64)>,
}

impl ArchiveReader for WpressReader {
    fn format(&self) -> FormatId {
        FormatId::Wpress
    }

    fn entries(&mut self) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn read_entry(&mut self, idx: usize, out: &mut dyn Write) -> Result<()> {
        let &(offset, size) = self.bodies.get(idx).ok_or(Error::InvalidIndex(idx))?;
        if size == 0 {
            return Ok(());
        }
        self.src.seek(SeekFrom::Start(offset))?;
        // `size` was bounded by the file length during the scan, but the copy is
        // still capped by `take` and the output grows as bytes arrive — nothing
        // is reserved up front.
        let copied = std::io::copy(&mut (&mut self.src).take(size), out)?;
        if copied != size {
            return Err(Error::Corrupt(format!(
                "wpress: truncated body at offset {offset} ({copied} of {size} bytes)"
            )));
        }
        Ok(())
    }
}

// ── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_is_wpress() {
        assert_eq!(WpressHandler.id(), FormatId::Wpress);
    }

    #[test]
    fn header_geometry_matches_the_reference() {
        // Pinned against `kwet`; see the module doc comment.
        assert_eq!(HEADER_LEN, 4377);
        assert_eq!(SIZE_OFF, 255);
        assert_eq!(MTIME_OFF, 269);
        assert_eq!(PREFIX_OFF, 281);
    }

    #[test]
    fn probe_positive_by_extension_any_case() {
        assert_eq!(
            WpressHandler.probe(&[], Some("site.wpress")),
            Confidence::EXTENSION
        );
        assert_eq!(
            WpressHandler.probe(&[], Some("SITE.WPRESS")),
            Confidence::EXTENSION
        );
    }

    #[test]
    fn probe_negative_without_the_extension() {
        assert_eq!(WpressHandler.probe(&[], Some("site.zip")), Confidence::NONE);
        assert_eq!(WpressHandler.probe(&[], Some("wpress")), Confidence::NONE);
        assert_eq!(WpressHandler.probe(&[], None), Confidence::NONE);
    }

    #[test]
    fn text_field_reads_padded_and_full_fields() {
        assert_eq!(text_field(b"a.txt\0\0\0"), Some(b"a.txt".as_slice()));
        assert_eq!(text_field(b"abc"), Some(b"abc".as_slice())); // no padding
        assert_eq!(text_field(b"\0\0\0"), Some(b"".as_slice()));
        // Garbage after the terminator: not a header.
        assert_eq!(text_field(b"a.txt\0X\0"), None);
    }

    #[test]
    fn decimal_field_parses_and_rejects() {
        assert_eq!(decimal_field(b"15\0\0\0"), Some(Some(15)));
        assert_eq!(decimal_field(b"00000000000015"), Some(Some(15)));
        assert_eq!(decimal_field(b"15  \0"), Some(Some(15)));
        assert_eq!(decimal_field(b"\0\0\0"), Some(None)); // unset
        assert_eq!(decimal_field(b"NOTANUMBER\0"), None);
        assert_eq!(decimal_field(b"12x4\0"), None);
        // 14 nines is the widest the field can hold — parses, no overflow.
        assert_eq!(
            decimal_field(b"99999999999999"),
            Some(Some(99_999_999_999_999))
        );
    }

    #[test]
    fn join_raw_builds_the_full_path() {
        assert_eq!(join_raw(b".", b"a.txt"), b"a.txt".to_vec());
        assert_eq!(join_raw(b"", b"a.txt"), b"a.txt".to_vec());
        assert_eq!(
            join_raw(b"wp-content", b"a.txt"),
            b"wp-content/a.txt".to_vec()
        );
        assert_eq!(join_raw(b"./sub", b"a.txt"), b"sub/a.txt".to_vec());
        assert_eq!(join_raw(b"sub/", b"a.txt"), b"sub/a.txt".to_vec());
        assert_eq!(join_raw(b"a/b/c", b"d.txt"), b"a/b/c/d.txt".to_vec());
    }

    #[test]
    fn raw_path_escapes_catches_traversal() {
        assert!(!raw_path_escapes(b"wp-content/a.txt"));
        assert!(!raw_path_escapes(b"a..b/c.txt")); // `..` inside a name is fine
        assert!(raw_path_escapes(b"../a.txt"));
        assert!(raw_path_escapes(b"a/../../b.txt"));
        assert!(raw_path_escapes(b"/etc/passwd"));
        assert!(raw_path_escapes(b"..\\a.txt"));
    }

    #[test]
    fn parse_header_rejects_a_name_holding_a_separator() {
        let mut block = vec![0u8; HEADER_LEN];
        block[..7].copy_from_slice(b"a/b.txt");
        block[SIZE_OFF] = b'0';
        assert!(parse_header(&block).is_none());
    }
}
