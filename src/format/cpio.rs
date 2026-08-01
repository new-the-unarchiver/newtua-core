//! cpio (`.cpio`) — the three ASCII variants read here: SVR4 "new ASCII"
//! (`070701`, what GNU/BSD `cpio -o -H newc` writes), the same layout with a
//! filled-in checksum field, `crc` (`070702`, `cpio -o -H crc`), and POSIX.1
//! "old portable" / odc (`070707`, what `ditto` writes).
//!
//! Reached two ways: from the registry, on a bare `.cpio`; and from
//! `detect.rs`, which checks a just-decompressed stream for a cpio magic once
//! tar has been ruled out. That second path is what opens a `.cpgz` from macOS
//! Archive Utility — odc inside gzip.
//!
//! All of them are parsed here, by hand. Nothing is delegated: a third-party
//! newc reader used to do this and turned every name that was not UTF-8 into an
//! open error, which is exactly the case `decode_names` exists for.
//!
//! `crc` is newc with two differences and no third: its magic, and its `check`
//! field, which newc leaves zero. So one parser walks both — see [`NewcVariant`]
//! — and the only extra work is at read time, where the checksum is verified.
//!
//! # How an archive is opened
//!
//! cpio is a sequential format, but the file it lives in usually is not, and
//! `open` leans on that: every variant is walked by exactly one parser, over a
//! source that can seek.
//!
//! * **Seekable source.** The listing is built from the headers alone: every
//!   body is *skipped by seeking*, never read, and the source stays open so
//!   `read_entry` can seek back to a body on demand (`CpioSeekReader`). No temp
//!   file is written at all. This is the path a `.cpgz` takes, where the
//!   decompression layer has already spent one temp file on the gzip stream.
//!   Integrity does not suffer: the file length is taken once at open time and
//!   every record is checked against it (`body offset + declared length ≤ file
//!   length`), which catches a truncation *earlier* than reading would, and the
//!   next record's magic still has to be where the skip lands.
//! * **`Source::Stream`.** Cannot seek, so it is spilled to a temp file whole
//!   and then walked exactly as above — one parser per variant rather than two,
//!   for all three of them. The cost is the one the old streaming pass already
//!   paid: it copied every body to a temp file, and the bodies are nearly the
//!   whole archive. `Source` is a public type, so a caller of the library can
//!   hand us a stream even though nothing inside the crate builds one.

use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::time::SystemTime;

use crate::archive::{
    ArchiveReader, Confidence, Entry, EntryKind, FormatHandler, FormatId, OpenOptions, ReadSeek,
    Source,
};
use crate::datetime::unix_secs_to_systime;
use crate::encoding::decode_names;
use crate::error::{Error, Result, io_err_to_corrupt};

// ── Mode constants (POSIX S_IFMT family) ────────────────────────────────────

const S_IFMT: u32 = 0o170000;
const S_IFLNK: u32 = 0o120000; // symbolic link
const S_IFDIR: u32 = 0o040000; // directory
const S_IFREG: u32 = 0o100000; // regular file

// ── Variant magics ───────────────────────────────────────────────────────────

/// SVR4 "new ASCII" — what GNU/BSD `cpio -o -H newc` writes.
pub(crate) const MAGIC_NEWC: &[u8; 6] = b"070701";
/// SVR4 "new ASCII" with a checksum — what `cpio -o -H crc` writes. The record
/// layout is byte-for-byte the newc one; see [`NewcVariant`].
pub(crate) const MAGIC_CRC: &[u8; 6] = b"070702";
/// POSIX.1 "old portable" (odc) — what `ditto`, and therefore macOS Archive
/// Utility, writes.
pub(crate) const MAGIC_ODC: &[u8; 6] = b"070707";
/// Length of every cpio ASCII magic; also the peek needed to pick a variant.
pub(crate) const MAGIC_LEN: usize = 6;

/// Whether `magic` is a variant this handler can open.
///
/// Kept in one place because `detect.rs` asks the same question of a
/// just-decompressed stream (`is_cpio`): what is claimed there has to be exactly
/// what `open` can then parse.
pub(crate) fn is_supported_magic(magic: &[u8]) -> bool {
    magic == MAGIC_NEWC || magic == MAGIC_CRC || magic == MAGIC_ODC
}

// ── Handler ──────────────────────────────────────────────────────────────────

pub struct CpioHandler;

impl FormatHandler for CpioHandler {
    fn id(&self) -> FormatId {
        FormatId::Cpio
    }

    fn probe(&self, header: &[u8], _name: Option<&str>) -> Confidence {
        // The three ASCII variants that can be read: SVR4 "new ASCII" (070701),
        // the same layout with a checksum (070702, crc) and POSIX "old
        // portable" / odc (070707).
        if header.len() >= MAGIC_LEN && is_supported_magic(&header[..MAGIC_LEN]) {
            Confidence::MAGIC
        } else {
            Confidence::NONE
        }
    }

    fn open(&self, src: Source, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        // Both kinds of source end up in the same place: one seekable handle on
        // the whole archive, walked by the one parser its variant has. A stream
        // cannot seek, so it is spilled to a temp file first — see the module
        // header for why that is cheaper than it looks.
        match src {
            Source::Seekable { mut inner, .. } => {
                let file_len = inner.seek(SeekFrom::End(0))?;
                open_seekable(inner, file_len, opts)
            }
            Source::Stream { inner, .. } => {
                let (file, file_len) = spill_to_temp(inner)?;
                open_seekable(Box::new(file), file_len, opts)
            }
        }
    }
}

/// List a seekable archive of whichever variant it turns out to be, then hand
/// back the reader that keeps it open so bodies can be read where they lie.
///
/// The leading magic picks the walk and nothing after it differs: `crc` is the
/// newc walk with the `check` field carried along, and the entry list, the name
/// decoding and the reader are shared by all three.
fn open_seekable(
    mut inner: Box<dyn ReadSeek>,
    file_len: u64,
    opts: &OpenOptions,
) -> Result<Box<dyn ArchiveReader>> {
    inner.seek(SeekFrom::Start(0))?;
    let mut magic = [0u8; MAGIC_LEN];
    // A file too short to hold a magic is truncated, not merely unsupported.
    inner.read_exact(&mut magic).map_err(io_err_to_corrupt)?;
    inner.seek(SeekFrom::Start(0))?;

    let (raw_names, metas) = match &magic {
        MAGIC_ODC => scan_odc_seekable(inner.as_mut(), file_len)?,
        MAGIC_NEWC => scan_newc_seekable(inner.as_mut(), file_len, NewcVariant::Newc)?,
        MAGIC_CRC => scan_newc_seekable(inner.as_mut(), file_len, NewcVariant::Crc)?,
        _ => return Err(unsupported_magic(&magic)),
    };
    let (entries, bodies) = build_entries(raw_names, metas, opts);
    Ok(Box::new(CpioSeekReader {
        src: inner,
        entries,
        bodies,
    }))
}

// ── Internal types ────────────────────────────────────────────────────────────

enum KindRaw {
    File,
    Dir,
    Symlink(Vec<u8>),
}

struct EntryMeta {
    kind: KindRaw,
    offset: u64,
    size: u64,
    mode: u32,
    modified: Option<SystemTime>,
    /// What the crc variant's `check` field promised the body adds up to;
    /// `None` for newc and odc, which carry no checksum at all — so every odc
    /// record below leaves it `None`.
    checksum: Option<u32>,
}

/// Where an entry's body lies in the archive, and what it has to add up to once
/// read. Offsets are always into the archive the reader holds open — which for
/// a spilled stream is the temp file that archive was copied to.
#[derive(Clone, Copy)]
struct Body {
    offset: u64,
    size: u64,
    /// See [`EntryMeta::checksum`]. Verified while the body is copied out, not
    /// while the listing is built — a listing must never read a body.
    checksum: Option<u32>,
}

/// Drop the trailing NUL bytes cpio pads names and link targets with.
fn trim_nuls(bytes: &mut Vec<u8>) {
    while bytes.last() == Some(&0) {
        bytes.pop();
    }
}

/// The error a magic that is neither variant produces.
fn unsupported_magic(magic: &[u8]) -> Error {
    Error::Corrupt(format!(
        "unsupported cpio magic {:?}",
        String::from_utf8_lossy(magic)
    ))
}

/// Drain `stream` into an unnamed temp file and hand back the file, rewound,
/// together with its length. Used for the one path that cannot seek.
///
/// `tempfile::tempfile()` is unlinked the moment it is created, so the file has
/// no name to leak and the operating system reclaims it when the last handle
/// closes — which happens when the reader holding it is dropped.
fn spill_to_temp(mut stream: Box<dyn Read>) -> Result<(std::fs::File, u64)> {
    let mut file = tempfile::tempfile()?;
    let len = std::io::copy(&mut stream, &mut file)?;
    file.seek(SeekFrom::Start(0))?;
    Ok((file, len))
}

// ── newc (070701) ────────────────────────────────────────────────────────────

/// Fixed header length of the newc variant: the magic plus thirteen fields of
/// eight ASCII hex digits each.
const NEWC_HEADER_LEN: usize = 110;

/// Field spans of the newc header (SVR4 "new ASCII"). Every field is eight
/// ASCII hexadecimal digits, no separators:
///
/// ```text
///  off  len  field
///    0    6  magic     "070701"
///    6    8  ino
///   14    8  mode
///   22    8  uid
///   30    8  gid
///   38    8  nlink
///   46    8  mtime
///   54    8  filesize
///   62    8  devmajor
///   70    8  devminor
///   78    8  rdevmajor
///   86    8  rdevminor
///   94    8  namesize  includes the name's trailing NUL
///  102    8  check     zero unless the variant is crc (070702)
/// ```
///
/// Unlike odc, newc pads: the name is followed by NULs until `110 + namesize`
/// is a multiple of four, and the body by NULs until `filesize` is. Getting
/// that wrong desynchronises every record after the first.
const NEWC_MODE: (usize, usize) = (14, 8);
const NEWC_MTIME: (usize, usize) = (46, 8);
const NEWC_FILESIZE: (usize, usize) = (54, 8);
const NEWC_NAMESIZE: (usize, usize) = (94, 8);
const NEWC_CHECK: (usize, usize) = (102, 8);

/// Which of the two newc-shaped variants an archive uses.
///
/// The record layout is identical down to the byte — the same 110-byte header,
/// the same thirteen fields, the same four-byte padding of name and body — so
/// one walk serves both and `newc` is the name every header-level error uses.
/// `Crc` differs in exactly two places: the magic, and the `check` field, which
/// it fills with the sum of the body's bytes instead of zero.
#[derive(Clone, Copy, PartialEq, Eq)]
enum NewcVariant {
    Newc,
    Crc,
}

impl NewcVariant {
    /// The six magic bytes every record of this variant must start with.
    fn magic(self) -> &'static [u8; MAGIC_LEN] {
        match self {
            Self::Newc => MAGIC_NEWC,
            Self::Crc => MAGIC_CRC,
        }
    }

    /// How the variant names itself in an error message.
    fn label(self) -> &'static str {
        match self {
            Self::Newc => "newc",
            Self::Crc => "crc",
        }
    }
}

/// The crc variant's checksum: every byte of the body added up, kept to 32 bits.
///
/// Despite the variant's name this is not a CRC at all — GNU cpio sums the
/// bytes as unsigned and lets the total wrap, which is what `wrapping_add`
/// reproduces.
fn body_checksum(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .fold(0u32, |acc, b| acc.wrapping_add(u32::from(*b)))
}

/// A `Write` that adds up every byte on its way through, so the crc variant's
/// checksum can be computed while the body streams to its destination. A body
/// can be gigabytes; nothing is held to be summed afterwards.
struct SummingWriter<'a> {
    inner: &'a mut dyn Write,
    sum: u32,
}

impl Write for SummingWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Only the bytes the sink actually took are counted: a short write must
        // not make the sum run ahead of the output.
        let n = self.inner.write(buf)?;
        self.sum = self.sum.wrapping_add(body_checksum(&buf[..n]));
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Parse one fixed-width ASCII-hex header field — the newc counterpart of
/// [`parse_octal`], and strict for the same reason: garbage in a header must be
/// an error, never a silently wrong number. Both digit cases are accepted (GNU
/// writes lowercase, some writers uppercase) and the space/NUL padding some
/// writers leave around the digits is tolerated. Accumulation goes through
/// `checked_*`, so an all-`f` field cannot wrap — it simply fails.
fn parse_hex(field: &[u8]) -> Option<u64> {
    let mut value: u64 = 0;
    let mut seen_digit = false;
    for &b in field {
        let digit = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            // Padding: skipped before the number, ends it after.
            b' ' | 0 => {
                if seen_digit {
                    break;
                }
                continue;
            }
            _ => return None,
        };
        seen_digit = true;
        value = value.checked_mul(16)?.checked_add(u64::from(digit))?;
    }
    seen_digit.then_some(value)
}

/// Read a newc header field by `(offset, len)` and parse it, or fail with a
/// message naming the field.
fn newc_field(header: &[u8], span: (usize, usize), name: &str) -> Result<u64> {
    let (off, len) = span;
    parse_hex(&header[off..off + len])
        .ok_or_else(|| Error::Corrupt(format!("cpio newc: bad hex in {name} field")))
}

/// Bytes of NUL padding that follow `len` to bring it up to a multiple of four.
fn pad4(len: u64) -> u64 {
    (4 - (len % 4)) % 4
}

/// Walk a newc-shaped archive — variant `Newc` or `Crc` — by its headers,
/// skipping every body by seeking. The counterpart of [`scan_odc_seekable`],
/// and the same shape: nothing is allocated to a declared size, and every
/// declared length is checked against the file length before it is used to
/// move.
///
/// For `Crc` the `check` field is picked up here and carried to `read_entry`;
/// it is *not* verified here, because verifying it means reading the body and a
/// listing must never do that.
fn scan_newc_seekable(
    src: &mut dyn ReadSeek,
    file_len: u64,
    variant: NewcVariant,
) -> Result<(Vec<Vec<u8>>, Vec<EntryMeta>)> {
    let mut reader = BufReader::with_capacity(SCAN_BUF, src);
    let mut raw_names: Vec<Vec<u8>> = Vec::new();
    let mut metas: Vec<EntryMeta> = Vec::new();
    let mut header = [0u8; NEWC_HEADER_LEN];
    let mut pos: u64 = 0;

    loop {
        // Where the skip landed must hold another record; an archive that ends
        // without its TRAILER is truncated, and says so here.
        let after_header = advance(
            pos,
            NEWC_HEADER_LEN as u64,
            file_len,
            format_args!("record header"),
        )?;
        reader.read_exact(&mut header).map_err(io_err_to_corrupt)?;
        if &header[..MAGIC_LEN] != variant.magic() {
            return Err(Error::Corrupt(format!(
                "cpio {}: record at offset {pos} does not start with {}",
                variant.label(),
                String::from_utf8_lossy(variant.magic()),
            )));
        }

        let mode = newc_field(&header, NEWC_MODE, "mode")? as u32;
        let mtime = newc_field(&header, NEWC_MTIME, "mtime")?;
        let filesize = newc_field(&header, NEWC_FILESIZE, "filesize")?;
        let namesize = newc_field(&header, NEWC_NAMESIZE, "namesize")?;
        // Only crc fills this field; newc writes zeros there and a zero is a
        // legitimate checksum, so the variant — not the value — decides whether
        // there is anything to verify. The field is eight hex digits, so it
        // cannot exceed u32.
        let checksum = match variant {
            NewcVariant::Crc => Some(newc_field(&header, NEWC_CHECK, "check")? as u32),
            NewcVariant::Newc => None,
        };

        if namesize == 0 {
            return Err(Error::Corrupt(format!(
                "cpio {}: zero-length name",
                variant.label()
            )));
        }
        let after_name = advance(after_header, namesize, file_len, format_args!("entry name"))?;
        let mut name = Vec::new();
        take_exact(&mut reader, namesize, &mut name, format_args!("entry name"))?;
        // `namesize` counts the terminating NUL; drop it and any extra padding.
        // The extra matters: `dracut-cpio` pads the name out to a filesystem
        // block boundary with further NULs, all of them counted in `namesize`.
        trim_nuls(&mut name);

        if name == b"TRAILER!!!" {
            break;
        }

        // Padding is counted from the start of the record, header included.
        let body_start = advance(
            after_name,
            pad4(NEWC_HEADER_LEN as u64 + namesize),
            file_len,
            format_args!("name padding"),
        )?;
        let after_body = advance(
            body_start,
            filesize,
            file_len,
            format_args!("body of {}", String::from_utf8_lossy(&name)),
        )?;
        // The body's own padding, unlike the name's, is counted from the body
        // alone — it starts on a four-byte boundary already.
        let next = advance(
            after_body,
            pad4(filesize),
            file_len,
            format_args!("body padding"),
        )?;
        let modified = unix_secs_to_systime(mtime);

        match mode & S_IFMT {
            S_IFREG => {
                // The body stays where it is; only its coordinates are kept.
                skip_to(&mut reader, after_name, next)?;
                raw_names.push(name);
                metas.push(EntryMeta {
                    kind: KindRaw::File,
                    offset: body_start,
                    size: filesize,
                    mode,
                    modified,
                    checksum,
                });
            }
            S_IFDIR => {
                // Directories carry no body, but skip `filesize` anyway so a
                // non-conforming writer cannot desynchronise the walk.
                skip_to(&mut reader, after_name, next)?;
                raw_names.push(name);
                metas.push(EntryMeta {
                    kind: KindRaw::Dir,
                    offset: 0,
                    size: 0,
                    mode,
                    modified,
                    checksum: None,
                });
            }
            S_IFLNK => {
                // Symlink targets are read here rather than skipped: they are a
                // few bytes each and the entry list needs them right away.
                skip_to(&mut reader, after_name, body_start)?;
                let mut target = Vec::new();
                take_exact(
                    &mut reader,
                    filesize,
                    &mut target,
                    format_args!("symlink target"),
                )?;
                trim_nuls(&mut target);
                skip_to(&mut reader, after_body, next)?;
                raw_names.push(name);
                metas.push(EntryMeta {
                    kind: KindRaw::Symlink(target),
                    offset: 0,
                    size: filesize,
                    mode,
                    modified,
                    // A symlink's target never goes through `read_entry`, so
                    // there is no copy to verify a checksum against.
                    checksum: None,
                });
            }
            _ => {
                // Special node (char/block device, fifo, socket) or a hardlink
                // body — skipped, as in the odc walk.
                skip_to(&mut reader, after_name, next)?;
            }
        }

        pos = next;
    }

    Ok((raw_names, metas))
}

// ── odc (070707) ─────────────────────────────────────────────────────────────

/// Fixed header length of the odc variant.
const ODC_HEADER_LEN: usize = 76;

/// Field spans of the odc header, all ASCII octal, no separators, no padding.
///
/// Verified empirically on `ditto -c` output (macOS 15) rather than taken from
/// a format description — the first record of `ditto -c src out.cpio` reads
/// `070707 000000 000000 040755 000765 000000 000004 000000 15233230255 000002
/// 00000000000` followed by `".\0"`, which pins every span below:
///
/// ```text
///  off  len  field
///    0    6  magic     "070707"
///    6    6  dev
///   12    6  ino
///   18    6  mode      040755 → S_IFDIR | 0755
///   24    6  uid       000765 → 501, the first macOS account
///   30    6  gid
///   36    6  nlink
///   42    6  rdev
///   48   11  mtime
///   59    6  namesize  includes the name's trailing NUL
///   65   11  filesize
/// ```
///
/// The name follows the header immediately and the body follows the name
/// immediately: odc has no alignment padding anywhere, unlike newc.
const ODC_MODE: (usize, usize) = (18, 6);
const ODC_MTIME: (usize, usize) = (48, 11);
const ODC_NAMESIZE: (usize, usize) = (59, 6);
const ODC_FILESIZE: (usize, usize) = (65, 11);

/// Parse one fixed-width ASCII-octal header field.
///
/// Tolerates the space/NUL padding some writers use around the digits and
/// refuses anything else, so garbage in a header is an error rather than a
/// silently wrong number. Accumulation goes through `checked_*`, so an
/// all-sevens field cannot wrap — it simply fails.
fn parse_octal(field: &[u8]) -> Option<u64> {
    let mut value: u64 = 0;
    let mut seen_digit = false;
    for &b in field {
        match b {
            b'0'..=b'7' => {
                seen_digit = true;
                value = value.checked_mul(8)?.checked_add(u64::from(b - b'0'))?;
            }
            // Padding: skipped before the number, ends it after.
            b' ' | 0 => {
                if seen_digit {
                    break;
                }
            }
            _ => return None,
        }
    }
    seen_digit.then_some(value)
}

/// Read a header field by `(offset, len)` and parse it, or fail with a message
/// naming the field.
fn odc_field(header: &[u8], span: (usize, usize), name: &str) -> Result<u64> {
    let (off, len) = span;
    parse_octal(&header[off..off + len])
        .ok_or_else(|| Error::Corrupt(format!("cpio odc: bad octal in {name} field")))
}

/// Move exactly `n` bytes from `reader` to `out`, or fail as truncated.
///
/// The one way a scanner reads part of a record rather than skipping it: names
/// and symlink targets go to a `Vec`. `n` comes straight out of
/// the archive, so it must never size an allocation on its own — `io::copy`
/// grows the destination only as far as the stream really reaches, and a short
/// read is a truncated archive, not a silently short entry. `what` names the
/// piece in the error and is formatted only when there is an error to report.
fn take_exact(
    reader: &mut dyn Read,
    n: u64,
    out: &mut dyn Write,
    what: std::fmt::Arguments<'_>,
) -> Result<()> {
    let moved = std::io::copy(&mut reader.take(n), out)?;
    if moved != n {
        return Err(Error::Corrupt(format!(
            "cpio: truncated {what} ({moved} of {n} bytes)"
        )));
    }
    Ok(())
}

// ── Seekable walks: shared machinery ─────────────────────────────────────────

/// Buffer the header walk reads through. Headers are 110 bytes (newc) or 76
/// plus a name (odc), so an unbuffered walk would cost two syscalls per record;
/// one fill covers a few hundred records of a small-file archive. Bodies are
/// skipped by seeking, so a large one costs at most one wasted fill.
const SCAN_BUF: usize = 64 * 1024;

/// Skip forward to `target`, keeping the buffer when the jump is short enough
/// to land inside it (`seek_relative` does that; a plain `seek` would always
/// throw the buffer away).
///
/// `from` and `target` are both already bounded by the file length, so the
/// difference cannot be negative; the `i64` conversion is guarded anyway rather
/// than assumed.
fn skip_to(reader: &mut BufReader<&mut dyn ReadSeek>, from: u64, target: u64) -> Result<()> {
    let delta = target.saturating_sub(from);
    if delta == 0 {
        return Ok(());
    }
    match i64::try_from(delta) {
        Ok(d) => reader.seek_relative(d)?,
        Err(_) => {
            reader.seek(SeekFrom::Start(target))?;
        }
    }
    Ok(())
}

/// Advance `pos` by `n`, refusing anything that would run past the end of the
/// file. This is the whole integrity story of the seekable walk: every length
/// in a cpio header is attacker-controlled, and this is where a length that
/// does not fit the file becomes an error instead of a seek into nowhere.
fn advance(pos: u64, n: u64, file_len: u64, what: std::fmt::Arguments<'_>) -> Result<u64> {
    match pos.checked_add(n) {
        Some(end) if end <= file_len => Ok(end),
        _ => Err(Error::Corrupt(format!(
            "cpio: {what} claims {n} bytes at offset {pos} but the file holds {file_len}"
        ))),
    }
}

/// Walk an odc archive by its headers, skipping every body by seeking.
///
/// Returns the entries' raw names and, parallel to them, their metadata — the
/// body offset being an offset **into the archive itself**, not into a temp
/// file. Nothing is allocated to a declared size: names and symlink targets
/// grow as `io::copy` really reaches them, bodies are not read at all.
fn scan_odc_seekable(
    src: &mut dyn ReadSeek,
    file_len: u64,
) -> Result<(Vec<Vec<u8>>, Vec<EntryMeta>)> {
    let mut reader = BufReader::with_capacity(SCAN_BUF, src);
    let mut raw_names: Vec<Vec<u8>> = Vec::new();
    let mut metas: Vec<EntryMeta> = Vec::new();
    let mut header = [0u8; ODC_HEADER_LEN];
    let mut pos: u64 = 0;

    loop {
        // Where the skip landed must hold another record; an archive that ends
        // without its TRAILER is truncated, and says so here.
        let after_header = advance(
            pos,
            ODC_HEADER_LEN as u64,
            file_len,
            format_args!("record header"),
        )?;
        reader.read_exact(&mut header).map_err(io_err_to_corrupt)?;
        if &header[..MAGIC_LEN] != MAGIC_ODC {
            return Err(Error::Corrupt(format!(
                "cpio odc: record at offset {pos} does not start with 070707"
            )));
        }

        let mode = odc_field(&header, ODC_MODE, "mode")? as u32;
        let mtime = odc_field(&header, ODC_MTIME, "mtime")?;
        let namesize = odc_field(&header, ODC_NAMESIZE, "namesize")?;
        let filesize = odc_field(&header, ODC_FILESIZE, "filesize")?;

        if namesize == 0 {
            return Err(Error::Corrupt("cpio odc: zero-length name".into()));
        }
        let after_name = advance(after_header, namesize, file_len, format_args!("entry name"))?;
        let mut name = Vec::new();
        take_exact(&mut reader, namesize, &mut name, format_args!("entry name"))?;
        // `namesize` counts the terminating NUL; drop it and any extra padding.
        trim_nuls(&mut name);

        if name == b"TRAILER!!!" {
            break;
        }

        let after_body = advance(
            after_name,
            filesize,
            file_len,
            format_args!("body of {}", String::from_utf8_lossy(&name)),
        )?;
        let modified = unix_secs_to_systime(mtime);

        match mode & S_IFMT {
            S_IFREG => {
                // The body stays where it is; only its coordinates are kept.
                skip_to(&mut reader, after_name, after_body)?;
                raw_names.push(name);
                metas.push(EntryMeta {
                    kind: KindRaw::File,
                    offset: after_name,
                    size: filesize,
                    mode,
                    modified,
                    checksum: None,
                });
            }
            S_IFDIR => {
                // Directories carry no body, but skip `filesize` anyway so a
                // non-conforming writer cannot desynchronise the walk.
                skip_to(&mut reader, after_name, after_body)?;
                raw_names.push(name);
                metas.push(EntryMeta {
                    kind: KindRaw::Dir,
                    offset: 0,
                    size: 0,
                    mode,
                    modified,
                    checksum: None,
                });
            }
            S_IFLNK => {
                // Symlink targets are read here rather than skipped: they are a
                // few bytes each and the entry list needs them right away.
                let mut target = Vec::new();
                take_exact(
                    &mut reader,
                    filesize,
                    &mut target,
                    format_args!("symlink target"),
                )?;
                trim_nuls(&mut target);
                raw_names.push(name);
                metas.push(EntryMeta {
                    kind: KindRaw::Symlink(target),
                    offset: 0,
                    size: filesize,
                    mode,
                    modified,
                    checksum: None,
                });
            }
            _ => {
                // Special node (char/block device, fifo, socket) — skipped, as
                // in the newc walk.
                skip_to(&mut reader, after_name, after_body)?;
            }
        }

        pos = after_body;
    }

    Ok((raw_names, metas))
}

// ── Shared tail: names, kinds, reader ────────────────────────────────────────

/// Build the entry list every variant shares: names are decoded once for the
/// whole archive, and each entry gets the [`Body`] it is read from, located in
/// the archive itself. `None` means there is no body to read (directory,
/// symlink).
fn build_entries(
    raw_names: Vec<Vec<u8>>,
    metas: Vec<EntryMeta>,
    opts: &OpenOptions,
) -> (Vec<Entry>, Vec<Option<Body>>) {
    let encoding_label = opts.encoding_override.as_deref();
    let names = decode_names(&raw_names, encoding_label);
    // Decode symlink targets only if there are any; on the common
    // symlink-free path this skips a whole charset-detection pass.
    let target_strings = if metas.iter().any(|m| matches!(m.kind, KindRaw::Symlink(_))) {
        let raw_targets: Vec<Vec<u8>> = metas
            .iter()
            .map(|m| match &m.kind {
                KindRaw::Symlink(t) => t.clone(),
                _ => Vec::new(),
            })
            .collect();
        decode_names(&raw_targets, encoding_label)
    } else {
        Vec::new()
    };

    let mut entries: Vec<Entry> = Vec::with_capacity(metas.len());
    // Where the body lives; `None` for entries with no body (dirs, symlinks).
    // `read_entry` keys off this, not off `size`.
    let mut offsets: Vec<Option<Body>> = Vec::with_capacity(metas.len());

    for (i, (meta, raw_name)) in metas.into_iter().zip(raw_names).enumerate() {
        let name_str = names[i].trim_end_matches('/');
        // Strip leading "./" that some cpio implementations prepend (`ditto`
        // always does; its first record is the bare "." for the packed root).
        let name_str = name_str.strip_prefix("./").unwrap_or(name_str);
        let (kind, body) = match meta.kind {
            KindRaw::File => (
                EntryKind::File,
                Some(Body {
                    offset: meta.offset,
                    size: meta.size,
                    checksum: meta.checksum,
                }),
            ),
            KindRaw::Dir => (EntryKind::Dir, None),
            KindRaw::Symlink(_) => (
                EntryKind::Symlink {
                    target: PathBuf::from(&target_strings[i]),
                },
                None,
            ),
        };
        entries.push(Entry {
            path_raw: raw_name,
            path: PathBuf::from(name_str),
            kind,
            size: meta.size,
            mode: Some(meta.mode),
            is_encrypted: false,
            modified: meta.modified,
        });
        offsets.push(body);
    }

    (entries, offsets)
}

// ── Reader ────────────────────────────────────────────────────────────────────

/// The one reader this format has: no copies — the archive itself is held open
/// and each body is read where it lies. For a spilled `Source::Stream` `src` is
/// the unnamed temp file the archive was copied to, and closing it here is what
/// releases that file.
///
/// The source has to outlive nothing else here, but it does have to die before
/// the temp path a `.cpgz` is unpacked to: that path belongs to
/// `TempBackedReader`, whose inner reader (this one) is declared first and so
/// drops first. On Windows an open handle would otherwise block the delete.
pub struct CpioSeekReader {
    src: Box<dyn ReadSeek>,
    entries: Vec<Entry>,
    /// Parallel to `entries`: where the body lies in the archive and what it
    /// must sum to; `None` for entries that have none (dirs, symlinks).
    bodies: Vec<Option<Body>>,
}

impl ArchiveReader for CpioSeekReader {
    fn format(&self) -> FormatId {
        FormatId::Cpio
    }

    fn entries(&mut self) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn read_entry(&mut self, idx: usize, out: &mut dyn Write) -> Result<()> {
        let slot = *self.bodies.get(idx).ok_or(Error::InvalidIndex(idx))?;
        let Some(Body {
            offset,
            size,
            checksum,
        }) = slot
        else {
            // Directory or symlink — no body to read.
            return Ok(());
        };
        if size == 0 {
            // No bytes, so nothing to copy — but an empty body still has to add
            // up to what the header claimed, which for crc is zero.
            return self.verify_checksum(idx, checksum, 0);
        }
        self.src.seek(SeekFrom::Start(offset))?;
        // `size` was checked against the file length while scanning, but the
        // copy is still capped by `take` and the output grows as bytes arrive —
        // nothing is reserved up front. A short read means the file shrank or
        // lied; it is an error, never a silently truncated entry.
        //
        // The crc variant's checksum is summed *through* the copy rather than
        // over a buffered body: a body can be gigabytes and must never be held
        // in memory just to be added up.
        let (copied, sum) = match checksum {
            None => (std::io::copy(&mut (&mut self.src).take(size), out)?, 0),
            Some(_) => {
                let mut summing = SummingWriter { inner: out, sum: 0 };
                let copied = std::io::copy(&mut (&mut self.src).take(size), &mut summing)?;
                (copied, summing.sum)
            }
        };
        if copied != size {
            return Err(Error::Corrupt(format!(
                "cpio: truncated body at offset {offset} ({copied} of {size} bytes)"
            )));
        }
        self.verify_checksum(idx, checksum, sum)
    }
}

impl CpioSeekReader {
    /// Hold a body's summed bytes against what its header promised.
    ///
    /// `declared` is `None` for every variant but crc, and then there is nothing
    /// to check. A mismatch is an error: crc is the only cpio variant that
    /// carries any integrity check at all, and handing out content that failed
    /// it would throw the one guarantee the variant exists for away.
    fn verify_checksum(&self, idx: usize, declared: Option<u32>, actual: u32) -> Result<()> {
        match declared {
            Some(want) if want != actual => Err(Error::Corrupt(format!(
                "cpio crc: checksum mismatch for {}: header says {want:#010x}, body sums to {actual:#010x}",
                self.entries[idx].path.display()
            ))),
            _ => Ok(()),
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Confidence;
    // Only the tests build an archive in memory; the parser itself never does.
    use std::io::Cursor;
    use std::path::Path;

    #[test]
    fn id_is_cpio() {
        assert_eq!(CpioHandler.id(), FormatId::Cpio);
    }

    #[test]
    fn probe_positive_newc() {
        let header = b"070701000000000000000000";
        assert_eq!(CpioHandler.probe(header, None), Confidence::MAGIC);
    }

    #[test]
    fn probe_negative_zip() {
        assert_eq!(CpioHandler.probe(b"PK\x03\x04", None), Confidence::NONE);
    }

    #[test]
    fn probe_accepts_odc() {
        // 070707 is the old portable (odc) variant — what `ditto`, and so macOS
        // Archive Utility, writes.
        assert_eq!(CpioHandler.probe(b"070707...", None), Confidence::MAGIC);
    }

    #[test]
    fn probe_accepts_crc_variant() {
        // 070702 is the crc variant: the newc layout with the `check` field
        // filled in. It used to be refused here on the grounds of not being
        // implemented; it is implemented now.
        assert_eq!(CpioHandler.probe(b"070702...", None), Confidence::MAGIC);
    }

    #[test]
    fn probe_rejects_short_header() {
        // Fewer bytes than the magic must not panic and must not match.
        assert_eq!(CpioHandler.probe(b"0707", None), Confidence::NONE);
        assert_eq!(CpioHandler.probe(b"", None), Confidence::NONE);
    }

    #[test]
    fn parse_octal_reads_plain_digits() {
        assert_eq!(parse_octal(b"000765"), Some(0o765));
        assert_eq!(parse_octal(b"100644"), Some(0o100644));
        assert_eq!(parse_octal(b"00000000000"), Some(0));
    }

    #[test]
    fn parse_octal_tolerates_space_and_nul_padding() {
        assert_eq!(parse_octal(b"  644 "), Some(0o644));
        assert_eq!(parse_octal(b"644\0\0\0"), Some(0o644));
    }

    #[test]
    fn parse_octal_rejects_garbage_without_panicking() {
        assert_eq!(parse_octal(b"zzzzzz"), None); // not octal at all
        assert_eq!(parse_octal(b"000899"), None); // 8 and 9 are not octal digits
        assert_eq!(parse_octal(b"      "), None); // no digits
        assert_eq!(parse_octal(b""), None);
        // 22 sevens overflow u64; `checked_*` turns that into None, not a wrap
        // and not a panic in release or debug.
        assert_eq!(parse_octal(&[b'7'; 22]), None);
    }

    #[test]
    fn parse_hex_reads_both_digit_cases() {
        assert_eq!(parse_hex(b"000081a4"), Some(0o100644));
        assert_eq!(parse_hex(b"000081A4"), Some(0o100644));
        assert_eq!(parse_hex(b"00000000"), Some(0));
        assert_eq!(parse_hex(b"ffffffff"), Some(u64::from(u32::MAX)));
    }

    #[test]
    fn parse_hex_tolerates_space_and_nul_padding() {
        assert_eq!(parse_hex(b"  1a4 "), Some(0x1a4));
        assert_eq!(parse_hex(b"1a4\0\0\0"), Some(0x1a4));
    }

    #[test]
    fn parse_hex_rejects_garbage_without_panicking() {
        assert_eq!(parse_hex(b"zzzzzzzz"), None); // not hex at all
        assert_eq!(parse_hex(b"0000g000"), None); // 'g' is past 'f'
        assert_eq!(parse_hex(b"        "), None); // no digits
        assert_eq!(parse_hex(b""), None);
        // 17 f's overflow u64; `checked_*` turns that into None, not a wrap and
        // not a panic in release or debug.
        assert_eq!(parse_hex(&[b'f'; 17]), None);
    }

    #[test]
    fn pad4_rounds_up_to_four() {
        assert_eq!(pad4(0), 0);
        assert_eq!(pad4(1), 3);
        assert_eq!(pad4(2), 2);
        assert_eq!(pad4(3), 1);
        assert_eq!(pad4(4), 0);
        // A name of 5 bytes after the 110-byte header lands on 115 → 1 pad byte.
        assert_eq!(pad4(NEWC_HEADER_LEN as u64 + 5), 1);
    }

    #[test]
    fn newc_header_spans_match_a_real_record() {
        // The first record of the committed `cpio_newc.cpio` fixture, verbatim:
        // one 6-byte file "a.txt" (namesize 6 counts the NUL). Thirteen fields
        // of eight hex digits after the magic — this pins every span below.
        let header: &[u8] = b"070701153d6720000081a4000001f500000000000000016a3c29d200000006000000010000001100000000000000000000000600000000";
        assert_eq!(header.len(), NEWC_HEADER_LEN);
        assert_eq!(&header[..MAGIC_LEN], MAGIC_NEWC);
        assert_eq!(newc_field(header, NEWC_MODE, "mode").unwrap(), 0o100644);
        assert_eq!(newc_field(header, NEWC_MTIME, "mtime").unwrap(), 0x6a3c29d2);
        assert_eq!(newc_field(header, NEWC_FILESIZE, "filesize").unwrap(), 6);
        assert_eq!(newc_field(header, NEWC_NAMESIZE, "namesize").unwrap(), 6);
    }

    #[test]
    fn odc_header_spans_match_a_ditto_record() {
        // The first record `ditto -c src out.cpio` writes for the packed root.
        let header: &[u8] =
            b"0707070000000000000407550007650000000000040000001523323025500000200000000000";
        assert_eq!(header.len(), ODC_HEADER_LEN);
        assert_eq!(&header[..MAGIC_LEN], MAGIC_ODC);
        assert_eq!(odc_field(header, ODC_MODE, "mode").unwrap(), 0o040755);
        assert_eq!(
            odc_field(header, ODC_MTIME, "mtime").unwrap(),
            0o15233230255
        );
        assert_eq!(odc_field(header, ODC_NAMESIZE, "namesize").unwrap(), 2);
        assert_eq!(odc_field(header, ODC_FILESIZE, "filesize").unwrap(), 0);
    }

    // ── Seekable odc: the listing must not read the bodies ───────────────────

    /// Build one odc record: the 76-byte header, the NUL-terminated name, then
    /// the body. Mirrors what `ditto` writes, minus the fields we ignore.
    fn odc_record(name: &[u8], mode: u32, body: &[u8]) -> Vec<u8> {
        let mut rec = Vec::new();
        rec.extend_from_slice(MAGIC_ODC);
        rec.extend_from_slice(b"000000"); // dev
        rec.extend_from_slice(b"000001"); // ino
        rec.extend_from_slice(format!("{mode:06o}").as_bytes());
        rec.extend_from_slice(b"000000"); // uid
        rec.extend_from_slice(b"000000"); // gid
        rec.extend_from_slice(b"000001"); // nlink
        rec.extend_from_slice(b"000000"); // rdev
        rec.extend_from_slice(b"00000000001"); // mtime
        rec.extend_from_slice(format!("{:06o}", name.len() + 1).as_bytes());
        rec.extend_from_slice(format!("{:011o}", body.len()).as_bytes());
        assert_eq!(rec.len(), ODC_HEADER_LEN);
        rec.extend_from_slice(name);
        rec.push(0);
        rec.extend_from_slice(body);
        rec
    }

    /// The closing record every odc archive ends with.
    fn odc_trailer() -> Vec<u8> {
        odc_record(b"TRAILER!!!", 0, b"")
    }

    /// A source that counts every byte handed out, so a test can tell reading
    /// from seeking apart.
    struct CountingSource {
        inner: Cursor<Vec<u8>>,
        read: std::sync::Arc<std::sync::atomic::AtomicU64>,
    }

    impl Read for CountingSource {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.read
                .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
            Ok(n)
        }
    }

    impl Seek for CountingSource {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            self.inner.seek(pos)
        }
    }

    /// Open `bytes` as a seekable odc archive and return the error it must
    /// fail with. (`ArchiveReader` is not `Debug`, so `expect_err` is out.)
    fn open_err(bytes: Vec<u8>) -> Error {
        let (src, _) = counting_source(bytes);
        match CpioHandler.open(src, &OpenOptions::default()) {
            Ok(_) => panic!("this archive must not open"),
            Err(e) => e,
        }
    }

    /// Wrap `bytes` in a seekable source plus the counter watching it.
    fn counting_source(bytes: Vec<u8>) -> (Source, std::sync::Arc<std::sync::atomic::AtomicU64>) {
        let read = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let src = Source::Seekable {
            inner: Box::new(CountingSource {
                inner: Cursor::new(bytes),
                read: read.clone(),
            }),
            path: None,
        };
        (src, read)
    }

    /// The point of the seekable path: listing a 4 MiB archive reads a few
    /// header-sized buffers, not the four megabytes.
    ///
    /// The bound is fixed by construction, not by timing: the walk reads a
    /// 76-byte header plus a short name per record and skips each body by
    /// seeking, so the only bytes that cross the boundary are the buffer fills
    /// those headers sit in — five records × 64 KiB at the very worst.
    #[test]
    fn seekable_odc_lists_without_reading_bodies() {
        const BODY: usize = 1024 * 1024;
        let bodies: Vec<Vec<u8>> = (0..4u8).map(|i| vec![b'a' + i; BODY]).collect();
        let mut archive = Vec::new();
        for (i, body) in bodies.iter().enumerate() {
            archive.extend_from_slice(&odc_record(
                format!("file{i}.bin").as_bytes(),
                S_IFREG | 0o644,
                body,
            ));
        }
        archive.extend_from_slice(&odc_trailer());
        let total = archive.len() as u64;
        assert!(total > 4 * 1024 * 1024);

        let (src, counter) = counting_source(archive);
        let mut reader = CpioHandler
            .open(src, &OpenOptions::default())
            .expect("open odc from a seekable source");

        let listing_reads = counter.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(reader.entries().expect("entries").len(), 4);
        assert!(
            listing_reads < 512 * 1024,
            "listing read {listing_reads} bytes of a {total}-byte archive; \
             bodies are being read instead of skipped"
        );

        // And the bodies are still readable — the offsets point into the
        // archive, and reading one costs its own size, not the whole file.
        let before = counter.load(std::sync::atomic::Ordering::Relaxed);
        let mut out = Vec::new();
        reader.read_entry(2, &mut out).expect("read_entry");
        assert_eq!(out, bodies[2]);
        let body_reads = counter.load(std::sync::atomic::Ordering::Relaxed) - before;
        assert!(
            body_reads < 2 * BODY as u64,
            "reading one 1 MiB body took {body_reads} bytes"
        );
    }

    /// Dirs and symlinks survive the seeking walk: the target is read at scan
    /// time (it is a few bytes and the entry list needs it), the directory has
    /// no body, and the file after them is still found — which is only true if
    /// the walk stayed in step.
    #[test]
    fn seekable_odc_keeps_dirs_and_symlinks() {
        let mut archive = Vec::new();
        archive.extend_from_slice(&odc_record(b"sub", S_IFDIR | 0o755, b""));
        archive.extend_from_slice(&odc_record(b"sub/link", S_IFLNK | 0o777, b"a.txt"));
        archive.extend_from_slice(&odc_record(b"a.txt", S_IFREG | 0o644, b"one\n"));
        archive.extend_from_slice(&odc_trailer());

        let (src, _) = counting_source(archive);
        let mut reader = CpioHandler.open(src, &OpenOptions::default()).unwrap();
        let entries = reader.entries().unwrap().to_vec();
        assert_eq!(entries.len(), 3);
        assert!(matches!(entries[0].kind, EntryKind::Dir));
        assert!(matches!(
            &entries[1].kind,
            EntryKind::Symlink { target } if target == Path::new("a.txt")
        ));
        assert_eq!(entries[2].path, Path::new("a.txt"));

        let mut out = Vec::new();
        reader.read_entry(2, &mut out).unwrap();
        assert_eq!(out, b"one\n");
        // No body, no bytes — and no error either.
        let mut empty = Vec::new();
        reader.read_entry(0, &mut empty).unwrap();
        assert!(empty.is_empty());
    }

    /// A body cut short is refused at open time, by arithmetic: the header says
    /// more bytes than the file holds.
    #[test]
    fn seekable_odc_truncated_body_is_corrupt_at_open() {
        let mut archive = odc_record(b"a.txt", S_IFREG | 0o644, &vec![b'x'; 4096]);
        archive.extend_from_slice(&odc_trailer());
        archive.truncate(archive.len() - 2048);

        let err = open_err(archive);
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }

    /// A crafted `filesize` far larger than the file must fail, not allocate.
    #[test]
    fn seekable_odc_oversized_filesize_is_corrupt() {
        let mut archive = odc_record(b"a.txt", S_IFREG | 0o644, b"tiny");
        // Overwrite the filesize field with ~8 GB.
        let (off, len) = ODC_FILESIZE;
        archive[off..off + len].copy_from_slice(b"77777777777");
        archive.extend_from_slice(&odc_trailer());

        let err = open_err(archive);
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }

    /// Junk where the next header belongs is caught even though the body it
    /// follows was never read — the structural check the skip does not lose.
    #[test]
    fn seekable_odc_rejects_a_bad_record_after_a_skipped_body() {
        let mut archive = odc_record(b"a.txt", S_IFREG | 0o644, &vec![b'x'; 4096]);
        let mut junk = odc_trailer();
        junk[..MAGIC_LEN].copy_from_slice(b"XXXXXX");
        archive.extend_from_slice(&junk);

        let err = open_err(archive);
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }

    // ── Seekable newc: the same walk, plus the alignment odc does not have ───

    /// Build one newc record: the 110-byte header, the NUL-terminated name
    /// padded so `110 + namesize` is a multiple of four, then the body padded
    /// the same way. `extra_nuls` appends further NULs to the name *inside*
    /// `namesize`, which is what `dracut-cpio` does.
    fn newc_record_padded(name: &[u8], mode: u32, body: &[u8], extra_nuls: usize) -> Vec<u8> {
        let namesize = name.len() + 1 + extra_nuls;
        let mut rec = Vec::new();
        rec.extend_from_slice(MAGIC_NEWC);
        // ino, mode, uid, gid, nlink, mtime, filesize, devmajor, devminor,
        // rdevmajor, rdevminor, namesize, check.
        let fields: [u64; 13] = [
            1,
            u64::from(mode),
            0,
            0,
            1,
            1,
            body.len() as u64,
            0,
            0,
            0,
            0,
            namesize as u64,
            0,
        ];
        for f in fields {
            rec.extend_from_slice(format!("{f:08x}").as_bytes());
        }
        assert_eq!(rec.len(), NEWC_HEADER_LEN);
        rec.extend_from_slice(name);
        rec.resize(rec.len() + 1 + extra_nuls, 0);
        rec.resize(
            rec.len() + pad4(NEWC_HEADER_LEN as u64 + namesize as u64) as usize,
            0,
        );
        rec.extend_from_slice(body);
        rec.resize(rec.len() + pad4(body.len() as u64) as usize, 0);
        rec
    }

    fn newc_record(name: &[u8], mode: u32, body: &[u8]) -> Vec<u8> {
        newc_record_padded(name, mode, body, 0)
    }

    /// The closing record every newc archive ends with.
    fn newc_trailer() -> Vec<u8> {
        newc_record(b"TRAILER!!!", 0, b"")
    }

    /// The point of the seekable path, for newc this time: listing a 4 MiB
    /// archive reads a few header-sized buffers, not the four megabytes.
    #[test]
    fn seekable_newc_lists_without_reading_bodies() {
        const BODY: usize = 1024 * 1024;
        let bodies: Vec<Vec<u8>> = (0..4u8).map(|i| vec![b'a' + i; BODY]).collect();
        let mut archive = Vec::new();
        for (i, body) in bodies.iter().enumerate() {
            archive.extend_from_slice(&newc_record(
                format!("file{i}.bin").as_bytes(),
                S_IFREG | 0o644,
                body,
            ));
        }
        archive.extend_from_slice(&newc_trailer());
        let total = archive.len() as u64;
        assert!(total > 4 * 1024 * 1024);

        let (src, counter) = counting_source(archive);
        let mut reader = CpioHandler
            .open(src, &OpenOptions::default())
            .expect("open newc from a seekable source");

        let listing_reads = counter.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(reader.entries().expect("entries").len(), 4);
        assert!(
            listing_reads < 512 * 1024,
            "listing read {listing_reads} bytes of a {total}-byte archive; \
             bodies are being read instead of skipped"
        );

        let before = counter.load(std::sync::atomic::Ordering::Relaxed);
        let mut out = Vec::new();
        reader.read_entry(2, &mut out).expect("read_entry");
        assert_eq!(out, bodies[2]);
        let body_reads = counter.load(std::sync::atomic::Ordering::Relaxed) - before;
        assert!(
            body_reads < 2 * BODY as u64,
            "reading one 1 MiB body took {body_reads} bytes"
        );
    }

    /// Alignment is the whole difference from odc, so it gets its own test: a
    /// name and a body that each need padding, followed by another record whose
    /// content proves the walk did not drift.
    #[test]
    fn seekable_newc_honours_name_and_body_padding() {
        // 110 + namesize must not already be a multiple of four, and the body
        // length must not either: "ab.txt" is 6 + 1 = 7 → 117, pad 3; the body
        // "odd" is 3 bytes → pad 1.
        let first = newc_record(b"ab.txt", S_IFREG | 0o644, b"odd");
        assert_eq!(pad4(NEWC_HEADER_LEN as u64 + 7), 3);
        assert_eq!(first.len() % 4, 0, "a record must end four-byte aligned");

        let mut archive = first;
        archive.extend_from_slice(&newc_record(b"second.bin", S_IFREG | 0o600, b"SECOND"));
        archive.extend_from_slice(&newc_trailer());

        let (src, _) = counting_source(archive);
        let mut reader = CpioHandler.open(src, &OpenOptions::default()).unwrap();
        let entries = reader.entries().unwrap().to_vec();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path, Path::new("ab.txt"));
        assert_eq!(entries[1].path, Path::new("second.bin"));

        let mut out = Vec::new();
        reader.read_entry(0, &mut out).unwrap();
        assert_eq!(out, b"odd", "the first body must not include its padding");
        out.clear();
        reader.read_entry(1, &mut out).unwrap();
        assert_eq!(out, b"SECOND", "the second record drifted");
    }

    /// Dirs and symlinks survive the seeking walk, and the record after them is
    /// still found — true only if the walk stayed in step across the padding.
    #[test]
    fn seekable_newc_keeps_dirs_and_symlinks() {
        let mut archive = Vec::new();
        archive.extend_from_slice(&newc_record(b"sub", S_IFDIR | 0o755, b""));
        archive.extend_from_slice(&newc_record(b"sub/link", S_IFLNK | 0o777, b"a.txt"));
        archive.extend_from_slice(&newc_record(b"a.txt", S_IFREG | 0o644, b"one\n"));
        archive.extend_from_slice(&newc_trailer());

        let (src, _) = counting_source(archive);
        let mut reader = CpioHandler.open(src, &OpenOptions::default()).unwrap();
        let entries = reader.entries().unwrap().to_vec();
        assert_eq!(entries.len(), 3);
        assert!(matches!(entries[0].kind, EntryKind::Dir));
        assert!(matches!(
            &entries[1].kind,
            EntryKind::Symlink { target } if target == Path::new("a.txt")
        ));
        assert_eq!(entries[2].path, Path::new("a.txt"));

        let mut out = Vec::new();
        reader.read_entry(2, &mut out).unwrap();
        assert_eq!(out, b"one\n");
    }

    /// A name padded with NULs beyond its terminator — what `dracut-cpio`
    /// writes — keeps the path it had before this parser was written: the
    /// previous one trimmed every trailing NUL, and so does this.
    #[test]
    fn seekable_newc_trims_extra_nuls_in_a_name() {
        let mut archive = newc_record_padded(b"a.txt", S_IFREG | 0o644, b"hi", 5);
        archive.extend_from_slice(&newc_trailer());

        let (src, _) = counting_source(archive);
        let mut reader = CpioHandler.open(src, &OpenOptions::default()).unwrap();
        let entries = reader.entries().unwrap().to_vec();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, Path::new("a.txt"));
        assert_eq!(entries[0].path_raw, b"a.txt");
        let mut out = Vec::new();
        reader.read_entry(0, &mut out).unwrap();
        assert_eq!(out, b"hi", "the record after a padded name must line up");
    }

    /// Names that are not UTF-8 open, decode through the shared one-encoding
    /// pass, and keep their exact bytes in `path_raw`. The old parser refused
    /// the whole archive here.
    #[test]
    fn seekable_newc_reads_non_utf8_names() {
        // "отчет.txt" and "письмо.txt" in windows-1251.
        let a: &[u8] = &[
            0xEE, 0xF2, 0xF7, 0xE5, 0xF2, b'.', b't', b'x', b't', // отчет.txt
        ];
        let b: &[u8] = &[
            0xEF, 0xE8, 0xF1, 0xFC, 0xEC, 0xEE, b'.', b't', b'x', b't', // письмо.txt
        ];
        let mut archive = newc_record(a, S_IFREG | 0o644, b"one");
        archive.extend_from_slice(&newc_record(b, S_IFREG | 0o644, b"two"));
        archive.extend_from_slice(&newc_trailer());

        let opts = OpenOptions {
            encoding_override: Some("windows-1251".into()),
            ..OpenOptions::default()
        };
        let (src, _) = counting_source(archive);
        let mut reader = CpioHandler
            .open(src, &opts)
            .expect("cp1251 names must open");
        let entries = reader.entries().unwrap().to_vec();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path, Path::new("отчет.txt"));
        assert_eq!(entries[1].path, Path::new("письмо.txt"));
        // The exact archive bytes survive, undecoded — path safety keys off
        // these, not off the decoded name.
        assert_eq!(entries[0].path_raw, a);
        assert_eq!(entries[1].path_raw, b);

        let mut out = Vec::new();
        reader.read_entry(1, &mut out).unwrap();
        assert_eq!(out, b"two");
    }

    /// A body cut short is refused at open time, by arithmetic.
    #[test]
    fn seekable_newc_truncated_body_is_corrupt_at_open() {
        let mut archive = newc_record(b"a.txt", S_IFREG | 0o644, &vec![b'x'; 4096]);
        archive.extend_from_slice(&newc_trailer());
        archive.truncate(archive.len() - 2048);

        let err = open_err(archive);
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }

    /// A crafted `filesize` far larger than the file must fail, not allocate.
    #[test]
    fn seekable_newc_oversized_filesize_is_corrupt() {
        let mut archive = newc_record(b"a.txt", S_IFREG | 0o644, b"tiny");
        // Overwrite the filesize field with 4 GB - 1.
        let (off, len) = NEWC_FILESIZE;
        archive[off..off + len].copy_from_slice(b"ffffffff");
        archive.extend_from_slice(&newc_trailer());

        let err = open_err(archive);
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }

    /// Garbage in a hex field is an error, not a silently wrong number.
    #[test]
    fn seekable_newc_garbage_field_is_corrupt() {
        let mut archive = newc_record(b"a.txt", S_IFREG | 0o644, b"tiny");
        let (off, len) = NEWC_NAMESIZE;
        archive[off..off + len].copy_from_slice(b"zzzzzzzz");
        archive.extend_from_slice(&newc_trailer());

        let err = open_err(archive);
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }

    /// Junk where the next header belongs is caught even though the body it
    /// follows was never read.
    #[test]
    fn seekable_newc_rejects_a_bad_record_after_a_skipped_body() {
        let mut archive = newc_record(b"a.txt", S_IFREG | 0o644, &vec![b'x'; 4096]);
        let mut junk = newc_trailer();
        junk[..MAGIC_LEN].copy_from_slice(b"XXXXXX");
        archive.extend_from_slice(&junk);

        let err = open_err(archive);
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }

    /// A `Source::Stream` cannot seek, so newc spills it to a temp file and
    /// walks that — same entries, same bodies.
    #[test]
    fn streamed_newc_goes_through_a_temp_file() {
        let mut archive = newc_record(b"a.txt", S_IFREG | 0o644, b"one\n");
        archive.extend_from_slice(&newc_record(b"b.bin", S_IFREG | 0o600, b"two two\n"));
        archive.extend_from_slice(&newc_trailer());

        let src = Source::Stream {
            inner: Box::new(Cursor::new(archive)),
            path: None,
        };
        let mut reader = CpioHandler
            .open(src, &OpenOptions::default())
            .expect("open newc from a stream");
        let entries = reader.entries().unwrap().to_vec();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].path, Path::new("b.bin"));

        let mut out = Vec::new();
        reader.read_entry(1, &mut out).unwrap();
        assert_eq!(out, b"two two\n");
    }

    #[test]
    fn is_supported_magic_covers_newc_crc_and_odc() {
        assert!(is_supported_magic(b"070701")); // newc
        assert!(is_supported_magic(b"070702")); // crc
        assert!(is_supported_magic(b"070707")); // odc
        // 070703 does not exist; only the three above do.
        assert!(!is_supported_magic(b"070703"));
        assert!(!is_supported_magic(b"PK\x03\x04"));
    }

    // ── crc (070702): the newc walk plus a checksum verified at read time ────

    /// The variant's checksum on a body whose bytes are known by hand: three
    /// bytes of 0xFF sum to 0x2FD, so the wrap is not what is being tested here
    /// — the plain sum is.
    #[test]
    fn body_checksum_sums_bytes_as_unsigned() {
        assert_eq!(body_checksum(b""), 0);
        assert_eq!(body_checksum(b"hi"), u32::from(b'h') + u32::from(b'i'));
        assert_eq!(body_checksum(&[0xFF, 0xFF, 0xFF]), 0x2FD);
        // A megabyte of 0xFF: 0x0FF0_0000. Far past what a u8 or u16
        // accumulator could hold, and the bytes are counted unsigned — a signed
        // reading would give -1 each and land nowhere near this.
        assert_eq!(body_checksum(&vec![0xFFu8; 1 << 20]), 0x0FF0_0000);
    }

    /// Build one crc record. Identical to [`newc_record`] but for the magic and
    /// the `check` field, which really is the sum of the body's bytes — unless
    /// `check` overrides it, which is how the mismatch test forges one.
    fn crc_record_with_check(name: &[u8], mode: u32, body: &[u8], check: Option<u32>) -> Vec<u8> {
        let mut rec = newc_record(name, mode, body);
        rec[..MAGIC_LEN].copy_from_slice(MAGIC_CRC);
        let (off, len) = NEWC_CHECK;
        let sum = check.unwrap_or_else(|| body_checksum(body));
        rec[off..off + len].copy_from_slice(format!("{sum:08x}").as_bytes());
        rec
    }

    fn crc_record(name: &[u8], mode: u32, body: &[u8]) -> Vec<u8> {
        crc_record_with_check(name, mode, body, None)
    }

    /// The closing record every crc archive ends with. Its `check` is zero,
    /// like every empty body's.
    fn crc_trailer() -> Vec<u8> {
        crc_record(b"TRAILER!!!", 0, b"")
    }

    /// The heart of the ticket: a crc archive lists as fast as a newc one. The
    /// checksum is *not* verified while the listing is built — doing so would
    /// mean reading every body, which is exactly what the seekable walk exists
    /// to avoid.
    #[test]
    fn seekable_crc_lists_without_reading_bodies() {
        const BODY: usize = 1024 * 1024;
        let bodies: Vec<Vec<u8>> = (0..4u8).map(|i| vec![b'a' + i; BODY]).collect();
        let mut archive = Vec::new();
        for (i, body) in bodies.iter().enumerate() {
            archive.extend_from_slice(&crc_record(
                format!("file{i}.bin").as_bytes(),
                S_IFREG | 0o644,
                body,
            ));
        }
        archive.extend_from_slice(&crc_trailer());
        let total = archive.len() as u64;
        assert!(total > 4 * 1024 * 1024);

        let (src, counter) = counting_source(archive);
        let mut reader = CpioHandler
            .open(src, &OpenOptions::default())
            .expect("open crc from a seekable source");

        let listing_reads = counter.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(reader.entries().expect("entries").len(), 4);
        assert!(
            listing_reads < 512 * 1024,
            "listing read {listing_reads} bytes of a {total}-byte archive; \
             the checksum is being verified at open time instead of at read time"
        );

        // And a matching checksum reads silently, at the cost of its own body.
        let before = counter.load(std::sync::atomic::Ordering::Relaxed);
        let mut out = Vec::new();
        reader.read_entry(2, &mut out).expect("read_entry");
        assert_eq!(out, bodies[2]);
        let body_reads = counter.load(std::sync::atomic::Ordering::Relaxed) - before;
        assert!(
            body_reads < 2 * BODY as u64,
            "reading one 1 MiB body took {body_reads} bytes"
        );
    }

    /// A forged `check` field is caught — and only when the body is read, not
    /// when the archive is opened.
    #[test]
    fn crc_checksum_mismatch_is_an_error_at_read_time() {
        let body = b"the quick brown fox";
        let mut archive = crc_record_with_check(
            b"a.txt",
            S_IFREG | 0o644,
            body,
            Some(body_checksum(body) ^ 1),
        );
        archive.extend_from_slice(&crc_record(b"b.txt", S_IFREG | 0o644, b"intact"));
        archive.extend_from_slice(&crc_trailer());

        let (src, _) = counting_source(archive);
        let mut reader = CpioHandler
            .open(src, &OpenOptions::default())
            .expect("a bad checksum must not stop the archive from opening");
        assert_eq!(reader.entries().unwrap().len(), 2);

        let err = reader
            .read_entry(0, &mut Vec::new())
            .expect_err("a mismatched checksum must be an error, not silent content");
        match err {
            Error::Corrupt(msg) => {
                assert!(msg.contains("a.txt"), "the entry must be named: {msg}");
                assert!(msg.contains("checksum"), "{msg}");
            }
            other => panic!("expected Corrupt, got {other:?}"),
        }

        // The neighbouring record is untouched by the failure.
        let mut out = Vec::new();
        reader.read_entry(1, &mut out).expect("read_entry 1");
        assert_eq!(out, b"intact");
    }

    /// The whole archive: dirs, symlinks, an empty file and the padding newc
    /// alignment demands — all read back with their checksums matching.
    #[test]
    fn crc_reads_a_whole_tree_with_matching_checksums() {
        let mut archive = crc_record(b"sub", S_IFDIR | 0o755, b"");
        archive.extend_from_slice(&crc_record(b"sub/link", S_IFLNK | 0o777, b"a.txt"));
        // A body of high bytes, so a sum that wrapped or treated bytes as signed
        // would not match.
        let high: Vec<u8> = (0..300u32).map(|i| (i % 256) as u8).collect();
        archive.extend_from_slice(&crc_record(b"a.txt", S_IFREG | 0o644, &high));
        archive.extend_from_slice(&crc_record(b"empty.bin", S_IFREG | 0o600, b""));
        archive.extend_from_slice(&crc_trailer());

        let (src, _) = counting_source(archive);
        let mut reader = CpioHandler.open(src, &OpenOptions::default()).unwrap();
        let entries = reader.entries().unwrap().to_vec();
        assert_eq!(entries.len(), 4);
        assert!(matches!(entries[0].kind, EntryKind::Dir));
        assert!(matches!(
            &entries[1].kind,
            EntryKind::Symlink { target } if target == Path::new("a.txt")
        ));
        assert_eq!(entries[2].path, Path::new("a.txt"));
        assert_eq!(entries[2].mode, Some(S_IFREG | 0o644));

        let mut out = Vec::new();
        reader.read_entry(2, &mut out).expect("read a.txt");
        assert_eq!(out, high);
        out.clear();
        reader.read_entry(3, &mut out).expect("read empty.bin");
        assert!(out.is_empty());
    }

    /// An empty body whose header claims a non-zero sum is still a mismatch —
    /// the zero-length shortcut must not skip the check.
    #[test]
    fn crc_empty_body_with_a_wrong_checksum_is_an_error() {
        let mut archive = crc_record_with_check(b"empty.bin", S_IFREG | 0o644, b"", Some(1));
        archive.extend_from_slice(&crc_trailer());

        let (src, _) = counting_source(archive);
        let mut reader = CpioHandler.open(src, &OpenOptions::default()).unwrap();
        let err = reader
            .read_entry(0, &mut Vec::new())
            .expect_err("an empty body must still add up to what was promised");
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }

    /// A crc record inside a newc archive (or the other way round) desynchronises
    /// nothing, because the walk pins the magic it started with.
    #[test]
    fn crc_walk_refuses_a_newc_record() {
        let mut archive = crc_record(b"a.txt", S_IFREG | 0o644, b"one");
        archive.extend_from_slice(&newc_record(b"b.txt", S_IFREG | 0o644, b"two"));
        archive.extend_from_slice(&crc_trailer());

        let err = open_err(archive);
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }

    /// A `Source::Stream` of crc bytes takes the same spill-to-temp path newc
    /// does, checksum and all.
    #[test]
    fn streamed_crc_goes_through_a_temp_file() {
        let mut archive = crc_record(b"a.txt", S_IFREG | 0o644, b"one\n");
        archive.extend_from_slice(&crc_record_with_check(
            b"bad.bin",
            S_IFREG | 0o600,
            b"two two\n",
            Some(0),
        ));
        archive.extend_from_slice(&crc_trailer());

        let src = Source::Stream {
            inner: Box::new(Cursor::new(archive)),
            path: None,
        };
        let mut reader = CpioHandler
            .open(src, &OpenOptions::default())
            .expect("open crc from a stream");
        assert_eq!(reader.entries().unwrap().len(), 2);

        let mut out = Vec::new();
        reader.read_entry(0, &mut out).expect("read_entry 0");
        assert_eq!(out, b"one\n");
        // The checksum survives the spill: the forged one still fails.
        let err = reader
            .read_entry(1, &mut Vec::new())
            .expect_err("the spilled path must verify the checksum too");
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }

    // ── A stream must read exactly like the same bytes on disk ───────────────

    /// The same little tree in whichever variant `rec` writes: a directory, a
    /// symlink, a file whose body length needs newc's padding, one body big
    /// enough to be worth truncating, and an empty file.
    fn sample_tree(rec: fn(&[u8], u32, &[u8]) -> Vec<u8>, trailer: fn() -> Vec<u8>) -> Vec<u8> {
        let mut archive = rec(b"sub", S_IFDIR | 0o755, b"");
        archive.extend_from_slice(&rec(b"sub/link", S_IFLNK | 0o777, b"a.txt"));
        archive.extend_from_slice(&rec(b"a.txt", S_IFREG | 0o644, b"odd"));
        archive.extend_from_slice(&rec(b"sub/big.bin", S_IFREG | 0o600, &vec![b'z'; 5000]));
        archive.extend_from_slice(&rec(b"empty.bin", S_IFREG | 0o600, b""));
        archive.extend_from_slice(&trailer());
        archive
    }

    /// Open the same bytes twice — once as a seekable source, once as a
    /// `Source::Stream` — and require the two readers to agree on every entry
    /// and every body. The stream is spilled to a temp file and then walked by
    /// the very same parser, so any divergence means the spill lost or shifted
    /// something.
    fn assert_stream_matches_file(archive: Vec<u8>, what: &str) {
        let (src, _) = counting_source(archive.clone());
        let mut from_file = CpioHandler
            .open(src, &OpenOptions::default())
            .unwrap_or_else(|e| panic!("{what}: the seekable open failed: {e}"));
        let stream = Source::Stream {
            inner: Box::new(Cursor::new(archive)),
            path: None,
        };
        let mut from_stream = CpioHandler
            .open(stream, &OpenOptions::default())
            .unwrap_or_else(|e| panic!("{what}: the stream open failed: {e}"));

        let listed = from_file.entries().expect("entries from the file").to_vec();
        let streamed = from_stream
            .entries()
            .expect("entries from the stream")
            .to_vec();
        assert_eq!(listed.len(), streamed.len(), "{what}: entry count");
        assert!(listed.len() >= 4, "{what}: the sample tree lost entries");

        for (i, (a, b)) in listed.iter().zip(&streamed).enumerate() {
            assert_eq!(a.path, b.path, "{what}: path of entry {i}");
            assert_eq!(a.path_raw, b.path_raw, "{what}: raw name of entry {i}");
            assert_eq!(a.kind, b.kind, "{what}: kind of entry {i}");
            assert_eq!(a.size, b.size, "{what}: size of entry {i}");
            assert_eq!(a.mode, b.mode, "{what}: mode of entry {i}");
            assert_eq!(a.modified, b.modified, "{what}: mtime of entry {i}");

            let mut file_body = Vec::new();
            let mut stream_body = Vec::new();
            from_file
                .read_entry(i, &mut file_body)
                .unwrap_or_else(|e| panic!("{what}: read_entry {i} from the file: {e}"));
            from_stream
                .read_entry(i, &mut stream_body)
                .unwrap_or_else(|e| panic!("{what}: read_entry {i} from the stream: {e}"));
            assert_eq!(file_body, stream_body, "{what}: body of entry {i}");
        }
    }

    #[test]
    fn streamed_odc_reads_like_the_same_archive_from_a_file() {
        assert_stream_matches_file(sample_tree(odc_record, odc_trailer), "odc");
    }

    #[test]
    fn streamed_newc_reads_like_the_same_archive_from_a_file() {
        assert_stream_matches_file(sample_tree(newc_record, newc_trailer), "newc");
    }

    #[test]
    fn streamed_crc_reads_like_the_same_archive_from_a_file() {
        assert_stream_matches_file(sample_tree(crc_record, crc_trailer), "crc");
    }

    /// A stream that stops mid-body is `Error::Corrupt`, not a quietly short
    /// listing: the spill copies whatever arrived, and the walk then finds a
    /// header claiming more bytes than the spilled file holds.
    #[test]
    fn a_truncated_stream_is_corrupt_for_every_variant() {
        for (what, mut archive) in [
            ("odc", sample_tree(odc_record, odc_trailer)),
            ("newc", sample_tree(newc_record, newc_trailer)),
            ("crc", sample_tree(crc_record, crc_trailer)),
        ] {
            // Cuts into the 5000-byte body, so the records before it are intact
            // and only the arithmetic can catch the loss.
            archive.truncate(archive.len() - 2500);
            let src = Source::Stream {
                inner: Box::new(Cursor::new(archive)),
                path: None,
            };
            match CpioHandler.open(src, &OpenOptions::default()) {
                Ok(_) => panic!("{what}: a truncated stream must not open"),
                Err(e) => assert!(matches!(e, Error::Corrupt(_)), "{what}: got {e:?}"),
            }
        }
    }

    /// An empty stream is a truncated archive, not a panic and not an empty
    /// listing: there is not even a magic to spill.
    #[test]
    fn an_empty_stream_is_corrupt() {
        let src = Source::Stream {
            inner: Box::new(Cursor::new(Vec::new())),
            path: None,
        };
        match CpioHandler.open(src, &OpenOptions::default()) {
            Ok(_) => panic!("an empty stream must not open"),
            Err(e) => assert!(matches!(e, Error::Corrupt(_)), "got {e:?}"),
        }
    }
}
