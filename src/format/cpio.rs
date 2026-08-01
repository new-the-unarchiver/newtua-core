//! cpio (`.cpio`) — the two ASCII variants that can be read here: SVR4 "new
//! ASCII" (`070701`, what GNU/BSD `cpio -o -H newc` writes) and POSIX.1 "old
//! portable" / odc (`070707`, what `ditto` writes). The crc variant (`070702`)
//! is not implemented and is deliberately not claimed — see
//! `is_supported_magic`.
//!
//! Reached two ways: from the registry, on a bare `.cpio`; and from
//! `detect.rs`, which checks a just-decompressed stream for a cpio magic once
//! tar has been ruled out. That second path is what opens a `.cpgz` from macOS
//! Archive Utility — odc inside gzip.
//!
//! # How an archive is opened
//!
//! cpio is a sequential format, but the file it lives in usually is not, and
//! that decides which of the two paths `open` takes:
//!
//! * **Seekable source, odc.** The listing is built from the headers alone:
//!   every body is *skipped by seeking*, never read, and the source stays open
//!   so `read_entry` can seek back to a body on demand (`CpioSeekReader`). No
//!   temp file is written at all. This is the path a `.cpgz` takes, where the
//!   decompression layer has already spent one temp file on the gzip stream.
//!   Integrity does not suffer: the file length is taken once at open time and
//!   every record is checked against it (`body offset + declared length ≤ file
//!   length`), which catches a truncation *earlier* than reading would, and the
//!   next record's magic still has to be where the skip lands.
//! * **Everything else** — a non-seekable `Source::Stream`, and newc for now —
//!   makes one streaming pass, concatenating every regular-file body into a
//!   temp file and keeping per-entry offsets into it (`Scan`).

use std::io::{BufReader, Cursor, Read, Seek, SeekFrom, Write};
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
/// POSIX.1 "old portable" (odc) — what `ditto`, and therefore macOS Archive
/// Utility, writes.
pub(crate) const MAGIC_ODC: &[u8; 6] = b"070707";
/// Length of every cpio ASCII magic; also the peek needed to pick a variant.
pub(crate) const MAGIC_LEN: usize = 6;

/// Whether `magic` is a variant this handler can open.
///
/// `070702` (crc) is deliberately absent: it is not implemented, so claiming it
/// would turn a readable single entry into an open error.
pub(crate) fn is_supported_magic(magic: &[u8]) -> bool {
    magic == MAGIC_NEWC || magic == MAGIC_ODC
}

// ── Handler ──────────────────────────────────────────────────────────────────

pub struct CpioHandler;

impl FormatHandler for CpioHandler {
    fn id(&self) -> FormatId {
        FormatId::Cpio
    }

    fn probe(&self, header: &[u8], _name: Option<&str>) -> Confidence {
        // Detect the two ASCII variants that can actually be read: SVR4 "new
        // ASCII" (070701) and POSIX "old portable" / odc (070707).
        // 070702 (crc) is future work.
        if header.len() >= MAGIC_LEN && is_supported_magic(&header[..MAGIC_LEN]) {
            Confidence::MAGIC
        } else {
            Confidence::NONE
        }
    }

    fn open(&self, src: Source, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        // cpio is a sequential streaming format; we can read from either source.
        let raw: Box<dyn Read> = match src {
            Source::Seekable { mut inner, .. } => {
                // A seekable source can be listed from the headers alone. Only
                // odc goes that way today; newc still streams (its parser is
                // the `cpio` crate's, which cannot seek).
                let file_len = inner.seek(SeekFrom::End(0))?;
                inner.seek(SeekFrom::Start(0))?;
                let mut magic = [0u8; MAGIC_LEN];
                inner.read_exact(&mut magic).map_err(io_err_to_corrupt)?;
                if &magic == MAGIC_ODC {
                    return open_odc_seekable(inner, file_len, opts);
                }
                inner.seek(SeekFrom::Start(0))?;
                inner
            }
            Source::Stream { inner, .. } => inner,
        };
        // Both scanners walk the stream header by header — 110 bytes for newc,
        // 76 plus the name for odc — and `Source` hands over an unbuffered
        // file. Without this, a tree of 10 000 files costs tens of thousands of
        // syscalls; bodies still go through `io::copy` and are unaffected.
        let mut reader: Box<dyn Read> = Box::new(BufReader::with_capacity(64 * 1024, raw));

        // Pick the variant from the leading magic. A `Source::Stream` cannot be
        // rewound, so the magic is chained back in front of the rest.
        let mut magic = [0u8; MAGIC_LEN];
        reader.read_exact(&mut magic).map_err(io_err_to_corrupt)?;
        let stream: Box<dyn Read> = Box::new(Cursor::new(magic).chain(reader));

        let scan = match &magic {
            MAGIC_NEWC => scan_newc(stream)?,
            MAGIC_ODC => scan_odc(stream)?,
            _ => {
                return Err(Error::Corrupt(format!(
                    "unsupported cpio magic {:?}",
                    String::from_utf8_lossy(&magic)
                )));
            }
        };

        finish(scan, opts)
    }
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
}

/// Result of one streaming pass over an archive: all regular-file bodies
/// concatenated into a single temp file, plus per-entry metadata.
struct Scan {
    temp: tempfile::NamedTempFile,
    raw_names: Vec<Vec<u8>>,
    metas: Vec<EntryMeta>,
}

/// Drop the trailing NUL bytes cpio pads names and link targets with.
fn trim_nuls(bytes: &mut Vec<u8>) {
    while bytes.last() == Some(&0) {
        bytes.pop();
    }
}

// ── newc (070701) ────────────────────────────────────────────────────────────

/// Stream a newc archive, copying regular-file bodies into one shared temp file
/// and recording `(offset, size)` per entry.
fn scan_newc(reader: Box<dyn Read>) -> Result<Scan> {
    let mut temp = tempfile::NamedTempFile::new()?;
    let mut raw_names: Vec<Vec<u8>> = Vec::new();
    let mut metas: Vec<EntryMeta> = Vec::new();

    let mut current: Box<dyn Read> = reader;

    loop {
        let entry_reader = cpio::NewcReader::new(current).map_err(io_err_to_corrupt)?;

        if entry_reader.entry().is_trailer() {
            // Consume the trailer; we don't need the underlying reader.
            let _ = entry_reader.finish();
            break;
        }

        let entry = entry_reader.entry().clone();
        let mode = entry.mode();
        let file_size = entry.file_size() as u64;
        let name_str = entry.name().to_owned();
        let modified = unix_secs_to_systime(entry.mtime() as u64);

        match mode & S_IFMT {
            S_IFREG => {
                // Regular file: stream body into the shared temp file.
                let offset = temp.seek(SeekFrom::End(0))?;
                current = Box::new(
                    entry_reader
                        .to_writer(&mut temp)
                        .map_err(io_err_to_corrupt)?,
                );
                raw_names.push(name_str.into_bytes());
                metas.push(EntryMeta {
                    kind: KindRaw::File,
                    offset,
                    size: file_size,
                    mode,
                    modified,
                });
            }
            S_IFDIR => {
                current = Box::new(entry_reader.finish().map_err(io_err_to_corrupt)?);
                raw_names.push(name_str.into_bytes());
                metas.push(EntryMeta {
                    kind: KindRaw::Dir,
                    offset: 0,
                    size: 0,
                    mode,
                    modified,
                });
            }
            S_IFLNK => {
                // Symlink: body is the link target. `file_size` is an
                // attacker-controlled header field, so cap the capacity hint
                // (the Vec still grows as `to_writer` streams the real bytes)
                // to avoid a multi-GB eager allocation on a crafted header.
                let cap = (file_size as usize).min(64 * 1024);
                let mut target_bytes = Vec::with_capacity(cap);
                current = Box::new(
                    entry_reader
                        .to_writer(&mut target_bytes)
                        .map_err(io_err_to_corrupt)?,
                );
                trim_nuls(&mut target_bytes);
                raw_names.push(name_str.into_bytes());
                metas.push(EntryMeta {
                    kind: KindRaw::Symlink(target_bytes),
                    offset: 0,
                    size: file_size,
                    mode,
                    modified,
                });
            }
            _ => {
                // Special node (char/block device, fifo, socket) or hardlink —
                // skip silently per the spec.
                current = Box::new(entry_reader.finish().map_err(io_err_to_corrupt)?);
            }
        }
    }

    Ok(Scan {
        temp,
        raw_names,
        metas,
    })
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
/// The one way this scanner crosses a record: names go to a `Vec`, bodies to
/// the temp file, skipped records to `io::sink()`. `n` comes straight out of
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
            "cpio odc: truncated {what} ({moved} of {n} bytes)"
        )));
    }
    Ok(())
}

/// Stream an odc archive; the counterpart of [`scan_newc`].
fn scan_odc(reader: Box<dyn Read>) -> Result<Scan> {
    let mut temp = tempfile::NamedTempFile::new()?;
    let mut raw_names: Vec<Vec<u8>> = Vec::new();
    let mut metas: Vec<EntryMeta> = Vec::new();

    let mut reader = reader;
    let mut header = [0u8; ODC_HEADER_LEN];

    loop {
        // A stream that ends without its TRAILER record is truncated; the
        // read_exact below turns that into Corrupt rather than a silent stop.
        reader.read_exact(&mut header).map_err(io_err_to_corrupt)?;
        if &header[..MAGIC_LEN] != MAGIC_ODC {
            return Err(Error::Corrupt(
                "cpio odc: record does not start with 070707".into(),
            ));
        }

        let mode = odc_field(&header, ODC_MODE, "mode")? as u32;
        let mtime = odc_field(&header, ODC_MTIME, "mtime")?;
        let namesize = odc_field(&header, ODC_NAMESIZE, "namesize")?;
        let filesize = odc_field(&header, ODC_FILESIZE, "filesize")?;

        if namesize == 0 {
            return Err(Error::Corrupt("cpio odc: zero-length name".into()));
        }
        let mut name = Vec::new();
        take_exact(&mut reader, namesize, &mut name, format_args!("entry name"))?;
        // `namesize` counts the terminating NUL; drop it and any extra padding.
        trim_nuls(&mut name);

        if name == b"TRAILER!!!" {
            break;
        }

        let modified = unix_secs_to_systime(mtime);

        match mode & S_IFMT {
            S_IFREG => {
                let offset = temp.seek(SeekFrom::End(0))?;
                // `filesize` is untrusted: stream it and check what actually
                // arrived instead of trusting the header.
                take_exact(
                    &mut reader,
                    filesize,
                    &mut temp,
                    format_args!("body of {}", String::from_utf8_lossy(&name)),
                )?;
                raw_names.push(name);
                metas.push(EntryMeta {
                    kind: KindRaw::File,
                    offset,
                    size: filesize,
                    mode,
                    modified,
                });
            }
            S_IFDIR => {
                // Directories carry no body, but skip `filesize` anyway so a
                // non-conforming writer cannot desynchronise the stream.
                take_exact(
                    &mut reader,
                    filesize,
                    &mut std::io::sink(),
                    format_args!("record body"),
                )?;
                raw_names.push(name);
                metas.push(EntryMeta {
                    kind: KindRaw::Dir,
                    offset: 0,
                    size: 0,
                    mode,
                    modified,
                });
            }
            S_IFLNK => {
                // Symlink: the body is the link target.
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
                });
            }
            _ => {
                // Special node (char/block device, fifo, socket) — skipped, as
                // in the newc path.
                take_exact(
                    &mut reader,
                    filesize,
                    &mut std::io::sink(),
                    format_args!("record body"),
                )?;
            }
        }
    }

    Ok(Scan {
        temp,
        raw_names,
        metas,
    })
}

// ── odc (070707), seekable: headers only ─────────────────────────────────────

/// Buffer the header walk reads through. Headers are 76 bytes plus a name, so
/// an unbuffered walk would cost two syscalls per record; one fill covers a few
/// hundred records of a small-file archive. Bodies are skipped by seeking, so a
/// large one costs at most one wasted fill.
const ODC_SCAN_BUF: usize = 64 * 1024;

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
/// in an odc header is attacker-controlled, and this is where a length that
/// does not fit the file becomes an error instead of a seek into nowhere.
fn advance(pos: u64, n: u64, file_len: u64, what: std::fmt::Arguments<'_>) -> Result<u64> {
    match pos.checked_add(n) {
        Some(end) if end <= file_len => Ok(end),
        _ => Err(Error::Corrupt(format!(
            "cpio odc: {what} claims {n} bytes at offset {pos} but the file holds {file_len}"
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
    let mut reader = BufReader::with_capacity(ODC_SCAN_BUF, src);
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
                });
            }
            _ => {
                // Special node (char/block device, fifo, socket) — skipped, as
                // in the streaming path.
                skip_to(&mut reader, after_name, after_body)?;
            }
        }

        pos = after_body;
    }

    Ok((raw_names, metas))
}

/// Open a seekable odc archive: list it from the headers, then keep `inner`
/// open so bodies can be read straight out of it.
fn open_odc_seekable(
    mut inner: Box<dyn ReadSeek>,
    file_len: u64,
    opts: &OpenOptions,
) -> Result<Box<dyn ArchiveReader>> {
    inner.seek(SeekFrom::Start(0))?;
    let (raw_names, metas) = scan_odc_seekable(inner.as_mut(), file_len)?;
    let (entries, bodies) = build_entries(raw_names, metas, opts);
    Ok(Box::new(CpioSeekReader {
        src: inner,
        entries,
        bodies,
    }))
}

// ── Shared tail: names, kinds, reader ────────────────────────────────────────

/// Turn a finished [`Scan`] into a reader: decode names once for the whole
/// archive, then build the entry list.
fn finish(scan: Scan, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
    let Scan {
        temp,
        raw_names,
        metas,
    } = scan;

    let (entries, offsets) = build_entries(raw_names, metas, opts);

    let temp_path = temp.into_temp_path();
    Ok(Box::new(CpioReader {
        entries,
        offsets,
        _temp: temp_path,
    }))
}

/// Build the entry list shared by both readers: names are decoded once for the
/// whole archive, and each entry gets the `(offset, size)` of its body — in the
/// temp file for the streaming path, in the archive itself for the seekable
/// one. `None` means there is no body to read (directory, symlink).
fn build_entries(
    raw_names: Vec<Vec<u8>>,
    metas: Vec<EntryMeta>,
    opts: &OpenOptions,
) -> (Vec<Entry>, Vec<Option<(u64, u64)>>) {
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
    let mut offsets: Vec<Option<(u64, u64)>> = Vec::with_capacity(metas.len());

    for (i, (meta, raw_name)) in metas.into_iter().zip(raw_names).enumerate() {
        let name_str = names[i].trim_end_matches('/');
        // Strip leading "./" that some cpio implementations prepend (`ditto`
        // always does; its first record is the bare "." for the packed root).
        let name_str = name_str.strip_prefix("./").unwrap_or(name_str);
        let (kind, body) = match meta.kind {
            KindRaw::File => (EntryKind::File, Some((meta.offset, meta.size))),
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

pub struct CpioReader {
    entries: Vec<Entry>,
    /// Per-entry body location `(offset_in_temp, byte_count)`; `None` for entries
    /// with no body (dirs, symlinks).
    offsets: Vec<Option<(u64, u64)>>,
    /// Temp file holding all regular-file bodies, concatenated.
    _temp: tempfile::TempPath,
}

impl ArchiveReader for CpioReader {
    fn format(&self) -> FormatId {
        FormatId::Cpio
    }

    fn entries(&mut self) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn read_entry(&mut self, idx: usize, out: &mut dyn Write) -> Result<()> {
        if idx >= self.entries.len() {
            return Err(Error::InvalidIndex(idx));
        }
        let Some((offset, size)) = self.offsets[idx] else {
            // Directory or symlink — no body to read.
            return Ok(());
        };
        crate::detect::read_temp_slice(&self._temp, offset, size, out)
    }
}

/// Reader for a seekable odc archive: no temp file, no copies — the archive
/// itself is held open and each body is read where it lies.
///
/// The source has to outlive nothing else here, but it does have to die before
/// the temp path a `.cpgz` is unpacked to: that path belongs to
/// `TempBackedReader`, whose inner reader (this one) is declared first and so
/// drops first. On Windows an open handle would otherwise block the delete.
pub struct CpioSeekReader {
    src: Box<dyn ReadSeek>,
    entries: Vec<Entry>,
    /// Parallel to `entries`: `(offset_in_archive, byte_count)` of the body,
    /// `None` for entries that have none (dirs, symlinks).
    bodies: Vec<Option<(u64, u64)>>,
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
        let Some((offset, size)) = slot else {
            // Directory or symlink — no body to read.
            return Ok(());
        };
        if size == 0 {
            return Ok(());
        }
        self.src.seek(SeekFrom::Start(offset))?;
        // `size` was checked against the file length while scanning, but the
        // copy is still capped by `take` and the output grows as bytes arrive —
        // nothing is reserved up front. A short read means the file shrank or
        // lied; it is an error, never a silently truncated entry.
        let copied = std::io::copy(&mut (&mut self.src).take(size), out)?;
        if copied != size {
            return Err(Error::Corrupt(format!(
                "cpio odc: truncated body at offset {offset} ({copied} of {size} bytes)"
            )));
        }
        Ok(())
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Confidence;
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
    fn probe_rejects_crc_variant() {
        // 070702 is the crc variant — not supported.
        assert_eq!(CpioHandler.probe(b"070702...", None), Confidence::NONE);
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

    #[test]
    fn is_supported_magic_covers_newc_and_odc_only() {
        assert!(is_supported_magic(b"070701"));
        assert!(is_supported_magic(b"070707"));
        assert!(!is_supported_magic(b"070702")); // crc — future work
        assert!(!is_supported_magic(b"PK\x03\x04"));
    }
}
