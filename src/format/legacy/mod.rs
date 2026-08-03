//! Adapters for the `newtua-formats` family of legacy-format decoders (ports
//! from XADMaster: `newtua-dos`/`mac`/`stuffit`/`amiga`/`alz`/`nsis`).
//!
//! Every upstream crate exposes a uniform `recognize`/`open`/`entries`/
//! `read_entry` API over `&[u8]`; these thin wrappers surface them through
//! core's [`FormatHandler`]/[`ArchiveReader`]. Legacy archives are small
//! (floppy/BBS-era), so each handler reads the whole [`Source`] into memory and
//! hands the byte slice to the upstream parser.
//!
//! Detection is content-first: `probe` calls the upstream `recognize` on the
//! registry's 512-byte header peek (where a format has no `recognize`, or its
//! signature sits past the peek, it falls back to the file extension).

use crate::archive::{ArchiveReader, Confidence, Entry, EntryKind, FormatId, OpenOptions, Source};
use crate::encoding::decode_names;
use crate::error::{Error, Result};
use std::io::{Read, Seek, SeekFrom, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub mod dos;
pub use dos::{ArcHandler, ArjHandler, CrunchHandler, LbrHandler, SqueezeHandler, ZooHandler};

pub mod mac;
pub use mac::{
    AppleSingleHandler, BinHexHandler, CompactProHandler, MacBinaryHandler, PackItHandler,
};

pub mod stuffit;
pub use stuffit::{StuffIt5Handler, StuffItHandler, StuffItXHandler};

pub mod alz;
pub use alz::AlzHandler;

pub mod nsis;
pub use nsis::NsisHandler;

pub mod amiga;
pub use amiga::{DmsHandler, LzxHandler, PowerPackerHandler};

/// Seconds between the classic Mac epoch (1904-01-01 GMT) and the Unix epoch.
/// MacBinary, Compact Pro, PackIt, StuffIt and StuffIt 5 all date their entries
/// from it.
const MAC_EPOCH_TO_UNIX: u64 = 2_082_844_800;
/// Seconds between the AppleSingle epoch (2000-01-01 GMT) and the Unix epoch.
/// AppleSingle is the odd one out: its dates count from 2000, and they are
/// *signed*, so a file older than that is a negative number.
const APPLESINGLE_EPOCH_TO_UNIX: i64 = 946_684_800;

/// Convert a classic Mac timestamp (seconds since 1904-01-01) to `SystemTime`.
///
/// `0` means "no date recorded" in every one of these formats, and a value
/// below the Unix epoch is a date before 1970 that `SystemTime` on some targets
/// cannot express — both become `None` rather than a wrong instant. Reporting a
/// date we are unsure of is worse than reporting none: the caller writes it to
/// the file and the user sees a confident lie.
pub(crate) fn mac_date_to_systime(secs: u32) -> Option<SystemTime> {
    let secs = u64::from(secs);
    if secs == 0 || secs < MAC_EPOCH_TO_UNIX {
        return None;
    }
    // Classic Mac OS had no notion of a timezone: the number is the clock on
    // the wall where the file was made. Read as UTC it shifts by the reader's
    // offset — `unar` reads it as local time and so do we.
    crate::datetime::local_unix_secs_to_systime(secs - MAC_EPOCH_TO_UNIX)
}

/// Convert an AppleSingle timestamp (signed seconds since 2000-01-01).
/// Dates before 1970 are representable here and are returned as such.
pub(crate) fn applesingle_date_to_systime(secs: Option<u32>) -> Option<SystemTime> {
    let secs = secs? as i32 as i64;
    let unix = secs.checked_add(APPLESINGLE_EPOCH_TO_UNIX)?;
    if unix >= 0 {
        Some(UNIX_EPOCH + Duration::from_secs(unix as u64))
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(unix.unsigned_abs()))
    }
}

/// One entry's raw metadata as reported by an upstream legacy archive, before
/// charset decoding of the name.
pub(crate) struct EntryMeta {
    pub raw: Vec<u8>,
    pub is_dir: bool,
    pub size: u64,
    pub is_encrypted: bool,
    /// The resource fork of the file named by `raw`, rather than the file.
    /// See [`Entry::is_resource_fork`] — the Mac formats report the two forks
    /// as two entries sharing one name, and losing this flag loses the fork.
    pub is_resource_fork: bool,
    /// Modification time as the archive recorded it. `None` when the format
    /// stores none, or when the upstream crate does not surface it yet.
    pub modified: Option<SystemTime>,
}

impl EntryMeta {
    /// An entry with a raw name, kind, and known size — not encrypted, not a
    /// fork, no timestamp (the common case; the rest build the struct
    /// literally or adjust with the builders below).
    pub(crate) fn named(raw: &[u8], is_dir: bool, size: u64) -> Self {
        Self {
            raw: raw.to_vec(),
            is_dir,
            size,
            is_encrypted: false,
            is_resource_fork: false,
            modified: None,
        }
    }

    /// A plain file entry (never a directory).
    pub(crate) fn file(raw: &[u8], size: u64) -> Self {
        Self::named(raw, false, size)
    }

    /// Mark this entry as the resource fork of its name.
    pub(crate) fn resource_fork(mut self, yes: bool) -> Self {
        self.is_resource_fork = yes;
        self
    }

    /// Attach the archive's recorded modification time.
    pub(crate) fn at(mut self, modified: Option<SystemTime>) -> Self {
        self.modified = modified;
        self
    }
}

/// The list-and-extract surface every legacy archive shares, made object-safe
/// so a single [`LegacyReader`] can wrap any of them. Implemented by a tiny
/// newtype per upstream archive — the orphan rule forbids implementing this on
/// the foreign types directly.
pub(crate) trait LegacyBackend {
    fn metas(&self) -> Vec<EntryMeta>;
    fn read(&self, idx: usize, out: &mut dyn Write) -> Result<()>;
}

/// A generic [`ArchiveReader`] over any [`LegacyBackend`]: entry names are
/// decoded once up front (bytes → charset via [`decode_names`]); extraction
/// delegates to the backend by index.
pub(crate) struct LegacyReader {
    format: FormatId,
    entries: Vec<Entry>,
    backend: Box<dyn LegacyBackend>,
}

impl LegacyReader {
    pub(crate) fn new(
        format: FormatId,
        backend: Box<dyn LegacyBackend>,
        opts: &OpenOptions,
    ) -> Self {
        let metas = backend.metas();
        let raw: Vec<Vec<u8>> = metas.iter().map(|m| m.raw.clone()).collect();
        let names = decode_names(&raw, opts.encoding_override.as_deref());
        let entries = metas
            .into_iter()
            .zip(names)
            .map(|(m, name)| Entry {
                path: std::path::PathBuf::from(name),
                path_raw: m.raw,
                kind: if m.is_dir {
                    EntryKind::Dir
                } else {
                    EntryKind::File
                },
                size: m.size,
                mode: None,
                is_encrypted: m.is_encrypted,
                modified: m.modified,
                is_resource_fork: m.is_resource_fork,
            })
            .collect();
        Self {
            format,
            entries,
            backend,
        }
    }
}

impl ArchiveReader for LegacyReader {
    fn format(&self) -> FormatId {
        self.format
    }

    fn entries(&mut self) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn read_entry(&mut self, idx: usize, out: &mut dyn Write) -> Result<()> {
        if idx >= self.entries.len() {
            return Err(Error::InvalidIndex(idx));
        }
        self.backend.read(idx, out)
    }
}

/// Read the whole [`Source`] into memory. Every upstream parser wants the
/// complete byte slice, and legacy archives are small, so buffering the lot is
/// the natural fit.
pub(crate) fn read_all(src: Source) -> Result<Vec<u8>> {
    let mut reader: Box<dyn Read> = match src {
        Source::Seekable { mut inner, .. } => {
            inner.seek(SeekFrom::Start(0))?;
            inner
        }
        Source::Stream { inner, .. } => inner,
    };
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Case-insensitive match of `name`'s extension against a set of `.ext` suffixes.
pub(crate) fn ext_matches(name: Option<&str>, exts: &[&str]) -> bool {
    name.map(|n| n.to_ascii_lowercase())
        .is_some_and(|n| exts.iter().any(|e| n.ends_with(e)))
}

/// The shared legacy detection rule: `MAGIC` if the content sniff matches OR
/// the name carries one of `exts`, else `NONE`. Used by the macro and by every
/// hand-written handler so the MAGIC/NONE branch lives in one place. Pass
/// `|_| false` for `recognize` when a format has no content sniff.
pub(crate) fn legacy_probe(
    header: &[u8],
    name: Option<&str>,
    recognize: fn(&[u8]) -> bool,
    exts: &[&str],
) -> Confidence {
    if recognize(header) || ext_matches(name, exts) {
        Confidence::MAGIC
    } else {
        Confidence::NONE
    }
}

/// The source file's stem as raw bytes (e.g. `hello.pp` → `hello`), or
/// `fallback` when the source has no usable name. Used by the formats that
/// carry no internal filename (PowerPacker) or name a synthesized output
/// (DMS `<stem>.adf`).
pub(crate) fn file_stem_bytes(src: &Source, fallback: &str) -> Vec<u8> {
    src.file_path()
        .and_then(|p| p.file_stem())
        .and_then(|s| s.to_str())
        .map(|s| s.as_bytes().to_vec())
        .unwrap_or_else(|| fallback.as_bytes().to_vec())
}

/// Generate a [`FormatHandler`] + [`LegacyBackend`] newtype for a "standard"
/// legacy archive — one whose upstream type parses from a byte slice and
/// extracts by entry index (`read_entry(idx, &mut dyn Write)`). Formats that
/// don't fit this shape (single-stream, entry-by-reference, disk images) get a
/// hand-written handler instead.
///
/// - `recognize`: `fn(&[u8]) -> bool` run on the header peek. Pass `|_| false`
///   for formats with no content sniff (detection then rests on `exts`).
/// - `exts`: extension fallbacks (empty = content-only detection).
/// - `open`: `fn(Vec<u8>, &OpenOptions) -> io::Result<Archive>`.
/// - `metas`: `fn(&Archive) -> Vec<EntryMeta>`.
macro_rules! legacy_std_handler {
    (
        $(#[$hmeta:meta])*
        $Handler:ident, $Backend:ident,
        id: $id:expr,
        archive: $Archive:ty,
        exts: [$($ext:literal),* $(,)?],
        recognize: $recog:expr,
        open: $open:expr,
        metas: $metas:expr $(,)?
    ) => {
        $(#[$hmeta])*
        pub struct $Handler;

        struct $Backend($Archive);

        impl $crate::format::legacy::LegacyBackend for $Backend {
            fn metas(&self) -> Vec<$crate::format::legacy::EntryMeta> {
                let f: fn(&$Archive) -> Vec<$crate::format::legacy::EntryMeta> = $metas;
                f(&self.0)
            }
            fn read(&self, idx: usize, out: &mut dyn ::std::io::Write) -> $crate::error::Result<()> {
                self.0.read_entry(idx, out).map_err($crate::error::io_err_to_corrupt)
            }
        }

        impl $crate::archive::FormatHandler for $Handler {
            fn id(&self) -> $crate::archive::FormatId {
                $id
            }
            fn probe(&self, header: &[u8], name: Option<&str>) -> $crate::archive::Confidence {
                $crate::format::legacy::legacy_probe(header, name, $recog, &[$($ext),*])
            }
            fn open(
                &self,
                src: $crate::archive::Source,
                opts: &$crate::archive::OpenOptions,
            ) -> $crate::error::Result<Box<dyn $crate::archive::ArchiveReader>> {
                let bytes = $crate::format::legacy::read_all(src)?;
                let open: fn(Vec<u8>, &$crate::archive::OpenOptions) -> ::std::io::Result<$Archive> = $open;
                let archive = open(bytes, opts).map_err($crate::error::io_err_to_corrupt)?;
                Ok(Box::new($crate::format::legacy::LegacyReader::new(
                    $id,
                    Box::new($Backend(archive)),
                    opts,
                )))
            }
        }
    };
}
pub(crate) use legacy_std_handler;
