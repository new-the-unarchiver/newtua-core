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

/// Convert the two MS-DOS timestamp words that ARC, ARJ, Zoo and every other
/// DOS-era container store.
///
/// Layout: the date word is year-since-1980 in bits 15..9, month in 8..5, day
/// in 4..0; the time word is hour in 15..11, minute in 10..5, and *half*
/// seconds in 4..0 — the format only resolves to two seconds.
///
/// A zero date is "not recorded" and yields `None`. The fields are read as
/// **local time**: MS-DOS knew nothing of timezones and stored the clock on the
/// wall, so this reproduces the hour the file's author saw.
pub(crate) fn dos_date_to_systime(date: u16, time: u16) -> Option<SystemTime> {
    if date == 0 {
        return None;
    }
    let year = 1980 + i32::from(date >> 9);
    let month = u32::from((date >> 5) & 0x0F);
    let day = u32::from(date & 0x1F);
    let hour = u64::from(time >> 11);
    let min = u64::from((time >> 5) & 0x3F);
    let sec = u64::from(time & 0x1F) * 2;
    if hour > 23 || min > 59 || sec > 59 {
        return None;
    }
    crate::datetime::local_civil_to_systime(year, month, day, hour, min, sec)
}

/// Convert Zoo's MS-DOS date/time pair using the timezone the packer recorded
/// alongside them.
///
/// Zoo is the only format here that writes that zone down, so its dates are a
/// real instant rather than a bare wall-clock reading: `tz` counts quarter
/// hours **west of GMT**, hence `UTC = wall clock + tz × 15 minutes`. The
/// direction is from zoo 2.1's own source — `zoolist.c::printtz` subtracts
/// `gettz() / 3600` from `file_tz / 4`, and `gettz()` returns seconds *west* of
/// GMT in both shipped implementations (`bsd.c`: `tz_minuteswest * 60`;
/// `sysv.c`: the SysV `timezone` global). Both sides of that subtraction are
/// therefore westward, so the stored field is too.
///
/// **This disagrees with `unar`**, which reads the same byte as an *eastward*
/// offset (`XADZooParser`: `timeZoneForSecondsFromGMT: tzoffs * 15 * 60`) and
/// so places every Zoo file twice its zone offset away. On the reference
/// `24mhzhck.zoo` — a US bulletin-board text from May 1992 — the stored `tz` of
/// 16 means four hours west, which is exactly US Eastern summer time; read
/// eastward it would claim the file came from the Gulf.
///
/// `None` for the zone means the archive recorded none (`NO_TZ`, or an old
/// type-1 entry). Then there is nothing to convert with, and the wall clock is
/// read as local time — the same fallback as every other DOS-era format.
pub(crate) fn zoo_date_to_systime(date: u16, time: u16, tz: Option<i8>) -> Option<SystemTime> {
    let Some(tz) = tz else {
        return dos_date_to_systime(date, time);
    };
    if date == 0 {
        return None;
    }
    let year = 1980 + i32::from(date >> 9);
    let month = u32::from((date >> 5) & 0x0F);
    let day = u32::from(date & 0x1F);
    let hour = u64::from(time >> 11);
    let min = u64::from((time >> 5) & 0x3F);
    let sec = u64::from(time & 0x1F) * 2;
    if hour > 23 || min > 59 || sec > 59 {
        return None;
    }
    // The wall clock as if it were UTC, then shifted by the recorded zone.
    let utc = crate::datetime::civil_to_systime(year, month, day, hour, min, sec)?;
    let shift = Duration::from_secs(u64::from(tz.unsigned_abs()) * 15 * 60);
    if tz >= 0 {
        utc.checked_add(shift)
    } else {
        utc.checked_sub(shift)
    }
}

/// Convert the CP/M date/time word pair an LBR directory stores.
///
/// The date word counts **days since 1978-12-31**, so day 1 is 1979-01-01; the
/// time word is packed exactly like the MS-DOS one (hour in 15..11, minute in
/// 10..5, half-seconds in 4..0). A zero date means the member carries no
/// timestamp.
///
/// Read as local time, for the same reason as [`dos_date_to_systime`]: CP/M had
/// no timezone either.
pub(crate) fn cpm_date_to_systime(date: u16, time: u16) -> Option<SystemTime> {
    if date == 0 {
        return None;
    }
    /// Seconds from the Unix epoch to 1978-12-31, the day the CP/M count is
    /// relative to (`SecondsFrom1970ToLastDayOf1978` in XADMaster).
    const CPM_EPOCH: u64 = 283_910_400;
    let hour = u64::from(time >> 11);
    let min = u64::from((time >> 5) & 0x3F);
    let sec = u64::from(time & 0x1F) * 2;
    if hour > 23 || min > 59 || sec > 59 {
        return None;
    }
    let secs = CPM_EPOCH + u64::from(date) * 86_400 + hour * 3600 + min * 60 + sec;
    crate::datetime::local_unix_secs_to_systime(secs)
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

    /// Mark this entry's data as encrypted. `extract_all` reads the flag to
    /// decide whether to call `verify_password` at all, so an unset flag means
    /// a wrong password is discovered mid-extraction rather than before it.
    pub(crate) fn encrypted(mut self, yes: bool) -> Self {
        self.is_encrypted = yes;
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

    /// See [`ArchiveReader::verify_password`] for the contract. Defaults to
    /// `Ok(())`, which is right for every legacy format that has no encryption
    /// at all — most of them.
    fn verify_password(&self) -> Result<()> {
        Ok(())
    }
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

    fn verify_password(&mut self) -> Result<()> {
        self.backend.verify_password()
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
/// - `verify` (optional): `fn(&Archive) -> Result<()>` implementing
///   [`ArchiveReader::verify_password`]. Omit it for a format with no
///   encryption, which is most of them.
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
        $crate::format::legacy::legacy_std_handler! {
            $(#[$hmeta])*
            $Handler, $Backend,
            id: $id,
            archive: $Archive,
            exts: [$($ext),*],
            recognize: $recog,
            open: $open,
            metas: $metas,
            verify: |_| Ok(()),
        }
    };
    (
        $(#[$hmeta:meta])*
        $Handler:ident, $Backend:ident,
        id: $id:expr,
        archive: $Archive:ty,
        exts: [$($ext:literal),* $(,)?],
        recognize: $recog:expr,
        open: $open:expr,
        metas: $metas:expr,
        verify: $verify:expr $(,)?
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
            fn verify_password(&self) -> $crate::error::Result<()> {
                let f: fn(&$Archive) -> $crate::error::Result<()> = $verify;
                f(&self.0)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datetime::local_civil_to_systime;
    use std::time::UNIX_EPOCH;

    /// The CP/M day count is relative to 1978-12-31, so day 1 is New Year's Day
    /// 1979. Stated against `local_civil_to_systime` rather than against a fixed
    /// number of seconds, because both sides are wall-clock readings and the
    /// answer therefore depends on the machine's timezone — which is the point.
    #[test]
    fn cpm_day_one_is_the_first_of_january_1979() {
        assert_eq!(
            cpm_date_to_systime(1, 0),
            local_civil_to_systime(1979, 1, 1, 0, 0, 0)
        );
    }

    /// A real record: `EGA.DOC` in `EGA.LBR` (sembiance corpus) carries creation
    /// date word 2829 and time word 0xBBCF, and `unar` unpacks its siblings with
    /// dates that match ours to the second.
    #[test]
    fn cpm_date_matches_a_real_lbr_record() {
        assert_eq!(
            cpm_date_to_systime(2829, 0xBBCF),
            local_civil_to_systime(1986, 9, 29, 23, 30, 30)
        );
    }

    /// Zoo's `24mhzhck.zoo`, the one reference we have: stored wall clock
    /// 1992-05-20 16:57:26 with `tz` = 16, i.e. four hours west of GMT, so the
    /// instant is 20:57:26 UTC. `unar` reports 12:57:26 for the same file —
    /// four hours the other way — because it reads the field as an eastward
    /// offset. The direction here is the one zoo's own source uses.
    #[test]
    fn zoo_date_shifts_west_by_the_recorded_zone() {
        let date = ((1992 - 1980) << 9) | (5 << 5) | 20;
        let time = (16 << 11) | (57 << 5) | 13; // 26 seconds / 2
        let t = zoo_date_to_systime(date, time, Some(16)).expect("an instant");
        let secs = t.duration_since(UNIX_EPOCH).unwrap().as_secs();
        // 1992-05-20T20:57:26Z
        assert_eq!(secs, 706_395_446);
    }

    /// A zone east of GMT shifts the other way, and the sign has to survive the
    /// byte being stored unsigned.
    #[test]
    fn zoo_date_shifts_east_for_a_negative_zone() {
        let date = ((1992 - 1980) << 9) | (5 << 5) | 20;
        let time = (16 << 11) | (57 << 5) | 13;
        let west = zoo_date_to_systime(date, time, Some(16)).unwrap();
        let east = zoo_date_to_systime(date, time, Some(-16)).unwrap();
        assert_eq!(
            west.duration_since(east).unwrap(),
            Duration::from_secs(2 * 4 * 3600)
        );
    }

    /// No recorded zone means no instant to compute: the wall clock is read
    /// locally, exactly as for every other DOS-era format.
    #[test]
    fn zoo_without_a_zone_falls_back_to_local_time() {
        let date = ((1992 - 1980) << 9) | (5 << 5) | 20;
        let time = (16 << 11) | (57 << 5) | 13;
        assert_eq!(
            zoo_date_to_systime(date, time, None),
            dos_date_to_systime(date, time)
        );
    }

    /// Zero is how the directory spells "no date", and the two-second resolution
    /// of the time word must not turn that into an instant.
    #[test]
    fn cpm_zero_date_is_no_date() {
        assert_eq!(cpm_date_to_systime(0, 0xBBCF), None);
    }

    /// A time word can hold values no clock ever shows (hour 31); those are
    /// rejected rather than silently wrapped into the next day.
    #[test]
    fn cpm_out_of_range_time_is_rejected() {
        assert_eq!(cpm_date_to_systime(2829, 0xF800), None);
    }
}
