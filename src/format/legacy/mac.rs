//! Classic Macintosh formats from `newtua-mac`: BinHex, MacBinary,
//! AppleSingle/AppleDouble, Compact Pro, PackIt. All are standard
//! index-extract containers; detection is content-first (each has a reliable
//! in-header `recognize`), so no extension fallbacks.
//!
//! Every one of these formats stores a file as **two** streams — the data fork
//! and the resource fork — and reports them as two entries sharing one name.
//! Which of the two an entry is comes from `is_resource_fork()`, and it has to
//! travel all the way to extraction: for a picture or an application the
//! resource fork is most of the file, and for some files it is the whole file.
//! See `Entry::is_resource_fork`.

use crate::archive::{ArchiveReader, Confidence, FormatHandler, FormatId, OpenOptions, Source};
use crate::error::{Result, io_err_to_corrupt};
use std::io::Cursor;

use super::{
    EntryMeta, LegacyBackend, LegacyReader, applesingle_date_to_systime, legacy_probe,
    legacy_std_handler, mac_date_to_systime, read_all,
};

use newtua_mac::applesingle::AppleSingleArchive;
use newtua_mac::binhex::BinHexArchive;
use newtua_mac::compactpro::CompactProArchive;
use newtua_mac::macbinary::MacBinaryArchive;
use newtua_mac::packit::PackItArchive;

// ── Envelopes ────────────────────────────────────────────────────────────────
//
// BinHex and MacBinary are not archives. They are ways to carry one Mac file —
// both of its forks, its type and creator — across seven-bit mail or a foreign
// filesystem, and what they usually carry is a real archive. Left as they are,
// a person opening `something.sit.hqx` gets one entry called `something.sit`
// and has to work out that it needs unpacking a second time.
//
// So the envelope is opened for them — but only when the name inside says what
// is in it. That is the same narrow rule XADMaster applies (`XADBinHexParser`,
// `XADMacBinaryParser`): the three classic-Mac archive extensions, and nothing
// else. It is deliberately not "re-dispatch whatever comes out": the general
// rule in this crate is that decompressed content is *not* handed back to the
// registry, or `.zip.gz` would stop being one entry (see `detect.rs`). This is
// a stated exception for two formats, keyed on a fixed list of three suffixes.
//
// The envelope's own resource fork is dropped when it unwraps — an envelope is
// a wrapper, and a wrapper's resource fork is not part of the payload. `unar`
// makes the same call: on `…sit.hqx` it lists the ten members of the archive
// inside, not the envelope's two forks.

/// Suffixes that mark an envelope's payload as an archive worth opening.
const NESTED_ARCHIVE_EXTS: [&str; 3] = [".sit", ".cpt", ".sea"];

fn payload_is_a_nested_archive(name: &[u8]) -> bool {
    let lower = name.to_ascii_lowercase();
    NESTED_ARCHIVE_EXTS
        .iter()
        .any(|ext| lower.ends_with(ext.as_bytes()))
}

/// If `backend` holds one of the three archive kinds above, extract it to a temp
/// file and open *that*, so the caller sees the archive rather than the
/// envelope. `None` when the payload is an ordinary file, and also whenever
/// unwrapping fails for any reason — a `.sea` we cannot open is still a file we
/// can hand over intact, and failing the whole open would be worse than showing
/// the envelope.
fn unwrap_envelope(
    backend: &dyn LegacyBackend,
    opts: &OpenOptions,
) -> Option<Box<dyn ArchiveReader>> {
    let metas = backend.metas();
    // The data fork is the payload; the resource fork belongs to the envelope.
    let idx = metas
        .iter()
        .position(|m| !m.is_resource_fork && payload_is_a_nested_archive(&m.raw))?;

    let mut temp = tempfile::NamedTempFile::new().ok()?;
    backend.read(idx, temp.as_file_mut()).ok()?;
    let path = temp.into_temp_path();
    let inner = crate::detect::open(&path, opts).ok()?;
    Some(Box::new(crate::detect::TempBackedReader::new(inner, path)))
}

/// BinHex 4.0 (`.hqx`) — 7-bit ASCII transport encoding with resource forks.
/// Carries no timestamps of its own. Unwraps an archive payload; see above.
pub struct BinHexHandler;

struct BinHexBackend(BinHexArchive);

impl LegacyBackend for BinHexBackend {
    fn metas(&self) -> Vec<EntryMeta> {
        self.0
            .entries()
            .iter()
            .map(|e| EntryMeta::file(e.name(), e.size()).resource_fork(e.is_resource_fork()))
            .collect()
    }
    fn read(&self, idx: usize, out: &mut dyn std::io::Write) -> Result<()> {
        self.0.read_entry(idx, out).map_err(io_err_to_corrupt)
    }
}

impl FormatHandler for BinHexHandler {
    fn id(&self) -> FormatId {
        FormatId::BinHex
    }
    fn probe(&self, header: &[u8], name: Option<&str>) -> Confidence {
        legacy_probe(header, name, BinHexArchive::recognize, &[])
    }
    fn open(&self, src: Source, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        let bytes = read_all(src)?;
        let archive = BinHexArchive::open(Cursor::new(bytes)).map_err(io_err_to_corrupt)?;
        let backend = BinHexBackend(archive);
        if let Some(inner) = unwrap_envelope(&backend, opts) {
            return Ok(inner);
        }
        Ok(Box::new(LegacyReader::new(
            FormatId::BinHex,
            Box::new(backend),
            opts,
        )))
    }
}

/// MacBinary I/II/III (`.bin`) — resource-fork container. Detected by its
/// 128-byte header (recognize-only; `.bin` is too generic to key on). Unwraps
/// an archive payload; see above.
pub struct MacBinaryHandler;

struct MacBinaryBackend(MacBinaryArchive);

impl LegacyBackend for MacBinaryBackend {
    fn metas(&self) -> Vec<EntryMeta> {
        self.0
            .entries()
            .iter()
            .map(|e| {
                EntryMeta::file(e.name(), e.size())
                    .resource_fork(e.is_resource_fork())
                    .at(mac_date_to_systime(e.modification_date()))
            })
            .collect()
    }
    fn read(&self, idx: usize, out: &mut dyn std::io::Write) -> Result<()> {
        self.0.read_entry(idx, out).map_err(io_err_to_corrupt)
    }
}

impl FormatHandler for MacBinaryHandler {
    fn id(&self) -> FormatId {
        FormatId::MacBinary
    }
    fn probe(&self, header: &[u8], name: Option<&str>) -> Confidence {
        legacy_probe(header, name, MacBinaryArchive::recognize, &[])
    }
    fn open(&self, src: Source, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        let bytes = read_all(src)?;
        let archive = MacBinaryArchive::open(Cursor::new(bytes)).map_err(io_err_to_corrupt)?;
        let backend = MacBinaryBackend(archive);
        if let Some(inner) = unwrap_envelope(&backend, opts) {
            return Ok(inner);
        }
        Ok(Box::new(LegacyReader::new(
            FormatId::MacBinary,
            Box::new(backend),
            opts,
        )))
    }
}

legacy_std_handler! {
    /// AppleSingle / AppleDouble — fork-preserving encoding (magic
    /// `0x00051600`/`0x00051607`). Dates count from 2000, not from 1904.
    AppleSingleHandler, AppleSingleBackend,
    id: FormatId::AppleSingle,
    archive: AppleSingleArchive,
    exts: [],
    recognize: AppleSingleArchive::recognize,
    open: |b, _o| AppleSingleArchive::open(Cursor::new(b)),
    metas: |a| a.entries().iter()
        .map(|e| EntryMeta::file(e.name(), e.size())
            .resource_fork(e.is_resource_fork())
            .at(applesingle_date_to_systime(e.modification_date())))
        .collect(),
}

legacy_std_handler! {
    /// Compact Pro (`.cpt`) — early-90s Mac archiver (has real directories).
    CompactProHandler, CompactProBackend,
    id: FormatId::CompactPro,
    archive: CompactProArchive,
    exts: [".cpt"],
    recognize: CompactProArchive::recognize,
    open: |b, _o| CompactProArchive::open(Cursor::new(b)),
    metas: |a| a.entries().iter()
        .map(|e| EntryMeta::named(e.name(), e.is_directory(), e.size())
            .resource_fork(e.is_resource_fork())
            .at(mac_date_to_systime(e.modification_date())))
        .collect(),
}

legacy_std_handler! {
    /// PackIt (`.pit`) — early Mac archiver, optionally password-protected.
    PackItHandler, PackItBackend,
    id: FormatId::PackIt,
    archive: PackItArchive,
    exts: [".pit"],
    recognize: PackItArchive::recognize,
    open: |b, o: &OpenOptions| match o.password.as_deref() {
        Some(p) => PackItArchive::open_with_password(Cursor::new(b), p.as_bytes()),
        None => PackItArchive::open(Cursor::new(b)),
    },
    metas: |a| a.entries().iter()
        .map(|e| EntryMeta::file(e.name(), e.size())
            .resource_fork(e.is_resource_fork())
            .at(mac_date_to_systime(e.modification_date())))
        .collect(),
}
