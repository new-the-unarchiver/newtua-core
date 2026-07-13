//! NSIS (`.exe`) from `newtua-nsis` — contents of a Nullsoft installer.
//!
//! An NSIS installer is a PE executable with the archive appended past the
//! stub; its firstheader sits far beyond the registry's 512-byte header peek,
//! so `probe` can never recognise it and always returns `NONE` — NSIS is
//! *registry-invisible*. Dispatch happens out-of-band in the `MZ` early branch
//! of `detect::open_single`, which reads the whole file once and hands the
//! bytes to [`NsisHandler::open_bytes`].

use crate::archive::{ArchiveReader, Confidence, FormatHandler, FormatId, OpenOptions, Source};
use crate::error::{Error, Result, io_err_to_corrupt};
use std::io::{Cursor, Write};

use super::{EntryMeta, LegacyBackend, LegacyReader, read_all};

use newtua_nsis::NsisArchive;

/// NSIS installer contents. See the module docs for why detection is out-of-band.
pub struct NsisHandler;

struct NsisBackend(NsisArchive);

impl LegacyBackend for NsisBackend {
    fn metas(&self) -> Vec<EntryMeta> {
        self.0
            .entries()
            .iter()
            .map(|e| EntryMeta::named(e.name(), e.is_dir(), e.size().unwrap_or(0)))
            .collect()
    }
    fn read(&self, idx: usize, out: &mut dyn Write) -> Result<()> {
        self.0.read_entry(idx, out).map_err(io_err_to_corrupt)
    }
}

impl NsisHandler {
    /// Dispatch entry for the `MZ` early branch: parse already-read installer
    /// bytes (no second disk read), or [`Error::UnknownFormat`] when they carry
    /// no NSIS firstheader — so detect can fall through to the generic SFX
    /// carve. A genuine NSIS installer that fails to parse surfaces its error
    /// instead of silently falling through.
    pub(crate) fn open_bytes(bytes: Vec<u8>, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        if !NsisArchive::recognize(&bytes) {
            return Err(Error::UnknownFormat);
        }
        let archive = NsisArchive::open(Cursor::new(bytes)).map_err(io_err_to_corrupt)?;
        Ok(Box::new(LegacyReader::new(
            FormatId::Nsis,
            Box::new(NsisBackend(archive)),
            opts,
        )))
    }
}

impl FormatHandler for NsisHandler {
    fn id(&self) -> FormatId {
        FormatId::Nsis
    }
    /// Always `NONE`: NSIS is registry-invisible and reached only via the `MZ`
    /// early branch (which calls [`open_bytes`](NsisHandler::open_bytes)).
    fn probe(&self, _header: &[u8], _name: Option<&str>) -> Confidence {
        Confidence::NONE
    }
    fn open(&self, src: Source, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        // Never selected by the registry (probe is NONE); kept so a direct
        // `NsisHandler.open(path)` still works, routing through open_bytes.
        Self::open_bytes(read_all(src)?, opts)
    }
}
