//! DOS / CP-M-era archivers from `newtua-dos`: ARJ, Zoo, LBR, Crunch, ARC
//! (all standard index-extract containers) and Squeeze (a single-stream file).

use crate::archive::{ArchiveReader, Confidence, FormatHandler, FormatId, OpenOptions, Source};
use crate::error::{Result, io_err_to_corrupt};
use std::io::{Cursor, Write};

use super::{EntryMeta, LegacyBackend, LegacyReader, legacy_probe, legacy_std_handler, read_all};

use newtua_dos::arc::ArcArchive;
use newtua_dos::arj::ArjArchive;
use newtua_dos::crunch_cpm::CrunchArchive;
use newtua_dos::lbr::LbrArchive;
use newtua_dos::squeeze::SqueezeFile;
use newtua_dos::zoo::ZooArchive;

legacy_std_handler! {
    /// ARJ (`.arj`) — Robert Jung's DOS archiver. Detected by its `0x60 0xEA`
    /// lead magic.
    ArjHandler, ArjBackend,
    id: FormatId::Arj,
    archive: ArjArchive,
    exts: [],
    recognize: ArjArchive::recognize,
    open: |b, _o| ArjArchive::open(Cursor::new(b)),
    metas: |a| a.entries().iter()
        .map(|e| EntryMeta::named(e.name(), e.is_dir(), e.size()))
        .collect(),
}

legacy_std_handler! {
    /// Zoo (`.zoo`) — Rahul Dhesi's cross-platform archiver.
    ZooHandler, ZooBackend,
    id: FormatId::Zoo,
    archive: ZooArchive,
    exts: [],
    recognize: ZooArchive::recognize,
    open: |b, _o| ZooArchive::open(Cursor::new(b)),
    metas: |a| a.entries().iter()
        .map(|e| EntryMeta::named(e.name(), e.is_dir(), e.size()))
        .collect(),
}

legacy_std_handler! {
    /// LBR (`.lbr`) — CP/M library container (members are always files).
    LbrHandler, LbrBackend,
    id: FormatId::Lbr,
    archive: LbrArchive,
    exts: [],
    recognize: LbrArchive::recognize,
    open: |b, _o| LbrArchive::open(Cursor::new(b)),
    metas: |a| a.entries().iter()
        .map(|e| EntryMeta::file(e.name(), e.size()))
        .collect(),
}

legacy_std_handler! {
    /// Crunch — DOS/CP-M LZW cruncher container (no per-entry size field).
    CrunchHandler, CrunchBackend,
    id: FormatId::Crunch,
    archive: CrunchArchive,
    exts: [],
    recognize: CrunchArchive::recognize,
    open: |b, _o| CrunchArchive::open(Cursor::new(b)),
    metas: |a| a.entries().iter()
        .map(|e| EntryMeta::file(e.name(), 0))
        .collect(),
}

legacy_std_handler! {
    /// ARC (`.arc`/`.ark`/`.pak`/`.spark`) — SEA's PC archiver. It has no
    /// content sniff upstream, so detection rests on the extension.
    ArcHandler, ArcBackend,
    id: FormatId::Arc,
    archive: ArcArchive,
    exts: [".arc", ".ark", ".pak", ".spark"],
    recognize: |_| false,
    open: |b, _o| ArcArchive::open(Cursor::new(b)),
    metas: |a| a.entries().iter()
        .map(|e| EntryMeta::named(e.name(), e.is_dir(), u64::from(e.size())))
        .collect(),
}

/// Squeeze (`.sq`/`.qqq`) — a single Huffman+RLE90-coded CP/M/DOS file. Unlike
/// the containers above it has no entry list (`decode()` yields the one file)
/// and no `recognize`, so this handler is hand-written: one entry, magic
/// `0x76 0xFF` or the extension.
pub struct SqueezeHandler;

struct SqueezeBackend(SqueezeFile);

impl LegacyBackend for SqueezeBackend {
    fn metas(&self) -> Vec<EntryMeta> {
        // Size is unknown until decoded, so it's reported as 0.
        vec![EntryMeta::file(self.0.name(), 0)]
    }
    fn read(&self, _idx: usize, out: &mut dyn Write) -> Result<()> {
        let bytes = self.0.decode().map_err(io_err_to_corrupt)?;
        out.write_all(&bytes)?;
        Ok(())
    }
}

impl FormatHandler for SqueezeHandler {
    fn id(&self) -> FormatId {
        FormatId::Squeeze
    }
    fn probe(&self, header: &[u8], name: Option<&str>) -> Confidence {
        legacy_probe(
            header,
            name,
            |h| h.starts_with(&[0x76, 0xFF]),
            &[".sq", ".qqq"],
        )
    }
    fn open(&self, src: Source, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        let bytes = read_all(src)?;
        let file = SqueezeFile::open(Cursor::new(bytes)).map_err(io_err_to_corrupt)?;
        Ok(Box::new(LegacyReader::new(
            FormatId::Squeeze,
            Box::new(SqueezeBackend(file)),
            opts,
        )))
    }
}
