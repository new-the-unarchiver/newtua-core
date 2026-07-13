//! Commodore Amiga formats from `newtua-amiga`. None fit the standard
//! index-extract macro, so each has a hand-written adapter:
//! - **PowerPacker** — a single nameless crunched stream (named from the source
//!   stem, per The Unarchiver convention).
//! - **Amiga LZX** — a container that extracts by `&LzxEntry`, not by index.
//! - **DMS** — a floppy container with two shapes: a disk image (surfaced as one
//!   `<stem>.adf` entry) or, less commonly, named FMS files.

use crate::archive::{ArchiveReader, Confidence, FormatHandler, FormatId, OpenOptions, Source};
use crate::error::{Error, Result, io_err_to_corrupt};
use std::io::Write;

use super::{EntryMeta, LegacyBackend, LegacyReader, file_stem_bytes, legacy_probe, read_all};

use newtua_amiga::dms::DmsArchive;
use newtua_amiga::lzx::LzxArchive;
use newtua_amiga::powerpacker::PowerPackerFile;

// ---- PowerPacker (single nameless stream) -----------------------------------

/// PowerPacker (`.pp`) — an Amiga single-file cruncher. `PP20` lead magic; the
/// output is named after the source stem (PowerPacker stores no filename).
pub struct PowerPackerHandler;

struct PowerPackerBackend {
    file: PowerPackerFile,
    name: Vec<u8>,
}

impl LegacyBackend for PowerPackerBackend {
    fn metas(&self) -> Vec<EntryMeta> {
        vec![EntryMeta::file(&self.name, self.file.decoded_len() as u64)]
    }
    fn read(&self, _idx: usize, out: &mut dyn Write) -> Result<()> {
        let bytes = self.file.decode().map_err(io_err_to_corrupt)?;
        out.write_all(&bytes)?;
        Ok(())
    }
}

impl FormatHandler for PowerPackerHandler {
    fn id(&self) -> FormatId {
        FormatId::PowerPacker
    }
    fn probe(&self, header: &[u8], name: Option<&str>) -> Confidence {
        legacy_probe(header, name, |h| h.starts_with(b"PP20"), &[".pp"])
    }
    fn open(&self, src: Source, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        let name = file_stem_bytes(&src, "powerpacker");
        let bytes = read_all(src)?;
        let file = PowerPackerFile::open(&bytes).map_err(io_err_to_corrupt)?;
        Ok(Box::new(LegacyReader::new(
            FormatId::PowerPacker,
            Box::new(PowerPackerBackend { file, name }),
            opts,
        )))
    }
}

// ---- Amiga LZX (extract by &entry) ------------------------------------------

/// Amiga LZX (`.lzx`) — extracts by `&LzxEntry`; the backend maps index → entry.
pub struct LzxHandler;

struct LzxBackend(LzxArchive);

impl LegacyBackend for LzxBackend {
    fn metas(&self) -> Vec<EntryMeta> {
        self.0
            .entries()
            .iter()
            .map(|e| EntryMeta::file(&e.name, e.size))
            .collect()
    }
    fn read(&self, idx: usize, out: &mut dyn Write) -> Result<()> {
        let entry = self.0.entries().get(idx).ok_or(Error::InvalidIndex(idx))?;
        let bytes = self.0.read_entry(entry).map_err(io_err_to_corrupt)?;
        out.write_all(&bytes)?;
        Ok(())
    }
}

impl FormatHandler for LzxHandler {
    fn id(&self) -> FormatId {
        FormatId::Lzx
    }
    fn probe(&self, header: &[u8], name: Option<&str>) -> Confidence {
        legacy_probe(header, name, LzxArchive::recognize, &[".lzx"])
    }
    fn open(&self, src: Source, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        let bytes = read_all(src)?;
        let archive = LzxArchive::open(&bytes).map_err(io_err_to_corrupt)?;
        Ok(Box::new(LegacyReader::new(
            FormatId::Lzx,
            Box::new(LzxBackend(archive)),
            opts,
        )))
    }
}

// ---- DMS (disk image or FMS files) ------------------------------------------

/// DMS (`.dms`) — a Disk Masher System floppy container. Most DMS archives are
/// disk images (surfaced as one `<stem>.adf` entry); the rarer FMS form holds
/// named files. `files()` is empty in disk mode, which selects the branch.
pub struct DmsHandler;

struct DmsBackend {
    archive: DmsArchive,
    /// `<stem>.adf`, used only in disk mode.
    adf_name: Vec<u8>,
}

impl LegacyBackend for DmsBackend {
    fn metas(&self) -> Vec<EntryMeta> {
        let files = self.archive.files();
        if files.is_empty() {
            // Disk image: one `.adf` entry. Its size is unknown until the
            // tracks are decrunched, so it's reported as 0.
            vec![EntryMeta::file(&self.adf_name, 0)]
        } else {
            files
                .iter()
                .map(|f| EntryMeta {
                    raw: f.name.clone(),
                    is_dir: false,
                    size: u64::from(f.size),
                    is_encrypted: f.is_crypted,
                })
                .collect()
        }
    }
    fn read(&self, idx: usize, out: &mut dyn Write) -> Result<()> {
        let files = self.archive.files();
        let bytes = if files.is_empty() {
            self.archive.read_disk_image().map_err(io_err_to_corrupt)?
        } else {
            let f = files.get(idx).ok_or(Error::InvalidIndex(idx))?;
            self.archive.read_file(f).map_err(io_err_to_corrupt)?
        };
        out.write_all(&bytes)?;
        Ok(())
    }
}

impl FormatHandler for DmsHandler {
    fn id(&self) -> FormatId {
        FormatId::Dms
    }
    fn probe(&self, header: &[u8], name: Option<&str>) -> Confidence {
        legacy_probe(header, name, DmsArchive::recognize, &[".dms"])
    }
    fn open(&self, src: Source, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        let mut adf_name = file_stem_bytes(&src, "disk");
        adf_name.extend_from_slice(b".adf");
        let bytes = read_all(src)?;
        let archive = match opts.password.as_deref() {
            Some(p) => DmsArchive::open_with_password(&bytes, Some(p.as_bytes())),
            None => DmsArchive::open(&bytes),
        }
        .map_err(io_err_to_corrupt)?;
        Ok(Box::new(LegacyReader::new(
            FormatId::Dms,
            Box::new(DmsBackend { archive, adf_name }),
            opts,
        )))
    }
}
