use std::io::{Read, Write};
use std::path::PathBuf;

use crate::archive::{
    ArchiveReader, Confidence, Entry, EntryKind, EntrySink, FormatHandler, FormatId, OpenOptions,
    ReadSeek, SinkStep, SinkWriter, Source,
};
use crate::datetime::dos_words_to_systime;
use crate::encoding::decode_names;
use crate::error::{Error, Result, io_err_to_corrupt};
use crate::path_safety::raw_path_escapes;
use crate::vendor::cab;

pub struct CabHandler;

impl FormatHandler for CabHandler {
    fn id(&self) -> FormatId {
        FormatId::Cab
    }

    fn probe(&self, header: &[u8], _name: Option<&str>) -> Confidence {
        if header.starts_with(b"MSCF") {
            Confidence::MAGIC
        } else {
            Confidence::NONE
        }
    }

    fn open(&self, src: Source, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        let inner: Box<dyn ReadSeek> = match src {
            Source::Seekable { inner, .. } => inner,
            Source::Stream { .. } => {
                return Err(Error::Unsupported {
                    format: "cab".into(),
                    feature: "streaming (cab requires seek)".into(),
                });
            }
        };
        let cab = cab::Cabinet::new(inner).map_err(io_err_to_corrupt)?;

        // Two passes, because the encoding of a name is decided from the whole
        // set at once: one archive, one encoding. A cabinet that declares its
        // names UTF-8 says so per entry, and that declaration is believed rather
        // than guessed at — a detector fed a handful of short ASCII names will
        // happily call them something else.
        let mut raw_names: Vec<Vec<u8>> = Vec::new();
        let mut declared_utf8: Vec<bool> = Vec::new();
        let mut places: Vec<Place> = Vec::new();
        let mut stamps: Vec<(u16, u16)> = Vec::new();
        for (folder_idx, folder) in cab.folder_entries().enumerate() {
            for file in folder.file_entries() {
                raw_names.push(file.name().to_vec());
                declared_utf8.push(file.name_is_utf8());
                stamps.push(file.dos_date_time());
                places.push(Place {
                    folder: folder_idx,
                    offset: file.uncompressed_offset() as u64,
                    size: file.uncompressed_size() as u64,
                });
            }
        }

        let names = decode_names(&raw_names, opts.encoding_override.as_deref());
        let entries = raw_names
            .into_iter()
            .zip(names)
            .zip(declared_utf8)
            .zip(&stamps)
            .zip(&places)
            .map(|((((raw, decoded), utf8), &(date, time)), place)| {
                let name = if utf8 {
                    String::from_utf8_lossy(&raw).into_owned()
                } else {
                    decoded
                };
                // An escaping name is rendered from its raw bytes, so the `..`
                // reaches `safe_join` verbatim: a multi-byte legacy charset can
                // otherwise swallow a separator into a lead byte and hand the
                // orchestrator a name that no longer looks like traversal.
                let name = if raw_path_escapes(&raw) {
                    String::from_utf8_lossy(&raw).into_owned()
                } else {
                    name
                };
                Entry {
                    path_raw: raw,
                    // CAB uses `\` separators; normalize to `/` so list output
                    // and common-root/wrapper detection (which read
                    // `Entry::path`) work. `safe_join` re-normalizes for the
                    // on-disk write path.
                    path: PathBuf::from(name.replace('\\', "/")),
                    kind: EntryKind::File,
                    size: place.size,
                    mode: None,
                    is_encrypted: false,
                    modified: dos_words_to_systime(date, time),
                    is_resource_fork: false,
                }
            })
            .collect();

        Ok(Box::new(CabReader {
            cab,
            entries,
            places,
        }))
    }
}

/// Where an entry's bytes live: which folder, and where within that folder's
/// decompressed stream.
///
/// This is what replaced looking a file up by name. Two files in different
/// folders may legally share a name, and the old reader resolved such a name to
/// whichever came first — so one of them was silently extracted twice and the
/// other never. Addressing by position cannot confuse them.
struct Place {
    folder: usize,
    offset: u64,
    size: u64,
}

struct CabReader {
    cab: cab::Cabinet<Box<dyn ReadSeek>>,
    entries: Vec<Entry>,
    /// Parallel to `entries`.
    places: Vec<Place>,
}

impl CabReader {
    /// Read `place`'s bytes out of an already-open folder reader.
    ///
    /// The reader must not have passed `place.offset` yet; seeking forward only
    /// decodes the blocks in between, while seeking back would restart the
    /// folder from its first block.
    fn copy_body(
        folder: &mut cab::FolderReader<'_, Box<dyn ReadSeek>>,
        place: &Place,
        out: &mut dyn Write,
    ) -> Result<()> {
        folder
            .seek_to_uncompressed_offset(place.offset)
            .map_err(io_err_to_corrupt)?;
        let copied = std::io::copy(&mut folder.by_ref().take(place.size), out)?;
        if copied != place.size {
            return Err(Error::Corrupt(format!(
                "cab: entry ends early — {copied} of {} bytes in folder {}",
                place.size, place.folder
            )));
        }
        Ok(())
    }
}

impl ArchiveReader for CabReader {
    fn format(&self) -> FormatId {
        FormatId::Cab
    }

    fn entries(&mut self) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn read_entry(&mut self, idx: usize, out: &mut dyn Write) -> Result<()> {
        let place = self.places.get(idx).ok_or(Error::InvalidIndex(idx))?;
        let mut folder = self
            .cab
            .open_folder(place.folder)
            .map_err(io_err_to_corrupt)?;
        Self::copy_body(&mut folder, place, out)
    }

    /// One pass per folder, instead of one pass per entry.
    ///
    /// A CAB folder is a single solid stream: reaching a file means decoding
    /// everything stored before it. Asking for entries one at a time therefore
    /// decoded the folder again for each of them — measured at seven times
    /// `7zz` on a thousand files, and growing.
    ///
    /// Two things make one pass possible. The folder decoder stays open for the
    /// whole folder, so a forward seek only walks the blocks in between; and the
    /// entries of a folder are visited in **stored order**, which is what a
    /// forward-only stream requires. Stored order is not always index order —
    /// the file list may name them in any order — so it is sorted here rather
    /// than assumed.
    fn read_entries(&mut self, indices: &[usize], sink: &mut dyn EntrySink) -> Result<()> {
        // Split the request into folders, keeping each folder's entries in the
        // order their bytes appear in the stream.
        let this: &CabReader = self;
        let mut wanted: Vec<(usize, usize)> = Vec::with_capacity(indices.len());
        for &idx in indices {
            let place = this.places.get(idx).ok_or(Error::InvalidIndex(idx))?;
            wanted.push((place.folder, idx));
        }
        wanted.sort_by_key(|&(folder, idx)| (folder, this.places[idx].offset));

        let mut pos = 0;
        while pos < wanted.len() {
            let folder_idx = wanted[pos].0;
            let end = wanted[pos..]
                .iter()
                .position(|&(f, _)| f != folder_idx)
                .map_or(wanted.len(), |n| pos + n);

            // Opened once per folder, and only when that folder is wanted —
            // opening it already reads and decodes its first data block.
            let mut folder = None;
            for &(_, idx) in &wanted[pos..end] {
                match sink.begin(idx)? {
                    SinkStep::Stop => return Ok(()),
                    SinkStep::Skip => continue,
                    SinkStep::Body => {}
                }
                let outcome = this.read_into_sink(idx, folder_idx, &mut folder, sink);
                if !sink.end(idx, outcome)? {
                    return Ok(());
                }
            }
            pos = end;
        }
        Ok(())
    }
}

impl CabReader {
    /// One entry of the batch pass: open the folder if this is the first entry
    /// wanted from it, then pour the body into the sink.
    ///
    /// A failure here belongs to this entry alone — `read_entries` hands it to
    /// `end` and carries on with the rest, because one unreadable file in a
    /// cabinet is no reason to abandon the others. The exception is a folder
    /// that will not open at all: `folder` then stays `None` and every entry in
    /// it fails the same way, which is the truth of the matter.
    fn read_into_sink<'a>(
        &'a self,
        idx: usize,
        folder_idx: usize,
        folder: &mut Option<cab::FolderReader<'a, Box<dyn ReadSeek>>>,
        sink: &mut dyn EntrySink,
    ) -> Result<()> {
        let place = &self.places[idx];
        if folder.is_none() {
            *folder = Some(
                self.cab
                    .open_folder(folder_idx)
                    .map_err(io_err_to_corrupt)?,
            );
        }
        let reader = folder.as_mut().expect("just filled in");

        let mut writer = SinkWriter::new(sink);
        let outcome = Self::copy_body(reader, place, &mut writer);
        // Приёмник важнее: только по его ошибке видно отмену.
        match writer.take_err() {
            Some(e) => Err(e),
            None => outcome,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_detects_mscf_magic() {
        assert_eq!(CabHandler.probe(b"MSCF\0\0\0\0", None), Confidence::MAGIC);
    }

    #[test]
    fn probe_rejects_other() {
        assert_eq!(CabHandler.probe(b"PK\x03\x04", None), Confidence::NONE);
    }

    #[test]
    fn probe_rejects_empty() {
        assert_eq!(CabHandler.probe(b"", None), Confidence::NONE);
    }

    #[test]
    fn cab_handler_id_is_cab() {
        assert_eq!(CabHandler.id(), FormatId::Cab);
    }

    /// The cabinet from the CAB specification: one uncompressed file `hi.txt`
    /// stamped 1997-03-12 11:13:52.
    const SPEC_CABINET: &[u8] = b"MSCF\0\0\0\0\x59\0\0\0\0\0\0\0\
        \x2c\0\0\0\0\0\0\0\x03\x01\x01\0\x01\0\0\0\x34\x12\0\0\
        \x43\0\0\0\x01\0\0\0\
        \x0e\0\0\0\0\0\0\0\0\0\x6c\x22\xba\x59\x01\0hi.txt\0\
        \x4c\x1a\x2e\x7f\x0e\0\x0e\0Hello, world!\n";

    fn open_bytes(bytes: &[u8]) -> Box<dyn ArchiveReader> {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut tmp, bytes).unwrap();
        let src = Source::path(tmp.path()).unwrap();
        // The temp file must outlive the reader, which keeps it open.
        let reader = CabHandler.open(src, &OpenOptions::default()).unwrap();
        std::mem::forget(tmp);
        reader
    }

    /// **A cabinet stores the clock on the wall, not an instant.**
    ///
    /// This read the fields as UTC until 2026-08-07, and the comment claiming
    /// that matched The Unarchiver was simply wrong: `unar` extracting
    /// `IE40CIF.CAB` sets the mtime six hours away from what we set, on a
    /// machine at UTC+5 — a whole timezone off, for every file in every
    /// cabinet. CAB stores the identical word pair zip does, so it converts by
    /// the identical rule.
    ///
    /// The corpus could not have caught this: the harness runs with `TZ=UTC`,
    /// where reading a wall clock as local and as UTC give the same answer.
    #[test]
    fn a_date_is_read_as_local_wall_clock_like_zip() {
        let mut ar = open_bytes(SPEC_CABINET);
        let entries = ar.entries().unwrap();
        assert_eq!(entries[0].modified, dos_words_to_systime(0x226c, 0x59ba));
        assert!(entries[0].modified.is_some());
    }

    #[test]
    fn a_name_is_carried_as_the_bytes_the_cabinet_holds() {
        let mut ar = open_bytes(SPEC_CABINET);
        let entries = ar.entries().unwrap();
        assert_eq!(entries[0].path_raw, b"hi.txt");
        assert_eq!(entries[0].path.to_str().unwrap(), "hi.txt");
    }
}
