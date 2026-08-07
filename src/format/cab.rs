use std::io::{Read, Write};
use std::time::SystemTime;

use crate::archive::{
    ArchiveReader, Confidence, Entry, EntryKind, EntrySink, FormatHandler, FormatId, OpenOptions,
    ReadSeek, SinkStep, SinkWriter, Source,
};
use crate::datetime::civil_to_systime;
use crate::error::{Error, Result, io_err_to_corrupt};
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

    fn open(&self, src: Source, _opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
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

        let mut entries: Vec<Entry> = Vec::new();
        let mut places: Vec<Place> = Vec::new();
        for (folder_idx, folder) in cab.folder_entries().enumerate() {
            let is_quantum = matches!(
                folder.compression_type(),
                cab::CompressionType::Quantum(_, _)
            );
            for file in folder.file_entries() {
                let raw = file.name();
                let (date, time) = file.dos_date_time();
                entries.push(Entry {
                    path_raw: raw.as_bytes().to_vec(),
                    // CAB uses `\` separators; normalize to `/` so list output and
                    // common-root/wrapper detection (which read `Entry::path`)
                    // work. `safe_join` re-normalizes for the on-disk write path.
                    path: std::path::PathBuf::from(raw.replace('\\', "/")),
                    kind: EntryKind::File,
                    size: file.uncompressed_size() as u64,
                    mode: None,
                    is_encrypted: false,
                    modified: cab_dos_to_systime(date, time),
                    is_resource_fork: false,
                });
                places.push(Place {
                    folder: folder_idx,
                    offset: file.uncompressed_offset() as u64,
                    size: file.uncompressed_size() as u64,
                    is_quantum,
                });
            }
        }

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
    /// This entry's folder uses Quantum compression, which nothing here decodes.
    is_quantum: bool,
}

/// The two packed MS-DOS words a cabinet stores, read as **UTC**.
///
/// The CAB spec calls the field local time with no zone attached, and every
/// other format of that era is read as local wall clock here (see
/// `datetime::dos_words_to_systime`). CAB is the exception on purpose: The
/// Unarchiver reads it as UTC, and the reference corpus is checked against that.
/// Changing it would move every date in every cabinet by the reader's offset,
/// which is a decision about listings, not about speed.
fn cab_dos_to_systime(date: u16, time: u16) -> Option<SystemTime> {
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
    civil_to_systime(year, month, day, hour, min, sec)
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

    fn quantum_error() -> Error {
        Error::Unsupported {
            format: "cab".into(),
            feature: "Quantum compression".into(),
        }
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
        if place.is_quantum {
            return Err(Self::quantum_error());
        }
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
        if place.is_quantum {
            return Err(Self::quantum_error());
        }
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

    #[test]
    fn dos_words_are_read_as_utc() {
        // 1997-03-12 11:13:52, the timestamp in the CAB spec's example cabinet.
        let t = cab_dos_to_systime(0x226c, 0x59ba).unwrap();
        let secs = t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(secs, 858_165_232);
    }

    #[test]
    fn a_zero_date_is_no_date() {
        assert_eq!(cab_dos_to_systime(0, 0), None);
    }

    #[test]
    fn a_clock_that_never_was_is_no_date() {
        // Hour 31 — five bits of hour, all set.
        assert_eq!(cab_dos_to_systime(0x226c, 0xF800), None);
    }
}
