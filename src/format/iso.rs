use std::io::{Read, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use cdfs::{DirectoryEntry, ExtraAttributes, ISO9660, ISOFile};

use crate::archive::{
    ArchiveReader, Confidence, Entry, EntryKind, FormatHandler, FormatId, OpenOptions, ReadSeek,
    Source,
};
use crate::error::{Error, Result};

// ── Handler ──────────────────────────────────────────────────────────────────

pub struct IsoHandler;

impl FormatHandler for IsoHandler {
    fn id(&self) -> FormatId {
        FormatId::Iso
    }

    /// Detect by `.iso` extension only: the CD001 signature lives at offset 0x8001,
    /// far beyond the 512-byte header that the registry peeks.
    fn probe(&self, _header: &[u8], name: Option<&str>) -> Confidence {
        if name
            .map(|n| {
                Path::new(n)
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("iso"))
            })
            .unwrap_or(false)
        {
            Confidence::MAGIC
        } else {
            Confidence::NONE
        }
    }

    fn open(&self, src: Source, _opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        let mut inner: Box<dyn ReadSeek> = match src {
            Source::Seekable { inner, .. } => inner,
            Source::Stream { .. } => {
                return Err(Error::Unsupported {
                    format: "iso".into(),
                    feature: "streaming (iso requires seek)".into(),
                });
            }
        };

        // Validate CD001 at offset 0x8001 before handing to cdfs.
        inner.seek(SeekFrom::Start(0x8001))?;
        let mut sig = [0u8; 5];
        inner.read_exact(&mut sig)?;
        if &sig != b"CD001" {
            return Err(Error::UnknownFormat);
        }
        inner.seek(SeekFrom::Start(0))?;

        // Construct the ISO filesystem.
        let iso = ISO9660::new(inner).map_err(map_iso_err)?;

        // Walk the directory tree from the best root (Rock Ridge > Joliet > 8.3).
        let mut entries: Vec<Entry> = Vec::new();
        let mut iso_files: Vec<Option<ISOFile<Box<dyn ReadSeek>>>> = Vec::new();

        walk_dir(iso.root(), "", &mut entries, &mut iso_files)?;

        Ok(Box::new(IsoReader { entries, iso_files }))
    }
}

// ── Tree walk ─────────────────────────────────────────────────────────────────

/// Recursively walk an `ISODirectory`, appending to `entries` and `iso_files`.
/// `prefix` is the slash-joined path from the root (empty for root entries).
fn walk_dir<T>(
    dir: &cdfs::ISODirectory<T>,
    prefix: &str,
    entries: &mut Vec<Entry>,
    iso_files: &mut Vec<Option<ISOFile<T>>>,
) -> Result<()>
where
    T: cdfs::ISO9660Reader,
{
    for item in dir.contents() {
        let item = item.map_err(map_iso_err)?;
        let name = item.identifier();

        // Skip the `.` and `..` self/parent entries.
        if name == "." || name == ".." {
            continue;
        }

        let full_path = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}/{name}")
        };

        match item {
            DirectoryEntry::File(f) => {
                let modified = offset_datetime_to_systime(f.modify_time());
                entries.push(Entry {
                    path_raw: full_path.as_bytes().to_vec(),
                    path: PathBuf::from(&full_path),
                    kind: EntryKind::File,
                    size: u64::from(f.size()),
                    mode: None,
                    is_encrypted: false,
                    modified,
                });
                iso_files.push(Some(f));
            }
            DirectoryEntry::Directory(d) => {
                entries.push(Entry {
                    path_raw: full_path.as_bytes().to_vec(),
                    path: PathBuf::from(&full_path),
                    kind: EntryKind::Dir,
                    size: 0,
                    mode: None,
                    is_encrypted: false,
                    modified: None,
                });
                iso_files.push(None); // no file body for directories
                walk_dir(&d, &full_path, entries, iso_files)?;
            }
            DirectoryEntry::Symlink(s) => {
                let target = s
                    .target()
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from(""));
                entries.push(Entry {
                    path_raw: full_path.as_bytes().to_vec(),
                    path: PathBuf::from(&full_path),
                    kind: EntryKind::Symlink { target },
                    size: 0,
                    mode: None,
                    is_encrypted: false,
                    modified: None,
                });
                iso_files.push(None); // no body
            }
        }
    }
    Ok(())
}

// ── Reader ────────────────────────────────────────────────────────────────────

struct IsoReader<T: cdfs::ISO9660Reader> {
    entries: Vec<Entry>,
    /// Parallel to `entries`: `Some(ISOFile)` for files, `None` for dirs/symlinks.
    iso_files: Vec<Option<ISOFile<T>>>,
}

impl<T: cdfs::ISO9660Reader> ArchiveReader for IsoReader<T> {
    fn format(&self) -> FormatId {
        FormatId::Iso
    }

    fn entries(&mut self) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn read_entry(&mut self, idx: usize, out: &mut dyn Write) -> Result<()> {
        if idx >= self.entries.len() {
            return Err(Error::InvalidIndex(idx));
        }
        let Some(ref iso_file) = self.iso_files[idx] else {
            // Directory or symlink — no body.
            return Ok(());
        };
        let mut reader = iso_file.read();
        std::io::copy(&mut reader, out)?;
        Ok(())
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Map a `cdfs::ISOError` onto our error model.
fn map_iso_err(e: cdfs::ISOError) -> Error {
    match e {
        cdfs::ISOError::Io(io_err) => Error::Io(io_err),
        cdfs::ISOError::InvalidFs(msg) => Error::Corrupt(msg.to_string()),
        _ => Error::Corrupt(e.to_string()),
    }
}

/// Convert a `time::OffsetDateTime` to `SystemTime`.
/// Returns `None` for pre-epoch timestamps.
fn offset_datetime_to_systime(dt: time::OffsetDateTime) -> Option<SystemTime> {
    let unix_ts = dt.unix_timestamp();
    if unix_ts < 0 {
        None
    } else {
        Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(unix_ts as u64))
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_is_iso() {
        assert_eq!(IsoHandler.id(), FormatId::Iso);
    }

    #[test]
    fn probe_positive_iso_extension() {
        assert_eq!(IsoHandler.probe(&[], Some("disk.iso")), Confidence::MAGIC);
    }

    #[test]
    fn probe_positive_iso_extension_uppercase() {
        assert_eq!(IsoHandler.probe(&[], Some("disk.ISO")), Confidence::MAGIC);
    }

    #[test]
    fn probe_negative_zip_extension() {
        assert_eq!(IsoHandler.probe(&[], Some("disk.zip")), Confidence::NONE);
    }

    #[test]
    fn probe_negative_no_name() {
        assert_eq!(IsoHandler.probe(&[], None), Confidence::NONE);
    }

    #[test]
    fn probe_negative_no_extension() {
        assert_eq!(IsoHandler.probe(&[], Some("isofile")), Confidence::NONE);
    }
}
