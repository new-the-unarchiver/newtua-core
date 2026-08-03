use std::collections::HashSet;
use std::io::{Seek, SeekFrom, Write};
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use cdfs::{DirectoryEntry, ExtraAttributes, ISO9660, ISOFile};

use crate::archive::{
    ArchiveReader, Confidence, Entry, EntryKind, FormatHandler, FormatId, OpenOptions, ReadSeek,
    Source,
};
use crate::error::{Error, Result};

// ── Handler ──────────────────────────────────────────────────────────────────

/// Depth cap on the directory-tree walk, guarding the same thing as
/// `MAX_APFS_DEPTH` in `apfs.rs`: a crafted image must not be able to drive our
/// own recursion off the end of the stack. It matters more here than there,
/// because a stack overflow is an *abort*, not a panic — `catch_iso_panic` is
/// powerless against it and the whole process dies.
///
/// The number is far below apfs's 256 on purpose, and it was measured rather
/// than guessed. One level of `walk_dir` costs roughly 12 KB of stack in a debug
/// build (each `ISODirectoryIterator` carries a 2048-byte block inline, and
/// `read_entry_at` allocates another on the frame), so a debug test binary
/// overflows somewhere between 160 and 170 levels. 32 keeps the worst case near
/// 400 KB — comfortable even for a caller whose thread has a 1 MiB stack.
///
/// 32 is also generous against real images: ISO 9660 § 6.8.2.1 caps the
/// hierarchy at 8 levels, and Rock Ridge's deep-directory relocation exists
/// precisely because of that cap. If some genuine image ever trips this, the
/// answer is to rewrite the walk with an explicit queue, not to raise the number.
const MAX_ISO_DEPTH: usize = 32;

pub struct IsoHandler;

impl FormatHandler for IsoHandler {
    fn id(&self) -> FormatId {
        FormatId::Iso
    }

    /// Detect by `.iso` extension only: the CD001 signature lives at offset 0x8001,
    /// far beyond the 512-byte header that the registry peeks. Reported at
    /// `EXTENSION` confidence (below `MAGIC`) so a genuine other-format file
    /// mislabeled `.iso` (e.g. a SquashFS image) still wins on content; a real
    /// ISO renamed away from `.iso` is instead caught by `has_iso_signature`.
    fn probe(&self, _header: &[u8], name: Option<&str>) -> Confidence {
        let is_iso = name.is_some_and(|n| {
            Path::new(n)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("iso"))
        });
        if is_iso {
            Confidence::EXTENSION
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
        if !cd001_matches(inner.as_mut())? {
            return Err(Error::UnknownFormat);
        }
        inner.seek(SeekFrom::Start(0))?;

        // The cdfs crate calls `unimplemented!()` deep in SUSP/Rock Ridge parsing
        // for certain extension records (e.g. IEEE_P1282 / ER version=0), producing
        // a panic that would otherwise crash the calling process or GUI.  There is
        // no header-detectable signature for this condition — it only surfaces during
        // the tree walk — so we guard the cdfs construction and walk via
        // catch_iso_panic (see below).
        let reader = catch_iso_panic(|| {
            // Construct the ISO filesystem, then walk the directory tree from the
            // best root (Rock Ridge > Joliet > 8.3).
            let iso = ISO9660::new(inner).map_err(map_iso_err)?;
            let mut entries: Vec<Entry> = Vec::new();
            let mut iso_files: Vec<Option<ISOFile<Box<dyn ReadSeek>>>> = Vec::new();
            // Seed the visited set with the root's own extent, so a child record
            // pointing back at the root is caught on the very first descent.
            let mut visited: HashSet<u32> = HashSet::new();
            visited.insert(iso.root().header().extent_loc);
            walk_dir(
                iso.root(),
                "",
                0,
                &mut visited,
                &mut entries,
                &mut iso_files,
            )?;
            Ok(IsoReader { entries, iso_files })
        })?;
        Ok(Box::new(reader))
    }
}

/// Read the 5-byte descriptor at 0x8001 and report whether it is the ISO 9660
/// `CD001` magic. Leaves the cursor just past the descriptor. Shared by
/// `IsoHandler::open` (validation) and `has_iso_signature` (content detection).
fn cd001_matches(r: &mut dyn ReadSeek) -> std::io::Result<bool> {
    r.seek(SeekFrom::Start(0x8001))?;
    let mut sig = [0u8; 5];
    r.read_exact(&mut sig)?;
    Ok(&sig == b"CD001")
}

/// Content probe: `true` when `path` carries the ISO 9660 `CD001` descriptor at
/// offset 0x8001. Used by `open_single` to detect an ISO whose extension was
/// changed or dropped, since the signature sits past the registry's header peek.
pub(crate) fn has_iso_signature(path: &Path) -> bool {
    std::fs::File::open(path)
        .and_then(|mut f| cd001_matches(&mut f))
        .unwrap_or(false)
}

// ── Tree walk ─────────────────────────────────────────────────────────────────

/// Recursively walk an `ISODirectory`, appending to `entries` and `iso_files`.
/// `prefix` is the slash-joined path from the root (empty for root entries).
/// `depth` counts levels below the root; `visited` holds the extent LBA of every
/// directory already entered, including the root's.
///
/// Both guards exist because the directory graph is attacker input: a record may
/// name itself as its own child, or a chain of records may close into a cycle,
/// and either drives this recursion until the stack gives out. A stack overflow
/// aborts the process — `catch_iso_panic` does not catch it — so the walk has to
/// refuse to go there rather than be rescued afterwards.
fn walk_dir<T>(
    dir: &cdfs::ISODirectory<T>,
    prefix: &str,
    depth: usize,
    visited: &mut HashSet<u32>,
    entries: &mut Vec<Entry>,
    iso_files: &mut Vec<Option<ISOFile<T>>>,
) -> Result<()>
where
    T: cdfs::ISO9660Reader,
{
    if depth > MAX_ISO_DEPTH {
        return Err(Error::Corrupt("iso: directory tree too deep".into()));
    }

    for item in dir.contents() {
        let item = item.map_err(map_iso_err)?;
        let name = item.identifier();

        // Skip the `.` and `..` self/parent entries. An empty identifier counts
        // as one of them: cdfs turns the single bytes 0x00 / 0x01 into "." / ".."
        // only when it decodes them as such — a Joliet (UTF-16BE) directory, or
        // one whose records carry no identifier at all, hands us "" for both, and
        // an empty name walked straight back into the root. That is what killed
        // the process on a type-1 AppImage.
        if name.is_empty() || name == "." || name == ".." {
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
                let mode = posix_mode(&f);
                let size = u64::from(f.size());
                let path = PathBuf::from(&full_path);
                entries.push(Entry {
                    path_raw: full_path.into_bytes(),
                    path,
                    kind: EntryKind::File,
                    size,
                    mode,
                    is_encrypted: false,
                    modified,
                    is_resource_fork: false,
                });
                iso_files.push(Some(f));
            }
            DirectoryEntry::Directory(d) => {
                // A directory extent we have already entered means the graph
                // loops. List the record (the name is real) but do not descend
                // again — descending is what never returns.
                let first_visit = visited.insert(d.header().extent_loc);
                let modified = offset_datetime_to_systime(d.modify_time());
                let mode = posix_mode(&d);
                entries.push(Entry {
                    path_raw: full_path.as_bytes().to_vec(),
                    path: PathBuf::from(&full_path),
                    kind: EntryKind::Dir,
                    size: 0,
                    mode,
                    is_encrypted: false,
                    modified,
                    is_resource_fork: false,
                });
                iso_files.push(None); // no file body for directories
                if first_visit {
                    walk_dir(&d, &full_path, depth + 1, visited, entries, iso_files)?;
                }
            }
            DirectoryEntry::Symlink(s) => {
                let target = s.target().map(PathBuf::from).unwrap_or_default();
                let modified = offset_datetime_to_systime(s.modify_time());
                let mode = posix_mode(&s);
                let path = PathBuf::from(&full_path);
                entries.push(Entry {
                    path_raw: full_path.into_bytes(),
                    path,
                    kind: EntryKind::Symlink { target },
                    size: 0,
                    mode,
                    is_encrypted: false,
                    modified,
                    is_resource_fork: false,
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

        // Guard the cdfs read too: a malformed data region could also trigger a
        // panic inside cdfs during reading. ISOFile::read() returns a fresh
        // ISOFileReader at seek=0, so repeated reads of the same index each return
        // the complete contents.
        catch_iso_panic(|| {
            let mut reader = iso_file.read();
            std::io::copy(&mut reader, out).map_err(Error::Io)?;
            Ok(())
        })
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Run a cdfs operation, converting a panic from the (panicking) `cdfs` crate
/// into `Error::Corrupt` instead of letting it unwind past our API. See the
/// callers for why cdfs panics and why catch_unwind is the right guard.
/// `AssertUnwindSafe` is justified: on a caught panic we discard all cdfs state.
fn catch_iso_panic<T>(f: impl FnOnce() -> Result<T>) -> Result<T> {
    match std::panic::catch_unwind(AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(_panic) => Err(Error::Corrupt(
            "iso: cdfs panicked (unsupported SUSP/Rock Ridge variant)".into(),
        )),
    }
}

/// Map a `cdfs::ISOError` onto our error model.
fn map_iso_err(e: cdfs::ISOError) -> Error {
    match e {
        cdfs::ISOError::Io(io_err) => Error::Io(io_err),
        cdfs::ISOError::InvalidFs(msg) => Error::Corrupt(msg.to_string()),
        _ => Error::Corrupt(e.to_string()),
    }
}

/// The Rock Ridge `PX` mode of a record, whole — the type bits included, the
/// way cpio and HFS+ also report it; `extract.rs::apply_mode` keeps only the
/// permission bits.
///
/// `None` when the record carries no `PX` entry, and that is not the same as
/// `0`: a plain ISO 9660 disc without Rock Ridge says nothing about
/// permissions at all, so there is nothing to restore and the extractor's own
/// default must stand. Handing out a made-up `0644` there would close a script
/// the disc never said was closed.
///
/// Directories and symlinks go through this too — the `PX` entry is the same
/// structure for every record kind, and a directory its owner had closed
/// (`0700`) is otherwise indistinguishable from a public one.
fn posix_mode(item: &impl ExtraAttributes) -> Option<u32> {
    item.mode().map(|m| m.bits())
}

/// Convert a `time::OffsetDateTime` to `SystemTime`.
/// Returns `None` for pre-epoch timestamps (`try_from` rejects negatives).
fn offset_datetime_to_systime(dt: time::OffsetDateTime) -> Option<SystemTime> {
    u64::try_from(dt.unix_timestamp())
        .ok()
        .map(|secs| SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs))
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
        assert_eq!(
            IsoHandler.probe(&[], Some("disk.iso")),
            Confidence::EXTENSION
        );
    }

    #[test]
    fn probe_positive_iso_extension_uppercase() {
        assert_eq!(
            IsoHandler.probe(&[], Some("disk.ISO")),
            Confidence::EXTENSION
        );
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
