//! APFS (Apple File System) — a bare container (`.apfs`, `NXSB` magic) or the
//! filesystem layer inside a DMG image (§7 of `dmg.rs`'s volume locator).
//!
//! Backed by the vendored `apfs-core` crate (see `crates/apfs-core/VENDORED.md`)
//! used at its low level (`dir`/`extent`/`xattr` free functions, no `vfs`
//! feature) — the same navigation sequence as its own `vfs::ApfsFs::open`.
//! Unlike the HFS+ handler (#21a), `extent::read_data` transparently decodes
//! `decmpfs`-compressed files (zlib/LZVN/LZFSE), so no file reads back empty.
//!
//! See `task_n_reports/task-21c-apfs.md` for the full format writeup.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use apfs_core::volume::ApfsVolume;
use apfs_core::{ApfsContainer, ApfsError, dir, extent, xattr};

use crate::archive::{
    ArchiveReader, Confidence, Entry, EntryKind, FormatHandler, FormatId, OpenOptions, Source,
};
use crate::error::{Error, Result};
use crate::format::hfsplus::OffsetReader;

/// Container superblock magic `NXSB`, checked as a byte pattern (mirrors
/// HFS+'s own `H+`/`HX` probe rather than reusing `apfs_core::container::NX_MAGIC`,
/// which is the same value in numeric LE form). `pub(crate)` so `dmg.rs`'s
/// volume locator can scan for the same signature.
pub(crate) const APFS_MAGIC: &[u8; 4] = b"NXSB";
/// Byte offset of `nx_magic` within the container superblock (`nx_superblock_t`).
/// Reachable within the registry's 512-byte header peek — unlike HFS+'s
/// Volume Header signature at offset 1024.
pub(crate) const APFS_MAGIC_OFFSET: u64 = 32;

/// `S_IFMT` mask isolating the file-type bits of a Unix `mode`, and the two
/// type bits this handler distinguishes (`apfs_core::vfs` has the same
/// constants privately; not part of the crate's public API).
const S_IFMT: u16 = 0xF000;
const S_IFDIR: u16 = 0x4000;
const S_IFLNK: u16 = 0xA000;

/// Depth cap on the directory-tree walk. `apfs-core`'s own `CycleGuard`
/// protects a single `list_dir`/`load_inode` B-tree descent against a cyclic
/// *node* graph, but not the *directory* graph our own recursion walks — a
/// crafted image could still nest `A/B/A/B/…` DIR_RECs forever without this.
const MAX_APFS_DEPTH: usize = 256;
/// Cap on the total number of entries collected (allocation-bomb defense
/// against a directory with a hostile fan-out).
const MAX_APFS_ENTRIES: usize = 1_000_000;

/// Reads APFS filesystems via the vendored `apfs-core` crate: a bare
/// container (`.apfs`, as produced by `hdiutil create -layout NONE`) or, via
/// [`open_apfs`], the filesystem embedded inside a DMG image.
pub struct ApfsHandler;

impl FormatHandler for ApfsHandler {
    fn id(&self) -> FormatId {
        FormatId::Apfs
    }

    /// Detect by content (`NXSB` at offset 32, inside the registry's
    /// 512-byte peek) or by `.apfs` extension as a fallback for a short
    /// header. A header shorter than 36 bytes reads as `NONE`, never panics.
    fn probe(&self, header: &[u8], name: Option<&str>) -> Confidence {
        let magic = header.get(32..36) == Some(APFS_MAGIC.as_slice());
        let ext = name.is_some_and(|n| {
            Path::new(n)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("apfs"))
        });
        if magic || ext {
            Confidence::MAGIC
        } else {
            Confidence::NONE
        }
    }

    fn open(&self, src: Source, _opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        // The `apfs-core` reader isn't reopened from the boxed Source (it
        // needs an owned, `'static` Read+Seek); reopen by path instead, like
        // hfsplus/squashfs/7z/rar. A pathless source (pure stream) is
        // unsupported.
        let path = src
            .file_path()
            .ok_or_else(|| Error::Unsupported {
                format: "apfs".into(),
                feature: "non-file source (apfs requires a file path)".into(),
            })?
            .to_path_buf();
        open_apfs(&path, 0)
    }
}

/// Map any `apfs-core` error onto our model. Every failure past a successful
/// magic check is structural — never a distinction our callers need — so it
/// all becomes `Corrupt`, mirroring `map_hfs_err` in `hfsplus.rs`.
fn map_apfs_err(e: ApfsError) -> Error {
    Error::Corrupt(format!("apfs: {e}"))
}

/// Convert an APFS timestamp (nanoseconds since the Unix epoch) to
/// `SystemTime`. `0` (no timestamp) maps to `None`.
fn apfs_ns_to_systime(ns: u64) -> Option<SystemTime> {
    (ns != 0).then(|| UNIX_EPOCH + Duration::from_nanos(ns))
}

/// Open the APFS container whose superblock begins `offset` bytes into
/// `path`, and build the flat entry list. `offset` is `0` for a bare `.apfs`
/// file and non-zero for a container embedded in a larger image (a partition
/// inside a DMG, #21c closing the #21b hole).
pub(crate) fn open_apfs(path: &Path, offset: u64) -> Result<Box<dyn ArchiveReader>> {
    let file = File::open(path)?;
    if offset == 0 {
        open_apfs_reader(file)
    } else {
        open_apfs_reader(OffsetReader::new(file, offset)?)
    }
}

/// Mount the first volume of an APFS container: open the container, resolve its
/// first volume superblock, and parse it. Mirrors apfs-core's own reference
/// sequence `apfs_core::vfs::ApfsFs::open_first_volume` (not called directly —
/// we don't enable the `vfs` feature, and drive the low-level `dir`/`extent`
/// free functions instead). Returns the underlying reader, the parsed volume,
/// and the container block size.
fn mount_first_volume<R: Read + Seek>(reader: R) -> Result<(R, ApfsVolume, usize)> {
    let mut container = ApfsContainer::open(reader).map_err(map_apfs_err)?;
    let block_size = container.superblock().block_size as usize;
    let addrs = container.volume_superblock_addrs().map_err(map_apfs_err)?;
    let vaddr = *addrs
        .first()
        .ok_or_else(|| Error::Corrupt("apfs: container has no volumes".into()))?;

    let mut reader = container.into_reader();
    let vol_offset = vaddr.saturating_mul(block_size as u64);
    reader.seek(SeekFrom::Start(vol_offset))?;
    let mut buf = vec![0u8; block_size];
    reader
        .read_exact(&mut buf)
        .map_err(crate::error::io_err_to_corrupt)?;
    let volume = ApfsVolume::parse(&buf).map_err(map_apfs_err)?;
    Ok((reader, volume, block_size))
}

fn open_apfs_reader<R: Read + Seek + 'static>(mut reader: R) -> Result<Box<dyn ArchiveReader>> {
    // Validate the NXSB signature ourselves, on the same reader the crate
    // will use, before handing it off. A non-APFS input (garbage, or a file
    // too short to hold the magic) yields a clean `UnknownFormat` instead of
    // leaking the crate's own error type.
    reader.seek(SeekFrom::Start(APFS_MAGIC_OFFSET))?;
    let mut magic = [0u8; 4];
    reader
        .read_exact(&mut magic)
        .map_err(|_| Error::UnknownFormat)?;
    if magic != *APFS_MAGIC {
        return Err(Error::UnknownFormat);
    }
    reader.seek(SeekFrom::Start(0))?;

    let (mut reader, volume, block_size) = mount_first_volume(reader)?;

    let mut entries = Vec::new();
    let mut node_ids = Vec::new();
    walk_tree(
        &mut reader,
        &volume,
        block_size,
        dir::ROOT_DIR_INO_NUM,
        "",
        0,
        &mut entries,
        &mut node_ids,
    )?;

    Ok(Box::new(ApfsReader {
        reader,
        volume,
        block_size,
        entries,
        node_ids,
    }))
}

/// Recursively list `parent_oid`'s children into `entries`/`node_ids` (parallel
/// vectors), descending into subdirectories. Paths are relative (no root
/// segment), matching hfsplus/squashfs/iso.
#[allow(clippy::too_many_arguments)]
fn walk_tree<R: Read + Seek>(
    reader: &mut R,
    volume: &ApfsVolume,
    block_size: usize,
    parent_oid: u64,
    prefix: &str,
    depth: usize,
    entries: &mut Vec<Entry>,
    node_ids: &mut Vec<u64>,
) -> Result<()> {
    if depth > MAX_APFS_DEPTH {
        return Err(Error::Corrupt("apfs: directory tree too deep".into()));
    }
    let dir_entries =
        dir::list_dir(reader, volume, parent_oid, block_size).map_err(map_apfs_err)?;
    for de in &dir_entries {
        if entries.len() >= MAX_APFS_ENTRIES {
            return Err(Error::Corrupt("apfs: too many entries".into()));
        }
        let inode =
            dir::load_inode(reader, volume, de.file_id, block_size).map_err(map_apfs_err)?;
        let rel_path = if prefix.is_empty() {
            de.name.clone()
        } else {
            format!("{prefix}/{}", de.name)
        };

        let ifmt = inode.mode & S_IFMT;
        let is_dir = ifmt == S_IFDIR;
        let kind = if is_dir {
            EntryKind::Dir
        } else if ifmt == S_IFLNK {
            let target = xattr::symlink_target(reader, volume, de.file_id, block_size)
                .map_err(map_apfs_err)?
                .map(PathBuf::from)
                .unwrap_or_default();
            EntryKind::Symlink { target }
        } else {
            EntryKind::File
        };
        let size = if kind == EntryKind::File {
            inode.size.unwrap_or(0)
        } else {
            0
        };

        entries.push(Entry {
            path_raw: rel_path.as_bytes().to_vec(),
            path: PathBuf::from(&rel_path),
            kind,
            size,
            mode: None,
            is_encrypted: false,
            modified: apfs_ns_to_systime(inode.mod_time),
        });
        node_ids.push(de.file_id);

        if is_dir {
            walk_tree(
                reader,
                volume,
                block_size,
                de.file_id,
                &rel_path,
                depth + 1,
                entries,
                node_ids,
            )?;
        }
    }
    Ok(())
}

/// Holds the opened container reader + mounted volume, plus the flat entry
/// list and a parallel `node_ids` vector (each entry's inode oid) for
/// on-demand extraction by index.
struct ApfsReader<R: Read + Seek> {
    reader: R,
    volume: ApfsVolume,
    block_size: usize,
    entries: Vec<Entry>,
    /// Parallel to `entries`: the inode oid `read_entry` re-loads on demand.
    node_ids: Vec<u64>,
}

impl<R: Read + Seek> ArchiveReader for ApfsReader<R> {
    fn format(&self) -> FormatId {
        FormatId::Apfs
    }

    fn entries(&mut self) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn read_entry(&mut self, idx: usize, out: &mut dyn Write) -> Result<()> {
        if idx >= self.entries.len() {
            return Err(Error::InvalidIndex(idx));
        }
        if self.entries[idx].kind != EntryKind::File {
            return Ok(()); // directory or symlink — no body to extract
        }
        let inode = dir::load_inode(
            &mut self.reader,
            &self.volume,
            self.node_ids[idx],
            self.block_size,
        )
        .map_err(map_apfs_err)?;
        // `read_data` transparently decodes decmpfs — never the raw extents.
        let data = extent::read_data(&mut self.reader, &self.volume, &inode, self.block_size)
            .map_err(map_apfs_err)?;
        out.write_all(&data)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // ── id / probe ───────────────────────────────────────────────────────────

    #[test]
    fn id_is_apfs() {
        assert_eq!(ApfsHandler.id(), FormatId::Apfs);
    }

    fn header_with_nxsb_at_32() -> Vec<u8> {
        let mut h = vec![0u8; 40];
        h[32..36].copy_from_slice(APFS_MAGIC);
        h
    }

    #[test]
    fn probe_nxsb_magic_is_magic() {
        assert_eq!(
            ApfsHandler.probe(&header_with_nxsb_at_32(), Some("image.bin")),
            Confidence::MAGIC
        );
    }

    #[test]
    fn probe_no_magic_other_name_is_none() {
        assert_eq!(
            ApfsHandler.probe(&[0u8; 40], Some("image.dmg")),
            Confidence::NONE
        );
    }

    #[test]
    fn probe_apfs_extension_without_magic_is_magic() {
        assert_eq!(
            ApfsHandler.probe(&[0u8; 40], Some("volume.apfs")),
            Confidence::MAGIC
        );
    }

    #[test]
    fn probe_short_header_is_none_not_panic() {
        assert_eq!(ApfsHandler.probe(&[0u8; 10], Some("x")), Confidence::NONE);
        assert_eq!(ApfsHandler.probe(&[], None), Confidence::NONE);
    }

    #[test]
    fn probe_no_name_no_magic_is_none() {
        assert_eq!(ApfsHandler.probe(&[0u8; 40], None), Confidence::NONE);
    }

    #[test]
    fn open_path_less_source_is_unsupported() {
        let src = Source::Stream {
            inner: Box::new(std::io::empty()),
            path: None,
        };
        let err = ApfsHandler
            .open(src, &OpenOptions::default())
            .err()
            .expect("path-less source must be unsupported");
        assert!(matches!(err, Error::Unsupported { .. }), "got {err:?}");
    }

    // ── time conversion ──────────────────────────────────────────────────────

    #[test]
    fn ns_to_systime_zero_is_none() {
        assert_eq!(apfs_ns_to_systime(0), None);
    }

    #[test]
    fn ns_to_systime_known_value() {
        let t = apfs_ns_to_systime(1_000_000_000).expect("some");
        assert_eq!(t, UNIX_EPOCH + Duration::from_secs(1));
    }

    // ── open_apfs_reader on synthetic input ──────────────────────────────────

    #[test]
    fn open_apfs_reader_rejects_short_input() {
        let short = Cursor::new(vec![0u8; 20]); // shorter than the 36-byte magic offset
        let err = open_apfs_reader(short).err().expect("must error");
        assert!(matches!(err, Error::UnknownFormat), "got {err:?}");
    }

    #[test]
    fn open_apfs_reader_rejects_bad_magic() {
        let bytes = vec![0u8; 40]; // zeroed — not NXSB
        let err = open_apfs_reader(Cursor::new(bytes))
            .err()
            .expect("must error");
        assert!(matches!(err, Error::UnknownFormat), "got {err:?}");
    }

    #[test]
    fn open_apfs_reader_nxsb_magic_but_corrupt_body_is_corrupt_not_panic() {
        // Magic present so we get past the UnknownFormat gate, but nothing
        // past offset 36 forms a valid checkpoint ring / omap.
        let bytes = header_with_nxsb_at_32();
        let err = open_apfs_reader(Cursor::new(bytes))
            .err()
            .expect("must error");
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }

    // ── open_apfs with a non-zero offset (the mechanism DMG relies on) ───────
    //
    // `open_apfs` is `pub(crate)`, so this must live here rather than in the
    // integration suite (an external crate only sees the public API).

    fn fixture_bytes(name: &str) -> Vec<u8> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name);
        std::fs::read(path).expect("read fixture")
    }

    fn write_temp(bytes: &[u8]) -> tempfile::NamedTempFile {
        use std::io::Write as _;
        let mut f = tempfile::NamedTempFile::new().expect("tmp file");
        f.write_all(bytes).expect("write tmp");
        f.flush().expect("flush tmp");
        f
    }

    #[test]
    fn open_apfs_with_offset_matches_zero_offset() {
        let plain = fixture_bytes("apfs_bare.img");

        let mut padded = vec![0u8; 4096];
        padded.extend_from_slice(&plain);

        let plain_tmp = write_temp(&plain);
        let padded_tmp = write_temp(&padded);

        let mut plain_reader = open_apfs(plain_tmp.path(), 0).expect("open plain");
        let mut padded_reader = open_apfs(padded_tmp.path(), 4096).expect("open padded");

        let plain_entries = plain_reader.entries().expect("entries").to_vec();
        let padded_entries = padded_reader.entries().expect("entries").to_vec();
        assert_eq!(plain_entries.len(), padded_entries.len());

        let idx_plain = plain_entries
            .iter()
            .position(|e| e.path.to_string_lossy() == "plain.txt")
            .expect("plain.txt in plain");
        let idx_padded = padded_entries
            .iter()
            .position(|e| e.path.to_string_lossy() == "plain.txt")
            .expect("plain.txt in padded");

        let mut plain_body = Vec::new();
        plain_reader
            .read_entry(idx_plain, &mut plain_body)
            .expect("read plain plain.txt");
        let mut padded_body = Vec::new();
        padded_reader
            .read_entry(idx_padded, &mut padded_body)
            .expect("read padded plain.txt");
        assert_eq!(plain_body, padded_body);
        assert_eq!(plain_body, b"APFS P4 plain file. Hello extents.\n");
    }

    // ── walk_tree guards ─────────────────────────────────────────────────────
    //
    // `apfs-core`'s own `CycleGuard` protects a single B-tree descent, not the
    // directory graph our recursion walks — these exercise our own caps
    // directly (mounting the real fixture, then calling `walk_tree` with a
    // pre-seeded depth/entry count past the cap), since crafting a genuinely
    // valid-but-cyclic APFS directory graph on disk is impractical.

    fn mount_bare_fixture() -> (Cursor<Vec<u8>>, ApfsVolume, usize) {
        let bytes = fixture_bytes("apfs_bare.img");
        mount_first_volume(Cursor::new(bytes)).expect("mount bare fixture")
    }

    #[test]
    fn walk_tree_rejects_depth_beyond_cap() {
        let (mut reader, volume, block_size) = mount_bare_fixture();
        let mut entries = Vec::new();
        let mut node_ids = Vec::new();
        let err = walk_tree(
            &mut reader,
            &volume,
            block_size,
            dir::ROOT_DIR_INO_NUM,
            "",
            MAX_APFS_DEPTH + 1,
            &mut entries,
            &mut node_ids,
        )
        .expect_err("must reject depth beyond cap");
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }

    #[test]
    fn walk_tree_rejects_entries_beyond_cap() {
        let (mut reader, volume, block_size) = mount_bare_fixture();
        let filler = Entry {
            path_raw: Vec::new(),
            path: PathBuf::new(),
            kind: EntryKind::File,
            size: 0,
            mode: None,
            is_encrypted: false,
            modified: None,
        };
        let mut entries = vec![filler; MAX_APFS_ENTRIES];
        let mut node_ids = vec![0u64; MAX_APFS_ENTRIES];
        let err = walk_tree(
            &mut reader,
            &volume,
            block_size,
            dir::ROOT_DIR_INO_NUM,
            "",
            0,
            &mut entries,
            &mut node_ids,
        )
        .expect_err("must reject entry count beyond cap");
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }
}
