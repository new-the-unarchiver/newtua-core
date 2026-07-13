use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use memmap2::Mmap;

use crate::archive::{
    ArchiveReader, Confidence, Entry, EntryKind, FormatHandler, FormatId, OpenOptions, Source,
};
use crate::error::{Error, Result};

/// HFS+ signature `H+` (big-endian `0x482B`, version 4).
pub(crate) const HFS_PLUS_SIGNATURE: u16 = 0x482B;
/// HFSX signature `HX` (big-endian `0x4858`, version 5) — case-sensitive HFS+.
pub(crate) const HFSX_SIGNATURE: u16 = 0x4858;
/// Byte offset of the Volume Header within an HFS+/HFSX volume.
pub(crate) const VOLUME_HEADER_OFFSET: u64 = 1024;
/// Seconds between the HFS+ epoch (1904-01-01 00:00 GMT) and the Unix epoch.
const HFS_EPOCH_TO_UNIX_EPOCH_SECS: u64 = 2_082_844_800;
/// `HFSPlusBSDInfo.fileMode` high nibble mask and the symlink bit pattern
/// within it (`S_IFMT`/`S_IFLNK`, matching the reserved TN1150 field
/// `hfsplus-forensic::HfsStat::mode` now surfaces).
const S_IFMT: u16 = 0xF000;
const S_IFLNK: u16 = 0xA000;

/// Reads HFS+/HFSX filesystem images via the vendored `hfsplus-forensic`
/// crate (`crates/hfsplus-forensic/`, see its `VENDORED.md`): a bare volume
/// (`.hfs`/`.hfsplus`/`.hfsx`, as produced by `newfs_hfs`) or, via
/// [`open_hfsplus`], the filesystem embedded inside a DMG image (#21b).
/// Transparently-compressed (`decmpfs`) files are decoded on read — the
/// reason #21a's `hfsplus` (Dil4rd) backend was replaced (#21a2), which
/// silently returned an empty body for them.
pub struct HfsPlusHandler;

impl FormatHandler for HfsPlusHandler {
    fn id(&self) -> FormatId {
        FormatId::HfsPlus
    }

    /// Detect by extension only: the Volume Header (and its `H+`/`HX`
    /// signature) sits at offset 1024, past the 512-byte header the registry
    /// peeks — same situation as ISO's `CD001` at 0x8001. A bare, extensionless
    /// HFS+ stream is therefore not detected via the registry; the DMG
    /// container (#21b) calls `open_hfsplus` directly instead, bypassing
    /// `probe` entirely.
    fn probe(&self, _header: &[u8], name: Option<&str>) -> Confidence {
        let is_hfs = name.is_some_and(|n| {
            Path::new(n).extension().is_some_and(|e| {
                e.eq_ignore_ascii_case("hfs")
                    || e.eq_ignore_ascii_case("hfsplus")
                    || e.eq_ignore_ascii_case("hfsx")
            })
        });
        if is_hfs {
            Confidence::MAGIC
        } else {
            Confidence::NONE
        }
    }

    fn open(&self, src: Source, _opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        // `hfsplus-forensic` reads over a byte buffer (mmap), which needs a
        // real path; reopen by path instead, like squashfs/7z/rar. A pathless
        // source (pure stream) is unsupported.
        let path = src
            .file_path()
            .ok_or_else(|| Error::Unsupported {
                format: "hfsplus".into(),
                feature: "non-file source (hfs+ requires a file path)".into(),
            })?
            .to_path_buf();
        open_hfsplus(&path, 0)
    }
}

/// Convert an HFS+ date (seconds since 1904-01-01 00:00 GMT) to `SystemTime`.
/// `0` (no timestamp) and any value before the Unix epoch map to `None`.
fn hfs_date_to_systime(date: u32) -> Option<SystemTime> {
    let secs = u64::from(date);
    if secs < HFS_EPOCH_TO_UNIX_EPOCH_SECS {
        None
    } else {
        Some(UNIX_EPOCH + Duration::from_secs(secs - HFS_EPOCH_TO_UNIX_EPOCH_SECS))
    }
}

/// True when a catalog file record's `(is_dir, mode)` mark it as a symlink
/// (`HFSPlusBSDInfo.fileMode & S_IFMT == S_IFLNK`). Folders are never
/// symlinks — `hfsplus-forensic` always reports `mode == 0` for them.
fn is_symlink_mode(is_dir: bool, mode: u16) -> bool {
    !is_dir && (mode & S_IFMT) == S_IFLNK
}

/// Wraps a `File` so that logical position 0 is `base` bytes into the
/// underlying file, and reads never cross past `base + len` (`len` is the
/// remaining tail of the file from `base`). `pub(crate)` so `format/apfs.rs`
/// (#21c) can reuse the same offset semantics for its own absolute
/// `seek(Start(0))` reads. HFS+ itself no longer uses this (mmap + slice
/// covers offset directly, see [`open_hfsplus`]) — kept for apfs.rs (#21c).
pub(crate) struct OffsetReader {
    file: File,
    base: u64,
    len: u64,
    /// Logical position, 0-based from `base`.
    pos: u64,
}

impl OffsetReader {
    pub(crate) fn new(mut file: File, base: u64) -> Result<OffsetReader> {
        let total_len = file.metadata()?.len();
        let len = total_len.saturating_sub(base);
        // Land the underlying file's physical position on `base` up front:
        // `read()` never seeks on its own, so without this a fresh reader
        // (logical pos 0, no explicit `seek()` yet) would read from the
        // file's actual position 0 instead of `base`.
        file.seek(SeekFrom::Start(base))?;
        Ok(OffsetReader {
            file,
            base,
            len,
            pos: 0,
        })
    }
}

impl Read for OffsetReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self.len.saturating_sub(self.pos);
        let cap = remaining.min(buf.len() as u64) as usize;
        if cap == 0 {
            return Ok(0);
        }
        let n = self.file.read(&mut buf[..cap])?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for OffsetReader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(p) => p as i64,
            SeekFrom::Current(d) => self.pos as i64 + d,
            SeekFrom::End(d) => self.len as i64 + d,
        };
        let new_pos = u64::try_from(new_pos).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek to a negative position",
            )
        })?;
        self.pos = new_pos;
        self.file.seek(SeekFrom::Start(self.base + self.pos))?;
        Ok(self.pos)
    }
}

/// Open the HFS+/HFSX volume whose Volume Header begins `offset` bytes into
/// `path`, and build the flat entry list. `offset` is `0` for a bare
/// `.hfs`/`.hfsplus`/`.hfsx` file and non-zero for a volume embedded in a
/// larger image (e.g. a partition inside a DMG, #21b).
pub(crate) fn open_hfsplus(path: &Path, offset: u64) -> Result<Box<dyn ArchiveReader>> {
    let file = File::open(path)?;
    // SAFETY: the mapping is only read through this handle for the reader's
    // lifetime; nothing in this process writes to `path` concurrently. The
    // usual memmap2 caveat (another process truncating/mutating the file
    // underneath the mapping is UB) is outside this tool's threat model —
    // same acceptance as ripgrep and other local-file mmap readers.
    let mmap = unsafe { Mmap::map(&file) }.map_err(|_| Error::UnknownFormat)?;
    let offset = usize::try_from(offset).map_err(|_| Error::UnknownFormat)?;
    if offset > mmap.len() {
        return Err(Error::UnknownFormat);
    }
    let volume = &mmap[offset..];
    // `parse` validates both the H+/HX signature at 1024 and that the buffer
    // is long enough to hold the Volume Header; anything else (too short, no
    // signature, legacy HFS `BD`, APFS `NXSB`, garbage) is `None`.
    hfsplus_forensic::parse(volume).ok_or(Error::UnknownFormat)?;
    let (entries, cnids) = build_entries(volume)?;

    Ok(Box::new(HfsPlusReader {
        mmap,
        offset,
        entries,
        cnids,
    }))
}

/// Walk the catalog and build the flat `Entry` list plus a parallel CNID
/// vector (the key `read_file`/`stat` need) for on-demand extraction by
/// index. Called only after the caller has confirmed the H+/HX signature, so
/// a `None` from the crate here means a structurally broken catalog, not an
/// unrecognised format — `Corrupt`, not `UnknownFormat`.
fn build_entries(volume: &[u8]) -> Result<(Vec<Entry>, Vec<u32>)> {
    let walked = hfsplus_forensic::walk(volume)
        .ok_or_else(|| Error::Corrupt("hfsplus: catalog B-tree unreadable".into()))?;

    let mut entries = Vec::with_capacity(walked.len());
    let mut cnids = Vec::with_capacity(walked.len());
    for w in walked {
        let st = hfsplus_forensic::stat(volume, w.cnid).ok_or_else(|| {
            Error::Corrupt(format!("hfsplus: no catalog record for cnid {}", w.cnid))
        })?;

        let kind = if is_symlink_mode(w.is_dir, st.mode) {
            // The symlink target is stored as the data fork's content.
            let target = hfsplus_forensic::read_file(volume, w.cnid)
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .map(PathBuf::from)
                .unwrap_or_default();
            EntryKind::Symlink { target }
        } else if w.is_dir {
            EntryKind::Dir
        } else {
            EntryKind::File
        };
        let size = if kind == EntryKind::File { st.size } else { 0 };

        entries.push(Entry {
            path_raw: w.path.as_bytes().to_vec(),
            path: PathBuf::from(&w.path),
            kind,
            size,
            mode: None,
            is_encrypted: false,
            modified: hfs_date_to_systime(st.modified),
        });
        cnids.push(w.cnid);
    }

    Ok((entries, cnids))
}

/// Holds the memory-mapped volume plus the flat entry list and a parallel
/// `cnids` vector (catalog node ID per entry, for `read_file`/`stat` by
/// index). `mmap` lives for as long as the reader — for DMG (#21b),
/// `TempBackedReader` drops this reader (and so the mapping) before deleting
/// the backing temp file.
struct HfsPlusReader {
    mmap: Mmap,
    /// Byte offset of the volume's start within `mmap` (0 for a bare file).
    offset: usize,
    entries: Vec<Entry>,
    /// Parallel to `entries`: the catalog node ID for on-demand extraction.
    cnids: Vec<u32>,
}

impl ArchiveReader for HfsPlusReader {
    fn format(&self) -> FormatId {
        FormatId::HfsPlus
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
        let volume = &self.mmap[self.offset..];
        let cnid = self.cnids[idx];
        // Already decodes decmpfs (zlib/LZVN/LZFSE, inline or resource-fork)
        // transparently; `None` means an unrecognised/undecodable file —
        // never a misleading empty body.
        let bytes = hfsplus_forensic::read_file(volume, cnid)
            .ok_or_else(|| Error::Corrupt(format!("hfsplus: failed to read/decode cnid {cnid}")))?;
        out.write_all(&bytes)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── id / probe ───────────────────────────────────────────────────────────

    #[test]
    fn id_is_hfsplus() {
        assert_eq!(HfsPlusHandler.id(), FormatId::HfsPlus);
    }

    #[test]
    fn probe_hfs_extension_is_magic() {
        assert_eq!(
            HfsPlusHandler.probe(&[], Some("image.hfs")),
            Confidence::MAGIC
        );
    }

    #[test]
    fn probe_hfsplus_extension_is_magic() {
        assert_eq!(
            HfsPlusHandler.probe(&[], Some("image.HFSPLUS")),
            Confidence::MAGIC
        );
    }

    #[test]
    fn probe_hfsx_extension_is_magic() {
        assert_eq!(
            HfsPlusHandler.probe(&[], Some("image.hfsx")),
            Confidence::MAGIC
        );
    }

    #[test]
    fn probe_other_extension_is_none() {
        assert_eq!(
            HfsPlusHandler.probe(&[], Some("image.dmg")),
            Confidence::NONE
        );
    }

    #[test]
    fn probe_no_name_is_none() {
        assert_eq!(HfsPlusHandler.probe(&[], None), Confidence::NONE);
    }

    #[test]
    fn open_path_less_source_is_unsupported() {
        let src = Source::Stream {
            inner: Box::new(std::io::empty()),
            path: None,
        };
        let err = HfsPlusHandler
            .open(src, &OpenOptions::default())
            .err()
            .expect("path-less source must be unsupported");
        assert!(matches!(err, Error::Unsupported { .. }), "got {err:?}");
    }

    // ── date conversion ──────────────────────────────────────────────────────

    #[test]
    fn hfs_date_zero_is_none() {
        assert_eq!(hfs_date_to_systime(0), None);
    }

    #[test]
    fn hfs_date_just_below_unix_epoch_is_none() {
        assert_eq!(
            hfs_date_to_systime((HFS_EPOCH_TO_UNIX_EPOCH_SECS - 1) as u32),
            None
        );
    }

    #[test]
    fn hfs_date_at_unix_epoch_is_some_epoch() {
        let t = hfs_date_to_systime(HFS_EPOCH_TO_UNIX_EPOCH_SECS as u32).expect("some");
        assert_eq!(t, UNIX_EPOCH);
    }

    #[test]
    fn hfs_date_one_day_after_unix_epoch() {
        let one_day = 86_400u64;
        let t = hfs_date_to_systime((HFS_EPOCH_TO_UNIX_EPOCH_SECS + one_day) as u32).expect("some");
        assert_eq!(t, UNIX_EPOCH + Duration::from_secs(one_day));
    }

    // ── symlink mode classification ─────────────────────────────────────────

    #[test]
    fn symlink_mode_is_detected() {
        assert!(is_symlink_mode(false, 0xA1ED)); // S_IFLNK | 0755-ish, real value seen on macOS
    }

    #[test]
    fn regular_file_mode_is_not_symlink() {
        assert!(!is_symlink_mode(false, 0x81A4)); // S_IFREG | 0644
    }

    #[test]
    fn folder_is_never_symlink_even_with_stray_mode_bits() {
        assert!(!is_symlink_mode(true, 0xA1ED));
    }

    // ── offset adapter ───────────────────────────────────────────────────────

    fn write_temp(bytes: &[u8]) -> tempfile::NamedTempFile {
        use std::io::Write as _;
        let mut f = tempfile::NamedTempFile::new().expect("tmp file");
        f.write_all(bytes).expect("write tmp");
        f.flush().expect("flush tmp");
        f
    }

    #[test]
    fn offset_reader_reads_from_base() {
        let data = b"0123456789ABCDEF";
        let tmp = write_temp(data);
        let file = File::open(tmp.path()).expect("reopen");
        let mut r = OffsetReader::new(file, 4).expect("adapter");

        let mut buf = [0u8; 4];
        r.read_exact(&mut buf).expect("read");
        assert_eq!(&buf, b"4567");
    }

    #[test]
    fn offset_reader_seek_start_is_relative_to_base() {
        let data = b"0123456789ABCDEF";
        let tmp = write_temp(data);
        let file = File::open(tmp.path()).expect("reopen");
        let mut r = OffsetReader::new(file, 4).expect("adapter");

        r.seek(SeekFrom::Start(2)).expect("seek");
        let mut buf = [0u8; 3];
        r.read_exact(&mut buf).expect("read");
        assert_eq!(&buf, b"678"); // base(4) + 2 = physical offset 6
    }

    #[test]
    fn offset_reader_seek_current_and_end() {
        let data = b"0123456789ABCDEF"; // 16 bytes
        let tmp = write_temp(data);
        let file = File::open(tmp.path()).expect("reopen");
        let mut r = OffsetReader::new(file, 4).expect("adapter"); // logical len = 12

        r.seek(SeekFrom::Current(3)).expect("seek current");
        let mut one = [0u8; 1];
        r.read_exact(&mut one).expect("read");
        assert_eq!(&one, b"7"); // physical offset 4+3=7

        let end = r.seek(SeekFrom::End(0)).expect("seek end");
        assert_eq!(end, 12); // logical length from base
        let mut empty = [0u8; 1];
        assert_eq!(r.read(&mut empty).expect("read at eof"), 0);
    }

    #[test]
    fn offset_reader_read_never_crosses_past_len() {
        let data = b"0123456789"; // 10 bytes, base=6 -> logical len=4
        let tmp = write_temp(data);
        let file = File::open(tmp.path()).expect("reopen");
        let mut r = OffsetReader::new(file, 6).expect("adapter");

        let mut buf = Vec::new();
        r.read_to_end(&mut buf).expect("read all");
        assert_eq!(buf, b"6789");
    }

    #[test]
    fn offset_reader_zero_base_matches_plain_read() {
        let data = b"hello world";
        let tmp = write_temp(data);
        let file = File::open(tmp.path()).expect("reopen");
        let mut r = OffsetReader::new(file, 0).expect("adapter");

        let mut buf = Vec::new();
        r.read_to_end(&mut buf).expect("read all");
        assert_eq!(buf, data);
    }

    // ── open_hfsplus (signature/bounds validation; fixture-backed listing/
    //    extraction lives in the integration suite) ─────────────────────────

    fn fixture_bytes(name: &str) -> Vec<u8> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name);
        std::fs::read(path).expect("read fixture")
    }

    /// Assert `open_hfsplus` rejects `bytes` at `offset` with `UnknownFormat`
    /// (never a panic) — the shared shape of every signature/bounds rejection.
    fn assert_unknown_format(bytes: &[u8], offset: u64) {
        let tmp = write_temp(bytes);
        let err = open_hfsplus(tmp.path(), offset).err().expect("must error");
        assert!(matches!(err, Error::UnknownFormat), "got {err:?}");
    }

    #[test]
    fn open_hfsplus_rejects_truncated_input() {
        assert_unknown_format(&[0u8; 600], 0); // shorter than the 1024 header offset
    }

    #[test]
    fn open_hfsplus_rejects_bad_signature() {
        let mut bytes = vec![0u8; 1024 + 52];
        bytes[1024..1026].copy_from_slice(&[0x00, 0x00]); // neither H+ nor HX
        assert_unknown_format(&bytes, 0);
    }

    #[test]
    fn open_hfsplus_rejects_legacy_hfs_bd_signature() {
        let mut bytes = vec![0u8; 1024 + 52];
        bytes[1024..1026].copy_from_slice(&[0x42, 0x44]); // 'BD' legacy HFS
        assert_unknown_format(&bytes, 0);
    }

    #[test]
    fn open_hfsplus_offset_beyond_file_is_unknown_format_not_panic() {
        assert_unknown_format(b"short file", 1_000_000);
    }

    // ── open_hfsplus with a non-zero offset (the mechanism #21b/DMG relies on) ─
    //
    // `open_hfsplus` is `pub(crate)`, so this must live here rather than in the
    // integration suite (an external crate that only sees the public API).

    #[test]
    fn open_hfsplus_with_offset_matches_zero_offset() {
        let plain = fixture_bytes("hfs_ci.hfs");

        let mut padded = vec![0u8; 4096];
        padded.extend_from_slice(&plain);

        let plain_tmp = write_temp(&plain);
        let padded_tmp = write_temp(&padded);

        let mut plain_reader = open_hfsplus(plain_tmp.path(), 0).expect("open plain");
        let mut padded_reader = open_hfsplus(padded_tmp.path(), 4096).expect("open padded");

        let plain_entries = plain_reader.entries().expect("entries").to_vec();
        let padded_entries = padded_reader.entries().expect("entries").to_vec();
        assert_eq!(plain_entries.len(), padded_entries.len());

        let hello_idx_plain = plain_entries
            .iter()
            .position(|e| e.path.to_string_lossy() == "hello.txt")
            .expect("hello.txt in plain");
        let hello_idx_padded = padded_entries
            .iter()
            .position(|e| e.path.to_string_lossy() == "hello.txt")
            .expect("hello.txt in padded");

        let mut plain_body = Vec::new();
        plain_reader
            .read_entry(hello_idx_plain, &mut plain_body)
            .expect("read plain hello.txt");
        let mut padded_body = Vec::new();
        padded_reader
            .read_entry(hello_idx_padded, &mut padded_body)
            .expect("read padded hello.txt");
        assert_eq!(plain_body, padded_body);
        assert_eq!(plain_body, b"hello hfs+\n");
    }
}
