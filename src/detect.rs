use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::archive::{
    ArchiveReader, Confidence, Entry, EntryKind, FormatHandler, FormatId, OpenOptions, Source,
};
use crate::decompress::{Compressor, decompressor};
use crate::error::{Error, Result};
use crate::format::{
    ArHandler, CabHandler, CpioHandler, DebHandler, IsoHandler, MsiHandler, RarHandler, RpmHandler,
    SevenZHandler, SfxHandler, TarHandler, WarcHandler, XarHandler, ZipHandler,
};
use crate::volume::{ConcatReader, volume_members};

/// Returns the full handler registry in priority order.
pub fn registry() -> Vec<Box<dyn FormatHandler>> {
    vec![
        Box::new(ZipHandler),
        Box::new(CpioHandler),
        Box::new(SevenZHandler),
        Box::new(RarHandler),
        Box::new(TarHandler),
        Box::new(CabHandler),
        // DebHandler MUST precede ArHandler: a .deb shares the `!<arch>\n` magic
        // with a plain ar archive, so both probe MAGIC. The selector keeps the
        // first MAGIC on a tie, so order is the tie-break (a plain ar still falls
        // through to ArHandler, since DebHandler probes NONE without debian-binary).
        Box::new(DebHandler),
        Box::new(ArHandler),
        // RpmHandler: unique lead magic (ED AB EE DB), no tie-break with peers.
        Box::new(RpmHandler),
        // XarHandler: unique magic "xar!" (78 61 72 21), used for .xar and .pkg.
        Box::new(XarHandler),
        // MsiHandler: CFB magic + .msi extension (model B — reuses CabHandler
        // for the embedded CAB streams in the Media table).
        Box::new(MsiHandler),
        // IsoHandler: detected by .iso extension; CD001 signature verified in open.
        Box::new(IsoHandler),
        // SfxHandler: MZ → Confidence(50), below MAGIC(100), so real archives always
        // win. Carves the appended archive past the PE overlay and reopens it.
        Box::new(SfxHandler),
        // WarcHandler: WARC/1.x magic; .warc.gz is handled by the early
        // extension branch in open_single and never reaches this registry probe.
        Box::new(WarcHandler),
    ]
}

/// Probe magic bytes to detect a compression wrapper.
///
/// Supported signatures:
/// - Gzip:  `1f 8b`
/// - Bzip2: `BZh`
/// - Xz:    `fd 37 7a 58 5a 00`
/// - Zstd:  `28 b5 2f fd`
pub fn detect_compressor(header: &[u8]) -> Option<Compressor> {
    if header.starts_with(&[0x1f, 0x8b]) {
        return Some(Compressor::Gzip);
    }
    if header.starts_with(b"BZh") {
        return Some(Compressor::Bzip2);
    }
    if header.starts_with(&[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]) {
        return Some(Compressor::Xz);
    }
    if header.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
        return Some(Compressor::Zstd);
    }
    None
}

// ── TempBackedReader ──────────────────────────────────────────────────────────

/// Generic wrapper that delegates all [`ArchiveReader`] calls to an inner reader
/// while keeping a temp file alive (and auto-deleted on drop).
///
/// Used for multi-volume reconstruction, the decompressed temp file backing a
/// tar-inside-compressed-file, SFX carving, and the format-specific readers
/// (deb/rpm) that decompress a payload to a temp file. By default `format()`
/// delegates to the inner reader; pass a `format_override` to report a wrapper
/// format (e.g. `Deb`/`Rpm`) instead of the inner payload format.
pub(crate) struct TempBackedReader {
    inner: Box<dyn ArchiveReader>,
    /// Keeps the temp file alive (deleted on drop).
    _temp: tempfile::TempPath,
    /// When set, `format()` reports this instead of the inner reader's format.
    format_override: Option<FormatId>,
}

impl TempBackedReader {
    /// Wrap `inner`, keeping `temp` alive; `format()` delegates to `inner`.
    pub(crate) fn new(inner: Box<dyn ArchiveReader>, temp: tempfile::TempPath) -> Self {
        Self {
            inner,
            _temp: temp,
            format_override: None,
        }
    }

    /// Like [`new`](Self::new) but `format()` reports `format` (e.g. the
    /// container format whose payload was decompressed to `temp`).
    pub(crate) fn with_format(
        inner: Box<dyn ArchiveReader>,
        temp: tempfile::TempPath,
        format: FormatId,
    ) -> Self {
        Self {
            inner,
            _temp: temp,
            format_override: Some(format),
        }
    }
}

impl ArchiveReader for TempBackedReader {
    fn format(&self) -> FormatId {
        self.format_override.unwrap_or_else(|| self.inner.format())
    }

    fn entries(&mut self) -> Result<&[Entry]> {
        self.inner.entries()
    }

    fn read_entry(&mut self, idx: usize, out: &mut dyn Write) -> Result<()> {
        self.inner.read_entry(idx, out)
    }

    fn verify_password(&mut self) -> Result<()> {
        self.inner.verify_password()
    }
}

// ── SingleFileReader ──────────────────────────────────────────────────────────

/// Reader that presents a single decompressed file as a one-entry archive.
///
/// The decompressed content lives in a `NamedTempFile` on disk; streaming is
/// done via a regular file seek/read so that large files never reside in RAM.
struct SingleFileReader {
    entries: Vec<Entry>,
    /// Path to the temp file on disk; owns the file so it is deleted on drop.
    temp_path: tempfile::TempPath,
}

impl SingleFileReader {
    /// Create a reader from an already-decompressed temp file.
    ///
    /// * `original_path` — path of the compressed source file (e.g. `notes.txt.gz`).
    ///   The compressor extension (`.gz`, `.bz2`, `.xz`) is stripped to derive the
    ///   entry name.
    /// * `tmp` — the `NamedTempFile` holding the decompressed payload.
    /// * `size` — decompressed byte count.
    /// * `modified` — optional modification timestamp (only gzip headers carry one).
    fn new(
        original_path: &Path,
        tmp: tempfile::NamedTempFile,
        size: u64,
        modified: Option<SystemTime>,
    ) -> Self {
        let entry_name = stem_without_compressor_ext(original_path);
        let path_raw = entry_name.as_bytes().to_vec();
        let entry = Entry {
            path_raw,
            path: PathBuf::from(&entry_name),
            kind: EntryKind::File,
            size,
            mode: None,
            is_encrypted: false,
            modified,
        };
        SingleFileReader {
            entries: vec![entry],
            temp_path: tmp.into_temp_path(),
        }
    }
}

/// Read the gzip mtime from the original `.gz` file.
///
/// The gzip header stores the original modification time as a little-endian
/// `u32` at byte offset 4 (seconds since Unix epoch; 0 = "no timestamp").
/// Returns `Some(timestamp)` if the mtime is non-zero, `None` otherwise.
fn read_gz_mtime(path: &Path) -> Option<SystemTime> {
    let mut buf = [0u8; 8];
    let mut f = std::fs::File::open(path).ok()?;
    // We only need bytes 0..8; a short read means the file is too small.
    let n = f.read(&mut buf).ok()?;
    if n < 8 {
        return None;
    }
    let mtime = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if mtime == 0 {
        None
    } else {
        Some(UNIX_EPOCH + Duration::from_secs(mtime as u64))
    }
}

impl ArchiveReader for SingleFileReader {
    fn format(&self) -> FormatId {
        FormatId::Raw
    }

    fn entries(&mut self) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn read_entry(&mut self, idx: usize, out: &mut dyn Write) -> Result<()> {
        if idx != 0 {
            return Err(Error::InvalidIndex(idx));
        }
        let mut file = std::fs::File::open(&self.temp_path)?;
        std::io::copy(&mut file, out)?;
        Ok(())
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Strip the outermost compressor extension from a path's file name.
///
/// Examples:
/// - `notes.txt.gz`  → `"notes.txt"`
/// - `data.gz`       → `"data"`
/// - `archive.tar.bz2` → `"archive.tar"`
/// - `file.xz`       → `"file"`
fn stem_without_compressor_ext(path: &Path) -> String {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("data");

    for ext in &[".gz", ".bz2", ".xz", ".zst"] {
        if let Some(stem) = name.strip_suffix(ext) {
            return stem.to_string();
        }
    }
    // No recognised compressor extension — use the full name.
    name.to_string()
}

/// Check whether the first 263 bytes of a reader contain the tar `ustar` magic
/// at offset 257. Rewinds the reader to position 0 after the check.
pub(crate) fn is_tar<R: Read + Seek>(reader: &mut R) -> std::io::Result<bool> {
    let mut buf = [0u8; 263];
    let mut filled = 0usize;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    reader.seek(SeekFrom::Start(0))?;
    Ok(filled >= 263 && &buf[257..262] == b"ustar")
}

// ── open_single ───────────────────────────────────────────────────────────────

/// Internal helper: open a single concrete file path (no volume logic).
///
/// This is the original `open()` body, now callable from both the normal code
/// path and the volume-reconstruction path.
pub(crate) fn open_single(path: &Path, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
    let mut src = Source::path(path)?;
    let header = src.peek_header(512)?;

    // Early WARC extension branch — MUST come before detect_compressor.
    //
    // A `.warc.gz` file uses per-record gzip (each WARC record is a separate
    // gzip member, concatenated). Its file magic is the gzip signature `1f 8b`,
    // so the generic compressor layer would decompress it as a single byte
    // stream and lose the record boundaries.  By routing `.warc` and `.warc.gz`
    // straight to WarcHandler here, we bypass that layer entirely and let the
    // handler apply MultiGzDecoder itself (which handles concatenated members).
    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let lower_name = file_name.to_ascii_lowercase();
    if lower_name.ends_with(".warc") || lower_name.ends_with(".warc.gz") {
        // `src` is already rewound to 0 by peek_header — reuse it directly.
        return WarcHandler.open(src, opts);
    }

    // Compression layer.
    if let Some(comp) = detect_compressor(&header) {
        // Step 1: decompress to a temp file via streaming io::copy (no RAM spike).
        let file = std::fs::File::open(path)?;
        let mut decoded: Box<dyn Read> = decompressor(comp, Box::new(file))?;
        let mut tmp = tempfile::NamedTempFile::new()?;
        let size = std::io::copy(&mut decoded, &mut tmp)?;

        // Step 2: peek the decompressed content for the tar ustar magic.
        // The io::copy above left the file cursor at the end; rewind first.
        tmp.as_file_mut().seek(SeekFrom::Start(0))?;
        let tar_detected = is_tar(tmp.as_file_mut())?;

        if tar_detected {
            // Open the temp file as a seekable tar archive.
            let temp_path = tmp.into_temp_path();
            let tar_src = Source::path(&temp_path)?;
            let inner = TarHandler.open(tar_src, opts)?;
            return Ok(Box::new(TempBackedReader::new(inner, temp_path)));
        } else {
            // Plain compressed file — present as one entry.
            // For gzip only: read the original-file mtime from the header (bytes 4..8).
            // bzip2, xz, and zstd carry no mtime in their standard headers.
            let modified = if comp == Compressor::Gzip {
                read_gz_mtime(path)
            } else {
                None
            };
            return Ok(Box::new(SingleFileReader::new(path, tmp, size, modified)));
        }
    }

    // Container formats: pick handler with highest probe confidence.
    let name = path.file_name().and_then(|s| s.to_str());
    let handlers = registry();
    let mut best: Option<(Confidence, usize)> = None;
    for (i, h) in handlers.iter().enumerate() {
        let c = h.probe(&header, name);
        if c > Confidence::NONE && best.is_none_or(|(bc, _)| c > bc) {
            best = Some((c, i));
        }
    }
    let (_, idx) = best.ok_or(Error::UnknownFormat)?;
    // Re-open to get a fresh seekable source at position 0.
    let fresh_src = Source::path(path)?;
    handlers.into_iter().nth(idx).unwrap().open(fresh_src, opts)
}

/// Public entry point: open an archive at `path`.
///
/// Logic:
/// 1. If `path` ends with `.001`, check for sibling volumes (`.002`, etc.).
///    If more than one member exists, concatenate all members into a temp file
///    and open the reconstructed archive from the temp path. The temp file is
///    kept alive via [`TempBackedReader`] until the reader is dropped.
/// 2. Otherwise (or when `.001` has no siblings), open the file directly.
///    Within direct open:
///
///    - If a compression wrapper is detected (gzip/bzip2/xz), decompress to a
///      temp file, then peek for tar magic at offset 257:
///      - If tar → open as tar (file-backed via temp), wrapped so the temp file
///        outlives the reader.
///      - If not tar → return a [`SingleFileReader`] with one entry whose name
///        is the original file name with the compressor extension stripped.
///    - Otherwise, select the handler with the highest `Confidence` from the
///      registry and delegate to it.
pub fn open(path: &Path, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
    // Check for generic raw byte-split volumes (.001/.002/... scheme).
    // The comparison is case-insensitive so that e.g. `ARCHIVE.ZIP.001` is
    // also handled correctly on case-sensitive file systems.
    let is_first_volume = path
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.to_ascii_lowercase().ends_with(".001"));

    if is_first_volume {
        let members = volume_members(path)?;
        if members.len() > 1 {
            // Reconstruct the original archive by concatenating all volumes.
            let mut tmp = tempfile::NamedTempFile::new()?;
            {
                let mut cat = ConcatReader::open(&members)?;
                std::io::copy(&mut cat, &mut tmp)?;
            }
            // Convert to TempPath so the file is deleted when it goes out of scope,
            // but first persist into a path we can open.
            let temp_path = tmp.into_temp_path();
            let inner = open_single(&temp_path, opts)?;
            return Ok(Box::new(TempBackedReader::new(inner, temp_path)));
        }
        // Exactly 1 member (the .001 file itself, no siblings) — open normally.
    }

    open_single(path, opts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_each_compressor() {
        assert_eq!(
            detect_compressor(&[0x1f, 0x8b, 0x08]),
            Some(Compressor::Gzip)
        );
        assert_eq!(detect_compressor(b"BZh9"), Some(Compressor::Bzip2));
        assert_eq!(
            detect_compressor(&[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]),
            Some(Compressor::Xz)
        );
        assert_eq!(
            detect_compressor(&[0x28, 0xB5, 0x2F, 0xFD]),
            Some(Compressor::Zstd)
        );
        assert_eq!(detect_compressor(b"PK\x03\x04"), None);
    }

    #[test]
    fn empty_header_returns_none() {
        assert_eq!(detect_compressor(&[]), None);
    }

    #[test]
    fn registry_has_fourteen_handlers() {
        assert_eq!(registry().len(), 14);
    }

    #[test]
    fn stem_strips_gz() {
        assert_eq!(
            stem_without_compressor_ext(Path::new("/tmp/notes.txt.gz")),
            "notes.txt"
        );
    }

    #[test]
    fn stem_strips_bz2() {
        assert_eq!(stem_without_compressor_ext(Path::new("data.bz2")), "data");
    }

    #[test]
    fn stem_strips_xz() {
        assert_eq!(
            stem_without_compressor_ext(Path::new("/path/to/archive.tar.xz")),
            "archive.tar"
        );
    }

    #[test]
    fn stem_strips_zst() {
        assert_eq!(
            stem_without_compressor_ext(Path::new("/tmp/data.tar.zst")),
            "data.tar"
        );
        assert_eq!(
            stem_without_compressor_ext(Path::new("notes.txt.zst")),
            "notes.txt"
        );
    }

    #[test]
    fn stem_no_compressor_ext_unchanged() {
        assert_eq!(
            stem_without_compressor_ext(Path::new("file.zip")),
            "file.zip"
        );
    }
}
