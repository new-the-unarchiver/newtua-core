use std::io::{Read, Write};
use std::path::Path;

use crate::archive::{
    ArchiveReader, Confidence, Entry, FormatHandler, FormatId, OpenOptions, Source,
};
use crate::decompress::{Compressor, decompressor};
use crate::error::{Error, Result};
use crate::format::{RarHandler, SevenZHandler, TarHandler, ZipHandler};
use crate::volume::{ConcatReader, volume_members};

/// Returns the full handler registry in priority order.
pub fn registry() -> Vec<Box<dyn FormatHandler>> {
    vec![
        Box::new(ZipHandler),
        Box::new(SevenZHandler),
        Box::new(RarHandler),
        Box::new(TarHandler),
    ]
}

/// Probe magic bytes to detect a compression wrapper.
///
/// Supported signatures:
/// - Gzip:  `1f 8b`
/// - Bzip2: `BZh`
/// - Xz:    `fd 37 7a 58 5a 00`
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
    None
}

/// Wrapper that keeps a reconstructed temp file alive for the lifetime of the
/// inner reader. When this is dropped, the temp file is deleted automatically.
struct VolumeBackedReader {
    inner: Box<dyn ArchiveReader>,
    /// Keeps the temp file alive (deleted on drop).
    _temp: tempfile::TempPath,
}

impl ArchiveReader for VolumeBackedReader {
    fn format(&self) -> FormatId {
        self.inner.format()
    }

    fn entries(&mut self) -> Result<&[Entry]> {
        self.inner.entries()
    }

    fn read_entry(&mut self, idx: usize, out: &mut dyn Write) -> Result<()> {
        self.inner.read_entry(idx, out)
    }
}

/// Internal helper: open a single concrete file path (no volume logic).
///
/// This is the original `open()` body, now callable from both the normal code
/// path and the volume-reconstruction path.
fn open_single(path: &Path, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
    let mut src = Source::path(path)?;
    let header = src.peek_header(512)?;

    // Compression layer: decompress and hand off to TarHandler.
    if let Some(comp) = detect_compressor(&header) {
        let file = std::fs::File::open(path)?;
        let decoded: Box<dyn Read> = decompressor(comp, Box::new(file));
        let stream = Source::Stream {
            inner: decoded,
            path: Some(path.to_path_buf()),
        };
        return TarHandler.open(stream, opts);
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
///    kept alive via [`VolumeBackedReader`] until the reader is dropped.
/// 2. Otherwise (or when `.001` has no siblings), open the file directly.
///    Within direct open:
///
///    - If a compression wrapper is detected (gzip/bzip2/xz), decompress and
///      hand the raw stream to `TarHandler` (v1 assumes tar inside).
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
            return Ok(Box::new(VolumeBackedReader {
                inner,
                _temp: temp_path,
            }));
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
        assert_eq!(detect_compressor(b"PK\x03\x04"), None);
    }

    #[test]
    fn empty_header_returns_none() {
        assert_eq!(detect_compressor(&[]), None);
    }

    #[test]
    fn registry_has_four_handlers() {
        assert_eq!(registry().len(), 4);
    }
}
