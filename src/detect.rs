use std::io::Read;
use std::path::Path;

use crate::archive::{ArchiveReader, Confidence, FormatHandler, OpenOptions, Source};
use crate::decompress::{decompressor, Compressor};
use crate::error::{Error, Result};
use crate::format::{RarHandler, SevenZHandler, TarHandler, ZipHandler};

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

/// Public entry point: open an archive at `path`.
///
/// Logic:
/// 1. Peek the first 512 bytes via a seekable source.
/// 2. If a compression wrapper is detected (gzip/bzip2/xz), decompress and
///    hand the raw stream to `TarHandler` (v1 assumes tar inside).
/// 3. Otherwise, select the handler with the highest `Confidence` from the
///    registry and delegate to it.
pub fn open(path: &Path, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
    let mut src = Source::path(path)?;
    let header = src.peek_header(512)?;

    // Compression layer: decompress and hand off to TarHandler.
    if let Some(comp) = detect_compressor(&header) {
        let file = std::fs::File::open(path)?;
        let decoded: Box<dyn Read> = decompressor(comp, Box::new(file));
        let stream = Source::Stream { inner: decoded, path: Some(path.to_path_buf()) };
        return TarHandler.open(stream, opts);
    }

    // Container formats: pick handler with highest probe confidence.
    let name = path.file_name().and_then(|s| s.to_str());
    let handlers = registry();
    let mut best: Option<(Confidence, usize)> = None;
    for (i, h) in handlers.iter().enumerate() {
        let c = h.probe(&header, name);
        if c > Confidence::NONE && best.map_or(true, |(bc, _)| c > bc) {
            best = Some((c, i));
        }
    }
    let (_, idx) = best.ok_or(Error::UnknownFormat)?;
    // Re-open to get a fresh seekable source at position 0.
    let fresh_src = Source::path(path)?;
    handlers.into_iter().nth(idx).unwrap().open(fresh_src, opts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_each_compressor() {
        assert_eq!(detect_compressor(&[0x1f, 0x8b, 0x08]), Some(Compressor::Gzip));
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
