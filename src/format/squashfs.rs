use std::io::Write;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use backhand::compression::{CompressionAction, Compressor, DefaultCompressor};
use backhand::kind::Kind;
use backhand::{
    BackhandError, FilesystemCompressor, FilesystemReader, InnerNode, SquashfsFileReader,
    SuperBlock,
};

use crate::archive::{
    ArchiveReader, Confidence, Entry, EntryKind, FormatHandler, FormatId, OpenOptions, Source,
};
use crate::error::{Error, Result};

/// SquashFS magic `hsqs` (little-endian v4) at offset 0.
const SQUASHFS_MAGIC: &[u8; 4] = b"hsqs";

/// Reads SquashFS images (`.squashfs` / `.sfs`) via the `backhand` crate.
pub struct SquashfsHandler;

impl FormatHandler for SquashfsHandler {
    fn id(&self) -> FormatId {
        FormatId::Squashfs
    }

    /// Detect by the `hsqs` magic at offset 0 OR the `.squashfs`/`.sfs`
    /// extension (case-insensitive). The magic lives at offset 0, well within
    /// the 512-byte header the registry peeks.
    fn probe(&self, header: &[u8], name: Option<&str>) -> Confidence {
        let magic_ok = header.starts_with(SQUASHFS_MAGIC);
        let ext_ok = name.is_some_and(|n| {
            let lower = n.to_ascii_lowercase();
            lower.ends_with(".squashfs") || lower.ends_with(".sfs")
        });
        if magic_ok || ext_ok {
            Confidence::MAGIC
        } else {
            Confidence::NONE
        }
    }

    fn open(&self, src: Source, _opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        // backhand's BufReadSeek requires Send; our Box<dyn ReadSeek> isn't Send,
        // so reopen the file by its real path (like 7z/rar). A source without a
        // path (a pure stream) is unsupported. In practice `detect::open` always
        // supplies a path.
        let path = src
            .file_path()
            .ok_or_else(|| Error::Unsupported {
                format: "squashfs".into(),
                feature: "non-file source (squashfs requires a file path)".into(),
            })?
            .to_path_buf();
        open_squashfs(&path, 0)
    }
}

/// Map a backhand error onto our model. Any parse/read failure (truncated image,
/// unknown version, big-endian v3, unsupported inner compressor) is structural →
/// `Corrupt`.
fn map_backhand_err(e: BackhandError) -> Error {
    Error::Corrupt(format!("squashfs: {e}"))
}

/// A [`CompressionAction`] that delegates every codec to backhand's
/// [`DefaultCompressor`] **except XZ**, which it decodes with `xz2`.
///
/// backhand's own `xz` feature pulls `liblzma` (→ `liblzma-sys`), which
/// collides with the workspace's existing `xz2` (→ `lzma-sys`): both declare
/// `links = "lzma"`, and Cargo forbids two packages linking the same native
/// library. So we keep backhand's `xz` feature off and route XZ through the
/// `xz2` we already link. squashfs stores each XZ block as a full `.xz` stream
/// (any BCJ filters are encoded in the stream itself), so the stream decoder
/// handles it directly — matching backhand's built-in xz path.
struct XzViaXz2;

impl CompressionAction for XzViaXz2 {
    type Error = BackhandError;
    type Compressor = Compressor;
    type FilesystemCompressor = FilesystemCompressor;
    type SuperBlock = SuperBlock;

    fn decompress(
        &self,
        bytes: &[u8],
        out: &mut Vec<u8>,
        compressor: Compressor,
    ) -> std::result::Result<(), BackhandError> {
        match compressor {
            // squashfs xz blocks are full `.xz` streams — decode with xz2.
            Compressor::Xz => {
                let mut decoder = xz2::read::XzDecoder::new(bytes);
                std::io::Read::read_to_end(&mut decoder, out)?;
                Ok(())
            }
            // gzip/zstd/lz4/lzo/uncompressed are handled by backhand as usual.
            other => DefaultCompressor.decompress(bytes, out, other),
        }
    }

    fn compress(
        &self,
        bytes: &[u8],
        fc: FilesystemCompressor,
        block_size: u32,
    ) -> std::result::Result<Vec<u8>, BackhandError> {
        // Never invoked on the read-only path; delegate for completeness.
        DefaultCompressor.compress(bytes, fc, block_size)
    }
}

/// `'static` instance backing the [`Kind`] (which stores `&'static` refs).
static XZ_VIA_XZ2: XzViaXz2 = XzViaXz2;

/// Convert a u32 Unix-seconds mtime to `SystemTime`; `0` means "no timestamp".
fn mtime_to_systime(mtime: u32) -> Option<SystemTime> {
    if mtime == 0 {
        None
    } else {
        Some(UNIX_EPOCH + Duration::from_secs(u64::from(mtime)))
    }
}

/// Open the SquashFS image whose superblock begins at `offset` bytes into
/// `path`, and build the flat entry list. `offset` is `0` for a bare `.squashfs`
/// file and non-zero for an embedded image (e.g. an AppImage Type 2 payload).
pub(crate) fn open_squashfs(path: &Path, offset: u64) -> Result<Box<dyn ArchiveReader>> {
    let file = std::fs::File::open(path)?;
    let buf = std::io::BufReader::new(file);
    // LE v4 with our custom decompressor (xz via xz2, everything else default).
    let kind = Kind::new_v4(&XZ_VIA_XZ2);
    let fs = FilesystemReader::from_reader_with_offset_and_kind(buf, offset, kind)
        .map_err(map_backhand_err)?;

    let mut entries: Vec<Entry> = Vec::new();
    let mut bodies: Vec<Option<SquashfsFileReader>> = Vec::new();

    for node in fs.files() {
        // squashfs paths are absolute from the root (`/a/b`); make them relative.
        let rel = node.fullpath.strip_prefix("/").unwrap_or(&node.fullpath);
        if rel.as_os_str().is_empty() {
            continue; // the root node itself
        }

        let (kind, body, size) = match &node.inner {
            InnerNode::File(f) => (EntryKind::File, Some(f.clone()), f.file_len() as u64),
            InnerNode::Dir(_) => (EntryKind::Dir, None, 0),
            InnerNode::Symlink(s) => (
                EntryKind::Symlink {
                    target: s.link.clone(),
                },
                None,
                0,
            ),
            // Special nodes (char/block device, fifo, socket) have no extractable
            // body — skip them.
            _ => continue,
        };

        // path_raw: bytes of the relative path. backhand already decoded names to
        // PathBuf; squashfs names are UTF-8 in practice (same assumption as the
        // conda/iso handlers).
        let path_raw = rel.to_string_lossy().into_owned().into_bytes();
        entries.push(Entry {
            path_raw,
            path: rel.to_path_buf(),
            kind,
            size,
            mode: Some(u32::from(node.header.permissions)),
            is_encrypted: false,
            modified: mtime_to_systime(node.header.mtime),
        });
        bodies.push(body);
    }

    Ok(Box::new(SquashfsReader {
        fs,
        entries,
        bodies,
    }))
}

/// Holds the `FilesystemReader` (owns the reopened file) plus the flat entry
/// list and a parallel `bodies` vector for on-demand extraction.
struct SquashfsReader {
    fs: FilesystemReader<'static>,
    entries: Vec<Entry>,
    /// Parallel to `entries`: `Some(file)` for files, `None` for dirs/symlinks.
    bodies: Vec<Option<SquashfsFileReader>>,
}

impl ArchiveReader for SquashfsReader {
    fn format(&self) -> FormatId {
        FormatId::Squashfs
    }

    fn entries(&mut self) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn read_entry(&mut self, idx: usize, out: &mut dyn Write) -> Result<()> {
        if idx >= self.entries.len() {
            return Err(Error::InvalidIndex(idx));
        }
        let Some(ref file) = self.bodies[idx] else {
            return Ok(()); // directory or symlink — no body
        };
        let mut reader = self.fs.file(file).reader();
        std::io::copy(&mut reader, out)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_is_squashfs() {
        assert_eq!(SquashfsHandler.id(), FormatId::Squashfs);
    }

    #[test]
    fn probe_magic_is_magic() {
        assert_eq!(
            SquashfsHandler.probe(b"hsqs\x00\x00", Some("img.bin")),
            Confidence::MAGIC
        );
    }

    #[test]
    fn probe_squashfs_extension_is_magic() {
        assert_eq!(
            SquashfsHandler.probe(b"\x00\x00\x00\x00", Some("disk.squashfs")),
            Confidence::MAGIC
        );
    }

    #[test]
    fn probe_sfs_extension_is_magic() {
        assert_eq!(
            SquashfsHandler.probe(b"\x00\x00\x00\x00", Some("disk.SFS")),
            Confidence::MAGIC
        );
    }

    #[test]
    fn probe_plain_zip_no_magic_is_none() {
        assert_eq!(
            SquashfsHandler.probe(b"PK\x03\x04", Some("a.zip")),
            Confidence::NONE
        );
    }

    #[test]
    fn probe_no_name_no_magic_is_none() {
        assert_eq!(
            SquashfsHandler.probe(b"\x00\x00\x00\x00", None),
            Confidence::NONE
        );
    }

    #[test]
    fn xz_via_xz2_delegates_non_xz() {
        // A non-xz codec must fall through to backhand's DefaultCompressor.
        // `Uncompressed` is the simplest: it copies the bytes verbatim.
        let mut out = Vec::new();
        XzViaXz2
            .decompress(b"raw bytes", &mut out, Compressor::Uncompressed)
            .expect("uncompressed delegate");
        assert_eq!(out, b"raw bytes");
    }

    #[test]
    fn xz_via_xz2_roundtrips_xz_stream() {
        use std::io::Write;
        // squashfs stores xz blocks as full `.xz` streams; produce one with xz2
        // and confirm our CompressionAction decodes it back byte-for-byte.
        let payload = b"squashfs xz block payload";
        let mut enc = xz2::write::XzEncoder::new(Vec::new(), 6);
        enc.write_all(payload).expect("xz encode");
        let compressed = enc.finish().expect("xz finish");

        let mut out = Vec::new();
        XzViaXz2
            .decompress(&compressed, &mut out, Compressor::Xz)
            .expect("xz decode");
        assert_eq!(out, payload);
    }

    #[test]
    fn open_path_less_source_is_unsupported() {
        // A pure stream has no file path → Unsupported (backhand needs a Send
        // file-backed reader; the public `open()` never hits this branch).
        let src = Source::Stream {
            inner: Box::new(std::io::empty()),
            path: None,
        };
        let err = SquashfsHandler
            .open(src, &OpenOptions::default())
            .err()
            .expect("path-less source must be unsupported");
        assert!(matches!(err, Error::Unsupported { .. }), "got {err:?}");
    }
}
