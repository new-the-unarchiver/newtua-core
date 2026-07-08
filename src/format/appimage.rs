use crate::archive::{
    ArchiveReader, Confidence, Entry, FormatHandler, FormatId, OpenOptions, Source,
};
use crate::detect::TempBackedReader;
use crate::error::{Error, Result};
use crate::format::{IsoHandler, squashfs};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

/// SquashFS magic (`hsqs`) at the embedded-fs offset → AppImage Type 2.
const SQUASHFS_MAGIC: &[u8; 4] = b"hsqs";
/// ISO 9660 `CD001` lives 0x8001 into the embedded filesystem → AppImage Type 1.
const ISO_SIG_OFFSET: u64 = 0x8001;
const ISO_SIG: &[u8; 5] = b"CD001";

/// Reads AppImage files: an ELF runtime with an appended filesystem.
pub struct AppImageHandler;

impl FormatHandler for AppImageHandler {
    fn id(&self) -> FormatId {
        FormatId::AppImage
    }

    /// Detect by ELF magic + the `AI` type marker at offset 8, OR the
    /// `.appimage` extension (case-insensitive). All bytes inspected are within
    /// the 512-byte header the registry peeks.
    fn probe(&self, header: &[u8], name: Option<&str>) -> Confidence {
        let magic_ok = header.starts_with(b"\x7fELF")
            && matches!(header.get(8..11), Some([b'A', b'I', 1 | 2]));
        let ext_ok = name.is_some_and(|n| n.to_ascii_lowercase().ends_with(".appimage"));
        if magic_ok || ext_ok {
            Confidence::MAGIC
        } else {
            Confidence::NONE
        }
    }

    fn open(&self, src: Source, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        // backhand/iso reopen by path, so a real file path is required. A pure
        // stream has none; in practice `detect::open` always supplies a path.
        let path = src
            .file_path()
            .ok_or_else(|| Error::Unsupported {
                format: "appimage".into(),
                feature: "non-file source (appimage requires a file path)".into(),
            })?
            .to_path_buf();

        let offset = appimage_fs_offset(&path)?;

        // Dispatch on the ACTUAL bytes at the offset — the AI type byte is
        // sometimes zeroed by appimagetool, so the filesystem magic is truth.
        if read_at(&path, offset, SQUASHFS_MAGIC.len())?.starts_with(SQUASHFS_MAGIC) {
            // Type 2: read the embedded SquashFS in place (no copy).
            let inner = squashfs::open_squashfs(&path, offset)?;
            return Ok(Box::new(AppImageReader { inner }));
        }
        if read_at(&path, offset + ISO_SIG_OFFSET, ISO_SIG.len())?.starts_with(ISO_SIG) {
            // Type 1: the filesystem is a known ISO 9660 (CD001 confirmed just
            // above), so carve [offset..EOF] to a temp file and hand it to
            // IsoHandler directly — no need to re-run format detection.
            // TempBackedReader keeps the temp alive and reports AppImage.
            let temp_path = carve_to_temp(&path, offset)?;
            let inner = IsoHandler.open(Source::path(&temp_path)?, opts)?;
            return Ok(Box::new(TempBackedReader::with_format(
                inner,
                temp_path,
                FormatId::AppImage,
            )));
        }
        Err(Error::Corrupt(
            "appimage: no squashfs/iso filesystem at the computed offset".into(),
        ))
    }
}

/// Read up to `n` bytes from `path` starting at `offset`. A short read at EOF is
/// NOT an error — the returned `Vec` is simply shorter than `n` (seeking past
/// EOF yields an empty read). Callers test the result with `starts_with`.
fn read_at(path: &Path, offset: u64, n: usize) -> Result<Vec<u8>> {
    let mut f = std::fs::File::open(path)?;
    f.seek(SeekFrom::Start(offset))?;
    // `read_to_end` retries on `Interrupted` and stops cleanly at EOF, so a short
    // read yields a shorter `Vec` rather than an error — exactly what we want.
    let mut buf = Vec::new();
    f.take(n as u64).read_to_end(&mut buf)?;
    Ok(buf)
}

/// Parse the ELF header at the start of `path` and return the offset of the
/// appended filesystem: `e_shoff + e_shentsize·e_shnum`. The section-header
/// table sits at the very end of an AppImage runtime, so its end is where the
/// payload begins. Only the fixed-layout header fields are read (no valid
/// section table required — AppImage runtimes rely on that). Handles ELF32/64
/// and little/big endian via `e_ident`.
fn appimage_fs_offset(path: &Path) -> Result<u64> {
    let head = read_at(path, 0, 64)?;
    if head.len() < 64 || !head.starts_with(b"\x7fELF") {
        return Err(Error::Corrupt("appimage: not an ELF image".into()));
    }
    let is_64 = head[4] == 2; // EI_CLASS: 1 = 32-bit, 2 = 64-bit
    let le = head[5] != 2; // EI_DATA: 1 (or 0) = little-endian, 2 = big-endian
    // One LE/BE branch per integer width, reused symmetrically for ELF32/64.
    // Every offset below is within the 64-byte header guaranteed above, so the
    // `try_into` on the fixed-width slice never fails.
    let u16_at = |o: usize| -> u16 {
        let b: [u8; 2] = head[o..o + 2].try_into().unwrap();
        if le {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        }
    };
    let u32_at = |o: usize| -> u32 {
        let b: [u8; 4] = head[o..o + 4].try_into().unwrap();
        if le {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        }
    };
    let u64_at = |o: usize| -> u64 {
        let b: [u8; 8] = head[o..o + 8].try_into().unwrap();
        if le {
            u64::from_le_bytes(b)
        } else {
            u64::from_be_bytes(b)
        }
    };
    let (shoff, shentsize, shnum) = if is_64 {
        (u64_at(0x28), u16_at(0x3a), u16_at(0x3c))
    } else {
        (u64::from(u32_at(0x20)), u16_at(0x2e), u16_at(0x30))
    };
    let offset = shoff
        .checked_add(u64::from(shentsize) * u64::from(shnum))
        .ok_or_else(|| Error::Corrupt("appimage: section-table offset overflow".into()))?;
    let len = std::fs::metadata(path)?.len();
    if offset == 0 || offset >= len {
        return Err(Error::Corrupt(format!(
            "appimage: computed fs offset {offset} out of range (file is {len} bytes)"
        )));
    }
    Ok(offset)
}

/// Carve `[offset..EOF]` from `path` into a temp file (streamed via
/// `io::copy`, no full-file buffering). The returned `TempPath` deletes the
/// file on drop.
fn carve_to_temp(path: &Path, offset: u64) -> Result<tempfile::TempPath> {
    let mut src = std::fs::File::open(path)?;
    src.seek(SeekFrom::Start(offset))?;
    let mut tmp = tempfile::NamedTempFile::new()?;
    std::io::copy(&mut src, tmp.as_file_mut())?;
    Ok(tmp.into_temp_path())
}

/// Wraps the embedded filesystem's reader so `format()` reports `AppImage`.
/// Used for Type 2 (SquashFS read in place — no temp file); Type 1 uses
/// [`TempBackedReader`], which already keeps its carved temp alive.
struct AppImageReader {
    inner: Box<dyn ArchiveReader>,
}

impl ArchiveReader for AppImageReader {
    fn format(&self) -> FormatId {
        FormatId::AppImage
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a 128-byte AppImage ELF64 prefix (little-endian): a 64-byte header
    /// with e_shoff=64, e_shentsize=64, e_shnum=1, followed by one 64-byte
    /// SHT_NULL section-header entry → fs offset = 64 + 64·1 = 128.
    fn elf64_prefix(ai_type: u8) -> Vec<u8> {
        let mut h = vec![0u8; 128];
        h[0..4].copy_from_slice(b"\x7fELF");
        h[4] = 2; // EI_CLASS = ELFCLASS64
        h[5] = 1; // EI_DATA  = ELFDATA2LSB
        h[6] = 1; // EI_VERSION
        h[8] = b'A';
        h[9] = b'I';
        h[10] = ai_type;
        h[16..18].copy_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
        h[18..20].copy_from_slice(&0x3eu16.to_le_bytes()); // e_machine = EM_X86_64
        h[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
        h[40..48].copy_from_slice(&64u64.to_le_bytes()); // e_shoff = 64
        h[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize = 64
        h[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize = 64
        h[60..62].copy_from_slice(&1u16.to_le_bytes()); // e_shnum = 1
        h
    }

    fn temp_with(bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("temp");
        f.write_all(bytes).expect("write");
        f.flush().expect("flush");
        f
    }

    #[test]
    fn fs_offset_is_128_for_standard_prefix() {
        // 128-byte prefix + a byte of payload so offset (128) < file len (129).
        let mut bytes = elf64_prefix(2);
        bytes.push(0xAA);
        let f = temp_with(&bytes);
        assert_eq!(appimage_fs_offset(f.path()).unwrap(), 128);
    }

    #[test]
    fn fs_offset_rejects_non_elf() {
        let f = temp_with(b"not an elf file at all, padding padding padding padding padding!!");
        let err = appimage_fs_offset(f.path()).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }

    #[test]
    fn fs_offset_rejects_offset_beyond_eof() {
        // e_shnum = 0xFFFF → offset = 64 + 64·65535, far past a tiny file.
        let mut bytes = elf64_prefix(2);
        bytes[60..62].copy_from_slice(&0xFFFFu16.to_le_bytes());
        let f = temp_with(&bytes);
        let err = appimage_fs_offset(f.path()).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }

    #[test]
    fn read_at_short_read_returns_partial() {
        let f = temp_with(b"abcdef");
        // Ask for 100 bytes starting at 4 → only "ef" (2 bytes) available.
        assert_eq!(read_at(f.path(), 4, 100).unwrap(), b"ef");
        // Seeking past EOF yields an empty read, not an error.
        assert!(read_at(f.path(), 999, 4).unwrap().is_empty());
    }

    #[test]
    fn id_is_appimage() {
        assert_eq!(AppImageHandler.id(), FormatId::AppImage);
    }

    #[test]
    fn probe_type2_magic_is_magic() {
        assert_eq!(
            AppImageHandler.probe(b"\x7fELF\x02\x01\x01\x00AI\x02", None),
            Confidence::MAGIC
        );
    }

    #[test]
    fn probe_type1_magic_is_magic() {
        assert_eq!(
            AppImageHandler.probe(b"\x7fELF\x02\x01\x01\x00AI\x01", None),
            Confidence::MAGIC
        );
    }

    #[test]
    fn probe_appimage_extension_is_magic() {
        // No AI magic, but the `.appimage` extension (any case) is enough.
        assert_eq!(
            AppImageHandler.probe(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00", Some("Foo.AppImage")),
            Confidence::MAGIC
        );
    }

    #[test]
    fn probe_plain_elf_without_ai_is_none() {
        assert_eq!(
            AppImageHandler.probe(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00", Some("a.out")),
            Confidence::NONE
        );
    }

    #[test]
    fn probe_foreign_magic_is_none() {
        assert_eq!(
            AppImageHandler.probe(b"PK\x03\x04", Some("a.zip")),
            Confidence::NONE
        );
    }

    #[test]
    fn probe_no_name_no_magic_is_none() {
        assert_eq!(
            AppImageHandler.probe(b"\x00\x00\x00\x00", None),
            Confidence::NONE
        );
    }

    #[test]
    fn open_path_less_source_is_unsupported() {
        let src = Source::Stream {
            inner: Box::new(std::io::empty()),
            path: None,
        };
        let err = AppImageHandler
            .open(src, &OpenOptions::default())
            .err()
            .expect("path-less source must be unsupported");
        assert!(matches!(err, Error::Unsupported { .. }), "got {err:?}");
    }
}
