use std::io::Write;

use crate::archive::{ArchiveReader, Confidence, FormatHandler, FormatId, OpenOptions, Source};
use crate::detect::{TempBackedReader, open_single};
use crate::error::{Error, Result};

/// Magic byte sequences to search for appended archives in an SFX `.exe`
/// (zip, 7z, rar, cab).
const MAGICS: &[&[u8]] = &[
    b"PK\x03\x04",
    &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],
    b"Rar!\x1A\x07",
    b"MSCF",
];

/// Mach-O magics as they appear at byte 0 of a macOS self-extractor.
///
/// A self-extractor built by 7-Zip on macOS (`7zz a -sfx`, stub shipped by
/// Homebrew as `default.sfx`) is an ordinary Mach-O executable with the archive
/// appended, exactly like the Windows PE case — only the wrapper differs. All
/// four single-architecture spellings are listed because the magic doubles as
/// the byte-order marker: `feedface`/`feedfacf` stored the other way round is
/// what a reader on the opposite endianness sees.
///
/// `cafebabe` is the universal ("fat") container, which is always big-endian on
/// disk. It is also the Java class-file magic — a collision we can afford:
/// a `.class` is not an archive, so it ends at `Error::UnknownFormat` either
/// way, only now via this handler instead of the registry.
///
/// The 64-bit fat variant `cafebabf` is deliberately absent: goblin 0.10 does
/// not parse it, so claiming it would only mean falling back to scanning the
/// whole executable for archive magic — worse than not claiming it at all.
const MACHO_MAGICS: &[[u8; 4]] = &[
    [0xCF, 0xFA, 0xED, 0xFE], // 64-bit, little-endian (the ordinary macOS one)
    [0xCE, 0xFA, 0xED, 0xFE], // 32-bit, little-endian
    [0xFE, 0xED, 0xFA, 0xCF], // 64-bit, big-endian
    [0xFE, 0xED, 0xFA, 0xCE], // 32-bit, big-endian
    [0xCA, 0xFE, 0xBA, 0xBE], // universal (fat), 32-bit offsets
];

fn is_macho(header: &[u8]) -> bool {
    MACHO_MAGICS.iter().any(|m| header.starts_with(m))
}

/// Compute the PE overlay offset — the byte position immediately after the last
/// raw section in the PE image. Returns `0` on any parse error so the caller
/// falls back to scanning the whole file.
fn pe_overlay_offset(bytes: &[u8]) -> usize {
    match goblin::pe::PE::parse(bytes) {
        Ok(pe) => pe
            .sections
            .iter()
            .map(|s| (s.pointer_to_raw_data as usize).saturating_add(s.size_of_raw_data as usize))
            .max()
            .unwrap_or(0),
        Err(_) => 0,
    }
}

/// The Mach-O counterpart: the byte position immediately after the last byte any
/// load command claims in the file. Same contract as `pe_overlay_offset` —
/// `0` on any parse error, so the caller scans the whole file.
///
/// Segments are what bounds the image: a signed binary keeps its signature
/// inside `__LINKEDIT`, so taking the furthest `fileoff + filesize` covers it
/// without having to walk `LC_CODE_SIGNATURE` separately. For a universal file
/// the bound is the furthest end of any architecture slice instead — the slices
/// are laid out one after another and the appended archive follows all of them.
fn macho_overlay_offset(bytes: &[u8]) -> usize {
    fn image_end(macho: &goblin::mach::MachO) -> usize {
        macho
            .segments
            .iter()
            .map(|s| usize::try_from(s.fileoff.saturating_add(s.filesize)).unwrap_or(usize::MAX))
            .max()
            .unwrap_or(0)
    }

    match goblin::mach::Mach::parse(bytes) {
        Ok(goblin::mach::Mach::Binary(macho)) => image_end(&macho),
        Ok(goblin::mach::Mach::Fat(multi)) => match multi.arches() {
            Ok(arches) => arches
                .iter()
                .map(|a| (a.offset as usize).saturating_add(a.size as usize))
                .max()
                .unwrap_or(0),
            Err(_) => 0,
        },
        Err(_) => 0,
    }
}

/// Find the earliest occurrence of any recognized archive magic in `data`,
/// returning its offset relative to the start of `data`.
fn find_archive_magic(data: &[u8]) -> Option<usize> {
    MAGICS
        .iter()
        .filter_map(|magic| data.windows(magic.len()).position(|w| w == *magic))
        .min()
}

pub struct SfxHandler;

impl FormatHandler for SfxHandler {
    fn id(&self) -> FormatId {
        FormatId::Sfx
    }

    fn probe(&self, header: &[u8], _name: Option<&str>) -> Confidence {
        if header.starts_with(b"MZ") || is_macho(header) {
            // Below MAGIC (100) so real zip/7z/rar/cab archives always win when
            // their magic appears at the very start of the file.
            Confidence(50)
        } else {
            Confidence::NONE
        }
    }

    fn open(&self, src: Source, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        // SFX needs the full file; require a seekable source with a real path so
        // that 7z/rar inner handlers can reopen by path after carving.
        let path = match &src {
            Source::Seekable { path: Some(p), .. } => p.clone(),
            Source::Stream { .. } => {
                return Err(Error::Unsupported {
                    format: "sfx".into(),
                    feature: "streaming (sfx requires seek)".into(),
                });
            }
            Source::Seekable { path: None, .. } => {
                return Err(Error::Unsupported {
                    format: "sfx".into(),
                    feature: "seekable source without path (sfx needs a file path)".into(),
                });
            }
        };

        // Read the full file. For v1 this is acceptable; SFX stubs are typically
        // a few hundred KB and the embedded archive is what the user actually wants.
        let bytes = std::fs::read(&path)?;

        // Compute the floor past which we scan for embedded archive magics —
        // goblin parses the executable's own headers to find where its image
        // ends. Which parser to use is decided by the same magic `probe` matched
        // on. If parsing fails, floor = 0 (scan the whole file).
        let floor = if is_macho(&bytes) {
            macho_overlay_offset(&bytes)
        } else {
            pe_overlay_offset(&bytes)
        };

        // Clamp the floor: a crafted PE could report a section past EOF; an empty
        // slice just yields no match.
        let floor = floor.min(bytes.len());
        let rel_offset = find_archive_magic(&bytes[floor..]).ok_or(Error::UnknownFormat)?;
        let abs_offset = floor + rel_offset;

        // Carve the appended archive into a named temp file (written through the
        // NamedTempFile's own handle — no second open).
        let mut tmp = tempfile::NamedTempFile::new()?;
        tmp.write_all(&bytes[abs_offset..])?;
        let temp_path = tmp.into_temp_path();

        // Reopen via the full pipeline (zip/7z/rar/cab handle the carved file).
        let inner = open_single(&temp_path, opts)?;

        // TempBackedReader keeps temp alive and delegates format() to the inner
        // reader, so the caller sees Zip / SevenZ / Rar / Cab — not Sfx.
        Ok(Box::new(TempBackedReader::new(inner, temp_path)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::FormatId;

    #[test]
    fn id_is_sfx() {
        assert_eq!(SfxHandler.id(), FormatId::Sfx);
    }

    #[test]
    fn probe_mz_returns_fifty() {
        let header = b"MZ\x90\x00";
        let c = SfxHandler.probe(header, None);
        assert!(c > Confidence::NONE, "expected > NONE, got {c:?}");
        assert!(c < Confidence::MAGIC, "expected < MAGIC, got {c:?}");
        assert_eq!(c, Confidence(50));
    }

    #[test]
    fn probe_non_mz_returns_none() {
        // PK magic — a real zip; SFX should not claim it.
        let header = b"PK\x03\x04";
        let c = SfxHandler.probe(header, None);
        assert_eq!(c, Confidence::NONE);
    }

    #[test]
    fn probe_every_macho_flavour_returns_fifty() {
        // Same confidence as MZ: a macOS self-extractor is the same shape of
        // file, and a real archive's own magic must still outrank it.
        for magic in MACHO_MAGICS {
            let mut header = magic.to_vec();
            header.extend_from_slice(&[0u8; 28]);
            assert_eq!(
                SfxHandler.probe(&header, None),
                Confidence(50),
                "magic {magic:02X?} should be claimed as an executable wrapper"
            );
        }
    }

    #[test]
    fn probe_fat64_magic_is_not_claimed() {
        // `cafebabf` is the 64-bit universal container. goblin 0.10 cannot parse
        // it, so claiming it would mean scanning the whole executable for
        // archive magic — see the note on MACHO_MAGICS.
        let header = [0xCA, 0xFE, 0xBA, 0xBF, 0, 0, 0, 1];
        assert_eq!(SfxHandler.probe(&header, None), Confidence::NONE);
    }

    #[test]
    fn macho_overlay_offset_of_garbage_is_zero() {
        // The documented fallback: unparseable input means "scan from the
        // start", never a bogus non-zero floor that would skip real data.
        assert_eq!(macho_overlay_offset(&[0xCF, 0xFA, 0xED, 0xFE, 0, 0, 0]), 0);
        assert_eq!(macho_overlay_offset(b""), 0);
    }

    #[test]
    fn probe_empty_returns_none() {
        let c = SfxHandler.probe(b"", None);
        assert_eq!(c, Confidence::NONE);
    }
}
