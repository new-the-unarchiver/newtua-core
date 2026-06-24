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
        if header.starts_with(b"MZ") {
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

        // Compute the floor past which we scan for embedded archive magics.
        // goblin parses the PE headers and sections to find the overlay start.
        // If parsing fails, floor = 0 (scan the whole file).
        let floor = pe_overlay_offset(&bytes);

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
        Ok(Box::new(TempBackedReader {
            inner,
            _temp: temp_path,
        }))
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
    fn probe_empty_returns_none() {
        let c = SfxHandler.probe(b"", None);
        assert_eq!(c, Confidence::NONE);
    }
}
