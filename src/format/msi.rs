//! MSI installer format handler.
//!
//! An `.msi` is a CFB (Compound File Binary) document containing database
//! tables and streams. Installable files are packed in one or more **embedded
//! CAB streams** referenced by the `Media` table (model B). We reuse the
//! existing [`CabHandler`] to read those files.
//!
//! Detection: CFB magic (`D0 CF 11 E0 A1 B1 1A E1`) **plus** `.msi` file
//! extension (case-insensitive) → `Confidence::MAGIC`. Without the extension
//! we return `Confidence::NONE` so that Office CFB files (`.doc`, `.xls`, …)
//! are not hijacked.

use std::io::Write;
use std::path::PathBuf;

use crate::archive::{
    ArchiveReader, Confidence, Entry, FormatHandler, FormatId, OpenOptions, Source,
};
use crate::error::{Error, Result};
use crate::format::CabHandler;

/// CFB file-format magic (8 bytes).
const CFB_MAGIC: &[u8] = &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

pub struct MsiHandler;

impl FormatHandler for MsiHandler {
    fn id(&self) -> FormatId {
        FormatId::Msi
    }

    /// `Confidence::MAGIC` only when BOTH conditions hold:
    /// 1. `header` starts with the 8-byte CFB magic.
    /// 2. `name` (the file name, not the full path) ends with `.msi`
    ///    (case-insensitive).
    fn probe(&self, header: &[u8], name: Option<&str>) -> Confidence {
        let has_cfb_magic = header.starts_with(CFB_MAGIC);
        let has_msi_ext = name
            .map(|n| n.to_ascii_lowercase().ends_with(".msi"))
            .unwrap_or(false);
        if has_cfb_magic && has_msi_ext {
            Confidence::MAGIC
        } else {
            Confidence::NONE
        }
    }

    fn open(&self, src: Source, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        // MSI requires a seekable source with a real on-disk path (the `msi`
        // crate opens by path).
        let path = match &src {
            Source::Seekable { path: Some(p), .. } => p.clone(),
            Source::Stream { .. } => {
                return Err(Error::Unsupported {
                    format: "msi".into(),
                    feature: "streaming (msi requires seek)".into(),
                });
            }
            Source::Seekable { path: None, .. } => {
                return Err(Error::Unsupported {
                    format: "msi".into(),
                    feature: "seekable source without a path".into(),
                });
            }
        };

        // Open the MSI package. An open failure at this stage means the file
        // is not a valid MSI/CFB database → UnknownFormat.
        let mut package =
            msi::Package::open(std::fs::File::open(&path)?).map_err(|_| Error::UnknownFormat)?;

        // A valid MSI must have the _Tables table (internal MSI metadata). If
        // it doesn't, we treat it as an unrecognised CFB document.
        if !package.has_table("_Tables") {
            return Err(Error::UnknownFormat);
        }

        // Read the Media table to find embedded CAB streams. Rows are only
        // present when the package actually has files to install; an empty
        // (or absent) Media table is valid — we just return zero entries.
        let cab_stream_names: Vec<String> = if package.has_table("Media") {
            let query = msi::Select::table("Media").columns(&["Cabinet"]);
            let rows = package
                .select_rows(query)
                .map_err(|e| Error::Corrupt(format!("msi: reading Media table: {e}")))?;
            let mut names = Vec::new();
            for row in rows {
                // Cabinet values: `#streamname` = embedded, plain name = external.
                // We only support embedded cabs (leading `#`).
                if let Some(cabinet) = row["Cabinet"].as_str() {
                    if let Some(stream_name) = cabinet.strip_prefix('#') {
                        names.push(stream_name.to_owned());
                    }
                    // External cabs (no '#') are silently skipped.
                }
            }
            names
        } else {
            Vec::new()
        };

        // For each embedded CAB stream: dump bytes to a NamedTempFile, then
        // open with CabHandler. We collect entries and build a routing map.
        let mut inner_readers: Vec<Box<dyn ArchiveReader>> = Vec::new();
        let mut temp_paths: Vec<tempfile::TempPath> = Vec::new();
        let mut all_entries: Vec<Entry> = Vec::new();
        // routing[outer_idx] = (cab_reader_idx, inner_idx)
        let mut routing: Vec<(usize, usize)> = Vec::new();

        let needs_prefix = cab_stream_names.len() > 1;

        for (cab_idx, stream_name) in cab_stream_names.iter().enumerate() {
            // Read the CFB stream into a temp file.
            let mut stream_reader = package
                .read_stream(stream_name)
                .map_err(|e| Error::Corrupt(format!("msi: opening stream {stream_name}: {e}")))?;
            let mut temp_cab = tempfile::NamedTempFile::new()?;
            std::io::copy(&mut stream_reader, &mut temp_cab)?;
            let temp_path = temp_cab.into_temp_path();

            // Open via CabHandler.
            let mut cab_reader = CabHandler
                .open(Source::path(&temp_path)?, opts)
                .map_err(|e| {
                    Error::Corrupt(format!("msi: opening embedded cab {stream_name}: {e}"))
                })?;

            // Collect entries; apply stream-name prefix when there is >1 cab.
            let cab_entries = cab_reader
                .entries()
                .map_err(|e| Error::Corrupt(format!("msi: listing cab {stream_name}: {e}")))?;

            for (inner_idx, entry) in cab_entries.iter().enumerate() {
                let mut e = entry.clone();
                if needs_prefix {
                    // Prefix path with the stream name to keep names unique
                    // across multiple embedded cabs.
                    let prefixed = PathBuf::from(stream_name).join(&e.path);
                    let prefixed_raw = {
                        let mut raw = stream_name.as_bytes().to_vec();
                        raw.push(b'/');
                        raw.extend_from_slice(&e.path_raw);
                        raw
                    };
                    e.path = prefixed;
                    e.path_raw = prefixed_raw;
                }
                routing.push((cab_idx, inner_idx));
                all_entries.push(e);
            }

            temp_paths.push(temp_path);
            inner_readers.push(cab_reader);
        }

        Ok(Box::new(MsiReader {
            inner_readers,
            _temps: temp_paths,
            entries: all_entries,
            routing,
        }))
    }
}

/// Reader for an MSI installer. Owns one or more inner CAB readers (one per
/// embedded cab stream) plus the temp files that back them (deleted on drop).
/// Reports `FormatId::Msi`.
struct MsiReader {
    inner_readers: Vec<Box<dyn ArchiveReader>>,
    /// Temp files for the extracted CAB bytes; kept alive until drop.
    _temps: Vec<tempfile::TempPath>,
    entries: Vec<Entry>,
    /// `routing[outer_idx] = (cab_reader_index, inner_idx)`
    routing: Vec<(usize, usize)>,
}

impl ArchiveReader for MsiReader {
    fn format(&self) -> FormatId {
        FormatId::Msi
    }

    fn entries(&mut self) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn read_entry(&mut self, idx: usize, out: &mut dyn Write) -> Result<()> {
        if idx >= self.routing.len() {
            return Err(Error::InvalidIndex(idx));
        }
        let (cab_idx, inner_idx) = self.routing[idx];
        self.inner_readers[cab_idx].read_entry(inner_idx, out)
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn cfb_header() -> Vec<u8> {
        let mut v = CFB_MAGIC.to_vec();
        v.extend_from_slice(&[0u8; 504]);
        v
    }

    #[test]
    fn id_is_msi() {
        assert_eq!(MsiHandler.id(), FormatId::Msi);
    }

    #[test]
    fn probe_positive_cfb_magic_and_msi_ext() {
        assert_eq!(
            MsiHandler.probe(&cfb_header(), Some("setup.msi")),
            Confidence::MAGIC
        );
    }

    #[test]
    fn probe_positive_case_insensitive_ext() {
        assert_eq!(
            MsiHandler.probe(&cfb_header(), Some("SETUP.MSI")),
            Confidence::MAGIC
        );
    }

    #[test]
    fn probe_negative_cfb_but_wrong_ext() {
        // CFB magic but .doc extension → NONE (don't hijack Office files).
        assert_eq!(
            MsiHandler.probe(&cfb_header(), Some("doc.doc")),
            Confidence::NONE
        );
    }

    #[test]
    fn probe_negative_non_cfb_magic() {
        // Non-CFB header + .msi name → NONE.
        assert_eq!(
            MsiHandler.probe(b"PK\x03\x04\x00\x00\x00\x00", Some("setup.msi")),
            Confidence::NONE
        );
    }

    #[test]
    fn probe_negative_no_name() {
        // CFB magic but no file name → NONE.
        assert_eq!(MsiHandler.probe(&cfb_header(), None), Confidence::NONE);
    }
}
