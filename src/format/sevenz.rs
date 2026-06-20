use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use crate::archive::{
    ArchiveReader, Confidence, Entry, FormatHandler, FormatId, OpenOptions, Source,
};
use crate::encoding::decode_names;
use crate::error::{Error, Result};

pub struct SevenZHandler;

const SEVENZ_MAGIC: &[u8] = &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

impl FormatHandler for SevenZHandler {
    fn id(&self) -> FormatId {
        FormatId::SevenZ
    }

    fn probe(&self, header: &[u8], _name: Option<&str>) -> Confidence {
        if header.starts_with(SEVENZ_MAGIC) {
            Confidence::MAGIC
        } else {
            Confidence::NONE
        }
    }

    fn open(&self, src: Source, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        // 7z requires seek. Extract the file path (needed for on-demand re-opens
        // in read_entry) and the seekable reader.
        let (inner, path) = match src {
            Source::Seekable { inner, path } => (inner, path),
            Source::Stream { .. } => {
                return Err(Error::Unsupported {
                    format: "7z".into(),
                    feature: "streaming (7z requires seek)".into(),
                });
            }
        };

        // We need a real file path so that read_entry can re-open the archive.
        // Source::path() always sets path; in-memory sources have None and are
        // not supported for on-demand extraction.
        let file_path = path.ok_or_else(|| Error::Unsupported {
            format: "7z".into(),
            feature: "in-memory source (7z on-demand extraction requires a file path)".into(),
        })?;

        let password: sevenz_rust2::Password = match opts.password.as_deref() {
            Some(pw) => pw.into(),
            None => sevenz_rust2::Password::empty(),
        };

        // Archive::read() parses ONLY the 7z header structures (pack-info,
        // unpack-info, files-info) WITHOUT decompressing any entry payloads.
        // For header-encrypted archives (-mhe=on) the header itself is AES-encrypted
        // and the password is required here to decrypt the header block.
        // Note: Archive::read<R: Read+Seek> requires a concrete Sized type, so we
        // dereference through the Box to pass &mut dyn ReadSeek directly won't work.
        // Instead we open the file a second time through the stored path for the
        // header-only read. The original `inner` is dropped here.
        drop(inner);
        let mut header_file = File::open(&file_path).map_err(Error::Io)?;
        let archive =
            sevenz_rust2::Archive::read(&mut header_file, password.as_ref()).map_err(map_7z_err)?;

        // Build entries from header metadata — no payload decompression occurs.
        let raw_names: Vec<Vec<u8>> = archive
            .files
            .iter()
            .map(|f| f.name().as_bytes().to_vec())
            .collect();
        let names = decode_names(&raw_names, opts.encoding_override.as_deref());

        let entries: Vec<Entry> = archive
            .files
            .iter()
            .zip(names)
            .map(|(file, name)| Entry {
                path_raw: file.name().as_bytes().to_vec(),
                path: std::path::PathBuf::from(name),
                size: file.size(),
                is_dir: file.is_directory(),
                is_encrypted: opts.password.is_some(),
                modified: None,
            })
            .collect();

        Ok(Box::new(SevenZReader {
            file_path,
            password: opts.password.clone(),
            entries,
        }))
    }
}

fn map_7z_err(e: sevenz_rust2::Error) -> Error {
    match e {
        sevenz_rust2::Error::PasswordRequired => Error::Encrypted,
        sevenz_rust2::Error::MaybeBadPassword(_) => Error::WrongPassword,
        sevenz_rust2::Error::ChecksumVerificationFailed => Error::WrongPassword,
        sevenz_rust2::Error::Io(io, _) => Error::Io(io),
        other => Error::Corrupt(other.to_string()),
    }
}

/// Archive reader that extracts entries on demand.
///
/// `open()` only parses the 7z header (zero payload decompression). Each call
/// to `read_entry()` re-opens the archive file and decompresses only the
/// requested entry, so at most one entry's data lives in RAM at a time.
struct SevenZReader {
    /// Path to the archive file on disk.
    file_path: PathBuf,
    /// Optional password (stored as the original UTF-8 string).
    password: Option<String>,
    /// Entry metadata populated at open time (headers only, no payloads).
    entries: Vec<Entry>,
}

impl ArchiveReader for SevenZReader {
    fn format(&self) -> FormatId {
        FormatId::SevenZ
    }

    fn entries(&mut self) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn read_entry(&mut self, idx: usize, out: &mut dyn Write) -> Result<()> {
        // Validate index before doing any I/O.
        if idx >= self.entries.len() {
            return Err(Error::InvalidIndex(idx));
        }

        let target_name = self.entries[idx].path_raw.clone();

        let password: sevenz_rust2::Password = match self.password.as_deref() {
            Some(pw) => pw.into(),
            None => sevenz_rust2::Password::empty(),
        };

        // Re-open the archive file for this extraction.  SevenZReader::open()
        // re-reads only the header; the actual payload is decompressed lazily
        // by for_each_entries as we iterate.
        let file = File::open(&self.file_path).map_err(Error::Io)?;
        let mut seven = sevenz_rust2::SevenZReader::new(file, password).map_err(map_7z_err)?;

        let mut found = false;
        let mut extract_err: Option<Error> = None;

        seven
            .for_each_entries(|entry, reader| {
                if entry.name().as_bytes() == target_name.as_slice() {
                    found = true;
                    // Copy only this entry's payload to out; return false to
                    // stop iteration early (no further decompression occurs).
                    if let Err(e) = std::io::copy(reader, out) {
                        extract_err = Some(Error::Io(e));
                    }
                    Ok(false)
                } else {
                    // Skip entries before the target.  For solid archives this
                    // still decompresses preceding data (unavoidable for solid
                    // streams), but we do NOT retain it in memory.
                    std::io::copy(reader, &mut std::io::sink())?;
                    Ok(true)
                }
            })
            .map_err(map_7z_err)?;

        if let Some(e) = extract_err {
            return Err(e);
        }

        if !found {
            return Err(Error::InvalidIndex(idx));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_detects_7z_magic() {
        assert_eq!(SevenZHandler.probe(SEVENZ_MAGIC, None), Confidence::MAGIC);
    }

    #[test]
    fn probe_rejects_other() {
        assert_eq!(SevenZHandler.probe(b"PK\x03\x04", None), Confidence::NONE);
    }

    #[test]
    fn sevenz_handler_id_is_sevenz() {
        assert_eq!(SevenZHandler.id(), FormatId::SevenZ);
    }
}
