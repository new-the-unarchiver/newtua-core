use std::io::Write;
use std::path::{Path, PathBuf};

use crate::archive::{ArchiveReader, Confidence, Entry, FormatHandler, FormatId, OpenOptions, Source};
use crate::encoding::decode_names;
use crate::error::{Error, Result};

pub struct RarHandler;

// RAR4: "Rar!\x1a\x07\x00"; RAR5: "Rar!\x1a\x07\x01\x00"
const RAR_MAGIC: &[u8] = b"Rar!\x1a\x07";

impl FormatHandler for RarHandler {
    fn id(&self) -> FormatId {
        FormatId::Rar
    }

    fn probe(&self, header: &[u8], _name: Option<&str>) -> Confidence {
        if header.starts_with(RAR_MAGIC) {
            Confidence::MAGIC
        } else {
            Confidence::NONE
        }
    }

    fn open(&self, src: Source, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        let path = src
            .file_path()
            .ok_or_else(|| Error::Unsupported {
                format: "rar".into(),
                feature: "non-file source".into(),
            })?
            .to_path_buf();

        // For data-encrypted RAR archives (common case), listing does not require
        // a password — only extraction does. For header-encrypted archives, we
        // need the password even for listing; try without first, then with.
        let encoding = opts.encoding_override.as_deref();
        let entries = match list_entries(path.as_path(), None, encoding) {
            Ok(e) => e,
            Err(_) => list_entries(path.as_path(), opts.password.as_deref(), encoding)?,
        };

        Ok(Box::new(RarReader {
            path,
            password: opts.password.clone(),
            entries,
        }))
    }
}

/// List all entries in the archive, collecting metadata.
fn list_entries(path: &Path, password: Option<&str>, encoding: Option<&str>) -> Result<Vec<Entry>> {
    let mut raw_names: Vec<Vec<u8>> = Vec::new();
    let mut metas: Vec<(u64, bool, bool)> = Vec::new();

    // The Iterator impl on OpenArchive<List, CursorBeforeHeader> yields Result<FileHeader>.
    // We use it for listing (payloads are skipped automatically).
    let iter: Box<dyn Iterator<Item = std::result::Result<unrar::FileHeader, unrar::error::UnrarError>>> =
        if let Some(pw) = password {
            let open = unrar::Archive::with_password(path, pw)
                .open_for_listing()
                .map_err(map_rar_err)?;
            Box::new(open)
        } else {
            let open = unrar::Archive::new(path)
                .open_for_listing()
                .map_err(map_rar_err)?;
            Box::new(open)
        };

    for item in iter {
        let header = item.map_err(map_rar_err)?;
        let raw = header.filename.to_string_lossy().as_bytes().to_vec();
        raw_names.push(raw);
        metas.push((header.unpacked_size, header.is_directory(), header.is_encrypted()));
    }

    let names = decode_names(&raw_names, encoding);
    let entries = raw_names
        .into_iter()
        .zip(metas)
        .enumerate()
        .map(|(i, (raw, (size, is_dir, is_encrypted)))| Entry {
            path_raw: raw,
            path: PathBuf::from(&names[i]),
            size,
            is_dir,
            is_encrypted,
            modified: None,
        })
        .collect();

    Ok(entries)
}

fn map_rar_err(e: unrar::error::UnrarError) -> Error {
    use unrar::error::Code;
    match e.code {
        Code::BadPassword => Error::WrongPassword,
        Code::MissingPassword => Error::Encrypted,
        _ => Error::Corrupt(e.to_string()),
    }
}

struct RarReader {
    path: PathBuf,
    password: Option<String>,
    entries: Vec<Entry>,
}

impl ArchiveReader for RarReader {
    fn format(&self) -> FormatId {
        FormatId::Rar
    }

    fn entries(&mut self) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn read_entry(&mut self, idx: usize, out: &mut dyn Write) -> Result<()> {
        let target = self
            .entries
            .get(idx)
            .ok_or(Error::UnknownFormat)?
            .path_raw
            .clone();

        // Re-open the archive in Process mode to read the target entry.
        // We scan sequentially and skip entries until we find the target.
        let password = self.password.as_deref();

        macro_rules! open_proc {
            () => {
                if let Some(pw) = password {
                    unrar::Archive::with_password(self.path.as_path(), pw)
                        .open_for_processing()
                        .map_err(map_rar_err)?
                } else {
                    unrar::Archive::new(self.path.as_path())
                        .open_for_processing()
                        .map_err(map_rar_err)?
                }
            };
        }

        let mut archive = open_proc!();

        loop {
            let header_archive = archive.read_header().map_err(map_rar_err)?;
            match header_archive {
                None => return Err(Error::UnknownFormat),
                Some(with_file) => {
                    let raw =
                        with_file.entry().filename.to_string_lossy().as_bytes().to_vec();
                    if raw == target {
                        // This is our entry — read it into the output.
                        let (data, _next) = with_file.read().map_err(map_rar_err)?;
                        out.write_all(&data)?;
                        return Ok(());
                    } else {
                        // Skip this entry and continue.
                        archive = with_file.skip().map_err(map_rar_err)?;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_detects_rar_magic() {
        assert_eq!(RarHandler.probe(b"Rar!\x1a\x07\x01\x00", None), Confidence::MAGIC);
    }

    #[test]
    fn probe_detects_rar4_magic() {
        assert_eq!(RarHandler.probe(b"Rar!\x1a\x07\x00", None), Confidence::MAGIC);
    }

    #[test]
    fn probe_rejects_other() {
        assert_eq!(RarHandler.probe(b"PK\x03\x04", None), Confidence::NONE);
    }

    #[test]
    fn rar_handler_id_is_rar() {
        assert_eq!(RarHandler.id(), FormatId::Rar);
    }
}
