use std::io::Write;

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
        // sevenz-rust2 requires a file path or Read+Seek source. We obtain the
        // inner reader from Source directly so we can pass it to SevenZReader::new.
        let inner = match src {
            Source::Seekable { inner, .. } => inner,
            Source::Stream { .. } => {
                return Err(Error::Unsupported {
                    format: "7z".into(),
                    feature: "streaming (7z requires seek)".into(),
                });
            }
        };

        // Build the password. sevenz-rust2 Password converts &str to UTF-16LE bytes.
        let password: sevenz_rust2::Password = match opts.password.as_deref() {
            Some(pw) => pw.into(),
            None => sevenz_rust2::Password::empty(),
        };

        let mut seven = sevenz_rust2::SevenZReader::new(inner, password).map_err(map_7z_err)?;

        let mut raw_names: Vec<Vec<u8>> = Vec::new();
        let mut sizes: Vec<u64> = Vec::new();
        let mut is_dirs: Vec<bool> = Vec::new();
        let mut all_data: Vec<Vec<u8>> = Vec::new();

        seven
            .for_each_entries(|entry, reader| {
                let name_bytes = entry.name().as_bytes().to_vec();
                let is_dir = entry.is_directory();
                let size = entry.size();
                let mut data = Vec::new();
                if !is_dir {
                    std::io::copy(reader, &mut data)?;
                }
                raw_names.push(name_bytes);
                sizes.push(size);
                is_dirs.push(is_dir);
                all_data.push(data);
                Ok(true)
            })
            .map_err(map_7z_err)?;

        let names = decode_names(&raw_names, opts.encoding_override.as_deref());
        let mut entries: Vec<Entry> = Vec::with_capacity(raw_names.len());
        for (i, name) in names.into_iter().enumerate() {
            entries.push(Entry {
                path_raw: raw_names[i].clone(),
                path: std::path::PathBuf::from(name),
                size: sizes[i],
                is_dir: is_dirs[i],
                is_encrypted: opts.password.is_some(),
                modified: None,
            });
        }

        Ok(Box::new(SevenZReader {
            entries,
            data: all_data,
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

struct SevenZReader {
    entries: Vec<Entry>,
    data: Vec<Vec<u8>>,
}

impl ArchiveReader for SevenZReader {
    fn format(&self) -> FormatId {
        FormatId::SevenZ
    }

    fn entries(&mut self) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn read_entry(&mut self, idx: usize, out: &mut dyn Write) -> Result<()> {
        let data = self.data.get(idx).ok_or(Error::UnknownFormat)?;
        out.write_all(data)?;
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
