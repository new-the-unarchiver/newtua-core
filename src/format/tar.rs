use std::io::{Read, Write};

use crate::archive::{ArchiveReader, Entry, FormatHandler, FormatId, OpenOptions, Source};
use crate::encoding::decode_names;
use crate::error::{Error, Result};

pub struct TarHandler;

impl FormatHandler for TarHandler {
    fn id(&self) -> FormatId {
        FormatId::Tar
    }

    fn probe(&self, header: &[u8], _name: Option<&str>) -> crate::Confidence {
        // "ustar" at offset 257 — tar magic.
        if header.len() >= 263 && &header[257..262] == b"ustar" {
            crate::Confidence::MAGIC
        } else {
            crate::Confidence::NONE
        }
    }

    fn open(&self, src: Source, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        // Fully read into memory for random-access to entries.
        let mut buf = Vec::new();
        match src {
            Source::Seekable { mut inner, .. } => inner.read_to_end(&mut buf)?,
            Source::Stream { mut inner, .. } => inner.read_to_end(&mut buf)?,
        };
        let mut reader = TarReader {
            data: buf,
            entries: Vec::new(),
            offsets: Vec::new(),
        };
        reader.index(opts)?;
        Ok(Box::new(reader))
    }
}

struct TarReader {
    data: Vec<u8>,
    entries: Vec<Entry>,
    offsets: Vec<u64>, // data offset of each entry's payload within `data`
}

impl TarReader {
    fn index(&mut self, opts: &OpenOptions) -> Result<()> {
        let mut raw_names: Vec<Vec<u8>> = Vec::new();
        let mut metas = Vec::new();
        let mut ar = tar::Archive::new(std::io::Cursor::new(&self.data));
        for entry in ar.entries().map_err(|e| Error::Corrupt(e.to_string()))? {
            let entry = entry.map_err(|e| Error::Corrupt(e.to_string()))?;
            let header = entry.header();
            let is_dir = header.entry_type().is_dir();
            // Header::size() returns io::Result<u64>; Entry::size() returns u64 directly.
            // Using Header::size() as in the brief for uniformity.
            let size = header.size().map_err(|e| Error::Corrupt(e.to_string()))?;
            let path_bytes = entry.path_bytes().to_vec();
            let offset = entry.raw_file_position();
            let modified = header
                .mtime()
                .ok()
                .map(|s| std::time::UNIX_EPOCH + std::time::Duration::from_secs(s));
            raw_names.push(path_bytes);
            metas.push((size, is_dir, offset, modified));
        }
        let names = decode_names(&raw_names, opts.encoding_override.as_deref());
        for (i, (size, is_dir, offset, modified)) in metas.into_iter().enumerate() {
            self.entries.push(Entry {
                path_raw: raw_names[i].clone(),
                path: std::path::PathBuf::from(&names[i]),
                size,
                is_dir,
                is_encrypted: false,
                modified,
            });
            self.offsets.push(offset);
        }
        Ok(())
    }
}

impl ArchiveReader for TarReader {
    fn format(&self) -> FormatId {
        FormatId::Tar
    }

    fn entries(&mut self) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn read_entry(&mut self, idx: usize, out: &mut dyn Write) -> Result<()> {
        let entry = self.entries.get(idx).ok_or(Error::UnknownFormat)?;
        let start = self.offsets[idx] as usize;
        let end = start + entry.size as usize;
        out.write_all(&self.data[start..end])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Confidence;

    #[test]
    fn probe_detects_ustar_magic() {
        let mut header = vec![0u8; 263];
        header[257..262].copy_from_slice(b"ustar");
        assert_eq!(TarHandler.probe(&header, None), Confidence::MAGIC);
    }

    #[test]
    fn probe_rejects_random_bytes() {
        assert_eq!(TarHandler.probe(&[0u8; 263], None), Confidence::NONE);
    }
}
