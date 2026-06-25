use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use crate::archive::{
    ArchiveReader, Entry, EntryKind, FormatHandler, FormatId, OpenOptions, Source,
};
use crate::encoding::decode_names;
use crate::error::{Error, Result, io_err_to_corrupt};

pub struct TarHandler;

/// Private staging enum used during tar indexing to carry entry-type info
/// before symlink targets have been decoded.
enum EntryKindRaw {
    File,
    Dir,
    Symlink(Vec<u8>),
}

/// Staging metadata collected for each entry during the index pass.
type EntryMeta = (
    u64,
    u64,
    Option<std::time::SystemTime>,
    Option<u32>,
    EntryKindRaw,
);

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
        // Choose backing strategy:
        // - Seekable source WITH a known file path → File strategy (no buffer).
        // - Everything else (Stream, or Seekable without path) → Buffer strategy.
        match src {
            Source::Seekable {
                mut inner,
                path: Some(ref path),
            } => {
                let path = path.clone();
                // Index by streaming over the file — reads only headers, not payloads.
                inner.seek(SeekFrom::Start(0))?;
                let (entries, offsets) = index_from_reader(inner, opts)?;
                let reader = TarReader {
                    backing: Backing::File { path, offsets },
                    entries,
                };
                Ok(Box::new(reader))
            }
            Source::Seekable {
                mut inner,
                path: None,
            } => {
                // Seekable but no path — fall back to buffer.
                let mut buf = Vec::new();
                inner.seek(SeekFrom::Start(0))?;
                inner.read_to_end(&mut buf)?;
                let (entries, offsets) = index_from_reader(std::io::Cursor::new(&buf), opts)?;
                let reader = TarReader {
                    backing: Backing::Buffer { data: buf, offsets },
                    entries,
                };
                Ok(Box::new(reader))
            }
            Source::Stream { mut inner, .. } => {
                // Stream — must buffer everything.
                let mut buf = Vec::new();
                inner.read_to_end(&mut buf)?;
                let (entries, offsets) = index_from_reader(std::io::Cursor::new(&buf), opts)?;
                let reader = TarReader {
                    backing: Backing::Buffer { data: buf, offsets },
                    entries,
                };
                Ok(Box::new(reader))
            }
        }
    }
}

// ── Backing strategies ────────────────────────────────────────────────────────

enum Backing {
    /// Entries are read directly from a file by seeking to recorded offsets.
    /// No archive data is held in memory.
    File { path: PathBuf, offsets: Vec<u64> },
    /// The entire archive is buffered in memory (Stream source or no file path).
    Buffer { data: Vec<u8>, offsets: Vec<u64> },
}

// ── TarReader ─────────────────────────────────────────────────────────────────

struct TarReader {
    backing: Backing,
    entries: Vec<Entry>,
}

// ── Indexing helpers ──────────────────────────────────────────────────────────

/// Index a tar archive from any `Read + Seek` source.
/// Reads only the headers; skips payloads via the tar crate's streaming API.
/// For an in-memory slice, wrap it in `std::io::Cursor::new(data)` before calling.
fn index_from_reader<R: Read + Seek>(
    reader: R,
    opts: &OpenOptions,
) -> Result<(Vec<Entry>, Vec<u64>)> {
    let mut raw_names: Vec<Vec<u8>> = Vec::new();
    let mut metas: Vec<EntryMeta> = Vec::new();

    let mut ar = tar::Archive::new(reader);
    for entry in ar.entries().map_err(io_err_to_corrupt)? {
        let entry = entry.map_err(io_err_to_corrupt)?;
        let header = entry.header();
        let entry_type = header.entry_type();
        let mode = header.mode().ok();
        let size = header.size().map_err(io_err_to_corrupt)?;
        let path_bytes = entry.path_bytes().to_vec();
        let offset = entry.raw_file_position();
        let modified = header
            .mtime()
            .ok()
            .map(|s| std::time::UNIX_EPOCH + std::time::Duration::from_secs(s));
        let kind_raw = if entry_type.is_symlink() {
            let target_raw = entry
                .link_name_bytes()
                .map(|c| c.into_owned())
                .unwrap_or_default();
            EntryKindRaw::Symlink(target_raw)
        } else if entry_type.is_dir() {
            EntryKindRaw::Dir
        } else {
            EntryKindRaw::File
        };
        raw_names.push(path_bytes);
        metas.push((size, offset, modified, mode, kind_raw));
    }

    build_entries(raw_names, metas, opts)
}

/// Convert raw name lists and metadata into `(Vec<Entry>, Vec<u64>)`.
fn build_entries(
    raw_names: Vec<Vec<u8>>,
    metas: Vec<EntryMeta>,
    opts: &OpenOptions,
) -> Result<(Vec<Entry>, Vec<u64>)> {
    let encoding_label = opts.encoding_override.as_deref();
    let names = decode_names(&raw_names, encoding_label);

    // Collect symlink target byte-strings in parallel so they can be decoded
    // with the same charset as the entry names.
    let raw_targets: Vec<Vec<u8>> = metas
        .iter()
        .map(|(_, _, _, _, kind_raw)| match kind_raw {
            EntryKindRaw::Symlink(t) => t.clone(),
            _ => Vec::new(),
        })
        .collect();
    let decoded_targets = decode_names(&raw_targets, encoding_label);

    let mut entries = Vec::with_capacity(metas.len());
    let mut offsets = Vec::with_capacity(metas.len());

    for (i, (size, offset, modified, mode, kind_raw)) in metas.into_iter().enumerate() {
        let kind = match kind_raw {
            EntryKindRaw::File => EntryKind::File,
            EntryKindRaw::Dir => EntryKind::Dir,
            EntryKindRaw::Symlink(_) => EntryKind::Symlink {
                target: std::path::PathBuf::from(&decoded_targets[i]),
            },
        };
        // Strip trailing slash from directory paths (tar stores "d/" for dirs).
        let path_str = names[i].trim_end_matches('/');
        entries.push(Entry {
            path_raw: raw_names[i].clone(),
            path: std::path::PathBuf::from(path_str),
            kind,
            size,
            mode,
            is_encrypted: false,
            modified,
        });
        offsets.push(offset);
    }

    Ok((entries, offsets))
}

// ── ArchiveReader impl ────────────────────────────────────────────────────────

impl ArchiveReader for TarReader {
    fn format(&self) -> FormatId {
        FormatId::Tar
    }

    fn entries(&mut self) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn read_entry(&mut self, idx: usize, out: &mut dyn Write) -> Result<()> {
        let entry = self.entries.get(idx).ok_or(Error::InvalidIndex(idx))?;
        let size = entry.size;

        match &self.backing {
            Backing::File { path, offsets } => {
                let offset = offsets[idx];
                let mut file = std::fs::File::open(path)?;
                file.seek(SeekFrom::Start(offset))?;
                // Read exactly `size` bytes — take() stops at EOF naturally.
                let mut limited = file.take(size);
                std::io::copy(&mut limited, out)?;
                Ok(())
            }
            Backing::Buffer { data, offsets } => {
                let start = offsets[idx] as usize;
                let end = start
                    .checked_add(size as usize)
                    .ok_or_else(|| Error::Corrupt("tar entry size arithmetic overflow".into()))?;
                if end > data.len() {
                    return Err(Error::Corrupt("tar entry size exceeds archive data".into()));
                }
                out.write_all(&data[start..end])?;
                Ok(())
            }
        }
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
