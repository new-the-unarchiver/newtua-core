use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::archive::{
    ArchiveReader, Confidence, Entry, EntryKind, FormatHandler, FormatId, OpenOptions, Source,
};
use crate::encoding::decode_names;
use crate::error::{Error, Result};

// ── Mode constants (POSIX S_IFMT family) ────────────────────────────────────

const S_IFMT: u32 = 0o170000;
const S_IFLNK: u32 = 0o120000; // symbolic link
const S_IFDIR: u32 = 0o040000; // directory
const S_IFREG: u32 = 0o100000; // regular file

/// Map a `cpio`-crate `io::Error` onto our error model (mirrors `map_cab_err`
/// / `map_ar_err`): structural problems are `Corrupt`, everything else is `Io`.
fn map_cpio_err(e: std::io::Error) -> Error {
    match e.kind() {
        std::io::ErrorKind::InvalidData | std::io::ErrorKind::UnexpectedEof => {
            Error::Corrupt(e.to_string())
        }
        _ => Error::Io(e),
    }
}

// ── Handler ──────────────────────────────────────────────────────────────────

pub struct CpioHandler;

impl FormatHandler for CpioHandler {
    fn id(&self) -> FormatId {
        FormatId::Cpio
    }

    fn probe(&self, header: &[u8], _name: Option<&str>) -> Confidence {
        // Detect only the SVR4 "new ASCII" variant (070701).
        // 070702 (crc) and 070707 (odc/binary) are future work.
        if header.starts_with(b"070701") {
            Confidence::MAGIC
        } else {
            Confidence::NONE
        }
    }

    fn open(&self, src: Source, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        // cpio is a sequential streaming format; we can read from either source.
        let reader: Box<dyn Read> = match src {
            Source::Seekable { mut inner, .. } => {
                inner.seek(SeekFrom::Start(0))?;
                inner
            }
            Source::Stream { inner, .. } => inner,
        };

        // Single-pass scan: stream all entries, copying file bodies into one
        // shared temp file while recording (offset, size) per regular file.
        let mut temp = tempfile::NamedTempFile::new()?;
        let mut raw_names: Vec<Vec<u8>> = Vec::new();
        let mut metas: Vec<EntryMeta> = Vec::new();

        let mut current: Box<dyn Read> = reader;

        loop {
            let entry_reader = cpio::NewcReader::new(current).map_err(map_cpio_err)?;

            if entry_reader.entry().is_trailer() {
                // Consume the trailer; we don't need the underlying reader.
                let _ = entry_reader.finish();
                break;
            }

            let entry = entry_reader.entry().clone();
            let mode = entry.mode();
            let file_size = entry.file_size() as u64;
            let name_str = entry.name().to_owned();
            let mtime = entry.mtime();
            let modified = if mtime != 0 {
                Some(UNIX_EPOCH + Duration::from_secs(mtime as u64))
            } else {
                None
            };

            match mode & S_IFMT {
                S_IFREG => {
                    // Regular file: stream body into the shared temp file.
                    let offset = temp.seek(SeekFrom::End(0))?;
                    current = Box::new(entry_reader.to_writer(&mut temp).map_err(map_cpio_err)?);
                    raw_names.push(name_str.into_bytes());
                    metas.push(EntryMeta {
                        kind: KindRaw::File,
                        offset,
                        size: file_size,
                        mode,
                        modified,
                    });
                }
                S_IFDIR => {
                    current = Box::new(entry_reader.finish().map_err(map_cpio_err)?);
                    raw_names.push(name_str.into_bytes());
                    metas.push(EntryMeta {
                        kind: KindRaw::Dir,
                        offset: 0,
                        size: 0,
                        mode,
                        modified,
                    });
                }
                S_IFLNK => {
                    // Symlink: body is the link target (at most file_size bytes).
                    let mut target_bytes = Vec::with_capacity(file_size as usize);
                    current = Box::new(
                        entry_reader
                            .to_writer(&mut target_bytes)
                            .map_err(map_cpio_err)?,
                    );
                    // Trim trailing NUL if any.
                    while target_bytes.last() == Some(&0) {
                        target_bytes.pop();
                    }
                    raw_names.push(name_str.into_bytes());
                    metas.push(EntryMeta {
                        kind: KindRaw::Symlink(target_bytes),
                        offset: 0,
                        size: file_size,
                        mode,
                        modified,
                    });
                }
                _ => {
                    // Special node (char/block device, fifo, socket) or hardlink —
                    // skip silently per the spec.
                    current = Box::new(entry_reader.finish().map_err(map_cpio_err)?);
                }
            }
        }

        let encoding_label = opts.encoding_override.as_deref();
        let names = decode_names(&raw_names, encoding_label);
        // Decode symlink targets only if there are any; on the common
        // symlink-free path this skips a whole charset-detection pass.
        let target_strings = if metas.iter().any(|m| matches!(m.kind, KindRaw::Symlink(_))) {
            let raw_targets: Vec<Vec<u8>> = metas
                .iter()
                .map(|m| match &m.kind {
                    KindRaw::Symlink(t) => t.clone(),
                    _ => Vec::new(),
                })
                .collect();
            decode_names(&raw_targets, encoding_label)
        } else {
            Vec::new()
        };

        let mut entries: Vec<Entry> = Vec::with_capacity(metas.len());
        // Body location in the temp file; `None` for entries with no body
        // (dirs, symlinks). `read_entry` keys off this, not off `size`.
        let mut offsets: Vec<Option<(u64, u64)>> = Vec::with_capacity(metas.len());

        for (i, meta) in metas.into_iter().enumerate() {
            let name_str = names[i].trim_end_matches('/');
            // Strip leading "./" that some cpio implementations prepend.
            let name_str = name_str.strip_prefix("./").unwrap_or(name_str);
            let (kind, body) = match meta.kind {
                KindRaw::File => (EntryKind::File, Some((meta.offset, meta.size))),
                KindRaw::Dir => (EntryKind::Dir, None),
                KindRaw::Symlink(_) => (
                    EntryKind::Symlink {
                        target: PathBuf::from(&target_strings[i]),
                    },
                    None,
                ),
            };
            entries.push(Entry {
                path_raw: raw_names[i].clone(),
                path: PathBuf::from(name_str),
                kind,
                size: meta.size,
                mode: Some(meta.mode),
                is_encrypted: false,
                modified: meta.modified,
            });
            offsets.push(body);
        }

        let temp_path = temp.into_temp_path();
        Ok(Box::new(CpioReader {
            entries,
            offsets,
            _temp: temp_path,
        }))
    }
}

// ── Internal types ────────────────────────────────────────────────────────────

enum KindRaw {
    File,
    Dir,
    Symlink(Vec<u8>),
}

struct EntryMeta {
    kind: KindRaw,
    offset: u64,
    size: u64,
    mode: u32,
    modified: Option<SystemTime>,
}

// ── Reader ────────────────────────────────────────────────────────────────────

pub struct CpioReader {
    entries: Vec<Entry>,
    /// Per-entry body location `(offset_in_temp, byte_count)`; `None` for entries
    /// with no body (dirs, symlinks).
    offsets: Vec<Option<(u64, u64)>>,
    /// Temp file holding all regular-file bodies, concatenated.
    _temp: tempfile::TempPath,
}

impl ArchiveReader for CpioReader {
    fn format(&self) -> FormatId {
        FormatId::Cpio
    }

    fn entries(&mut self) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn read_entry(&mut self, idx: usize, out: &mut dyn Write) -> Result<()> {
        if idx >= self.entries.len() {
            return Err(Error::InvalidIndex(idx));
        }
        let Some((offset, size)) = self.offsets[idx] else {
            // Directory or symlink — no body to read.
            return Ok(());
        };
        let mut file = std::fs::File::open(&self._temp)?;
        file.seek(SeekFrom::Start(offset))?;
        let mut limited = file.take(size);
        std::io::copy(&mut limited, out)?;
        Ok(())
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Confidence;

    #[test]
    fn id_is_cpio() {
        assert_eq!(CpioHandler.id(), FormatId::Cpio);
    }

    #[test]
    fn probe_positive_newc() {
        let header = b"070701000000000000000000";
        assert_eq!(CpioHandler.probe(header, None), Confidence::MAGIC);
    }

    #[test]
    fn probe_negative_zip() {
        assert_eq!(CpioHandler.probe(b"PK\x03\x04", None), Confidence::NONE);
    }

    #[test]
    fn probe_rejects_odc() {
        // 070707 is the old portable (odc) format — not supported.
        assert_eq!(CpioHandler.probe(b"070707...", None), Confidence::NONE);
    }

    #[test]
    fn probe_rejects_crc_variant() {
        // 070702 is the crc variant — not supported.
        assert_eq!(CpioHandler.probe(b"070702...", None), Confidence::NONE);
    }
}
