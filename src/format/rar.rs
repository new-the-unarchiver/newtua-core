use std::io::Write;
use std::path::{Path, PathBuf};

use crate::archive::{
    ArchiveReader, Confidence, Entry, EntryKind, FormatHandler, FormatId, OpenOptions, Source,
};
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
        let (entries, is_multivolume) = match list_entries(path.as_path(), None, encoding) {
            Ok(r) => r,
            Err(_) => list_entries(path.as_path(), opts.password.as_deref(), encoding)?,
        };

        Ok(Box::new(RarReader {
            path,
            password: opts.password.clone(),
            entries,
            is_multivolume,
        }))
    }
}

/// List all entries in the archive, collecting metadata.
///
/// Returns `(entries, is_multivolume)`.  `is_multivolume` is `true` when the
/// archive header reports that this file is the first (or a subsequent) volume
/// in a multi-part RAR set, as indicated by `VolumeInfo::First` /
/// `VolumeInfo::Subsequent` from the unrar crate.
fn list_entries(
    path: &Path,
    password: Option<&str>,
    encoding: Option<&str>,
) -> Result<(Vec<Entry>, bool)> {
    let mut raw_names: Vec<Vec<u8>> = Vec::new();
    let mut metas: Vec<(u64, bool, bool, Option<u32>)> = Vec::new();

    // The Iterator impl on OpenArchive<List, CursorBeforeHeader> yields Result<FileHeader>.
    // We use it for listing (payloads are skipped automatically).
    //
    // We also read `volume_info()` from the opened archive before consuming it
    // as an iterator, so we can detect multi-volume sets without filename sniffing.
    let (is_multivolume, iter): (
        bool,
        Box<dyn Iterator<Item = std::result::Result<unrar::FileHeader, unrar::error::UnrarError>>>,
    ) = if let Some(pw) = password {
        let open = unrar::Archive::with_password(path, pw)
            .open_for_listing()
            .map_err(map_rar_err)?;
        let mv = open.volume_info() != unrar::VolumeInfo::None;
        (mv, Box::new(open))
    } else {
        let open = unrar::Archive::new(path)
            .open_for_listing()
            .map_err(map_rar_err)?;
        let mv = open.volume_info() != unrar::VolumeInfo::None;
        (mv, Box::new(open))
    };

    for item in iter {
        let header = item.map_err(map_rar_err)?;
        let raw = header.filename.to_string_lossy().as_bytes().to_vec();
        raw_names.push(raw);
        // Best-effort unix mode: for Unix-created RARs the unrar crate exposes
        // file_attr: u32 on FileHeader.  The host OS field exists in the native
        // HeaderDataEx struct but is NOT forwarded by the vendored FileHeader.
        //
        // On Unix hosts (macOS, Linux) RAR stores the full POSIX st_mode value
        // directly in file_attr (e.g. 0o100755 = 0x81ED for a regular file
        // with rwxr-xr-x permissions).  The file-type nibble occupies the top
        // bits of the low 16 bits (S_IFREG = 0o100000 = 0x8000, etc.).
        //
        // On Windows hosts file_attr carries FAT/NTFS attribute flags
        // (FILE_ATTRIBUTE_READONLY = 0x1, DIRECTORY = 0x10, etc.) which are
        // always small positive integers that cannot set the high bits used by
        // Unix file-type nibbles.  We detect Unix attributes by checking for a
        // known POSIX file-type nibble (S_IFREG, S_IFDIR, S_IFLNK).
        const S_IFMT: u32 = 0o170000;
        const S_IFREG: u32 = 0o100000;
        const S_IFDIR: u32 = 0o040000;
        const S_IFLNK: u32 = 0o120000;
        let attr = header.file_attr;
        let file_type = attr & S_IFMT;
        let mode = if file_type == S_IFREG || file_type == S_IFDIR || file_type == S_IFLNK {
            Some(attr & 0o7777)
        } else {
            None
        };
        metas.push((
            header.unpacked_size,
            header.is_directory(),
            header.is_encrypted(),
            mode,
        ));
    }

    let names = decode_names(&raw_names, encoding);
    let entries = raw_names
        .into_iter()
        .zip(metas)
        .enumerate()
        .map(|(i, (raw, (size, is_dir, is_encrypted, mode)))| Entry {
            path_raw: raw,
            path: PathBuf::from(&names[i]),
            kind: if is_dir {
                EntryKind::Dir
            } else {
                EntryKind::File
            },
            size,
            mode,
            is_encrypted,
            modified: None,
        })
        .collect();

    Ok((entries, is_multivolume))
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
    /// True when the opened file is the first or a subsequent volume in a
    /// multi-part RAR set.  Multi-volume entries are extracted via
    /// `read_entry_via_extract` (libunrar RAR_EXTRACT mode, which follows
    /// volume continuations by path) instead of the in-memory `read()` fast
    /// path used for single-volume archives.
    is_multivolume: bool,
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
            .ok_or(Error::InvalidIndex(idx))?
            .path_raw
            .clone();

        if self.is_multivolume {
            // For multi-volume RAR archives the unrar 0.5.8 crate's in-memory
            // `read()` API (which uses RAR_TEST mode internally) SIGABRTs when
            // the payload crosses a volume boundary.  The `extract_to` API
            // (RAR_EXTRACT mode, writes to disk) correctly follows the volume
            // continuation chain — libunrar locates the next volumes by path,
            // calling the UCM_CHANGEVOLUMEW callback with RAR_VOL_NOTIFY (found)
            // rather than RAR_VOL_ASK (missing), so no abort occurs.
            //
            // Strategy: open the archive in Process mode, iterate headers
            // sequentially (skip non-targets), and for the target entry call
            // `extract_to(temp_file)`.  Then stream the temp file into `out`.
            return self.read_entry_via_extract(idx, &target, out);
        }

        // Single-volume fast path: in-memory read via the unrar crate.
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
                None => return Err(Error::InvalidIndex(idx)),
                Some(with_file) => {
                    let raw = with_file
                        .entry()
                        .filename
                        .to_string_lossy()
                        .as_bytes()
                        .to_vec();
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

impl RarReader {
    /// Multi-volume extraction path: extract the target entry to a temporary
    /// file on disk, then stream that file into `out`.
    ///
    /// Using `extract_to` (RAR_EXTRACT mode) instead of `read()` (RAR_TEST
    /// mode) is required for multi-volume archives because libunrar must write
    /// through its normal extraction path for volume continuation to work
    /// correctly.  The next-volume files must exist on disk in the same
    /// directory as `self.path`.
    fn read_entry_via_extract(&self, idx: usize, target: &[u8], out: &mut dyn Write) -> Result<()> {
        use std::io::Read as _;

        // Create a temp file to receive the extracted bytes.
        let tmp = tempfile::NamedTempFile::new().map_err(Error::Io)?;
        let tmp_path = tmp.path().to_path_buf();
        // We must close/drop the NamedTempFile handle so that the OS allows
        // libunrar to write to the same path (important on Windows; on macOS
        // both handles can coexist, but keeping it explicit is cleaner).
        // We keep the path around to read back and then remove.
        drop(tmp);

        let password = self.password.as_deref();

        let mut archive = if let Some(pw) = password {
            unrar::Archive::with_password(self.path.as_path(), pw)
                .open_for_processing()
                .map_err(map_rar_err)?
        } else {
            unrar::Archive::new(self.path.as_path())
                .open_for_processing()
                .map_err(map_rar_err)?
        };

        let mut found = false;
        loop {
            let header_archive = archive.read_header().map_err(map_rar_err)?;
            match header_archive {
                None => {
                    if !found {
                        let _ = std::fs::remove_file(&tmp_path);
                        return Err(Error::InvalidIndex(idx));
                    }
                    break;
                }
                Some(with_file) => {
                    let raw = with_file
                        .entry()
                        .filename
                        .to_string_lossy()
                        .as_bytes()
                        .to_vec();
                    if raw == target {
                        // Extract to the temp file on disk.
                        let _next = with_file.extract_to(&tmp_path).map_err(map_rar_err)?;
                        found = true;
                        // The archive might have more entries but we are done.
                        break;
                    } else {
                        archive = with_file.skip().map_err(map_rar_err)?;
                    }
                }
            }
        }

        if !found {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(Error::InvalidIndex(idx));
        }

        // Stream the extracted temp file into `out`.
        let mut f = std::fs::File::open(&tmp_path).map_err(Error::Io)?;
        let mut buf = [0u8; 65536];
        loop {
            let n = f.read(&mut buf).map_err(Error::Io)?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])?;
        }
        drop(f);
        let _ = std::fs::remove_file(&tmp_path);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_detects_rar_magic() {
        assert_eq!(
            RarHandler.probe(b"Rar!\x1a\x07\x01\x00", None),
            Confidence::MAGIC
        );
    }

    #[test]
    fn probe_detects_rar4_magic() {
        assert_eq!(
            RarHandler.probe(b"Rar!\x1a\x07\x00", None),
            Confidence::MAGIC
        );
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
