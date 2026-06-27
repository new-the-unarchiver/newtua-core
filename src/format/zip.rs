use std::io::{Read, Write};

use crate::archive::{
    ArchiveReader, Confidence, Entry, EntryKind, FormatHandler, FormatId, OpenOptions, Source,
};
use crate::encoding::decode_names;
use crate::error::{Error, Result};

pub struct ZipHandler;

type ZipArc = zip::ZipArchive<Box<dyn crate::archive::ReadSeek>>;

/// Private staging enum used during zip indexing to carry entry-type info
/// before symlink targets have been decoded.
enum EntryKindRaw {
    File,
    Dir,
    Symlink(Vec<u8>),
}

/// Staging metadata collected for each entry during the index pass.
type EntryMeta = (
    u64,
    bool,
    bool,
    Option<std::time::SystemTime>,
    Option<u32>,
    EntryKindRaw,
);

impl FormatHandler for ZipHandler {
    fn id(&self) -> FormatId {
        FormatId::Zip
    }

    fn probe(&self, header: &[u8], _name: Option<&str>) -> Confidence {
        if header.starts_with(b"PK\x03\x04") || header.starts_with(b"PK\x05\x06") {
            Confidence::MAGIC
        } else {
            Confidence::NONE
        }
    }

    fn open(&self, src: Source, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        open_zip(src, opts, FormatId::Zip)
    }
}

/// Открыть zip-источник, рапортуя подтип `format` (Zip для обычного zip, либо
/// конкретный бандл — Apk/Epub/Crx/…). Вся логика индексации записей,
/// символлинков, LZMA и паролей общая для всех подтипов.
pub(crate) fn open_zip(
    src: Source,
    opts: &OpenOptions,
    format: FormatId,
) -> Result<Box<dyn ArchiveReader>> {
    let inner: Box<dyn crate::archive::ReadSeek> = match src {
        Source::Seekable { inner, .. } => inner,
        Source::Stream { .. } => {
            return Err(Error::Unsupported {
                format: "zip".into(),
                feature: "streaming (zip requires seek)".into(),
            });
        }
    };
    let mut zip = zip::ZipArchive::new(inner).map_err(map_zip_err)?;
    let mut raw_names: Vec<Vec<u8>> = Vec::new();
    let mut metas: Vec<EntryMeta> = Vec::new();
    let mut is_lzma: Vec<bool> = Vec::new();
    for i in 0..zip.len() {
        let f = zip.by_index_raw(i).map_err(map_zip_err)?;
        is_lzma.push(f.compression() == zip::CompressionMethod::Lzma);
        // unix_mode() returns the full 16-bit value (type bits + perms).
        // Use the crate's is_symlink() for detection: unix_permissions() on
        // write strips type bits and always sets S_IFREG, so checking raw
        // mode bits ourselves is unreliable. is_symlink() checks S_IFLNK
        // which is only set when the entry was written via add_symlink().
        let is_symlink = f.is_symlink();
        // Strip the file-type nibble so `mode` holds only permission bits,
        // matching the convention used by the tar handler.
        let mode = f.unix_mode().map(|m| m & 0o7777);
        let is_dir = f.is_dir();
        let size = f.size();
        let is_encrypted = f.encrypted();
        let modified = f.last_modified().and_then(zip_dt_to_systime);
        raw_names.push(f.name_raw().to_vec());
        let kind_raw = if is_symlink {
            EntryKindRaw::Symlink(Vec::new()) // filled in next loop
        } else if is_dir {
            EntryKindRaw::Dir
        } else {
            EntryKindRaw::File
        };
        metas.push((size, is_dir, is_encrypted, modified, mode, kind_raw));
    }
    // Second pass: read symlink targets via by_index (decompressed).
    // This is best-effort: if the entry is encrypted or otherwise unreadable,
    // we fall back to an empty target so that listing still succeeds.
    for (i, meta) in metas.iter_mut().enumerate() {
        if matches!(meta.5, EntryKindRaw::Symlink(_)) {
            let buf = zip
                .by_index(i)
                .ok()
                .and_then(|mut f| {
                    let mut buf = Vec::new();
                    f.read_to_end(&mut buf).ok().map(|_| buf)
                })
                .unwrap_or_default();
            meta.5 = EntryKindRaw::Symlink(buf);
        }
    }

    let encoding_label = opts.encoding_override.as_deref();
    let names = decode_names(&raw_names, encoding_label);

    // Collect symlink target byte-strings for batch decoding with same charset.
    let raw_targets: Vec<Vec<u8>> = metas
        .iter()
        .map(|(_, _, _, _, _, kind_raw)| match kind_raw {
            EntryKindRaw::Symlink(t) => t.clone(),
            _ => Vec::new(),
        })
        .collect();
    let decoded_targets = decode_names(&raw_targets, encoding_label);

    let mut entries = Vec::with_capacity(zip.len());
    for (i, (size, _, is_encrypted, modified, mode, kind_raw)) in metas.into_iter().enumerate() {
        let kind = match kind_raw {
            EntryKindRaw::File => EntryKind::File,
            EntryKindRaw::Dir => EntryKind::Dir,
            EntryKindRaw::Symlink(_) => EntryKind::Symlink {
                target: std::path::PathBuf::from(&decoded_targets[i]),
            },
        };
        entries.push(Entry {
            path_raw: raw_names[i].clone(),
            path: std::path::PathBuf::from(&names[i]),
            kind,
            size,
            mode,
            is_encrypted,
            modified,
        });
    }
    Ok(Box::new(ZipReader {
        zip,
        entries,
        is_lzma,
        password: opts.password.clone(),
        format,
    }))
}

/// Convert a `zip::DateTime` (MS-DOS civil fields) to `SystemTime`.
fn zip_dt_to_systime(dt: zip::DateTime) -> Option<std::time::SystemTime> {
    crate::datetime::civil_to_systime(
        dt.year() as i32,
        dt.month() as u32,
        dt.day() as u32,
        dt.hour() as u64,
        dt.minute() as u64,
        dt.second() as u64,
    )
}

fn map_zip_err(e: zip::result::ZipError) -> Error {
    use zip::result::ZipError;
    match e {
        ZipError::Io(io) => Error::Io(io),
        // In zip 2.x, wrong password yields InvalidPassword
        ZipError::InvalidPassword => Error::WrongPassword,
        ZipError::UnsupportedArchive(s) if s == ZipError::PASSWORD_REQUIRED => Error::Encrypted,
        ZipError::UnsupportedArchive(s) => Error::Unsupported {
            format: "zip".into(),
            feature: s.into(),
        },
        other => Error::Corrupt(other.to_string()),
    }
}

/// Upper bound on the LZMA dictionary `lzma_rs` may allocate while decoding a
/// ZIP member, guarding against a crafted `dict_size` in the properties byte.
/// Real ZIP-LZMA rarely exceeds a 64 MiB dictionary.
const MAX_LZMA_DICT: usize = 256 << 20; // 256 MiB

/// Decompress a ZIP method-14 (LZMA) member.
///
/// ZIP-LZMA (APPNOTE 5.8.8) prepends a 4-byte wrapper to the LZMA data —
/// `[SDK version major/minor: 2 bytes][properties size: 2 bytes LE]` — followed
/// by `properties size` bytes of LZMA properties and then the LZMA1 stream. It
/// omits the 8-byte uncompressed-size field that `.lzma` files carry and ends
/// the stream with an EOS marker. We strip the wrapper, then hand the 5 property
/// bytes + stream to `lzma_rs` with the uncompressed `size` taken from the
/// central directory (`UseProvided`) — exactly the field the format lacks.
/// `zip` 2.x instead assumes `ReadFromHeader` and mis-decodes the stream.
fn decode_zip_lzma<R: Read>(raw: R, size: u64, mut out: &mut dyn Write) -> Result<()> {
    use lzma_rs::decompress::{Options, UnpackedSize};

    let mut reader = std::io::BufReader::new(raw);
    // 4-byte ZIP-LZMA wrapper: 2 bytes SDK version, 2 bytes (LE) properties len.
    let mut head = [0u8; 4];
    reader
        .read_exact(&mut head)
        .map_err(|e| Error::Corrupt(format!("zip-lzma header: {e}")))?;
    let prop_len = u16::from_le_bytes([head[2], head[3]]);
    if prop_len != 5 {
        // lzma_rs consumes a fixed 5-byte property header; any other size is not
        // a standard ZIP-LZMA member.
        return Err(Error::Unsupported {
            format: "zip".into(),
            feature: "LZMA (zip) with non-standard property size".into(),
        });
    }
    let opts = Options {
        unpacked_size: UnpackedSize::UseProvided(Some(size)),
        memlimit: Some(MAX_LZMA_DICT),
        allow_incomplete: false,
    };
    lzma_rs::lzma_decompress_with_options(&mut reader, &mut out, &opts)
        .map_err(|e| Error::Corrupt(format!("zip-lzma decode: {e}")))
}

struct ZipReader {
    zip: ZipArc,
    entries: Vec<Entry>,
    /// Parallel to `entries`: true where the member uses the LZMA method.
    is_lzma: Vec<bool>,
    password: Option<String>,
    /// Рапортуемый подтип (Zip, либо Apk/Epub/Crx/… для бандлов).
    format: FormatId,
}

impl ArchiveReader for ZipReader {
    fn format(&self) -> FormatId {
        self.format
    }

    fn entries(&mut self) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn verify_password(&mut self) -> Result<()> {
        let Some(idx) = self.entries.iter().position(|e| e.is_encrypted) else {
            return Ok(());
        };
        let pw = self.password.as_deref().ok_or(Error::Encrypted)?;
        // Конструирование дешифратора проверяет пароль по заголовку записи
        // (ZipCrypto — контрольный байт, AES — верификатор), без чтения тела.
        self.zip
            .by_index_decrypt(idx, pw.as_bytes())
            .map(|_| ())
            .map_err(map_zip_err)
    }

    fn read_entry(&mut self, idx: usize, out: &mut dyn Write) -> Result<()> {
        let is_encrypted = self
            .entries
            .get(idx)
            .ok_or(Error::InvalidIndex(idx))?
            .is_encrypted;

        // zip 2.x's own LZMA decoder cannot read the EOS-terminated streams that
        // real ZIP-LZMA producers (7-Zip, Python) emit — it assumes an 8-byte
        // uncompressed-size field the format omits. We decode the member
        // ourselves instead (see decode_zip_lzma). The method was captured at
        // open() time, so no second local-header read is needed here.
        if self.is_lzma[idx] {
            if is_encrypted {
                // Encrypted LZMA: by_index_raw yields still-encrypted bytes and
                // the decryptor lives inside the zip crate's (broken) LZMA path,
                // out of our reach. Rare combination; report it honestly.
                return Err(Error::Unsupported {
                    format: "zip".into(),
                    feature: "encrypted LZMA (zip)".into(),
                });
            }
            let size = self.entries[idx].size;
            let raw = self.zip.by_index_raw(idx).map_err(map_zip_err)?;
            return decode_zip_lzma(raw, size, out);
        }

        if is_encrypted {
            let pw = self.password.clone().ok_or(Error::Encrypted)?;
            let mut f = self
                .zip
                .by_index_decrypt(idx, pw.as_bytes())
                .map_err(map_zip_err)?;
            std::io::copy(&mut f, out)?;
        } else {
            let mut f = self.zip.by_index(idx).map_err(map_zip_err)?;
            std::io::copy(&mut f, out)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Confidence;

    /// Собрать минимальный валидный zip в памяти (один файл "hello.txt" = "hi").
    fn tiny_zip_bytes() -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let o: zip::write::FileOptions<()> = zip::write::FileOptions::default();
            w.start_file("hello.txt", o).unwrap();
            std::io::Write::write_all(&mut w, b"hi").unwrap();
            w.finish().unwrap();
        }
        buf
    }

    #[test]
    fn open_zip_reports_requested_format() {
        let bytes = tiny_zip_bytes();
        let src = Source::Seekable {
            inner: Box::new(std::io::Cursor::new(bytes)),
            path: None,
        };
        let mut reader = open_zip(src, &OpenOptions::default(), FormatId::Apk).unwrap();
        assert_eq!(reader.format(), FormatId::Apk);
        let entries = reader.entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path.to_string_lossy(), "hello.txt");
    }

    #[test]
    fn probe_detects_pk_magic() {
        assert_eq!(ZipHandler.probe(b"PK\x03\x04....", None), Confidence::MAGIC);
    }

    #[test]
    fn probe_detects_empty_archive_magic() {
        assert_eq!(ZipHandler.probe(b"PK\x05\x06....", None), Confidence::MAGIC);
    }

    #[test]
    fn probe_rejects_other() {
        assert_eq!(ZipHandler.probe(b"7z\xbc\xaf", None), Confidence::NONE);
    }

    #[test]
    fn probe_rejects_empty_header() {
        assert_eq!(ZipHandler.probe(b"", None), Confidence::NONE);
    }

    #[test]
    fn zip_handler_id_is_zip() {
        assert_eq!(ZipHandler.id(), FormatId::Zip);
    }

    // ── decode_zip_lzma robustness on crafted input ─────────────────────────

    #[test]
    fn zip_lzma_truncated_header_is_corrupt() {
        // Fewer than 4 bytes: the ZIP-LZMA wrapper can't be read.
        let mut out = Vec::new();
        let err = decode_zip_lzma(&b"\x00\x00"[..], 10, &mut out).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }

    #[test]
    fn zip_lzma_nonstandard_property_size_is_unsupported() {
        // properties size != 5 is not a standard ZIP-LZMA member.
        let mut out = Vec::new();
        let input = [0x00, 0x00, 0x09, 0x00]; // version 0.0, prop_len = 9
        let err = decode_zip_lzma(&input[..], 10, &mut out).unwrap_err();
        assert!(matches!(err, Error::Unsupported { .. }), "got {err:?}");
    }

    #[test]
    fn zip_lzma_garbage_stream_is_corrupt_not_panic() {
        // Valid 4-byte wrapper + 5 plausible property bytes (1 MiB dict) but a
        // bogus LZMA1 stream: must error as Corrupt, never panic or hang.
        let mut input = vec![0x00, 0x00, 0x05, 0x00]; // version 0.0, prop_len = 5
        input.extend_from_slice(&[0x5d, 0x00, 0x00, 0x10, 0x00]); // lc3lp0pb2, dict 1 MiB
        input.extend_from_slice(&[0xff; 16]); // garbage range-coder data
        let mut out = Vec::new();
        let err = decode_zip_lzma(&input[..], 64, &mut out).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }
}
