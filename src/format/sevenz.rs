use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::archive::{
    ArchiveReader, Confidence, Entry, EntryKind, FormatHandler, FormatId, OpenOptions, Source,
};
use crate::encoding::decode_names;
use crate::error::{Error, Result};

pub struct SevenZHandler;

const SEVENZ_MAGIC: &[u8] = &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

/// Sanity-check the 32-byte 7z signature header before handing the file to
/// `sevenz-rust2`, which trusts the size/count fields it reads. On a bad start
/// header the library falls back to a tail-scan recovery that can request an
/// enormous allocation — a malformed 7z could OOM the whole process (found by
/// the fuzz harness; see `fuzz/fuzz_targets/fuzz_open.rs`). We reject up front:
/// a genuine 7z has a correct StartHeaderCRC and a next-header region that fits
/// inside the file.
///
/// LIMITATION: this does not fully close the hole. A crafted 7z with a valid
/// start header but huge internal varint counts (file/block/coder counts) can
/// still drive a large allocation inside the dependency. A complete fix belongs
/// upstream in `sevenz-rust2` (validate every count against the remaining input).
///
/// 7z signature header layout (32 bytes):
///   0..6  magic · 6..8 version · 8..12 StartHeaderCRC (u32 LE)
///   12..20 NextHeaderOffset (u64 LE) · 20..28 NextHeaderSize (u64 LE)
///   28..32 NextHeaderCRC (u32 LE).  StartHeaderCRC covers bytes 12..32.
fn validate_7z_header(path: &Path) -> Result<()> {
    let mut f = File::open(path).map_err(Error::Io)?;
    let mut hdr = [0u8; 32];
    f.read_exact(&mut hdr)
        .map_err(|_| Error::Corrupt("7z: truncated signature header".into()))?;

    let stored_crc = u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
    let mut crc = flate2::Crc::new();
    crc.update(&hdr[12..32]);
    if crc.sum() != stored_crc {
        return Err(Error::Corrupt("7z: bad start-header CRC".into()));
    }

    let next_off = u64::from_le_bytes(hdr[12..20].try_into().unwrap());
    let next_size = u64::from_le_bytes(hdr[20..28].try_into().unwrap());
    let file_len = f.metadata().map_err(Error::Io)?.len();
    // The next header must lie within the file: 32 + offset + size <= len.
    let fits = 32u64
        .checked_add(next_off)
        .and_then(|x| x.checked_add(next_size))
        .is_some_and(|end| end <= file_len);
    if !fits {
        return Err(Error::Corrupt(
            "7z: next-header region exceeds file size".into(),
        ));
    }
    Ok(())
}

/// Как найти запись при обходе архива.
///
/// По позиции искать нельзя: `for_each_entries` отдаёт сперва записи с потоком
/// данных, и только потом каталоги и пустые файлы, а `archive.files` хранит
/// порядок из заголовка. Поэтому запись ищется по имени; имя само по себе не
/// уникально (архив — вход злоумышленника, одинаковые имена в нём законны),
/// поэтому к имени добавлены класс записи и номер повтора.
///
/// Имя не дублируем: оно уже лежит в `Entry::path_raw` с тем же индексом.
struct EntryKey {
    /// Есть ли у записи поток данных. Записи с потоком и без него идут при
    /// обходе двумя отдельными группами, внутри группы порядок заголовка
    /// сохраняется — значит, считать повторы надо внутри своей группы.
    has_stream: bool,
    /// Сколько записей с тем же именем и тем же `has_stream` лежат раньше.
    occurrence: usize,
}

/// Ограничение на длину цели символьной ссылки. Длину задаёт архив, поэтому
/// доверять ей нельзя: без предела «ссылка» с телом на гигабайты съела бы
/// память прямо в `open()`. 4096 — предел пути в Linux (в macOS он вчетверо
/// меньше), настоящая цель в него укладывается всегда.
const MAX_SYMLINK_TARGET: usize = 4096;

/// Приёмник для цели символьной ссылки: копит байты в памяти, но обрывается
/// ошибкой, как только превышен лимит.
struct CappedBuf {
    buf: Vec<u8>,
    limit: usize,
}

impl Write for CappedBuf {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if data.len() > self.limit - self.buf.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "7z: symlink target too long",
            ));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Копирует содержимое одной записи архива в `out`, отыскав её по `name` и
/// `key` — то есть по имени, классу и номеру повтора, а не по позиции обхода.
///
/// Открывает архив заново: `ArchiveReader::new` перечитывает только заголовок,
/// тела распаковываются по ходу обхода. Обход прекращается на нужной записи.
fn read_entry_by_key(
    file_path: &Path,
    password: sevenz_rust2::Password,
    name: &[u8],
    key: &EntryKey,
    out: &mut dyn Write,
) -> Result<()> {
    let file = File::open(file_path).map_err(Error::Io)?;
    let mut seven = sevenz_rust2::ArchiveReader::new(file, password).map_err(map_7z_err)?;

    let mut seen: usize = 0;
    let mut found = false;
    let mut extract_err: Option<Error> = None;

    seven
        .for_each_entries(|entry, reader| {
            if !found && entry.has_stream == key.has_stream && entry.name().as_bytes() == name {
                if seen == key.occurrence {
                    found = true;
                    // Копируем только тело этой записи; `false` прекращает обход,
                    // дальше ничего не распаковывается.
                    if let Err(e) = std::io::copy(reader, out) {
                        extract_err = Some(Error::Io(e));
                    }
                    return Ok(false);
                }
                seen += 1;
            }
            // Не наша запись: пропускаем. В сплошном (solid) архиве это всё
            // равно распаковывает данные — иначе до нужного тела не добраться, —
            // но в памяти мы их не держим.
            std::io::copy(reader, &mut std::io::sink())?;
            Ok(true)
        })
        .map_err(map_7z_err)?;

    if let Some(e) = extract_err {
        return Err(e);
    }
    if !found {
        // Заголовок обещал запись, которой обход не выдал: архив противоречит
        // сам себе. Отдать чужие байты вместо неё нельзя.
        return Err(Error::Corrupt(format!(
            "7z: entry not found while extracting: {}",
            String::from_utf8_lossy(name)
        )));
    }
    Ok(())
}

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
        // Reject malformed start headers before the library can OOM on them.
        validate_7z_header(&file_path)?;
        let mut header_file = File::open(&file_path).map_err(Error::Io)?;
        let archive =
            sevenz_rust2::Archive::read(&mut header_file, &password).map_err(map_7z_err)?;

        // Build entries from header metadata — no payload decompression occurs.
        let raw_names: Vec<Vec<u8>> = archive
            .files
            .iter()
            .map(|f| f.name().as_bytes().to_vec())
            .collect();
        let names = decode_names(&raw_names, opts.encoding_override.as_deref());

        // Build a per-file encryption lookup: does the file's folder use AES?
        // archive.stream_map.file_block_index[i] maps file index → block index
        // (None for files that have no data stream, e.g. empty dirs).
        // Folders whose coder list contains the AES-256/SHA-256 method ID are
        // considered encrypted regardless of whether a password was supplied.
        let aes_id = sevenz_rust2::EncoderMethod::ID_AES256_SHA256;
        let folder_is_encrypted: Vec<bool> = archive
            .blocks
            .iter()
            .map(|folder| {
                folder
                    .coders
                    .iter()
                    .any(|coder| coder.encoder_method_id() == aes_id)
            })
            .collect();

        let mut entries: Vec<Entry> = archive
            .files
            .iter()
            .enumerate()
            .zip(names)
            .map(|((file_idx, file), name)| {
                // Resolve per-entry encryption from the folder coder chain.
                let is_encrypted = archive
                    .stream_map
                    .file_block_index
                    .get(file_idx)
                    .and_then(|&fi| fi)
                    .and_then(|fi| folder_is_encrypted.get(fi))
                    .copied()
                    .unwrap_or(false);
                // 7z stores Windows FILE_ATTRIBUTE_* in windows_attributes.
                // Unix tools (including 7zz on macOS/Linux) set bit 15 (0x8000,
                // FILE_ATTRIBUTE_UNIX_EXTENSION) and place the full st_mode in
                // the high 16 bits: unix_mode = windows_attributes >> 16.
                // We extract the permission bits with & 0o7777.
                const UNIX_EXT_BIT: u32 = 0x8000;
                const S_IFLNK: u32 = 0o120000;
                const S_IFMT: u32 = 0o170000;

                let (kind, mode) = if file.has_windows_attributes
                    && (file.windows_attributes & UNIX_EXT_BIT) != 0
                {
                    let unix_mode = file.windows_attributes >> 16;
                    let perm_bits = unix_mode & 0o7777;
                    let kind = if file.is_directory() {
                        EntryKind::Dir
                    } else if (unix_mode & S_IFMT) == S_IFLNK {
                        // Symlink target is the entry's content — read on demand.
                        // We do not decompress here; leave target empty and let
                        // callers use read_entry() to obtain the target path.
                        EntryKind::Symlink {
                            target: std::path::PathBuf::new(),
                        }
                    } else {
                        EntryKind::File
                    };
                    (kind, Some(perm_bits))
                } else {
                    let kind = if file.is_directory() {
                        EntryKind::Dir
                    } else {
                        EntryKind::File
                    };
                    (kind, None)
                };

                Entry {
                    path_raw: file.name().as_bytes().to_vec(),
                    path: std::path::PathBuf::from(name),
                    kind,
                    size: file.size(),
                    mode,
                    is_encrypted,
                    modified: None,
                }
            })
            .collect();

        // Ключи поиска — по одному на запись, в том же порядке, что и entries.
        // Считаем повторы имени внутри своего класса (с потоком / без).
        let mut seen_names: std::collections::HashMap<(&[u8], bool), usize> =
            std::collections::HashMap::new();
        let keys: Vec<EntryKey> = archive
            .files
            .iter()
            .map(|f| {
                let has_stream = f.has_stream;
                let counter = seen_names
                    .entry((f.name().as_bytes(), has_stream))
                    .or_insert(0);
                let occurrence = *counter;
                *counter += 1;
                EntryKey {
                    has_stream,
                    occurrence,
                }
            })
            .collect();

        // Second pass: populate symlink targets.
        // Symlink content (the link target path) is stored as the entry's payload.
        // Каждая ссылка читается отдельным проходом по архиву, и запись ищется
        // по имени и номеру повтора (см. `EntryKey`): позиция обхода не совпадает
        // с позицией в заголовке, как только в архиве есть хоть один каталог.
        let symlink_indices: Vec<usize> = entries
            .iter()
            .enumerate()
            .filter(|(_, e)| matches!(e.kind, EntryKind::Symlink { .. }))
            .map(|(i, _)| i)
            .collect();

        for sym_idx in symlink_indices {
            let expected_name = entries[sym_idx].path_raw.clone();
            // best-effort: ignore errors — open() must not fail due to symlink target reads.
            // Returns the decoded, non-empty target if one was successfully read.
            let target: Option<PathBuf> = (|| -> Option<PathBuf> {
                // Длина цели ограничена: размер из заголовка — вход злоумышленника.
                let mut sink = CappedBuf {
                    buf: Vec::new(),
                    limit: MAX_SYMLINK_TARGET,
                };
                read_entry_by_key(
                    &file_path,
                    password.clone(),
                    &expected_name,
                    &keys[sym_idx],
                    &mut sink,
                )
                .ok()?;
                let buf = sink.buf;
                // Trim any trailing null bytes, then decode the target with the
                // SAME charset as entry names (honoring opts.encoding_override),
                // matching how tar/zip decode their symlink targets.
                let trimmed: Vec<u8> = buf
                    .iter()
                    .rposition(|&b| b != 0)
                    .map(|p| buf[..=p].to_vec())
                    .unwrap_or_default();
                let s = decode_names(&[trimmed], opts.encoding_override.as_deref())
                    .pop()
                    .unwrap_or_default();
                if s.is_empty() {
                    return None;
                }
                Some(PathBuf::from(s))
            })();

            match target {
                Some(target) => entries[sym_idx].kind = EntryKind::Symlink { target },
                // No usable target was read (empty/unreadable): fall back to a
                // regular File so extraction produces a real file, not a dangling
                // symlink pointing at "".
                None => entries[sym_idx].kind = EntryKind::File,
            }
        }

        Ok(Box::new(SevenZReader {
            file_path,
            password: opts.password.clone(),
            entries,
            keys,
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
    /// Чем искать запись при обходе — по одному ключу на запись `entries`.
    keys: Vec<EntryKey>,
}

impl ArchiveReader for SevenZReader {
    fn format(&self) -> FormatId {
        FormatId::SevenZ
    }

    fn entries(&mut self) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn verify_password(&mut self) -> Result<()> {
        let Some(idx) = self.entries.iter().position(|e| e.is_encrypted) else {
            return Ok(());
        };
        if self.password.is_none() {
            return Err(Error::Encrypted);
        }
        // У AES-7z нет дешёвой проверки заголовка: расшифровываем первую
        // зашифрованную запись «в раковину». Заголовок уже разобран в open(),
        // поэтому отказ при заданном пароле трактуем как неверный пароль.
        // (Ограничение sevenz-rust2: на content-7z чужой пароль иногда даёт
        // мусор без ошибки — см. spec; этот случай поймать нельзя.)
        self.read_entry(idx, &mut std::io::sink())
            .map_err(|_| Error::WrongPassword)
    }

    fn read_entry(&mut self, idx: usize, out: &mut dyn Write) -> Result<()> {
        // Validate index before doing any I/O.
        // `entries` и `keys` строятся из одного и того же `archive.files`, так
        // что одной проверки хватает на оба обращения по индексу.
        let (Some(entry), Some(key)) = (self.entries.get(idx), self.keys.get(idx)) else {
            return Err(Error::InvalidIndex(idx));
        };

        let password: sevenz_rust2::Password = match self.password.as_deref() {
            Some(pw) => pw.into(),
            None => sevenz_rust2::Password::empty(),
        };

        // Ищем запись ПО ИМЕНИ, а не по позиции обхода: `for_each_entries`
        // выдаёт сперва записи с потоком данных и лишь затем каталоги и пустые
        // файлы, тогда как `archive.files` (из него собран `entries`) хранит
        // порядок заголовка. Счётчик обхода поэтому указывает на чужую запись
        // в любом архиве, где есть хотя бы один каталог, — и подменял бы
        // содержимое молча, без ошибки.
        read_entry_by_key(&self.file_path, password, &entry.path_raw, key, out)
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

    /// Fix B: the symlink target must be decoded with the SAME charset layer as
    /// names (honoring an encoding override), not hard-coded UTF-8. This mirrors
    /// the decode applied to the raw target bytes inside `open()`.
    #[test]
    fn symlink_target_honors_encoding_override() {
        // 0xE9 = 'é' in windows-1252; UTF-8 lossy would mangle it to U+FFFD.
        let raw_target = vec![b'c', b'a', b'f', 0xE9];
        let decoded = decode_names(&[raw_target], Some("windows-1252"))
            .pop()
            .unwrap();
        assert_eq!(decoded, "café");
    }

    /// Fix A: an empty (unreadable) target decodes to an empty string, which the
    /// handler treats as "no usable target" and falls back to `EntryKind::File`.
    #[test]
    fn empty_symlink_target_yields_empty_string() {
        let decoded = decode_names(&[Vec::new()], None).pop().unwrap();
        assert!(decoded.is_empty());
    }
}
