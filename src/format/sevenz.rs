use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::archive::{
    ArchiveReader, Confidence, Entry, EntryKind, EntrySink, FormatHandler, FormatId, OpenOptions,
    SinkStep, SinkWriter, Source,
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
/// The internal counts are no longer our problem: since 0.21.3/0.21.4 the
/// dependency bounds every varint count (files, blocks, pack streams, coders,
/// name bytes) against the remaining header input — `bounded_count` in its
/// `reader.rs` — and caps eager pre-allocation. That is exactly the upstream fix
/// this comment used to ask for, so what is left here is the cheap up-front
/// check: a bad start header never reaches the tail-scan recovery at all.
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

/// Ограничение на длину цели символьной ссылки. Длину задаёт архив, поэтому
/// доверять ей нельзя: без предела «ссылка» с телом на гигабайты съела бы
/// память прямо в `open()`. 4096 — предел пути в Linux (в macOS он вчетверо
/// меньше), настоящая цель в него укладывается всегда.
const MAX_SYMLINK_TARGET: usize = 4096;

/// Один проход по одному сплошному блоку.
///
/// Блок 7z — это последовательный поток: до тела пятой записи не добраться,
/// не распаковав четыре предыдущих. Поэтому единственный дешёвый способ взять
/// из блока несколько записей — взять их все за один проход, а чужие тела
/// протащить в раковину. Именно этого и не делал прежний код: он заводил
/// распаковщик заново на каждую запись, и цена распаковки росла квадратично.
///
/// `wanted` — нужные записи этого блока, по возрастанию. Возвращает `true`,
/// если приёмник попросил остановиться совсем.
fn decode_block(
    dec: sevenz_rust2::BlockDecoder<'_, File>,
    first_file: usize,
    wanted: &[usize],
    sink: &mut dyn EntrySink,
) -> Result<bool> {
    let mut file_index = first_file;
    let mut next = 0usize;
    let mut stop = false;
    // Ошибка приёмника: наружу её через `sevenz_rust2::Error` не пронести.
    let mut sink_err: Option<Error> = None;

    let walk = dec.for_each_entries(&mut |_entry, reader| {
        let idx = file_index;
        file_index += 1;

        // Нужное кончилось — хвост блока не распаковываем вовсе.
        if next >= wanted.len() {
            return Ok(false);
        }
        if wanted[next] != idx {
            // Чужое тело. Протащить его через распаковщик всё равно надо —
            // иначе сплошной поток съедет и следующая запись прочтёт чужие
            // байты, — но на диск и в память оно не идёт.
            std::io::copy(reader, &mut std::io::sink())?;
            return Ok(true);
        }
        next += 1;

        match sink.begin(idx) {
            Ok(SinkStep::Body) => {}
            Ok(SinkStep::Skip) => {
                std::io::copy(reader, &mut std::io::sink())?;
                return Ok(true);
            }
            Ok(SinkStep::Stop) => {
                stop = true;
                return Ok(false);
            }
            Err(e) => {
                sink_err = Some(e);
                return Ok(false);
            }
        }

        let mut w = SinkWriter::new(sink);
        let copied = std::io::copy(reader, &mut w);
        let body = match w.take_err() {
            // Ошибка приёмника (в том числе отмена) важнее: `io::Error` донёс
            // бы только текст.
            Some(e) => Err(e),
            None => copied.map(|_| ()).map_err(Error::Io),
        };
        if body.is_err() {
            // Тело не дочитано: домотать, иначе следующая запись блока
            // прочтёт его остаток.
            let _ = std::io::copy(reader, &mut std::io::sink());
        }

        match sink.end(idx, body) {
            Ok(true) => Ok(true),
            Ok(false) => {
                stop = true;
                Ok(false)
            }
            Err(e) => {
                sink_err = Some(e);
                Ok(false)
            }
        }
    });

    if let Some(e) = sink_err {
        return Err(e);
    }
    walk.map_err(map_7z_err)?;
    Ok(stop)
}

/// Что нужно знать проходу, кроме самого файла архива.
struct BlockCtx<'a> {
    archive: &'a sevenz_rust2::Archive,
    password: &'a sevenz_rust2::Password,
    thread_count: u32,
}

/// Приёмник на одну запись: мост от пакетного прохода к обычному
/// `read_entry(idx, out)`.
struct OneEntry<'a> {
    out: &'a mut dyn Write,
    err: Option<Error>,
}

impl EntrySink for OneEntry<'_> {
    fn begin(&mut self, _idx: usize) -> Result<SinkStep> {
        Ok(SinkStep::Body)
    }

    fn write_body(&mut self, buf: &[u8]) -> Result<()> {
        self.out.write_all(buf).map_err(Error::Io)
    }

    fn end(&mut self, _idx: usize, outcome: Result<()>) -> Result<bool> {
        self.err = outcome.err();
        Ok(false)
    }
}

/// Приёмник для целей символьных ссылок: копит тела в памяти, каждое — под
/// потолком, потому что длину задаёт архив.
struct TargetSink {
    got: std::collections::HashMap<usize, Vec<u8>>,
    cur: Option<(usize, Vec<u8>)>,
}

impl EntrySink for TargetSink {
    fn begin(&mut self, idx: usize) -> Result<SinkStep> {
        self.cur = Some((idx, Vec::new()));
        Ok(SinkStep::Body)
    }

    fn write_body(&mut self, buf: &[u8]) -> Result<()> {
        let Some((_, acc)) = self.cur.as_mut() else {
            return Err(Error::Corrupt("7z: symlink body without begin".into()));
        };
        if acc.len() + buf.len() > MAX_SYMLINK_TARGET {
            return Err(Error::Corrupt("7z: symlink target too long".into()));
        }
        acc.extend_from_slice(buf);
        Ok(())
    }

    fn end(&mut self, _idx: usize, outcome: Result<()>) -> Result<bool> {
        // Неудачную ссылку просто не запоминаем: `open()` из-за неё падать не
        // должен, а звать будет нечего — запись станет обычным файлом.
        if let (Some((idx, acc)), Ok(())) = (self.cur.take(), outcome) {
            self.got.insert(idx, acc);
        }
        Ok(true)
    }
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

        let entries: Vec<Entry> = archive
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
                    // The flag has to be consulted: in 7z the timestamp is
                    // optional, and the raw field of an entry that carries none
                    // reads as the year 1601, not as "unknown". Stamping today's
                    // date on a file is bad; stamping 1601 is worse.
                    modified: file
                        .has_last_modified_date
                        .then(|| u64::from(file.last_modified_date()))
                        .and_then(crate::datetime::filetime_to_systime),
                    is_resource_fork: false,
                }
            })
            .collect();

        let symlink_indices: Vec<usize> = entries
            .iter()
            .enumerate()
            .filter(|(_, e)| matches!(e.kind, EntryKind::Symlink { .. }))
            .map(|(i, _)| i)
            .collect();

        let mut reader = SevenZReader {
            file_path,
            password: opts.password.clone(),
            entries,
            archive,
            thread_count: default_thread_count(),
        };

        // Second pass: populate symlink targets.
        // Symlink content (the link target path) is stored as the entry's payload.
        // Все ссылки читаются **одним** проходом: раньше на каждую заводился
        // свой обход всего архива, и открытие образа с десятком ссылок стоило
        // десяти распаковок подряд.
        if !symlink_indices.is_empty() {
            let mut targets = TargetSink {
                got: std::collections::HashMap::new(),
                cur: None,
            };
            // best-effort: ошибка чтения целей не должна валить open().
            let _ = reader.read_entries(&symlink_indices, &mut targets);

            for sym_idx in symlink_indices {
                // Trim any trailing null bytes, then decode the target with the
                // SAME charset as entry names (honoring opts.encoding_override),
                // matching how tar/zip decode their symlink targets.
                let target = targets.got.get(&sym_idx).and_then(|buf| {
                    let trimmed: Vec<u8> = buf
                        .iter()
                        .rposition(|&b| b != 0)
                        .map(|p| buf[..=p].to_vec())
                        .unwrap_or_default();
                    let s = decode_names(&[trimmed], opts.encoding_override.as_deref())
                        .pop()
                        .unwrap_or_default();
                    (!s.is_empty()).then(|| PathBuf::from(s))
                });

                match target {
                    Some(target) => reader.entries[sym_idx].kind = EntryKind::Symlink { target },
                    // No usable target was read (empty/unreadable): fall back to a
                    // regular File so extraction produces a real file, not a dangling
                    // symlink pointing at "".
                    None => reader.entries[sym_idx].kind = EntryKind::File,
                }
            }
        }

        Ok(Box::new(reader))
    }
}

/// Столько же потоков, сколько берёт сам `sevenz_rust2::ArchiveReader::new`:
/// на LZMA2, упакованном с поддержкой многопоточности, это ускоряет распаковку,
/// а на остальных кодеках ничего не меняет.
fn default_thread_count() -> u32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1)
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
/// `open()` only parses the 7z header (zero payload decompression). Разобранный
/// заголовок хранится здесь целиком: по нему видно, в каком сплошном блоке
/// лежит каждая запись, а значит — какие записи можно взять одним проходом.
struct SevenZReader {
    /// Path to the archive file on disk.
    file_path: PathBuf,
    /// Optional password (stored as the original UTF-8 string).
    password: Option<String>,
    /// Entry metadata populated at open time (headers only, no payloads).
    entries: Vec<Entry>,
    /// Разобранный заголовок: карта «запись → блок» и границы блоков.
    archive: sevenz_rust2::Archive,
    thread_count: u32,
}

impl SevenZReader {
    /// Проход по архиву, отдающий приёмнику запрошенные записи.
    ///
    /// Идёт блоками: все нужные записи одного блока берутся за один его
    /// разбор, блоки без нужных записей не открываются вовсе. Последнее и
    /// лечит несплошной архив, где блок заведён на каждый файл.
    fn walk(&mut self, indices: &[usize], sink: &mut dyn EntrySink) -> Result<()> {
        let password: sevenz_rust2::Password = match self.password.as_deref() {
            Some(pw) => pw.into(),
            None => sevenz_rust2::Password::empty(),
        };
        let ctx = BlockCtx {
            archive: &self.archive,
            password: &password,
            thread_count: self.thread_count,
        };
        let mut source = File::open(&self.file_path).map_err(Error::Io)?;

        let mut i = 0usize;
        while i < indices.len() {
            let idx = indices[i];
            if idx >= self.entries.len() {
                return Err(Error::InvalidIndex(idx));
            }

            // Границы блока, которому принадлежит запись. Файлы блока лежат в
            // заголовке подряд, поэтому все нужные записи блока идут в
            // `indices` тоже подряд.
            let mut handled = false;
            if let Some(b) = ctx
                .archive
                .stream_map
                .file_block_index
                .get(idx)
                .copied()
                .flatten()
                && let Some(&start) = ctx.archive.stream_map.block_first_file_index.get(b)
            {
                let dec = sevenz_rust2::BlockDecoder::new(
                    ctx.thread_count,
                    b,
                    ctx.archive,
                    ctx.password,
                    &mut source,
                );
                // Сколько записей отдаст сам распаковщик — спрашиваем у него,
                // а не считаем по заголовку: разойтись эти два числа не должны,
                // и если разойдутся, то не по-нашему.
                let end = start.saturating_add(dec.entry_count());
                if idx >= start && idx < end {
                    let mut j = i;
                    while j < indices.len() && indices[j] >= start && indices[j] < end {
                        j += 1;
                    }
                    if decode_block(dec, start, &indices[i..j], sink)? {
                        return Ok(());
                    }
                    i = j;
                    handled = true;
                }
            }
            if handled {
                continue;
            }

            // Тела у записи нет. Обычный случай — каталог или пустой файл: 7z
            // хранит их без потока данных. Редкий — заголовок противоречит сам
            // себе: запись обещает данные, а в границы своего блока не
            // попадает. Подсунуть вместо неё пустоту нельзя, это была бы тихая
            // потеря содержимого.
            let claims_data = ctx
                .archive
                .files
                .get(idx)
                .is_some_and(|f| f.has_stream && f.size > 0);
            match sink.begin(idx)? {
                SinkStep::Stop => return Ok(()),
                SinkStep::Skip => {}
                SinkStep::Body => {
                    let outcome = if claims_data {
                        Err(Error::Corrupt(format!(
                            "7z: entry {idx} claims data but lies outside its block"
                        )))
                    } else {
                        Ok(())
                    };
                    if !sink.end(idx, outcome)? {
                        return Ok(());
                    }
                }
            }
            i += 1;
        }
        Ok(())
    }
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
        if idx >= self.entries.len() {
            return Err(Error::InvalidIndex(idx));
        }
        let mut one = OneEntry { out, err: None };
        self.walk(&[idx], &mut one)?;
        match one.err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn read_entries(&mut self, indices: &[usize], sink: &mut dyn EntrySink) -> Result<()> {
        self.walk(indices, sink)
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
