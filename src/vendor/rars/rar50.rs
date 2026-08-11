use crate::vendor::rars::crc32::crc32;
use crate::vendor::rars::crypto::cache::DerivedSecretCache;
use crate::vendor::rars::crypto::rar50::{Rar50Cipher, Rar50Keys};
use crate::vendor::rars::detect::{ArchiveSignature, RAR50_SIGNATURE};
use crate::vendor::rars::error::{Error, Result};
use crate::vendor::rars::io_util::{align16 as checked_align16, read_exact_at, read_u32};
pub(crate) use crate::vendor::rars::source::ArchiveSource;
use crate::vendor::rars::version::ArchiveFamily;
use std::fs::File;
use std::io::Read;
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;

mod blake2sp;
mod extract;

pub use extract::extract_volumes_to_with_redirections;

const HEAD_MAIN: u64 = 1;
const HEAD_FILE: u64 = 2;
const HEAD_SERVICE: u64 = 3;
const HEAD_CRYPT: u64 = 4;
const HEAD_END: u64 = 5;

const HFL_EXTRA: u64 = 0x0001;
const HFL_DATA: u64 = 0x0002;
const HFL_SPLIT_BEFORE: u64 = 0x0008;
const HFL_SPLIT_AFTER: u64 = 0x0010;

const MHFL_VOLUME: u64 = 0x0001;
const MHFL_VOLUME_NUMBER: u64 = 0x0002;
const MHFL_SOLID: u64 = 0x0004;

const FHFL_DIRECTORY: u64 = 0x0001;
const FHFL_MTIME: u64 = 0x0002;
const FHFL_CRC32: u64 = 0x0004;

const MHEXTRA_LOCATOR: u64 = 0x01;
const MHEXTRA_LOCATOR_QUICK_OPEN: u64 = 0x0001;
const MHEXTRA_LOCATOR_RECOVERY: u64 = 0x0002;

const FHEXTRA_CRYPT: u64 = 0x01;
const FHEXTRA_HASH: u64 = 0x02;
// NEWTUA: запись времени файла. Апстрим её не разбирал вовсе — см.
// `parse_file_time_record`.
const FHEXTRA_HTIME: u64 = 0x03;
const FHEXTRA_HTIME_UNIXTIME: u64 = 0x0001;
const FHEXTRA_HTIME_MTIME: u64 = 0x0002;
const FHEXTRA_REDIR: u64 = 0x05;
const FHEXTRA_SUBDATA: u64 = 0x07;
const MHEXTRA_ARCHIVE_METADATA: u64 = 0x02;
const MHEXTRA_ARCHIVE_METADATA_NAME: u64 = 0x0001;
const MHEXTRA_ARCHIVE_METADATA_TIME: u64 = 0x0002;

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Archive {
    /// NEWTUA: `allow(dead_code)` — где кончилась самораспаковывающая
    /// заглушка. Разбор это поле заполняет, движок его не читает: за
    /// самораспаковку у нас отвечает `format/sfx.rs`, а сюда архив приходит
    /// уже целым файлом. Убрать поле — значит потерять единственное место,
    /// где смещение вообще сохранено.
    #[allow(dead_code)]
    pub sfx_offset: usize,
    pub main: MainHeader,
    pub blocks: Vec<Block>,
    source: ArchiveSource,
    /// NEWTUA: кэш выведенного ключа шифрования, тикет 33. Живёт на архиве, а
    /// не на записи, потому что соль и число итераций в архиве одни на всех, а
    /// вывод ключа стоит 32 768 раундов HMAC.
    key_cache: Rar50KeyCache,
}

/// NEWTUA (тикет 33): выведенный ключ RAR 5, запомненный на весь архив.
///
/// Ключ кэша — «пароль + соль + число итераций»; зачем кэш вообще и почему
/// промах обязателен, написано у самого типа в `crypto/cache.rs`.
#[derive(Debug, Default, Clone)]
pub(crate) struct Rar50KeyCache {
    inner: DerivedSecretCache<([u8; 16], u8), Rar50Keys>,
}

impl Rar50KeyCache {
    /// Выводит ключ или отдаёт запомненный. Проверку пароля по `check_value`
    /// делает вызывающий: она стоит одного SHA-256 и обязана идти и на
    /// попадании в кэш тоже, иначе путь «неверный пароль» изменился бы.
    fn derive(&self, password: &[u8], salt: [u8; 16], kdf_count: u8) -> Result<Rar50Keys> {
        self.inner.get_or_derive(password, (salt, kdf_count), || {
            Rar50Keys::derive(password, salt, kdf_count).map_err(map_rar50_crypto_error)
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MainHeader {
    pub block: BlockHeader,
    pub archive_flags: u64,
    pub volume_number: Option<u64>,
    pub extras: Vec<MainExtraRecord>,
}

impl MainHeader {
    pub fn is_volume(&self) -> bool {
        self.archive_flags & MHFL_VOLUME != 0
    }

    pub fn is_solid(&self) -> bool {
        self.archive_flags & MHFL_SOLID != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MainExtraRecord {
    Locator(LocatorRecord),
    ArchiveMetadata(ArchiveMetadataRecord),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LocatorRecord {
    pub flags: u64,
    pub quick_open_offset: Option<u64>,
    pub recovery_record_offset: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ArchiveMetadataRecord {
    pub flags: u64,
    pub name: Option<Vec<u8>>,
    pub creation_time: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Block {
    File(FileHeader),
    Service(FileHeader),
    End(BlockHeader),
    Unknown(BlockHeader),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BlockHeader {
    pub header_crc: u32,
    pub header_size: u64,
    pub header_type: u64,
    pub flags: u64,
    pub extra_area_size: Option<u64>,
    pub data_size: Option<u64>,
    pub offset: usize,
    // Type-specific header bytes are archive-relative. Payload bytes are
    // source-absolute so SFX-prefixed archives can be read directly.
    pub header_range: Range<usize>,
    pub data_range: Range<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FileHeader {
    pub block: BlockHeader,
    pub file_flags: u64,
    pub unpacked_size: u64,
    pub attributes: u64,
    pub mtime: Option<u32>,
    pub data_crc32: Option<u32>,
    pub compression_info: u64,
    pub host_os: u64,
    pub name: Vec<u8>,
    pub hash: Option<FileHash>,
    pub redirection: Option<FileRedirection>,
    pub service_data: Option<Vec<u8>>,
    pub encrypted: bool,
    pub encryption: Option<FileEncryption>,
    crypto: Option<FileCryptoState>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FileRedirection {
    pub redirection_type: u64,
    pub flags: u64,
    pub target_name: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FileHash {
    pub hash_type: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FileEncryption {
    pub version: u64,
    pub flags: u64,
    pub kdf_count: u8,
    pub salt: [u8; 16],
    pub iv: [u8; 16],
    pub check_value: Option<[u8; 12]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileCryptoState {
    keys: Rar50Keys,
    iv: [u8; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct CompressionInfo {
    pub algorithm_version: u8,
    pub solid: bool,
    pub method: u8,
    pub dictionary_power: u8,
    pub dictionary_fraction: u8,
    pub rar5_compat: bool,
    pub dictionary_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExtractedEntryMeta {
    pub name: Vec<u8>,
    pub file_time: u32,
    pub attr: u64,
    pub host_os: u64,
    pub is_directory: bool,
}

impl FileHeader {
    pub fn is_split_before(&self) -> bool {
        self.block.flags & HFL_SPLIT_BEFORE != 0
    }

    pub fn is_split_after(&self) -> bool {
        self.block.flags & HFL_SPLIT_AFTER != 0
    }

    pub fn is_directory(&self) -> bool {
        self.file_flags & FHFL_DIRECTORY != 0
    }

    pub fn is_stored(&self) -> bool {
        compression_method(self.compression_info) == 0
    }

    pub fn decoded_compression_info(&self) -> Result<CompressionInfo> {
        decode_compression_info(self.compression_info)
    }

    pub fn packed_size(&self) -> u64 {
        self.block.data_size.unwrap_or(0)
    }

    fn uses_hash_mac(&self) -> bool {
        self.encryption
            .as_ref()
            .is_some_and(|encryption| encryption.flags & 0x0002 != 0)
    }
}

impl Archive {
    pub fn parse_path_with_signature(
        path: impl AsRef<Path>,
        signature: ArchiveSignature,
        options: crate::vendor::rars::ArchiveReadOptions<'_>,
    ) -> Result<Self> {
        // NEWTUA: ячейка ключа приходит сюда, а не приделывается к тому после
        // разбора — при `-hp` ключ нужен, чтобы прочитать заголовки.
        let key_cache = options
            .volume_keys
            .map(|keys| keys.rar50.clone())
            .unwrap_or_default();
        let password = options.password;
        if signature.family != ArchiveFamily::Rar50Plus {
            return Err(Error::UnsupportedSignature);
        }
        let path = Arc::new(path.as_ref().to_path_buf());
        let mut file = File::open(path.as_ref())?;
        let len = file.metadata()?.len();
        let archive_len = usize::try_from(len)
            .map_err(|_| Error::InvalidHeader("RAR 5 archive size overflows usize"))?
            .checked_sub(signature.offset)
            .ok_or(Error::TooShort)?;
        Self::parse_file_backed(
            &mut file,
            archive_len,
            signature.offset,
            ArchiveSource::file(path),
            password,
            key_cache,
        )
    }

    fn parse_file_backed(
        file: &mut File,
        archive_len: usize,
        sfx_offset: usize,
        source: ArchiveSource,
        password: Option<&[u8]>,
        key_cache: Rar50KeyCache,
    ) -> Result<Self> {
        let signature = read_exact_at(file, sfx_offset, RAR50_SIGNATURE.len())?;
        if signature != RAR50_SIGNATURE {
            return Err(Error::UnsupportedSignature);
        }

        let file_cell = std::cell::RefCell::new(file);
        let (main, blocks) = parse_archive_blocks(
            archive_len,
            password,
            &key_cache,
            |offset| {
                read_block_header_at(&mut file_cell.borrow_mut(), offset, archive_len, sfx_offset)
            },
            |offset, keys| {
                read_encrypted_block_header_at(
                    &mut file_cell.borrow_mut(),
                    offset,
                    archive_len,
                    sfx_offset,
                    keys,
                )
            },
        )?;

        Ok(Self {
            sfx_offset,
            main,
            blocks,
            source,
            key_cache,
        })
    }

    fn range_reader(&self, range: Range<usize>) -> Result<Box<dyn Read + '_>> {
        self.source.range_reader(range)
    }

    pub fn files(&self) -> impl Iterator<Item = &FileHeader> {
        self.blocks.iter().filter_map(|block| match block {
            Block::File(file) => Some(file),
            _ => None,
        })
    }
}

fn parse_main_header_bytes(parsed: &ParsedBlockHeader) -> Result<MainHeader> {
    let mut reader = HeaderReader::new(&parsed.header, parsed.type_specific_range.clone())?;
    let archive_flags = reader.read_vint()?;
    let volume_number = if archive_flags & MHFL_VOLUME_NUMBER != 0 {
        Some(reader.read_vint()?)
    } else {
        None
    };
    let extras = parse_main_extra_area(&parsed.header, parsed.extra_range.clone())?;
    Ok(MainHeader {
        block: parsed.block.clone(),
        archive_flags,
        volume_number,
        extras,
    })
}

fn parse_main_extra_area(input: &[u8], range: Range<usize>) -> Result<Vec<MainExtraRecord>> {
    let mut records = Vec::new();
    parse_extra_records(input, range, |record_type, data| match record_type {
        MHEXTRA_LOCATOR => {
            let mut reader = SliceReader::new(input, data.start, data.end);
            let flags = reader.read_vint()?;
            let quick_open_offset = if flags & MHEXTRA_LOCATOR_QUICK_OPEN != 0 {
                Some(reader.read_vint()?)
            } else {
                None
            };
            let recovery_record_offset = if flags & MHEXTRA_LOCATOR_RECOVERY != 0 {
                Some(reader.read_vint()?)
            } else {
                None
            };
            // LOCATOR records are intentionally forward-compatible: known
            // offsets are parsed and any trailing bytes remain reserved for
            // future flags.
            records.push(MainExtraRecord::Locator(LocatorRecord {
                flags,
                quick_open_offset,
                recovery_record_offset,
            }));
            Ok(())
        }
        MHEXTRA_ARCHIVE_METADATA => {
            let mut reader = SliceReader::new(input, data.start, data.end);
            let flags = reader.read_vint()?;
            let name = if flags & MHEXTRA_ARCHIVE_METADATA_NAME != 0 {
                let name_len = usize_from_u64(
                    reader.read_vint()?,
                    "RAR 5 archive metadata name length overflows usize",
                )?;
                Some(reader.read_bytes(name_len)?.to_vec())
            } else {
                None
            };
            let creation_time = if flags & MHEXTRA_ARCHIVE_METADATA_TIME != 0 {
                Some(reader.read_u64()?)
            } else {
                None
            };
            if reader.pos != reader.end {
                return Err(Error::InvalidHeader(
                    "RAR 5 archive metadata record has trailing bytes",
                ));
            }
            records.push(MainExtraRecord::ArchiveMetadata(ArchiveMetadataRecord {
                flags,
                name,
                creation_time,
            }));
            Ok(())
        }
        _ => Ok(()),
    })?;
    Ok(records)
}

fn parse_file_header_bytes(parsed: &ParsedBlockHeader) -> Result<FileHeader> {
    let mut reader = HeaderReader::new(&parsed.header, parsed.type_specific_range.clone())?;
    let file_flags = reader.read_vint()?;
    let unpacked_size = reader.read_vint()?;
    let attributes = reader.read_vint()?;
    let mtime = if file_flags & FHFL_MTIME != 0 {
        Some(reader.read_u32()?)
    } else {
        None
    };
    let data_crc32 = if file_flags & FHFL_CRC32 != 0 {
        Some(reader.read_u32()?)
    } else {
        None
    };
    let compression_info = reader.read_vint()?;
    let host_os = reader.read_vint()?;
    let name_len = usize_from_u64(
        reader.read_vint()?,
        "RAR 5 file name length overflows usize",
    )?;
    let name = reader.read_bytes(name_len)?.to_vec();
    let mut file = FileHeader {
        block: parsed.block.clone(),
        file_flags,
        unpacked_size,
        attributes,
        mtime,
        data_crc32,
        compression_info,
        host_os,
        name,
        hash: None,
        redirection: None,
        service_data: None,
        encrypted: false,
        encryption: None,
        crypto: None,
    };
    parse_file_extra_area(&parsed.header, parsed.extra_range.clone(), &mut file)?;
    Ok(file)
}

fn parse_file_extra_area(input: &[u8], range: Range<usize>, file: &mut FileHeader) -> Result<()> {
    if file.block.extra_area_size.is_none() {
        return Ok(());
    }
    parse_extra_records(input, range, |record_type, data| {
        match record_type {
            FHEXTRA_CRYPT => {
                file.encrypted = true;
                file.encryption = Some(parse_file_encryption_record(input, data)?);
            }
            FHEXTRA_HASH => {
                let (hash_type, hash_type_len) = read_vint_at(input, data.start, data.end)?;
                file.hash = Some(FileHash {
                    hash_type,
                    data: input[data.start + hash_type_len..data.end].to_vec(),
                });
            }
            FHEXTRA_HTIME => {
                if let Some(mtime) = parse_file_time_record(input, data)? {
                    file.mtime = Some(mtime);
                }
            }
            FHEXTRA_REDIR => {
                file.redirection = Some(parse_file_redirection_record(input, data)?);
            }
            FHEXTRA_SUBDATA => {
                file.service_data = Some(input[data].to_vec());
            }
            _ => {}
        }
        Ok(())
    })
}

/// NEWTUA: время изменения из записи `FHEXTRA_HTIME`.
///
/// Апстрим этой записи не знал, и до тикета 26 это было незаметно: RAR читался
/// через libunrar. Между тем современный `rar` (проверено на 7.22) флаг
/// `FHFL_MTIME` в заголовке не ставит вовсе и кладёт время только сюда — либо
/// секундами Unix, либо восьмибайтовым `FILETIME` Windows (сотни наносекунд от
/// 1601-01-01). Без разбора этой записи у архивов RAR 5, собранных за последние
/// годы, времени нет ни у одной записи.
///
/// Наружу отдаются целые секунды от эпохи Unix — столько же вмещает поле
/// заголовка и столько же показывает `unar`. Даты до 1970 года пропускаются:
/// поле беззнаковое, а прежний путь (слово MS-DOS) не выражал и того, что
/// раньше 1980-го. Время создания и доступа лежит в этой же записи и пока не
/// читается — за ними придёт тикет 15.
fn parse_file_time_record(input: &[u8], range: Range<usize>) -> Result<Option<u32>> {
    let mut reader = HeaderReader::new(input, range)?;
    let flags = reader.read_vint()?;
    if flags & FHEXTRA_HTIME_MTIME == 0 {
        return Ok(None);
    }
    // Время изменения лежит первым из трёх, поэтому дочитывать до него нечего.
    if flags & FHEXTRA_HTIME_UNIXTIME != 0 {
        return Ok(Some(u32::from_le_bytes(reader.read_array()?)));
    }
    Ok(windows_filetime_to_unix_seconds(u64::from_le_bytes(
        reader.read_array()?,
    )))
}

/// Сотни наносекунд от 1601-01-01 — в целые секунды от 1970-01-01.
fn windows_filetime_to_unix_seconds(filetime: u64) -> Option<u32> {
    const EPOCH_DIFFERENCE: u64 = 11_644_473_600;
    let seconds = filetime / 10_000_000;
    u32::try_from(seconds.checked_sub(EPOCH_DIFFERENCE)?).ok()
}

fn parse_file_redirection_record(input: &[u8], range: Range<usize>) -> Result<FileRedirection> {
    let (redirection_type, type_len) = read_vint_at(input, range.start, range.end)?;
    let flags_start = range.start + type_len;
    let (flags, flags_len) = read_vint_at(input, flags_start, range.end)?;
    let name_len_start = flags_start + flags_len;
    let (name_len, name_len_len) = read_vint_at(input, name_len_start, range.end)?;
    let name_start = name_len_start + name_len_len;
    let name_len = usize::try_from(name_len).map_err(|_| {
        Error::InvalidHeader("RAR 5 file redirection target length overflows host address size")
    })?;
    let name_end = name_start
        .checked_add(name_len)
        .ok_or(Error::InvalidHeader(
            "RAR 5 file redirection target length overflows",
        ))?;
    if name_end != range.end {
        return Err(Error::InvalidHeader(
            "RAR 5 file redirection record has trailing bytes",
        ));
    }
    Ok(FileRedirection {
        redirection_type,
        flags,
        target_name: input[name_start..name_end].to_vec(),
    })
}

fn parse_file_encryption_record(input: &[u8], range: Range<usize>) -> Result<FileEncryption> {
    let (version, version_len) = read_vint_at(input, range.start, range.end)?;
    let flags_pos = range.start + version_len;
    let (flags, flags_len) = read_vint_at(input, flags_pos, range.end)?;
    let mut pos = flags_pos + flags_len;
    if pos >= range.end {
        return Err(Error::TooShort);
    }
    let kdf_count = input[pos];
    pos += 1;
    let salt = read_array_at::<16>(input, &mut pos, range.end)?;
    let iv = read_array_at::<16>(input, &mut pos, range.end)?;
    let check_value = if flags & 0x0001 != 0 {
        Some(read_array_at::<12>(input, &mut pos, range.end)?)
    } else {
        None
    };
    if pos != range.end {
        return Err(Error::InvalidHeader(
            "RAR 5 file encryption record has trailing bytes",
        ));
    }
    Ok(FileEncryption {
        version,
        flags,
        kdf_count,
        salt,
        iv,
        check_value,
    })
}

fn parse_archive_encryption_header(
    parsed: &ParsedBlockHeader,
    password: Option<&[u8]>,
    key_cache: &Rar50KeyCache,
) -> Result<Rar50Keys> {
    let password = password.ok_or(Error::NeedPassword)?;
    let mut reader = HeaderReader::new(&parsed.header, parsed.type_specific_range.clone())?;
    let version = reader.read_vint()?;
    if version != 0 {
        return Err(Error::UnsupportedFeature {
            version: crate::vendor::rars::version::ArchiveVersion::Rar50,
            feature: "RAR 5 unknown header encryption version",
        });
    }
    let flags = reader.read_vint()?;
    let kdf_count = reader.read_byte()?;
    let salt = reader.read_array::<16>()?;
    let check_value = if flags & 0x0001 != 0 {
        Some(reader.read_array::<12>()?)
    } else {
        None
    };
    if reader.pos != reader.range.end {
        return Err(Error::InvalidHeader(
            "RAR 5 archive encryption header has trailing bytes",
        ));
    }
    // NEWTUA (тикет 33): через тот же кэш. У архива с зашифрованными
    // заголовками (`rar a -hp`) соль здесь и соль в записях совпадают, так что
    // на весь архив остаётся один вывод ключа, а не два.
    let keys = key_cache.derive(password, salt, kdf_count)?;
    if let Some(check_value) = check_value {
        keys.check_password(&check_value)
            .map_err(map_rar50_crypto_error)?;
    }
    Ok(keys)
}

/// Ключ записи по её записи шифрования: проверить версию, вывести (или взять из
/// кэша), сверить пароль.
///
/// NEWTUA: одно место на два пути. Правило приёма зашифрованной записи нужно и
/// разбору (`attach_file_crypto`), и распаковке
/// (`extract.rs`, `crypto_with_password`), а лежало оно там двумя копиями —
/// тикет 33 чуть не развёл их окончательно, протащив кэш в обе. Разойдись они,
/// разбор и распаковка стали бы принимать разные архивы.
pub(super) fn keys_from_encryption(
    encryption: &FileEncryption,
    password: &[u8],
    key_cache: &Rar50KeyCache,
) -> Result<Rar50Keys> {
    if encryption.version != 0 {
        return Err(Error::UnsupportedFeature {
            version: crate::vendor::rars::version::ArchiveVersion::Rar50,
            feature: "RAR 5 unknown file encryption version",
        });
    }
    // NEWTUA (тикет 33): через кэш. Иначе ключ выводился заново на каждую
    // запись при распаковке и на каждый заголовок при разборе архива с
    // зашифрованными заголовками (`rar a -hp`).
    let keys = key_cache.derive(password, encryption.salt, encryption.kdf_count)?;
    if let Some(check_value) = encryption.check_value {
        keys.check_password(&check_value)
            .map_err(map_rar50_crypto_error)?;
    }
    Ok(keys)
}

fn attach_file_crypto(
    file: &mut FileHeader,
    password: Option<&[u8]>,
    key_cache: &Rar50KeyCache,
) -> Result<()> {
    if !file.encrypted || file.crypto.is_some() {
        return Ok(());
    }
    let Some(password) = password else {
        return Ok(());
    };
    let encryption = file.encryption.as_ref().ok_or(Error::InvalidHeader(
        "RAR 5 encrypted file is missing encryption record",
    ))?;
    let keys = keys_from_encryption(encryption, password, key_cache)?;
    file.crypto = Some(FileCryptoState {
        keys,
        iv: encryption.iv,
    });
    Ok(())
}

fn attach_service_crypto(
    service: &mut FileHeader,
    password: Option<&[u8]>,
    key_cache: &Rar50KeyCache,
) -> Result<()> {
    // WinRAR can emit encrypted QO metadata whose service-local password
    // check does not validate with the archive password. QuickOpen is an
    // optional cache, so keep archive parsing and file extraction independent
    // from that service.
    if service.name == b"QO" {
        return Ok(());
    }
    attach_file_crypto(service, password, key_cache)
}

fn map_rar50_crypto_error(error: crate::vendor::rars::crypto::rar50::Error) -> Error {
    match error {
        crate::vendor::rars::crypto::rar50::Error::KdfCountTooLarge => Error::UnsupportedFeature {
            version: crate::vendor::rars::version::ArchiveVersion::Rar50,
            feature: "RAR 5 KDF count",
        },
        crate::vendor::rars::crypto::rar50::Error::BadPassword => Error::WrongPasswordOrCorruptData,
        crate::vendor::rars::crypto::rar50::Error::UnalignedInput => {
            Error::InvalidHeader("RAR 5 AES input is not block aligned")
        }
    }
}

fn read_array_at<const N: usize>(input: &[u8], pos: &mut usize, end: usize) -> Result<[u8; N]> {
    if pos.checked_add(N).is_none_or(|next| next > end) {
        return Err(Error::TooShort);
    }
    let mut out = [0; N];
    out.copy_from_slice(&input[*pos..*pos + N]);
    *pos += N;
    Ok(out)
}

fn parse_archive_blocks<F, G>(
    archive_len: usize,
    password: Option<&[u8]>,
    key_cache: &Rar50KeyCache,
    mut read_block: F,
    mut read_encrypted_block: G,
) -> Result<(MainHeader, Vec<Block>)>
where
    F: FnMut(usize) -> Result<ParsedBlockHeader>,
    G: FnMut(usize, &Rar50Keys) -> Result<ParsedBlockHeader>,
{
    let mut pos = RAR50_SIGNATURE.len();
    let first = read_block(pos).map_err(|error| error.at_archive_offset(pos))?;
    let header_keys = if first.block.header_type == HEAD_CRYPT {
        pos = first.next_offset;
        Some(parse_archive_encryption_header(
            &first, password, key_cache,
        )?)
    } else {
        None
    };

    let main_pos = pos;
    let main_block;
    let first = if let Some(keys) = &header_keys {
        main_block =
            read_encrypted_block(pos, keys).map_err(|error| error.at_archive_offset(pos))?;
        &main_block
    } else {
        &first
    };
    if first.block.header_type != HEAD_MAIN {
        return Err(Error::InvalidHeader("RAR 5 main header is missing"));
    }
    let main = parse_main_header_bytes(first).map_err(|error| error.at_archive_offset(main_pos))?;
    pos = first.next_offset;

    let mut blocks = Vec::new();
    while pos < archive_len {
        let parsed = if let Some(keys) = &header_keys {
            read_encrypted_block(pos, keys).map_err(|error| error.at_archive_offset(pos))?
        } else {
            read_block(pos).map_err(|error| error.at_archive_offset(pos))?
        };
        let next = parsed.next_offset;
        match parsed.block.header_type {
            HEAD_FILE => {
                let mut file = parse_file_header_bytes(&parsed)
                    .map_err(|error| error.at_archive_offset(pos))?;
                attach_file_crypto(&mut file, password, key_cache)
                    .map_err(|error| error.at_archive_offset(pos))?;
                blocks.push(Block::File(file));
            }
            HEAD_SERVICE => {
                let mut service = parse_file_header_bytes(&parsed)
                    .map_err(|error| error.at_archive_offset(pos))?;
                attach_service_crypto(&mut service, password, key_cache)
                    .map_err(|error| error.at_archive_offset(pos))?;
                blocks.push(Block::Service(service));
            }
            HEAD_CRYPT => {
                return Err(Error::UnsupportedFeature {
                    version: crate::vendor::rars::version::ArchiveVersion::Rar50,
                    feature: "RAR 5 encrypted headers",
                });
            }
            HEAD_END => {
                blocks.push(Block::End(parsed.block));
                break;
            }
            _ => blocks.push(Block::Unknown(parsed.block)),
        }
        pos = next;
    }

    Ok((main, blocks))
}

fn parse_extra_records<F>(input: &[u8], range: Range<usize>, mut handle: F) -> Result<()>
where
    F: FnMut(u64, Range<usize>) -> Result<()>,
{
    let mut pos = range.start;
    while pos < range.end {
        let record_start = pos;
        let (record_size, size_len) = read_vint_at(input, pos, range.end)?;
        pos += size_len;
        let record_payload_len =
            usize_from_u64(record_size, "RAR 5 extra record size overflows usize")?;
        let record_end = pos
            .checked_add(record_payload_len)
            .ok_or(Error::InvalidHeader(
                "RAR 5 extra record size overflows usize",
            ))?;
        if record_end > range.end {
            return Err(Error::TooShort);
        }
        let (record_type, type_len) = read_vint_at(input, pos, record_end)?;
        let data_start = pos + type_len;
        handle(record_type, data_start..record_end)?;
        if record_end <= record_start {
            return Err(Error::InvalidHeader("RAR 5 extra record does not advance"));
        }
        pos = record_end;
    }
    Ok(())
}

struct ParsedBlockHeader {
    block: BlockHeader,
    header: Vec<u8>,
    type_specific_range: Range<usize>,
    extra_range: Range<usize>,
    next_offset: usize,
}

fn read_block_header_at(
    file: &mut File,
    offset: usize,
    archive_len: usize,
    sfx_offset: usize,
) -> Result<ParsedBlockHeader> {
    let remaining = archive_len.checked_sub(offset).ok_or(Error::TooShort)?;
    if remaining < 5 {
        return Err(Error::TooShort);
    }
    let prefix_len = remaining.min(14);
    let prefix = read_exact_at(file, sfx_offset + offset, prefix_len)?;
    let header_crc = read_u32(&prefix, 0)?;
    let (header_size, header_size_len) = read_vint_at(&prefix, 4, prefix.len())?;
    let header_body_len = usize_from_u64(header_size, "RAR 5 header size overflows usize")?;
    let header_total = 4usize
        .checked_add(header_size_len)
        .and_then(|size| size.checked_add(header_body_len))
        .ok_or(Error::InvalidHeader("RAR 5 header size overflows usize"))?;
    if header_total > remaining {
        return Err(Error::TooShort);
    }

    let header = read_exact_at(file, sfx_offset + offset, header_total)?;
    parse_block_header_image(
        header,
        offset,
        archive_len,
        sfx_offset,
        header_crc,
        header_total,
    )
}

fn read_encrypted_block_header_at(
    file: &mut File,
    offset: usize,
    archive_len: usize,
    sfx_offset: usize,
    keys: &Rar50Keys,
) -> Result<ParsedBlockHeader> {
    let remaining = archive_len.checked_sub(offset).ok_or(Error::TooShort)?;
    if remaining < 32 {
        return Err(Error::TooShort);
    }
    let first = read_exact_at(file, sfx_offset + offset, 32)?;
    let mut iv = [0; 16];
    iv.copy_from_slice(&first[..16]);
    let mut first_plain = first[16..32].to_vec();
    Rar50Cipher::new(keys.key, iv)
        .decrypt_in_place(&mut first_plain)
        .map_err(map_rar50_crypto_error)?;
    let header_crc = read_u32(&first_plain, 0)?;
    let (header_size, header_size_len) = read_vint_at(&first_plain, 4, first_plain.len())?;
    let header_body_len = usize_from_u64(header_size, "RAR 5 header size overflows usize")?;
    let header_total = 4usize
        .checked_add(header_size_len)
        .and_then(|size| size.checked_add(header_body_len))
        .ok_or(Error::InvalidHeader("RAR 5 header size overflows usize"))?;
    let encrypted_len = checked_align16(header_total, "RAR 5 encrypted header size overflows")?;
    let disk_header_len = 16usize
        .checked_add(encrypted_len)
        .ok_or(Error::InvalidHeader(
            "RAR 5 encrypted header size overflows",
        ))?;
    if disk_header_len > remaining {
        return Err(Error::TooShort);
    }
    let encrypted = read_exact_at(file, sfx_offset + offset + 16, encrypted_len)?;
    let mut header = encrypted;
    Rar50Cipher::new(keys.key, iv)
        .decrypt_in_place(&mut header)
        .map_err(map_rar50_crypto_error)?;
    header.truncate(header_total);

    parse_block_header_image(
        header,
        offset,
        archive_len,
        sfx_offset,
        header_crc,
        disk_header_len,
    )
}

fn parse_block_header_image(
    header: Vec<u8>,
    offset: usize,
    archive_len: usize,
    sfx_offset: usize,
    header_crc: u32,
    disk_header_len: usize,
) -> Result<ParsedBlockHeader> {
    let header_total = header.len();
    let (decoded_header_size, header_size_len) = read_vint_at(&header, 4, header_total)?;
    validate_block_header_crc(&header, header_crc)?;
    let type_start = 4 + header_size_len;
    let mut reader = SliceReader::new(&header, type_start, header_total);
    let header_type = reader.read_vint()?;
    let flags = reader.read_vint()?;
    let extra_area_size = if flags & HFL_EXTRA != 0 {
        Some(reader.read_vint()?)
    } else {
        None
    };
    let data_size = if flags & HFL_DATA != 0 {
        Some(reader.read_vint()?)
    } else {
        None
    };
    let extra_len = extra_area_size
        .map(|size| usize_from_u64(size, "RAR 5 extra area size overflows usize"))
        .transpose()?
        .unwrap_or(0);
    if extra_len > header_total.saturating_sub(reader.pos) {
        return Err(Error::TooShort);
    }
    let type_specific_end = header_total - extra_len;
    let data_len = data_size
        .map(|size| usize_from_u64(size, "RAR 5 data size overflows usize"))
        .transpose()?
        .unwrap_or(0);
    let next_offset = offset
        .checked_add(disk_header_len)
        .and_then(|pos| pos.checked_add(data_len))
        .ok_or(Error::InvalidHeader("RAR 5 data size overflows usize"))?;
    if next_offset > archive_len {
        return Err(Error::TooShort);
    }
    let type_specific_start = reader.pos;
    let data_start = sfx_offset
        .checked_add(offset)
        .and_then(|pos| pos.checked_add(disk_header_len))
        .ok_or(Error::InvalidHeader("RAR 5 data offset overflows usize"))?;
    let data_end = data_start
        .checked_add(data_len)
        .ok_or(Error::InvalidHeader("RAR 5 data size overflows usize"))?;

    Ok(ParsedBlockHeader {
        block: BlockHeader {
            header_crc,
            header_size: decoded_header_size,
            header_type,
            flags,
            extra_area_size,
            data_size,
            offset: sfx_offset + offset,
            header_range: (offset + type_specific_start)..(offset + type_specific_end),
            data_range: data_start..data_end,
        },
        header,
        type_specific_range: type_specific_start..type_specific_end,
        extra_range: type_specific_end..header_total,
        next_offset,
    })
}

fn validate_block_header_crc(header: &[u8], expected: u32) -> Result<()> {
    let actual = crc32(header.get(4..).ok_or(Error::TooShort)?);
    if actual != expected {
        return Err(Error::Crc32Mismatch { expected, actual });
    }
    Ok(())
}

struct HeaderReader<'a> {
    input: &'a [u8],
    range: Range<usize>,
    pos: usize,
}

impl<'a> HeaderReader<'a> {
    fn new(input: &'a [u8], range: Range<usize>) -> Result<Self> {
        if range.end > input.len() {
            return Err(Error::TooShort);
        }
        Ok(Self {
            input,
            pos: range.start,
            range,
        })
    }

    fn read_vint(&mut self) -> Result<u64> {
        let (value, len) = read_vint_at(self.input, self.pos, self.range.end)?;
        self.pos += len;
        Ok(value)
    }

    fn read_u32(&mut self) -> Result<u32> {
        let value = read_u32(self.input, self.pos)?;
        self.pos += 4;
        Ok(value)
    }

    fn read_byte(&mut self) -> Result<u8> {
        if self.pos >= self.range.end {
            return Err(Error::TooShort);
        }
        let value = self.input[self.pos];
        self.pos += 1;
        Ok(value)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        read_array_at::<N>(self.input, &mut self.pos, self.range.end)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(Error::InvalidHeader("RAR 5 field size overflows usize"))?;
        if end > self.range.end {
            return Err(Error::TooShort);
        }
        let bytes = &self.input[self.pos..end];
        self.pos = end;
        Ok(bytes)
    }
}

struct SliceReader<'a> {
    input: &'a [u8],
    end: usize,
    pos: usize,
}

impl<'a> SliceReader<'a> {
    fn new(input: &'a [u8], pos: usize, end: usize) -> Self {
        Self { input, pos, end }
    }

    fn read_vint(&mut self) -> Result<u64> {
        let (value, len) = read_vint_at(self.input, self.pos, self.end)?;
        self.pos += len;
        Ok(value)
    }

    fn read_u64(&mut self) -> Result<u64> {
        let bytes = self.read_bytes(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(Error::InvalidHeader("RAR 5 field size overflows usize"))?;
        if end > self.end {
            return Err(Error::TooShort);
        }
        let bytes = &self.input[self.pos..end];
        self.pos = end;
        Ok(bytes)
    }
}

fn read_vint_at(input: &[u8], offset: usize, end: usize) -> Result<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;
    for i in 0..10 {
        let pos = offset.checked_add(i).ok_or(Error::TooShort)?;
        if pos >= end {
            return Err(Error::TooShort);
        }
        let byte = *input.get(pos).ok_or(Error::TooShort)?;
        if shift == 63 && byte & 0x7e != 0 {
            return Err(Error::InvalidHeader("RAR 5 vint overflows u64"));
        }
        value = value
            .checked_add(((byte & 0x7f) as u64) << shift)
            .ok_or(Error::InvalidHeader("RAR 5 vint overflows u64"))?;
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
        shift += 7;
    }
    Err(Error::InvalidHeader("RAR 5 vint is too long"))
}

fn usize_from_u64(value: u64, message: &'static str) -> Result<usize> {
    usize::try_from(value).map_err(|_| Error::InvalidHeader(message))
}

fn compression_method(compression_info: u64) -> u64 {
    (compression_info >> 7) & 0x07
}

fn decode_compression_info(raw: u64) -> Result<CompressionInfo> {
    let algorithm_version = (raw & 0x3f) as u8;
    if algorithm_version > 1 {
        return Err(Error::UnsupportedFeature {
            version: crate::vendor::rars::version::ArchiveVersion::Rar50,
            feature: "RAR 5 unknown compression algorithm version",
        });
    }

    let dictionary_power = ((raw >> 10) & 0x1f) as u8;
    let dictionary_fraction = ((raw >> 15) & 0x1f) as u8;
    let rar5_compat = raw & 0x100000 != 0;
    if algorithm_version == 0 && (dictionary_fraction != 0 || rar5_compat) {
        return Err(Error::InvalidHeader(
            "RAR 5 v0 compression info uses v1 dictionary fields",
        ));
    }
    if algorithm_version == 0 && dictionary_power > 15 {
        return Err(Error::InvalidHeader(
            "RAR 5 v0 dictionary power exceeds 4 GiB limit",
        ));
    }

    let dictionary_size = if algorithm_version == 1 {
        u64::from(dictionary_fraction + 32)
            .checked_shl(u32::from(dictionary_power) + 12)
            .ok_or(Error::InvalidHeader("RAR 5 dictionary size overflows u64"))?
    } else {
        (128 * 1024_u64)
            .checked_shl(u32::from(dictionary_power))
            .ok_or(Error::InvalidHeader("RAR 5 dictionary size overflows u64"))?
    };

    Ok(CompressionInfo {
        algorithm_version,
        solid: raw & 0x40 != 0,
        method: ((raw >> 7) & 0x07) as u8,
        dictionary_power,
        dictionary_fraction,
        rar5_compat,
        dictionary_size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_vint_at_honors_logical_end_before_decoding() {
        assert_eq!(read_vint_at(&[0x01], 0, 0), Err(Error::TooShort));
        assert_eq!(read_vint_at(&[0x81, 0x01], 0, 1), Err(Error::TooShort));
        assert_eq!(read_vint_at(&[0x81, 0x01], 0, 2).unwrap(), (129, 2));
    }

    #[test]
    fn read_vint_at_rejects_values_wider_than_u64() {
        let max = [0xff; 9].into_iter().chain([0x01]).collect::<Vec<_>>();
        assert_eq!(read_vint_at(&max, 0, max.len()).unwrap(), (u64::MAX, 10));

        let overflow = [0xff; 9].into_iter().chain([0x02]).collect::<Vec<_>>();
        assert_eq!(
            read_vint_at(&overflow, 0, overflow.len()),
            Err(Error::InvalidHeader("RAR 5 vint overflows u64"))
        );
    }

    #[test]
    fn parses_file_redirection_extra_record() {
        let input = [1, 1, 6, b't', b'a', b'r', b'g', b'e', b't'];
        let record = parse_file_redirection_record(&input, 0..input.len()).unwrap();

        assert_eq!(record.redirection_type, 1);
        assert_eq!(record.flags, 1);
        assert_eq!(record.target_name, b"target");
    }

    #[test]
    fn rejects_file_redirection_record_with_trailing_bytes() {
        let input = [1, 0, 3, b'f', b'o', b'o', 0];

        assert!(matches!(
            parse_file_redirection_record(&input, 0..input.len()),
            Err(Error::InvalidHeader(
                "RAR 5 file redirection record has trailing bytes"
            ))
        ));
    }

    // NEWTUA (тикет 33): кэш ключа обязан промахиваться по любой части своего
    // ключа. Промах — правильный ответ, а не потеря скорости: архив с разными
    // солями законен, и чужой ключ расшифровал бы мусор.
    //
    // `kdf_count` здесь маленький нарочно: боевые 15 — это 32 768 раундов HMAC
    // на каждый вывод, тест на них стоил бы десятков миллисекунд.
    #[test]
    fn key_cache_returns_the_same_key_and_misses_on_a_different_salt() {
        let cache = Rar50KeyCache::default();
        let salt = [7u8; 16];
        let other_salt = [9u8; 16];

        let first = cache.derive(b"pw", salt, 1).unwrap();
        let hit = cache.derive(b"pw", salt, 1).unwrap();
        assert_eq!(first, hit);
        assert_eq!(first, Rar50Keys::derive(b"pw", salt, 1).unwrap());

        let other = cache.derive(b"pw", other_salt, 1).unwrap();
        assert_ne!(first, other);
        assert_eq!(other, Rar50Keys::derive(b"pw", other_salt, 1).unwrap());

        // Прежняя соль после вытеснения выводится заново, а не берётся из
        // занятой ячейки.
        assert_eq!(first, cache.derive(b"pw", salt, 1).unwrap());
    }

    #[test]
    fn key_cache_misses_on_a_different_password_or_kdf_count() {
        let cache = Rar50KeyCache::default();
        let salt = [3u8; 16];

        let first = cache.derive(b"pw", salt, 1).unwrap();
        let other_password = cache.derive(b"other", salt, 1).unwrap();
        assert_ne!(first, other_password);
        assert_eq!(
            other_password,
            Rar50Keys::derive(b"other", salt, 1).unwrap()
        );

        let other_count = cache.derive(b"pw", salt, 2).unwrap();
        assert_ne!(first, other_count);
        assert_eq!(other_count, Rar50Keys::derive(b"pw", salt, 2).unwrap());
    }
}
