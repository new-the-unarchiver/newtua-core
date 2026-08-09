use crate::vendor::rars::codec::rar13::Unpack15;
use crate::vendor::rars::codec::rar20::Unpack20;
use crate::vendor::rars::codec::rar29::Unpack29;
use crate::vendor::rars::crc32::{Crc32, crc32};
use crate::vendor::rars::crypto::rar15::Rar15Cipher;
use crate::vendor::rars::crypto::rar20::Rar20Cipher;
use crate::vendor::rars::crypto::rar30::{Error as Rar30Error, Rar30Cipher};
use crate::vendor::rars::detect::{ArchiveSignature, RAR15_SIGNATURE};
use crate::vendor::rars::error::{Error, Result};

use crate::vendor::rars::io_util::{align16 as checked_align16, read_exact_at, read_u16, read_u32};
pub(crate) use crate::vendor::rars::source::ArchiveSource;
use crate::vendor::rars::version::ArchiveFamily;
use std::fs::File;
use std::io::{Read, Write};
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;

mod extract;
pub use extract::extract_volumes_to;
use extract::{DecoderSession, DecryptingReader};

const MARK_HEAD: u8 = 0x72;
const MAIN_HEAD: u8 = 0x73;
const FILE_HEAD: u8 = 0x74;
const COMM_HEAD: u8 = 0x75;
const PROTECT_HEAD: u8 = 0x78;
const NEWSUB_HEAD: u8 = 0x7a;
const ENDARC_HEAD: u8 = 0x7b;

const LONG_BLOCK: u16 = 0x8000;
const MHD_VOLUME: u16 = 0x0001;
const MHD_COMMENT: u16 = 0x0002;
const MHD_SOLID: u16 = 0x0008;

const MHD_PASSWORD: u16 = 0x0080;

const MHD_ENCRYPTVER: u16 = 0x0200;

const FHD_SPLIT_BEFORE: u16 = 0x0001;
const FHD_SPLIT_AFTER: u16 = 0x0002;
const FHD_PASSWORD: u16 = 0x0004;
const FHD_COMMENT: u16 = 0x0008;
const FHD_SOLID: u16 = 0x0010;
const FHD_LARGE: u16 = 0x0100;
const FHD_UNICODE: u16 = 0x0200;
const FHD_SALT: u16 = 0x0400;
const FHD_EXTTIME: u16 = 0x1000;
const FHD_DIRECTORY_MASK: u16 = 0x00e0;

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
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MainHeader {
    pub head_crc: u16,
    pub flags: u16,
    pub head_size: u16,
    pub reserved1: u16,
    pub reserved2: u32,
    pub encrypt_version: Option<u8>,
}

impl MainHeader {
    pub fn is_volume(&self) -> bool {
        self.flags & MHD_VOLUME != 0
    }

    pub fn is_solid(&self) -> bool {
        self.flags & MHD_SOLID != 0
    }

    pub fn has_encrypted_headers(&self) -> bool {
        self.flags & MHD_PASSWORD != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Block {
    File(FileHeader),
    Comment(CommentHeader),
    Protect(ProtectHeader),
    NewSub(NewSubHeader),
    End(BlockHeader),
    Unknown(BlockHeader),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BlockHeader {
    pub head_crc: u16,
    pub head_type: u8,
    pub flags: u16,
    pub head_size: u16,
    pub add_size: Option<u64>,
    pub offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FileHeader {
    pub block: BlockHeader,
    pub pack_size: u64,
    pub unp_size: u64,
    pub host_os: u8,
    pub file_crc: u32,
    pub file_time: u32,
    pub unp_ver: u8,
    pub method: u8,
    pub name: Vec<u8>,
    pub attr: u32,
    pub salt: Option<[u8; 8]>,
    pub file_comment: Vec<u8>,
    pub ext_time: Vec<u8>,
    pub packed_range: Range<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NewSubHeader {
    pub file: FileHeader,
    pub kind: NewSubKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CommentHeader {
    pub block: BlockHeader,
    pub unp_size: u16,
    pub unp_ver: u8,
    pub method: u8,
    pub comment_crc: u16,
    pub packed_range: Range<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProtectHeader {
    pub block: BlockHeader,
    pub version: u8,
    pub rec_sectors: u16,
    pub total_blocks: u32,
    pub mark: [u8; 8],
    pub data_range: Range<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NewSubKind {
    ArchiveComment,
    RecoveryRecord,
    Unknown(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExtractedEntryMeta {
    pub name: Vec<u8>,
    pub file_time: u32,
    pub attr: u32,
    pub host_os: u8,
    pub is_directory: bool,
}

impl FileHeader {
    pub fn is_split_before(&self) -> bool {
        self.block.flags & FHD_SPLIT_BEFORE != 0
    }

    pub fn is_split_after(&self) -> bool {
        self.block.flags & FHD_SPLIT_AFTER != 0
    }

    pub fn is_encrypted(&self) -> bool {
        self.block.flags & FHD_PASSWORD != 0
    }

    pub fn is_solid(&self) -> bool {
        self.block.flags & FHD_SOLID != 0
    }

    pub fn is_directory(&self) -> bool {
        self.block.flags & FHD_DIRECTORY_MASK == FHD_DIRECTORY_MASK
    }

    pub fn has_file_comment(&self) -> bool {
        self.block.flags & FHD_COMMENT != 0 && !self.file_comment.is_empty()
    }

    pub fn is_stored(&self) -> bool {
        self.method == 0x30
    }

    pub(super) fn packed_reader_for_decode<'a>(
        &self,
        archive: &'a Archive,
        password: Option<&[u8]>,
    ) -> Result<Box<dyn Read + 'a>> {
        let reader = archive.range_reader(self.packed_range.clone())?;
        if !self.is_encrypted() {
            return Ok(reader);
        }
        let Some(password) = password else {
            return Err(Error::NeedPassword);
        };
        if (self.unp_ver == 20 || self.unp_ver == 26 || self.unp_ver >= 29)
            && !self.packed_range.len().is_multiple_of(16)
        {
            return Err(Error::InvalidHeader(
                "RAR encrypted payload is not block aligned",
            ));
        }
        Ok(Box::new(DecryptingReader::new(
            reader,
            self.unp_ver,
            password,
            self.salt,
        )?))
    }

    pub fn metadata(&self) -> ExtractedEntryMeta {
        ExtractedEntryMeta {
            name: self.name.clone(),
            file_time: self.file_time,
            attr: self.attr,
            host_os: self.host_os,
            is_directory: self.is_directory(),
        }
    }

    pub fn write_to(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
        out: &mut impl Write,
    ) -> Result<()> {
        if self.is_directory() {
            return Ok(());
        }
        // NEWTUA: ветка для несжатой записи. Без неё `write_to` уводило
        // `-m0` в выбор кодека по `unp_ver` — а он у несжатой записи такой
        // же, как у сжатой, — и запись «распаковывалась» как сжатая. Обход
        // всего архива (`extract_to`) эту развилку делает у себя, поэтому
        // наружу порок не вылезал: `write_to` там не зовётся.
        if self.is_stored() {
            return self.write_stored_to(archive, password, out);
        }
        let mut session = DecoderSession::new_with_password(false, password);
        session.write_file_to(archive, self, out)
    }

    fn write_stored_to(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
        out: &mut impl Write,
    ) -> Result<()> {
        if !self.is_stored() {
            return Err(self.unsupported_compression());
        }
        if !self.is_encrypted() && self.pack_size != self.unp_size {
            return Err(Error::InvalidHeader(
                "RAR 1.5 stored file has mismatched packed and unpacked sizes",
            ));
        }
        let mut reader = self
            .packed_reader_for_decode(archive, password)
            .map_err(|error| self.map_encrypted_payload_error(password, error))?;
        let expected_len = usize::try_from(self.unp_size)
            .map_err(|_| Error::InvalidHeader("RAR 1.5 unpacked size overflows usize"))?;
        let mut crc = Crc32::new();
        let mut crc_writer = CrcWriter {
            inner: out,
            crc: &mut crc,
        };
        let copied = std::io::copy(
            &mut reader.by_ref().take(expected_len as u64),
            &mut crc_writer,
        )?;
        if copied != expected_len as u64 {
            return Err(self.map_encrypted_payload_error(
                password,
                Error::InvalidHeader("RAR 1.5 stored file ended before unpacked size"),
            ));
        }
        let actual = crc.finish();
        if actual == self.file_crc {
            Ok(())
        } else {
            Err(self.map_encrypted_payload_error(
                password,
                Error::Crc32Mismatch {
                    expected: self.file_crc,
                    actual,
                },
            ))
        }
    }

    fn map_encrypted_payload_error(&self, password: Option<&[u8]>, error: Error) -> Error {
        if !self.is_encrypted() || password.is_none() {
            return error;
        }
        match error {
            Error::NeedPassword => Error::NeedPassword,
            Error::UnsupportedSignature
            | Error::UnsupportedVersion(_)
            | Error::UnsupportedFeature { .. }
            | Error::Rar50BufferedDecodeLimitExceeded { .. }
            | Error::UnsupportedFamilyFeature { .. }
            | Error::UnsupportedCompression { .. }
            | Error::UnsupportedEncryption { .. }
            | Error::TooShort
            | Error::Io(_)
            | Error::AtArchiveOffset { .. }
            | Error::AtEntry { .. }
            | Error::Cancelled => error,
            Error::InvalidHeader(_)
            | Error::Codec(_)
            | Error::Rar20Crypto(_)
            | Error::Rar30Crypto(_)
            | Error::Rar50Crypto(_)
            | Error::CrcMismatch { .. }
            | Error::Crc32Mismatch { .. }
            | Error::HashMismatch { .. }
            | Error::WrongPasswordOrCorruptData => Error::WrongPasswordOrCorruptData,
        }
    }

    fn entry_error(&self, operation: &'static str, error: Error) -> Error {
        if matches!(
            error,
            Error::NeedPassword | Error::WrongPasswordOrCorruptData
        ) {
            return error;
        }
        error.at_entry(self.name.clone(), operation)
    }

    fn crc_result(&self, actual: u32, password: Option<&[u8]>) -> Result<()> {
        if actual == self.file_crc {
            Ok(())
        } else {
            Err(self.map_encrypted_payload_error(
                password,
                Error::Crc32Mismatch {
                    expected: self.file_crc,
                    actual,
                },
            ))
        }
    }

    fn write_rar29_to(
        &self,
        archive: &Archive,
        decoder: &mut Unpack29,
        out: &mut impl Write,
    ) -> Result<()> {
        if self.is_stored() {
            return self.write_stored_to(archive, None, out);
        }
        if self.is_encrypted() {
            return Err(self.unsupported_encryption());
        }
        if self.unp_ver < 29 {
            return Err(self.unsupported_compression());
        }

        let mut packed = archive.range_reader(self.packed_range.clone())?;
        let mut crc = Crc32::new();
        let mut crc_writer = CrcWriter {
            inner: out,
            crc: &mut crc,
        };
        decoder
            .decode_member_from_reader(
                &mut packed,
                usize::try_from(self.unp_size)
                    .map_err(|_| Error::InvalidHeader("RAR 1.5 unpacked size overflows usize"))?,
                &mut crc_writer,
            )
            .map_err(Error::from)?;
        let actual = crc.finish();
        if actual == self.file_crc {
            Ok(())
        } else {
            Err(Error::Crc32Mismatch {
                expected: self.file_crc,
                actual,
            })
        }
    }

    fn write_unpack15_to(
        &self,
        archive: &Archive,
        decoder: &mut Unpack15,
        solid: bool,
        password: Option<&[u8]>,
        out: &mut impl Write,
    ) -> Result<()> {
        if self.is_stored() {
            return self.write_stored_to(archive, password, out);
        }
        if self.unp_ver != 15 {
            return Err(self.unsupported_compression());
        }

        let mut input = self
            .packed_reader_for_decode(archive, password)
            .map_err(|error| self.map_encrypted_payload_error(password, error))?;
        self.write_unpack15_decoded(decoder, solid, &mut input, out, password)
            .map_err(|error| self.map_encrypted_payload_error(password, error))
    }

    fn write_unpack15_decoded(
        &self,
        decoder: &mut Unpack15,
        solid: bool,
        input: &mut impl Read,
        out: &mut impl Write,
        password: Option<&[u8]>,
    ) -> Result<()> {
        let mut crc = Crc32::new();
        let mut crc_writer = CrcWriter {
            inner: out,
            crc: &mut crc,
        };
        decoder
            .decode_member_from_reader(
                input,
                usize::try_from(self.unp_size)
                    .map_err(|_| Error::InvalidHeader("RAR 1.5 unpacked size overflows usize"))?,
                solid,
                &mut crc_writer,
            )
            .map_err(Error::from)?;
        let actual = crc.finish();
        self.crc_result(actual, password)
    }

    fn write_unpack20_to(
        &self,
        archive: &Archive,
        decoder: &mut Unpack20,
        password: Option<&[u8]>,
        out: &mut impl Write,
    ) -> Result<()> {
        if self.is_stored() {
            return self.write_stored_to(archive, password, out);
        }
        if self.unp_ver != 20 && self.unp_ver != 26 {
            return Err(self.unsupported_compression());
        }

        let mut crc = Crc32::new();
        let mut crc_writer = CrcWriter {
            inner: out,
            crc: &mut crc,
        };
        let target = usize::try_from(self.unp_size)
            .map_err(|_| Error::InvalidHeader("RAR 2.0 unpacked size overflows usize"))?;
        let mut packed = self
            .packed_reader_for_decode(archive, password)
            .map_err(|error| self.map_encrypted_payload_error(password, error))?;
        decoder
            .decode_member_from_reader(&mut packed, target, &mut crc_writer)
            .map_err(Error::from)
            .map_err(|error| self.map_encrypted_payload_error(password, error))?;
        let actual = crc.finish();
        self.crc_result(actual, password)
    }

    fn unsupported_compression(&self) -> Error {
        Error::UnsupportedCompression {
            family: "RAR 1.5-4.x",
            unpack_version: self.unp_ver,
            method: self.method,
        }
    }

    fn unsupported_encryption(&self) -> Error {
        Error::UnsupportedEncryption {
            family: "RAR 1.5-4.x",
            unpack_version: self.unp_ver,
        }
    }
}

impl Archive {
    pub fn parse_path_with_signature(
        path: impl AsRef<Path>,
        signature: ArchiveSignature,
        options: crate::vendor::rars::ArchiveReadOptions<'_>,
    ) -> Result<Self> {
        Self::parse_path_with_signature_and_password(path, signature, options.password)
    }

    pub fn parse_path_with_signature_and_password(
        path: impl AsRef<Path>,
        signature: ArchiveSignature,
        password: Option<&[u8]>,
    ) -> Result<Self> {
        if signature.family != ArchiveFamily::Rar15To40 {
            return Err(Error::UnsupportedSignature);
        }
        let path = Arc::new(path.as_ref().to_path_buf());
        let file = File::open(path.as_ref())?;
        let len = file.metadata()?.len();
        Self::parse_seekable(
            file,
            len,
            signature.offset,
            ArchiveSource::File(path),
            password,
        )
    }

    fn parse_seekable(
        mut file: File,
        file_len: u64,
        sfx_offset: usize,
        source: ArchiveSource,
        password: Option<&[u8]>,
    ) -> Result<Self> {
        let marker = read_block_header_at(&mut file, file_len, sfx_offset, 0)?;
        if marker.head_type != MARK_HEAD || marker.head_size != RAR15_SIGNATURE.len() as u16 {
            return Err(Error::InvalidHeader("RAR 1.5 marker block is invalid"));
        }

        let main_block =
            read_block_header_at(&mut file, file_len, sfx_offset, marker.head_size as usize)?;
        if main_block.head_type != MAIN_HEAD {
            return Err(Error::InvalidHeader("RAR 1.5 main header is missing"));
        }
        let main_header = read_exact_at(
            &mut file,
            sfx_offset + main_block.offset,
            main_block.head_size as usize,
        )?;
        let main = parse_main_header(&main_header, &relative_block(&main_block))?;
        let mut pos = main_block.offset + main_block.head_size as usize;
        let mut blocks = Vec::new();
        let mut encrypted_header_ciphers = EncryptedHeaderCipherCache::default();

        while (sfx_offset + pos) as u64 + 7 <= file_len {
            let (block, header, total) = if main.has_encrypted_headers() {
                let password = password.ok_or(Error::NeedPassword)?;
                let encrypted = read_encrypted_header_at(
                    &mut file,
                    file_len,
                    sfx_offset,
                    pos,
                    password,
                    &mut encrypted_header_ciphers,
                )?;
                (encrypted.block, encrypted.header, encrypted.total_size)
            } else {
                let block = read_block_header_at(&mut file, file_len, sfx_offset, pos)?;
                let total = block_total_size(&block)?;
                let header = read_exact_at(&mut file, sfx_offset + pos, block.head_size as usize)?;
                (block, header, total)
            };
            match block.head_type {
                FILE_HEAD => {
                    let mut file_header =
                        parse_file_like_header(&header, relative_block(&block), 0)?;
                    let total = file_block_total_size(&block, total, file_header.pack_size)?;
                    let next = checked_file_block_next(sfx_offset, &block, total, file_len)?;
                    file_header.block.offset = block.offset;
                    file_header.packed_range =
                        packed_range(sfx_offset, block.offset, total, file_header.pack_size)?;
                    blocks.push(Block::File(file_header));
                    pos = next;
                }
                NEWSUB_HEAD => {
                    let mut file_header =
                        parse_file_like_header(&header, relative_block(&block), 0)?;
                    let total = file_block_total_size(&block, total, file_header.pack_size)?;
                    let next = checked_file_block_next(sfx_offset, &block, total, file_len)?;
                    file_header.block.offset = block.offset;
                    file_header.packed_range =
                        packed_range(sfx_offset, block.offset, total, file_header.pack_size)?;
                    let kind = classify_new_sub(&file_header.name);
                    blocks.push(Block::NewSub(NewSubHeader {
                        file: file_header,
                        kind,
                    }));
                    pos = next;
                }
                COMM_HEAD => {
                    let next = checked_file_block_next(sfx_offset, &block, total, file_len)?;
                    let mut comment = parse_comment_header(&header, relative_block(&block))?;
                    comment.block.offset = block.offset;
                    comment.packed_range =
                        sfx_offset + block.offset + 13..sfx_offset + block.offset + total;
                    blocks.push(Block::Comment(comment));
                    pos = next;
                }
                PROTECT_HEAD => {
                    let next = checked_file_block_next(sfx_offset, &block, total, file_len)?;
                    let protect = parse_protect_header(&header, &block, sfx_offset, total)?;
                    blocks.push(Block::Protect(protect));
                    pos = next;
                }
                ENDARC_HEAD => {
                    let _next = checked_file_block_next(sfx_offset, &block, total, file_len)?;
                    blocks.push(Block::End(block));
                    break;
                }
                _ => {
                    let next = checked_file_block_next(sfx_offset, &block, total, file_len)?;
                    blocks.push(Block::Unknown(block));
                    pos = next;
                }
            }
        }

        Ok(Self {
            sfx_offset,
            main,
            blocks,
            source,
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

fn classify_new_sub(name: &[u8]) -> NewSubKind {
    match name {
        b"CMT" => NewSubKind::ArchiveComment,
        b"RR" => NewSubKind::RecoveryRecord,
        _ => NewSubKind::Unknown(name.to_vec()),
    }
}

fn parse_main_header(input: &[u8], block: &BlockHeader) -> Result<MainHeader> {
    if block.head_size < 13 {
        return Err(Error::InvalidHeader("RAR 1.5 main header is too short"));
    }
    let start = block.offset;
    let head_end = start + block.head_size as usize;
    if head_end > input.len() {
        return Err(Error::TooShort);
    }

    let encrypt_version = if block.flags & MHD_ENCRYPTVER != 0 {
        Some(*input.get(start + 13).ok_or(Error::TooShort)?)
    } else {
        None
    };

    Ok(MainHeader {
        head_crc: block.head_crc,
        flags: block.flags,
        head_size: block.head_size,
        reserved1: read_u16(input, start + 7)?,
        reserved2: read_u32(input, start + 9)?,
        encrypt_version,
    })
}

fn parse_comment_header(input: &[u8], block: BlockHeader) -> Result<CommentHeader> {
    if block.head_size < 13 {
        return Err(Error::InvalidHeader("RAR 1.5 comment header is too short"));
    }
    let start = block.offset;
    Ok(CommentHeader {
        block,
        unp_size: read_u16(input, start + 7)?,
        unp_ver: *input.get(start + 9).ok_or(Error::TooShort)?,
        method: *input.get(start + 10).ok_or(Error::TooShort)?,
        comment_crc: read_u16(input, start + 11)?,
        packed_range: 0..0,
    })
}

fn parse_protect_header(
    input: &[u8],
    block: &BlockHeader,
    archive_offset: usize,
    total_size: usize,
) -> Result<ProtectHeader> {
    if block.head_size != 26 {
        return Err(Error::InvalidHeader(
            "RAR 2.x recovery header size is invalid",
        ));
    }
    let add_size = block.add_size.ok_or(Error::InvalidHeader(
        "RAR 2.x recovery header is missing data size",
    ))?;
    let rec_sectors = read_u16(input, 12)?;
    let total_blocks = read_u32(input, 14)?;
    let expected_add_size = u64::from(total_blocks)
        .checked_mul(2)
        .and_then(|size| size.checked_add(u64::from(rec_sectors) * 512))
        .ok_or(Error::InvalidHeader("RAR 2.x recovery data size overflows"))?;
    if add_size != expected_add_size {
        return Err(Error::InvalidHeader(
            "RAR 2.x recovery data size does not match header",
        ));
    }
    let mark: [u8; 8] = input
        .get(18..26)
        .ok_or(Error::TooShort)?
        .try_into()
        .expect("RAR protect mark size");
    let data_start = archive_offset
        .checked_add(block.offset)
        .and_then(|offset| offset.checked_add(block.head_size as usize))
        .ok_or(Error::InvalidHeader(
            "RAR 2.x recovery data range overflows",
        ))?;
    let data_end = archive_offset
        .checked_add(block.offset)
        .and_then(|offset| offset.checked_add(total_size))
        .ok_or(Error::InvalidHeader(
            "RAR 2.x recovery data range overflows",
        ))?;
    Ok(ProtectHeader {
        block: block.clone(),
        version: *input.get(11).ok_or(Error::TooShort)?,
        rec_sectors,
        total_blocks,
        mark,
        data_range: data_start..data_end,
    })
}

struct EncryptedHeader {
    block: BlockHeader,
    header: Vec<u8>,
    total_size: usize,
}

#[derive(Default)]
struct EncryptedHeaderCipherCache {
    salt: Option<[u8; 8]>,
    cipher: Option<Rar30Cipher>,
}

impl EncryptedHeaderCipherCache {
    fn cipher(&mut self, password: &[u8], salt: [u8; 8]) -> Result<Rar30Cipher> {
        if self.salt != Some(salt) {
            self.salt = Some(salt);
            self.cipher =
                Some(Rar30Cipher::new(password, Some(salt)).map_err(map_rar30_crypto_error)?);
        }
        Ok(self
            .cipher
            .as_ref()
            .expect("RAR 3 encrypted header cipher cache initialized")
            .clone())
    }
}

fn map_rar30_crypto_error(error: Rar30Error) -> Error {
    Error::from(error)
}

fn read_encrypted_header_at(
    file: &mut File,
    file_len: u64,
    archive_offset: usize,
    offset: usize,
    password: &[u8],
    cipher_cache: &mut EncryptedHeaderCipherCache,
) -> Result<EncryptedHeader> {
    let absolute = archive_offset
        .checked_add(offset)
        .ok_or(Error::InvalidHeader("RAR 1.5 block offset overflows usize"))?;
    if absolute as u64 + 24 > file_len {
        return Err(Error::TooShort);
    }
    let first = read_exact_at(file, absolute, 24)?;
    let salt = read_header_salt(&first, 0)?;
    let mut cipher = cipher_cache.cipher(password, salt)?;
    let mut first_block = [0u8; 16];
    first_block.copy_from_slice(&first[8..24]);
    cipher
        .decrypt_in_place(&mut first_block)
        .map_err(map_rar30_crypto_error)?;
    let head_size = read_u16(&first_block, 5)? as usize;
    if head_size < 7 {
        return Err(Error::InvalidHeader("RAR 1.5 block header is too short"));
    }
    let encrypted_header_size = checked_align16(head_size, "RAR 1.5 block size overflows usize")?;
    let encrypted_start = absolute
        .checked_add(8)
        .ok_or(Error::InvalidHeader("RAR 1.5 block offset overflows usize"))?;
    if encrypted_start as u64 + encrypted_header_size as u64 > file_len {
        return Err(Error::TooShort);
    }
    let encrypted_rest = read_exact_at(file, encrypted_start + 16, encrypted_header_size - 16)?;
    let mut header = Vec::with_capacity(encrypted_header_size);
    header.extend_from_slice(&first_block);
    header.extend_from_slice(&encrypted_rest);
    cipher
        .decrypt_in_place(&mut header[16..])
        .map_err(map_rar30_crypto_error)?;
    header.truncate(head_size);

    let mut block = parse_block_header(&header, 0)?;
    block.offset = offset;
    let payload_size = usize::try_from(block.add_size.unwrap_or(0))
        .map_err(|_| Error::InvalidHeader("RAR 1.5 block size overflows usize"))?;
    let total_size = 8usize
        .checked_add(encrypted_header_size)
        .and_then(|size| size.checked_add(payload_size))
        .ok_or(Error::InvalidHeader("RAR 1.5 block size overflows usize"))?;
    Ok(EncryptedHeader {
        block,
        header,
        total_size,
    })
}

fn read_header_salt(input: &[u8], offset: usize) -> Result<[u8; 8]> {
    input
        .get(offset..offset + 8)
        .ok_or(Error::TooShort)
        .map(|salt| salt.try_into().expect("RAR 3 salt size"))
}

fn parse_file_like_header(
    input: &[u8],
    block: BlockHeader,
    archive_offset: usize,
) -> Result<FileHeader> {
    if block.head_size < 32 {
        return Err(Error::InvalidHeader("RAR 1.5 file header is too short"));
    }
    if block.flags & LONG_BLOCK == 0 {
        return Err(Error::InvalidHeader(
            "RAR 1.5 file header is missing packed data size",
        ));
    }

    let start = block.offset;
    let head_end = start + block.head_size as usize;
    if head_end > input.len() {
        return Err(Error::TooShort);
    }

    let pack_low = read_u32(input, start + 7)? as u64;
    let unp_low = read_u32(input, start + 11)? as u64;
    let host_os = input[start + 15];
    let file_crc = read_u32(input, start + 16)?;
    let file_time = read_u32(input, start + 20)?;
    let unp_ver = input[start + 24];
    let method = input[start + 25];
    let name_size = read_u16(input, start + 26)? as usize;
    let attr = read_u32(input, start + 28)?;
    let mut pos = start + 32;

    let (pack_size, unp_size) = if block.flags & FHD_LARGE != 0 {
        let high_pack = read_u32(input, pos)? as u64;
        let high_unp = read_u32(input, pos + 4)? as u64;
        pos += 8;
        ((high_pack << 32) | pack_low, (high_unp << 32) | unp_low)
    } else {
        (pack_low, unp_low)
    };

    let name_end = pos
        .checked_add(name_size)
        .ok_or(Error::InvalidHeader("RAR 1.5 file name size overflows"))?;
    if name_end > head_end {
        return Err(Error::InvalidHeader(
            "RAR 1.5 file name extends beyond header",
        ));
    }
    let name = decode_file_name(&input[pos..name_end], block.flags);
    pos = name_end;

    let salt = if block.flags & FHD_SALT != 0 {
        let salt_end = pos
            .checked_add(8)
            .ok_or(Error::InvalidHeader("RAR 1.5 salt size overflows"))?;
        if salt_end > head_end {
            return Err(Error::InvalidHeader(
                "RAR 1.5 salt extends beyond file header",
            ));
        }
        let salt_bytes = input.get(pos..salt_end).ok_or(Error::TooShort)?;
        pos = salt_end;
        Some(
            salt_bytes
                .try_into()
                .expect("RAR 1.5 salt slice has fixed length"),
        )
    } else {
        None
    };

    let file_comment = if block.flags & FHD_COMMENT != 0 {
        if pos + 2 <= head_end {
            let comment_len = read_u16(input, pos)? as usize;
            let comment_total = comment_len
                .checked_add(2)
                .ok_or(Error::InvalidHeader("RAR 1.5 file comment size overflows"))?;
            let comment_end = pos
                .checked_add(comment_total)
                .ok_or(Error::InvalidHeader("RAR 1.5 file comment size overflows"))?;
            if comment_end <= head_end {
                let comment = input[pos..comment_end].to_vec();
                pos = comment_end;
                comment
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let ext_time = if block.flags & FHD_EXTTIME != 0 {
        input[pos..head_end].to_vec()
    } else {
        Vec::new()
    };
    let data_start = head_end;
    let data_len = usize::try_from(pack_size)
        .map_err(|_| Error::InvalidHeader("RAR 1.5 packed file size overflows usize"))?;
    let data_end = data_start
        .checked_add(data_len)
        .ok_or(Error::InvalidHeader(
            "RAR 1.5 packed file size overflows usize",
        ))?;
    Ok(FileHeader {
        block,
        pack_size,
        unp_size,
        host_os,
        file_crc,
        file_time,
        unp_ver,
        method,
        name,
        attr,
        salt,
        file_comment,
        ext_time,
        packed_range: archive_offset + data_start..archive_offset + data_end,
    })
}

fn decode_file_name(raw: &[u8], flags: u16) -> Vec<u8> {
    if flags & FHD_UNICODE == 0 {
        return raw.to_vec();
    }

    let Some(zero_pos) = raw.iter().position(|byte| *byte == 0) else {
        return raw.to_vec();
    };
    if zero_pos + 1 >= raw.len() {
        return raw[..zero_pos].to_vec();
    }

    let fallback = &raw[..zero_pos];
    let high_byte = raw[zero_pos + 1];
    let encoded = &raw[zero_pos + 2..];
    let mut pos = 0usize;
    let mut flag_byte = 0u8;
    let mut flag_bits = 0u8;
    let mut dst_pos = 0usize;
    let mut units = Vec::new();

    while pos < encoded.len() {
        if flag_bits == 0 {
            flag_byte = encoded[pos];
            pos += 1;
            flag_bits = 8;
        }
        let mode = flag_byte >> 6;
        flag_byte <<= 2;
        flag_bits -= 2;

        match mode {
            0 => {
                let Some(&low) = encoded.get(pos) else {
                    return raw.to_vec();
                };
                pos += 1;
                units.push(u16::from(low));
                dst_pos += 1;
            }
            1 => {
                let Some(&low) = encoded.get(pos) else {
                    return raw.to_vec();
                };
                pos += 1;
                units.push((u16::from(high_byte) << 8) | u16::from(low));
                dst_pos += 1;
            }
            2 => {
                let Some((&low, &high)) = encoded.get(pos).zip(encoded.get(pos + 1)) else {
                    return raw.to_vec();
                };
                pos += 2;
                units.push((u16::from(high) << 8) | u16::from(low));
                dst_pos += 1;
            }
            3 => {
                let Some(&length_byte) = encoded.get(pos) else {
                    return raw.to_vec();
                };
                pos += 1;
                let (count, correction, high) = if length_byte & 0x80 != 0 {
                    let Some(&correction) = encoded.get(pos) else {
                        return raw.to_vec();
                    };
                    pos += 1;
                    ((length_byte & 0x7f) as usize + 2, correction, high_byte)
                } else {
                    (length_byte as usize + 2, 0, 0)
                };
                for _ in 0..count {
                    let low = fallback
                        .get(dst_pos)
                        .copied()
                        .unwrap_or(b'?')
                        .wrapping_add(correction);
                    units.push((u16::from(high) << 8) | u16::from(low));
                    dst_pos += 1;
                }
            }
            _ => unreachable!("2-bit filename mode"),
        }
    }

    char::decode_utf16(units)
        .map(|unit| unit.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect::<String>()
        .into_bytes()
}

fn read_block_header_at(
    file: &mut File,
    file_len: u64,
    archive_offset: usize,
    offset: usize,
) -> Result<BlockHeader> {
    let absolute = archive_offset
        .checked_add(offset)
        .ok_or(Error::InvalidHeader("RAR 1.5 block offset overflows usize"))?;
    if absolute as u64 + 7 > file_len {
        return Err(Error::TooShort);
    }
    let base = read_exact_at(file, absolute, 7)?;
    let head_size = read_u16(&base, 5)? as usize;
    if head_size < 7 {
        return Err(Error::InvalidHeader("RAR 1.5 block header is too short"));
    }
    if absolute as u64 + head_size as u64 > file_len {
        return Err(Error::TooShort);
    }
    let header = if head_size == 7 {
        base
    } else {
        read_exact_at(file, absolute, head_size)?
    };
    let mut block = parse_block_header(&header, 0)?;
    block.offset = offset;
    Ok(block)
}

fn relative_block(block: &BlockHeader) -> BlockHeader {
    let mut relative = block.clone();
    relative.offset = 0;
    relative
}

struct CrcWriter<'a, W: Write + ?Sized> {
    inner: &'a mut W,
    crc: &'a mut Crc32,
}

impl<W: Write + ?Sized> Write for CrcWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.crc.update(&buf[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn parse_block_header(input: &[u8], offset: usize) -> Result<BlockHeader> {
    if input.len() < offset + 7 {
        return Err(Error::TooShort);
    }
    let head_crc = read_u16(input, offset)?;
    let head_type = input[offset + 2];
    let flags = read_u16(input, offset + 3)?;
    let head_size = read_u16(input, offset + 5)?;
    if head_size < 7 {
        return Err(Error::InvalidHeader("RAR 1.5 block header is too short"));
    }
    let add_size = if flags & LONG_BLOCK != 0 {
        Some(read_u32(input, offset + 7)? as u64)
    } else {
        None
    };
    if offset + head_size as usize > input.len() {
        return Err(Error::TooShort);
    }
    if head_type != MARK_HEAD && should_validate_header_crc(head_type) {
        let header_end = header_crc_end(input, offset, head_type, flags, head_size)?;
        let actual = (crc32(&input[offset + 2..header_end]) & 0xffff) as u16;
        if actual != head_crc {
            return Err(Error::CrcMismatch {
                expected: head_crc,
                actual,
            });
        }
    }
    validate_legacy_auth_block_size(head_type, head_size)?;

    Ok(BlockHeader {
        head_crc,
        head_type,
        flags,
        head_size,
        add_size,
        offset,
    })
}

fn header_crc_end(
    input: &[u8],
    offset: usize,
    head_type: u8,
    flags: u16,
    head_size: u16,
) -> Result<usize> {
    let full_end = offset + head_size as usize;
    let fixed_end = match head_type {
        MAIN_HEAD if flags & MHD_COMMENT != 0 => Some(offset + 13),
        COMM_HEAD => Some(offset + 13),
        FILE_HEAD if flags & FHD_COMMENT != 0 => Some(file_header_comment_crc_end(input, offset)?),
        _ => None,
    };
    Ok(fixed_end.unwrap_or(full_end).min(full_end))
}

fn file_header_comment_crc_end(input: &[u8], offset: usize) -> Result<usize> {
    if input.len() < offset + 32 {
        return Err(Error::TooShort);
    }
    let flags = read_u16(input, offset + 3)?;
    let name_size = read_u16(input, offset + 26)? as usize;
    let mut end = offset + 32;
    if flags & FHD_LARGE != 0 {
        end = end
            .checked_add(8)
            .ok_or(Error::InvalidHeader("RAR 1.5 file header size overflows"))?;
    }
    end = end
        .checked_add(name_size)
        .ok_or(Error::InvalidHeader("RAR 1.5 file header size overflows"))?;
    if flags & FHD_SALT != 0 {
        end = end
            .checked_add(8)
            .ok_or(Error::InvalidHeader("RAR 1.5 file header size overflows"))?;
    }
    Ok(end)
}

fn should_validate_header_crc(head_type: u8) -> bool {
    // Historical AV/SIGN blocks are documented with inconsistent CRC fields in
    // real archives, so readers must not reject them solely on HEAD_CRC.
    !matches!(head_type, 0x76 | 0x79)
}

fn validate_legacy_auth_block_size(head_type: u8, head_size: u16) -> Result<()> {
    let minimum = match head_type {
        0x76 => 21,
        0x79 => 182,
        _ => return Ok(()),
    };
    if head_size < minimum {
        return Err(Error::InvalidHeader(
            "RAR legacy authenticity block is too short",
        ));
    }
    Ok(())
}

fn block_total_size(block: &BlockHeader) -> Result<usize> {
    let total = block.head_size as u64 + block.add_size.unwrap_or(0);
    usize::try_from(total).map_err(|_| Error::InvalidHeader("RAR 1.5 block size overflows usize"))
}

fn file_block_total_size(
    block: &BlockHeader,
    default_total: usize,
    pack_size: u64,
) -> Result<usize> {
    let low_payload_size = usize::try_from(block.add_size.unwrap_or(0))
        .map_err(|_| Error::InvalidHeader("RAR 1.5 block size overflows usize"))?;
    let header_prefix = default_total
        .checked_sub(low_payload_size)
        .ok_or(Error::InvalidHeader("RAR 1.5 block size overflows usize"))?;
    let pack_size = usize::try_from(pack_size)
        .map_err(|_| Error::InvalidHeader("RAR 1.5 packed file size overflows usize"))?;
    header_prefix
        .checked_add(pack_size)
        .ok_or(Error::InvalidHeader("RAR 1.5 block size overflows usize"))
}

fn checked_file_block_next(
    sfx_offset: usize,
    block: &BlockHeader,
    total: usize,
    file_len: u64,
) -> Result<usize> {
    let next = block
        .offset
        .checked_add(total)
        .ok_or(Error::InvalidHeader("RAR 1.5 block size overflows usize"))?;
    let absolute_next = sfx_offset
        .checked_add(next)
        .ok_or(Error::InvalidHeader("RAR 1.5 block size overflows usize"))?;
    if absolute_next as u64 > file_len {
        return Err(Error::TooShort);
    }
    Ok(next)
}

fn packed_range(
    archive_offset: usize,
    block_offset: usize,
    total: usize,
    pack_size: u64,
) -> Result<Range<usize>> {
    let pack_size = usize::try_from(pack_size)
        .map_err(|_| Error::InvalidHeader("RAR 1.5 packed file size overflows usize"))?;
    let block_end = archive_offset
        .checked_add(block_offset)
        .and_then(|start| start.checked_add(total))
        .ok_or(Error::InvalidHeader("RAR 1.5 block size overflows usize"))?;
    let block_start = block_end
        .checked_sub(pack_size)
        .ok_or(Error::InvalidHeader("RAR 1.5 block size overflows usize"))?;
    Ok(block_start..block_end)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn legacy_auth_block(head_type: u8, head_size: u16) -> Vec<u8> {
        let mut block = vec![0; head_size as usize];
        block[2] = head_type;
        block[5..7].copy_from_slice(&head_size.to_le_bytes());
        block
    }

    #[test]
    fn rejects_too_short_legacy_auth_blocks_even_without_crc_check() {
        assert!(matches!(
            parse_block_header(&legacy_auth_block(0x76, 20), 0),
            Err(Error::InvalidHeader(
                "RAR legacy authenticity block is too short"
            ))
        ));
        assert!(matches!(
            parse_block_header(&legacy_auth_block(0x79, 181), 0),
            Err(Error::InvalidHeader(
                "RAR legacy authenticity block is too short"
            ))
        ));
    }

    #[test]
    fn accepts_minimum_legacy_auth_block_sizes_with_bad_crc() {
        assert_eq!(
            parse_block_header(&legacy_auth_block(0x76, 21), 0)
                .unwrap()
                .head_size,
            21
        );
        assert_eq!(
            parse_block_header(&legacy_auth_block(0x79, 182), 0)
                .unwrap()
                .head_size,
            182
        );
    }

    #[test]
    fn parses_fhd_large_high_size_fields_from_file_header() {
        let name = b"large.bin";
        let head_size = 32 + 8 + name.len();
        let mut header = Vec::new();
        header.extend_from_slice(&0u16.to_le_bytes());
        header.push(FILE_HEAD);
        header.extend_from_slice(&(LONG_BLOCK | FHD_LARGE).to_le_bytes());
        header.extend_from_slice(&(head_size as u16).to_le_bytes());
        header.extend_from_slice(&0x89ab_cdefu32.to_le_bytes());
        header.extend_from_slice(&0x7654_3210u32.to_le_bytes());
        header.push(3);
        header.extend_from_slice(&0x1234_5678u32.to_le_bytes());
        header.extend_from_slice(&0x5a21_0000u32.to_le_bytes());
        header.push(29);
        header.push(0x35);
        header.extend_from_slice(&(name.len() as u16).to_le_bytes());
        header.extend_from_slice(&0x20u32.to_le_bytes());
        header.extend_from_slice(&1u32.to_le_bytes());
        header.extend_from_slice(&2u32.to_le_bytes());
        header.extend_from_slice(name);

        let block = BlockHeader {
            head_crc: 0,
            head_type: FILE_HEAD,
            flags: LONG_BLOCK | FHD_LARGE,
            head_size: head_size as u16,
            add_size: Some(0x89ab_cdef),
            offset: 0,
        };
        let file = parse_file_like_header(&header, block, 0).unwrap();

        assert_eq!(file.pack_size, 0x0000_0001_89ab_cdef);
        assert_eq!(file.unp_size, 0x0000_0002_7654_3210);
        assert_eq!(file.name, name);
        assert_eq!(
            file.packed_range,
            head_size..head_size + 0x0000_0001_89ab_cdefusize
        );
    }

    fn block_header_with(flags: u16) -> BlockHeader {
        BlockHeader {
            head_crc: 0,
            head_type: FILE_HEAD,
            flags,
            head_size: 32,
            add_size: None,
            offset: 0,
        }
    }

    fn file_header_with(flags: u16) -> FileHeader {
        FileHeader {
            block: block_header_with(flags),
            pack_size: 0,
            unp_size: 0,
            host_os: 0,
            file_crc: 0,
            file_time: 0,
            unp_ver: 29,
            method: 0x30,
            name: b"entry".to_vec(),
            attr: 0,
            salt: None,
            file_comment: Vec::new(),
            ext_time: Vec::new(),
            packed_range: 0..0,
        }
    }

    #[test]
    fn file_header_unsupported_compression_describes_method_and_unpack_version() {
        let mut header = file_header_with(0);
        header.method = 0x33;
        header.unp_ver = 26;
        let err = header.unsupported_compression();
        assert!(matches!(
            err,
            Error::UnsupportedCompression {
                family: "RAR 1.5-4.x",
                unpack_version: 26,
                method: 0x33,
            }
        ));
    }

    #[test]
    fn file_header_unsupported_encryption_describes_unpack_version() {
        let mut header = file_header_with(FHD_PASSWORD);
        header.unp_ver = 36;
        let err = header.unsupported_encryption();
        assert!(matches!(
            err,
            Error::UnsupportedEncryption {
                family: "RAR 1.5-4.x",
                unpack_version: 36,
            }
        ));
    }

    #[test]
    fn crc_writer_flush_propagates_to_inner_writer() {
        struct FlushSpy {
            data: Vec<u8>,
            flushed: usize,
        }
        impl Write for FlushSpy {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.data.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.flushed += 1;
                Ok(())
            }
        }
        let mut inner = FlushSpy {
            data: Vec::new(),
            flushed: 0,
        };
        let mut crc = Crc32::new();
        let mut writer = CrcWriter {
            inner: &mut inner,
            crc: &mut crc,
        };
        writer.write_all(b"hi").unwrap();
        writer.flush().unwrap();
        assert_eq!(inner.data, b"hi");
        assert_eq!(inner.flushed, 1);
    }

    #[test]
    fn parse_main_header_rejects_block_size_below_minimum() {
        let block = BlockHeader {
            head_crc: 0,
            head_type: MAIN_HEAD,
            flags: 0,
            head_size: 12,
            add_size: None,
            offset: 0,
        };
        let err = parse_main_header(&[0u8; 32], &block).unwrap_err();
        assert_eq!(
            err,
            Error::InvalidHeader("RAR 1.5 main header is too short")
        );
    }

    #[test]
    fn parse_main_header_rejects_block_extending_past_input_buffer() {
        let block = BlockHeader {
            head_crc: 0,
            head_type: MAIN_HEAD,
            flags: 0,
            head_size: 13,
            add_size: None,
            offset: 8,
        };
        // Buffer is shorter than offset + head_size.
        let err = parse_main_header(&[0u8; 16], &block).unwrap_err();
        assert_eq!(err, Error::TooShort);
    }

    #[test]
    fn parse_main_header_reads_encrypt_version_when_flag_is_set() {
        // Build a synthetic main header at offset 0: 13 bytes of base + 1 byte
        // for the encrypt_version field at position 13.
        let mut input = vec![0u8; 14];
        input[13] = 0x29;
        let block = BlockHeader {
            head_crc: 0,
            head_type: MAIN_HEAD,
            flags: MHD_ENCRYPTVER,
            head_size: 14,
            add_size: None,
            offset: 0,
        };
        let main = parse_main_header(&input, &block).unwrap();
        assert_eq!(main.encrypt_version, Some(0x29));
    }

    #[test]
    fn decode_file_name_returns_raw_when_unicode_flag_is_clear() {
        let raw = b"plain.txt";
        let decoded = decode_file_name(raw, 0);
        assert_eq!(decoded, raw);
    }

    #[test]
    fn decode_file_name_returns_raw_when_unicode_marker_is_missing() {
        // FHD_UNICODE set but no zero byte to split fallback from encoded
        // payload — the decoder falls back to the raw bytes.
        let raw = b"no-zero-marker";
        let decoded = decode_file_name(raw, FHD_UNICODE);
        assert_eq!(decoded, raw);
    }

    #[test]
    fn decode_file_name_returns_fallback_when_no_encoded_payload_follows_zero() {
        // Zero byte present but nothing after it — the decoder returns just
        // the fallback prefix.
        let mut raw = b"fallback".to_vec();
        raw.push(0);
        let decoded = decode_file_name(&raw, FHD_UNICODE);
        assert_eq!(decoded, b"fallback");
    }

    #[test]
    fn decode_file_name_decodes_mode_zero_low_byte_only_units() {
        // Mode 0 emits one ASCII byte per code unit. Encoded payload format:
        //   high_byte, flag_byte, byte0, byte1, ...
        // flag_byte = 0b00_00_00_00 → four mode-0 emits.
        let mut raw = b"orig".to_vec();
        raw.push(0); // separator
        raw.push(0); // high_byte (unused for mode 0)
        raw.push(0b00_00_00_00); // flag_byte: four mode-0 codes
        raw.extend_from_slice(b"abcd");
        let decoded = decode_file_name(&raw, FHD_UNICODE);
        assert_eq!(decoded, b"abcd");
    }

    #[test]
    fn decode_file_name_decodes_mode_two_full_two_byte_units() {
        // Mode 2 reads (low, high) bytes for a full UTF-16 code unit.
        // Encode "Hi" via mode 2 twice: flag_byte = 0b10_10_00_00.
        let mut raw = b"".to_vec();
        raw.push(0); // separator (zero_pos = 0)
        raw.push(0); // high_byte placeholder
        // Two mode-2 units, then two mode-0 units which we will not reach.
        raw.push(0b10_10_00_00);
        // First unit 'H' = U+0048: low=0x48, high=0x00
        raw.extend_from_slice(&[0x48, 0x00]);
        // Second unit 'i' = U+0069
        raw.extend_from_slice(&[0x69, 0x00]);
        let decoded = decode_file_name(&raw, FHD_UNICODE);
        // The decoder may emit further units from the trailing flag bits;
        // accept any output that begins with "Hi".
        assert!(decoded.starts_with(b"Hi"), "got {decoded:?}");
    }
}
