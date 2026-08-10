use crate::vendor::rars::codec::rar13::Unpack15;
use crate::vendor::rars::crypto::rar13::{Rar13Cipher, Rar13DecryptReader};
use crate::vendor::rars::detect::{ArchiveSignature, RAR13_SIGNATURE};
use crate::vendor::rars::error::{Error, Result};

use crate::vendor::rars::io_util::{read_exact_at, read_u16, read_u32};
pub(crate) use crate::vendor::rars::source::ArchiveSource;
use crate::vendor::rars::version::ArchiveFamily;
use std::fs::File;
use std::io::{Read, Write};
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;

const MAIN_HEAD_SIZE: u16 = 7;
const FILE_HEAD_BASE_SIZE: usize = 21;
const MHD_VOLUME: u8 = 0x01;

const MHD_SOLID: u8 = 0x08;

const LHD_SPLIT_BEFORE: u8 = 0x01;
const LHD_SPLIT_AFTER: u8 = 0x02;
const LHD_PASSWORD: u8 = 0x04;
const LHD_COMMENT: u8 = 0x08;

const METHOD_STORE: u8 = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MainHeader {
    pub flags: u8,
    pub head_size: u16,
    pub extra: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FileHeader {
    pub flags: u8,
    pub pack_size: u32,
    pub unp_size: u32,
    pub file_crc: u16,
    pub file_time: u32,
    pub file_attr: u8,
    pub unp_ver: u8,
    pub method: u8,
    pub head_size: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Entry {
    pub header: FileHeader,
    pub name: Vec<u8>,
    pub extra: Vec<u8>,
    pub packed_range: Range<usize>,
}

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
    pub entries: Vec<Entry>,
    source: ArchiveSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExtractedEntryMeta {
    pub name: Vec<u8>,
    pub file_time: u32,
    pub file_attr: u8,
    pub is_directory: bool,
}

impl MainHeader {
    pub fn is_volume(&self) -> bool {
        self.flags & MHD_VOLUME != 0
    }

    pub fn is_solid(&self) -> bool {
        self.flags & MHD_SOLID != 0
    }

    fn parse(input: &[u8]) -> Result<Self> {
        if input.len() < MAIN_HEAD_SIZE as usize {
            return Err(Error::TooShort);
        }
        if !input.starts_with(RAR13_SIGNATURE) {
            return Err(Error::UnsupportedSignature);
        }

        let head_size = read_u16(input, 4)?;
        let flags = input[6];
        if head_size < MAIN_HEAD_SIZE {
            return Err(Error::InvalidHeader(
                "RAR 1.3 main header is shorter than 7 bytes",
            ));
        }
        if head_size as usize > input.len() {
            return Err(Error::TooShort);
        }

        let extra = input[MAIN_HEAD_SIZE as usize..head_size as usize].to_vec();

        Ok(Self {
            flags,
            head_size,
            extra,
        })
    }
}

impl FileHeader {
    fn parse(input: &[u8]) -> Result<(Self, Vec<u8>, Vec<u8>, usize)> {
        if input.len() < FILE_HEAD_BASE_SIZE {
            return Err(Error::TooShort);
        }

        let pack_size = read_u32(input, 0)?;
        let unp_size = read_u32(input, 4)?;
        let file_crc = read_u16(input, 8)?;
        let head_size = read_u16(input, 10)?;
        let file_time = read_u32(input, 12)?;
        let file_attr = input[16];
        let flags = input[17];
        let unp_ver = input[18];
        let name_size = input[19] as usize;
        let method = input[20];
        let minimum_size = FILE_HEAD_BASE_SIZE + name_size;

        if (head_size as usize) < minimum_size {
            return Err(Error::InvalidHeader(
                "RAR 1.3 file header is shorter than its name",
            ));
        }
        if input.len() < head_size as usize {
            return Err(Error::TooShort);
        }

        let name = input[FILE_HEAD_BASE_SIZE..FILE_HEAD_BASE_SIZE + name_size].to_vec();
        let extra = input[minimum_size..head_size as usize].to_vec();
        Ok((
            Self {
                flags,
                pack_size,
                unp_size,
                file_crc,
                file_time,
                file_attr,
                unp_ver,
                method,
                head_size,
            },
            name,
            extra,
            head_size as usize,
        ))
    }
}

impl Archive {
    pub fn parse_path_with_signature(
        path: impl AsRef<Path>,
        signature: ArchiveSignature,
    ) -> Result<Self> {
        if signature.family != ArchiveFamily::Rar13 {
            return Err(Error::UnsupportedSignature);
        }
        let path = Arc::new(path.as_ref().to_path_buf());
        let file = File::open(path.as_ref())?;
        let len = file.metadata()?.len();
        Self::parse_seekable(file, len, signature.offset, ArchiveSource::file(path))
    }

    fn parse_seekable(
        mut file: File,
        file_len: u64,
        sfx_offset: usize,
        source: ArchiveSource,
    ) -> Result<Self> {
        let main_prefix = read_exact_at(&mut file, sfx_offset, MAIN_HEAD_SIZE as usize)?;
        let head_size = read_u16(&main_prefix, 4)? as usize;
        let main_bytes = read_exact_at(&mut file, sfx_offset, head_size)?;
        let main = MainHeader::parse(&main_bytes)?;
        let mut pos = main.head_size as usize;
        let mut entries = Vec::new();

        while (sfx_offset + pos) as u64 + FILE_HEAD_BASE_SIZE as u64 <= file_len {
            let header_prefix = read_exact_at(&mut file, sfx_offset + pos, FILE_HEAD_BASE_SIZE)?;
            let head_size = read_u16(&header_prefix, 10)? as usize;
            let header_bytes = read_exact_at(&mut file, sfx_offset + pos, head_size)?;
            let (header, name, extra, consumed) = FileHeader::parse(&header_bytes)?;
            let data_start = pos + consumed;
            let data_end =
                data_start
                    .checked_add(header.pack_size as usize)
                    .ok_or(Error::InvalidHeader(
                        "RAR 1.3 file data size overflows usize",
                    ))?;
            if (sfx_offset + data_end) as u64 > file_len {
                return Err(Error::TooShort);
            }
            entries.push(Entry {
                header,
                name,
                extra,
                packed_range: sfx_offset + data_start..sfx_offset + data_end,
            });
            pos = data_end;
        }

        Ok(Self {
            sfx_offset,
            main,
            entries,
            source,
        })
    }

    fn copy_range_to(&self, range: Range<usize>, out: &mut impl Write) -> Result<()> {
        self.source.copy_range_to(range, out)
    }

    fn range_reader(&self, range: Range<usize>) -> Result<Box<dyn Read + '_>> {
        self.source.range_reader(range)
    }

    fn copy_decrypted_range_to(
        &self,
        range: Range<usize>,
        cipher: Rar13Cipher,
        out: &mut impl Write,
    ) -> Result<()> {
        // NEWTUA: и разветвление по виду источника, и свой цикл расшифровки
        // отсюда ушли (тикет 30, этап Е3; довершено `/simplify`). Обе ветки
        // делали одно — читать диапазон кусками и расшифровывать, — а диапазон
        // умеет отдать сам источник, расшифровку же по дороге делает
        // `Rar13DecryptReader`, которым этот файл пользуется и в двух других
        // местах. Обрыв посреди диапазона остаётся отказом: считаем байты.
        let expected = range.len() as u64;
        let reader = self.source.range_reader(range)?;
        let mut reader = Rar13DecryptReader::new(reader, cipher);
        if std::io::copy(&mut reader, out)? != expected {
            return Err(Error::TooShort);
        }
        Ok(())
    }
}

impl Entry {
    pub fn is_encrypted(&self) -> bool {
        self.header.flags & LHD_PASSWORD != 0
    }

    pub fn is_split_before(&self) -> bool {
        self.header.flags & LHD_SPLIT_BEFORE != 0
    }

    pub fn is_split_after(&self) -> bool {
        self.header.flags & LHD_SPLIT_AFTER != 0
    }

    pub fn is_directory(&self) -> bool {
        self.header.file_attr & 0x10 != 0
    }

    pub fn has_file_comment(&self) -> bool {
        self.header.flags & LHD_COMMENT != 0
    }

    pub fn is_stored(&self) -> bool {
        self.header.method == METHOD_STORE
    }

    pub fn write_packed_data(&self, archive: &Archive, out: &mut impl Write) -> Result<()> {
        archive.copy_range_to(self.packed_range.clone(), out)
    }

    pub fn metadata(&self) -> ExtractedEntryMeta {
        ExtractedEntryMeta {
            name: self.name.clone(),
            file_time: self.header.file_time,
            file_attr: self.header.file_attr,
            is_directory: self.is_directory(),
        }
    }

    fn write_stored_to(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
        out: &mut impl Write,
    ) -> Result<()> {
        if !self.is_stored() {
            return Err(Error::InvalidHeader("RAR 1.3 entry is not stored"));
        }
        if self.is_encrypted() {
            let password = password.ok_or(Error::NeedPassword)?;
            let mut checksum = Rar13Checksum::new();
            let mut checksum_writer = Rar13ChecksumWriter {
                inner: out,
                checksum: &mut checksum,
            };
            archive.copy_decrypted_range_to(
                self.packed_range.clone(),
                Rar13Cipher::new(password),
                &mut checksum_writer,
            )?;
            let actual = checksum.finish();
            return if actual == self.header.file_crc {
                Ok(())
            } else {
                Err(Error::CrcMismatch {
                    expected: self.header.file_crc,
                    actual,
                })
            };
        }
        let mut checksum = Rar13Checksum::new();
        let mut checksum_writer = Rar13ChecksumWriter {
            inner: out,
            checksum: &mut checksum,
        };
        self.write_packed_data(archive, &mut checksum_writer)?;
        let actual = checksum.finish();
        if actual == self.header.file_crc {
            Ok(())
        } else {
            Err(Error::CrcMismatch {
                expected: self.header.file_crc,
                actual,
            })
        }
    }

    fn write_compressed_to(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
        unpack15: &mut Unpack15,
        solid: bool,
        out: &mut impl Write,
    ) -> Result<()> {
        if self.is_stored() || self.is_directory() {
            return self.write_stored_to(archive, password, out);
        }
        let mut checksum = Rar13Checksum::new();
        let mut checksum_writer = Rar13ChecksumWriter {
            inner: out,
            checksum: &mut checksum,
        };
        if self.is_encrypted() {
            let password = password.ok_or(Error::NeedPassword)?;
            let packed = archive.range_reader(self.packed_range.clone())?;
            let mut packed = Rar13DecryptReader::new(packed, Rar13Cipher::new(password));
            unpack15.decode_member_from_reader(
                &mut packed,
                self.header.unp_size as usize,
                solid,
                &mut checksum_writer,
            )?;
        } else {
            let mut packed = archive.range_reader(self.packed_range.clone())?;
            unpack15.decode_member_from_reader(
                &mut packed,
                self.header.unp_size as usize,
                solid,
                &mut checksum_writer,
            )?;
        }
        let actual = checksum.finish();
        if actual == self.header.file_crc {
            Ok(())
        } else {
            Err(Error::CrcMismatch {
                expected: self.header.file_crc,
                actual,
            })
        }
    }

    pub fn write_to(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
        out: &mut impl Write,
    ) -> Result<()> {
        self.write_compressed_to(archive, password, &mut Unpack15::new(), false, out)
    }

    fn entry_error(&self, operation: &'static str, error: Error) -> Error {
        if matches!(
            error,
            Error::NeedPassword | Error::WrongPasswordOrCorruptData
        ) {
            return error;
        }
        if self.is_encrypted()
            && matches!(
                error,
                Error::InvalidHeader(_)
                    | Error::Codec(_)
                    | Error::CrcMismatch { .. }
                    | Error::Crc32Mismatch { .. }
                    | Error::HashMismatch { .. }
            )
        {
            return Error::WrongPasswordOrCorruptData;
        }
        error.at_entry(self.name.clone(), operation)
    }
}

/// Streams a multivolume archive set to caller-provided writers.
///
/// NEWTUA: писарь получил время жизни (`'w`). У апстрима он `Box<dyn Write>`,
/// то есть `'static`, и вызывающий не мог отдать писаря, который пишет в
/// заимствованный приёмник, — тело приходилось копить целиком в памяти
/// (тикет 29). Правка одинаковая во всех трёх поколениях формата.
pub fn extract_volumes_to<'w, F>(
    volumes: &[Archive],
    password: Option<&[u8]>,
    mut open: F,
) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write + 'w>>,
{
    let mut pending: Option<PendingSplitRefs> = None;
    let mut unpack15 = Unpack15::new();
    let mut extracted_count = 0usize;

    for (volume_index, archive) in volumes.iter().enumerate() {
        for (entry_index, entry) in archive.entries.iter().enumerate() {
            if !entry.is_split_before() && !entry.is_split_after() {
                if pending.is_some() {
                    return Err(Error::InvalidHeader(
                        "RAR 1.3 split entry is interrupted by a regular entry",
                    ));
                }
                let meta = entry.metadata();
                if meta.is_directory {
                    let _ = open(&meta)?;
                    extracted_count += 1;
                    continue;
                }
                let mut writer = open(&meta)?;
                entry
                    .write_compressed_to(
                        archive,
                        password,
                        &mut unpack15,
                        archive.main.is_solid() && extracted_count != 0,
                        &mut writer,
                    )
                    .map_err(|error| entry.entry_error("extracting", error))?;
                extracted_count += 1;
                continue;
            }

            match (
                &mut pending,
                entry.is_split_before(),
                entry.is_split_after(),
            ) {
                (None, false, true) => {
                    pending = Some(PendingSplitRefs::new(entry, volume_index, entry_index));
                }
                (Some(current), true, true) => {
                    current.append(entry, volume_index, entry_index)?;
                }
                (Some(current), true, false) => {
                    current.append(entry, volume_index, entry_index)?;
                    let completed = pending.take().expect("pending split");
                    let solid = archive.main.is_solid() && extracted_count != 0;
                    completed
                        .write_to(volumes, entry, password, &mut unpack15, solid, &mut open)
                        .map_err(|error| entry.entry_error("extracting", error))?;
                    extracted_count += 1;
                }
                _ => {
                    return Err(Error::InvalidHeader(
                        "RAR 1.3 split entry flags are inconsistent",
                    ));
                }
            }
        }
    }

    if pending.is_some() {
        return Err(Error::InvalidHeader("RAR 1.3 split entry is incomplete"));
    }

    Ok(())
}

struct Rar13ChecksumWriter<'a, W: Write + ?Sized> {
    inner: &'a mut W,
    checksum: &'a mut Rar13Checksum,
}

impl<W: Write + ?Sized> Write for Rar13ChecksumWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.checksum.update(&buf[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

struct Rar13Checksum {
    value: u16,
}

impl Rar13Checksum {
    fn new() -> Self {
        Self { value: 0 }
    }

    fn update(&mut self, input: &[u8]) {
        for &byte in input {
            self.value = self.value.wrapping_add(byte as u16).rotate_left(1);
        }
    }

    fn finish(self) -> u16 {
        self.value
    }
}

struct PendingSplitRefs {
    name: Vec<u8>,
    fragments: Vec<(usize, usize)>,
    file_time: u32,
    file_attr: u8,
    method: u8,
    unp_ver: u8,
    was_encrypted: bool,
}

impl PendingSplitRefs {
    fn new(entry: &Entry, volume_index: usize, entry_index: usize) -> Self {
        Self {
            name: entry.name.clone(),
            fragments: vec![(volume_index, entry_index)],
            file_time: entry.header.file_time,
            file_attr: entry.header.file_attr,
            method: entry.header.method,
            unp_ver: entry.header.unp_ver,
            was_encrypted: entry.is_encrypted(),
        }
    }

    fn append(&mut self, entry: &Entry, volume_index: usize, entry_index: usize) -> Result<()> {
        if entry.name != self.name {
            return Err(Error::InvalidHeader("RAR 1.3 split entry name changed"));
        }
        if entry.header.method != self.method {
            return Err(Error::InvalidHeader(
                "RAR 1.3 split entry compression method changed",
            ));
        }
        if entry.header.unp_ver != self.unp_ver {
            return Err(Error::InvalidHeader(
                "RAR 1.3 split entry unpack version changed",
            ));
        }
        if entry.is_encrypted() != self.was_encrypted {
            return Err(Error::InvalidHeader(
                "RAR 1.3 split entry encryption flag changed",
            ));
        }
        self.fragments.push((volume_index, entry_index));
        Ok(())
    }

    fn write_to<'w, F>(
        self,
        volumes: &[Archive],
        final_entry: &Entry,
        password: Option<&[u8]>,
        unpack15: &mut Unpack15,
        solid: bool,
        open: &mut F,
    ) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write + 'w>>,
    {
        let mut reader = self.fragment_reader(volumes, password)?;
        let meta = ExtractedEntryMeta {
            name: self.name,
            file_time: self.file_time,
            file_attr: self.file_attr,
            is_directory: false,
        };
        let mut writer = open(&meta)?;
        let mut checksum = Rar13Checksum::new();
        let mut checksum_writer = Rar13ChecksumWriter {
            inner: &mut writer,
            checksum: &mut checksum,
        };
        if self.method == METHOD_STORE {
            std::io::copy(&mut reader, &mut checksum_writer)?;
        } else {
            unpack15.decode_member_from_reader(
                &mut reader,
                final_entry.header.unp_size as usize,
                solid,
                &mut checksum_writer,
            )?;
        }
        let actual = checksum.finish();
        if actual == final_entry.header.file_crc {
            Ok(())
        } else {
            Err(Error::CrcMismatch {
                expected: final_entry.header.file_crc,
                actual,
            })
        }
    }

    fn fragment_reader<'a>(
        &self,
        volumes: &'a [Archive],
        password: Option<&'a [u8]>,
    ) -> Result<ChainedReader<'a>> {
        let mut readers = Vec::with_capacity(self.fragments.len());
        for &(volume_index, entry_index) in &self.fragments {
            let archive = volumes
                .get(volume_index)
                .ok_or(Error::InvalidHeader("RAR 1.3 split volume is missing"))?;
            let entry = archive
                .entries
                .get(entry_index)
                .ok_or(Error::InvalidHeader("RAR 1.3 split entry is missing"))?;
            let reader = archive.range_reader(entry.packed_range.clone())?;
            if entry.is_encrypted() {
                let password = password.ok_or(Error::NeedPassword)?;
                readers.push(
                    Box::new(Rar13DecryptReader::new(reader, Rar13Cipher::new(password)))
                        as Box<dyn Read + 'a>,
                );
            } else {
                readers.push(reader);
            }
        }
        Ok(ChainedReader { readers, index: 0 })
    }
}

struct ChainedReader<'a> {
    readers: Vec<Box<dyn Read + 'a>>,
    index: usize,
}

impl Read for ChainedReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        while let Some(reader) = self.readers.get_mut(self.index) {
            let read = reader.read(out)?;
            if read != 0 {
                return Ok(read);
            }
            self.index += 1;
        }
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rar13_checksum_writer_flush_propagates_to_inner_writer() {
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
        let mut checksum = Rar13Checksum::new();
        let mut writer = Rar13ChecksumWriter {
            inner: &mut inner,
            checksum: &mut checksum,
        };
        writer.write_all(b"hello").unwrap();
        writer.flush().unwrap();
        assert_eq!(inner.data, b"hello");
        assert_eq!(inner.flushed, 1);
    }

    #[test]
    fn file_header_parse_rejects_input_below_base_size() {
        let err = FileHeader::parse(&[0u8; FILE_HEAD_BASE_SIZE - 1]).unwrap_err();
        assert_eq!(err, Error::TooShort);
    }

    #[test]
    fn file_header_parse_rejects_truncated_input_against_declared_head_size() {
        // Build a syntactically OK FILE_HEAD_BASE_SIZE buffer that declares a
        // head_size larger than the slice we pass in — exercises the
        // post-name-size length check at the end of FileHeader::parse.
        let mut header = [0u8; FILE_HEAD_BASE_SIZE];
        // pack_size, unp_size, file_crc, file_time stay zero.
        let declared_head_size: u16 = (FILE_HEAD_BASE_SIZE + 32) as u16;
        header[10..12].copy_from_slice(&declared_head_size.to_le_bytes());
        // name_size = 0 keeps minimum_size == FILE_HEAD_BASE_SIZE so the
        // earlier "shorter than its name" branch is bypassed.
        header[19] = 0;
        let err = FileHeader::parse(&header).unwrap_err();
        assert_eq!(err, Error::TooShort);
    }
}
