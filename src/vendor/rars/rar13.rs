use crate::vendor::rars::codec::rar13::{Unpack15, unpack15_decode};
use crate::vendor::rars::crypto::rar13::{Rar13Cipher, Rar13DecryptReader};
use crate::vendor::rars::detect::{
    ArchiveSignature, RAR13_SIGNATURE, SFX_SCAN_LIMIT, find_archive_start,
};
use crate::vendor::rars::error::{Error, Result};
use crate::vendor::rars::features::FeatureSet;
use crate::vendor::rars::io_util::{read_exact_at, read_u16, read_u32};
pub(crate) use crate::vendor::rars::source::ArchiveSource;
use crate::vendor::rars::version::{ArchiveFamily, ArchiveVersion};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;

const MAIN_HEAD_SIZE: u16 = 7;
const FILE_HEAD_BASE_SIZE: usize = 21;
const MHD_VOLUME: u8 = 0x01;
const MHD_COMMENT: u8 = 0x02;
const MHD_SOLID: u8 = 0x08;
const MHD_PACK_COMMENT: u8 = 0x10;
const MHD_AV: u8 = 0x20;
const MHD_ALWAYS_SET: u8 = 0x80;
const RAR13_AV_PREFIX: &[u8; 6] = b"\x1ai\x6d\x02\xda\xae";
const COPY_BUFFER_SIZE: usize = 64 * 1024;
const LHD_SPLIT_BEFORE: u8 = 0x01;
const LHD_SPLIT_AFTER: u8 = 0x02;
const LHD_PASSWORD: u8 = 0x04;
const LHD_COMMENT: u8 = 0x08;
const LHD_SOLID: u8 = 0x10;
const METHOD_STORE: u8 = 0;
const METHOD_BEST: u8 = 5;
const DEFAULT_UNP_VER: u8 = 2;

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
    pub sfx_offset: usize,
    pub main: MainHeader,
    pub entries: Vec<Entry>,
    source: ArchiveSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuthenticityVerification {
    pub size: u16,
    pub prefix: [u8; 6],
    pub cipher_body: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthenticityVerificationStatus {
    Absent,
    StructurallyPresent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExtractedEntryMeta {
    pub name: Vec<u8>,
    pub file_time: u32,
    pub file_attr: u8,
    pub is_directory: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct WriterOptions {
    pub target: ArchiveVersion,
    pub features: FeatureSet,
    pub compression_level: Option<u8>,
}

impl WriterOptions {
    pub const fn new(target: ArchiveVersion, features: FeatureSet) -> Self {
        Self {
            target,
            features,
            compression_level: None,
        }
    }

    pub const fn with_compression_level(mut self, level: u8) -> Self {
        self.compression_level = Some(level);
        self
    }
}

impl Default for WriterOptions {
    fn default() -> Self {
        Self {
            target: ArchiveVersion::Rar14,
            features: FeatureSet::store_only(),
            compression_level: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredEntry<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub file_time: u32,
    pub file_attr: u8,
    pub password: Option<&'a [u8]>,
    pub file_comment: Option<&'a [u8]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileEntry<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub file_time: u32,
    pub file_attr: u8,
    pub password: Option<&'a [u8]>,
    pub file_comment: Option<&'a [u8]>,
}

impl MainHeader {
    pub fn is_volume(&self) -> bool {
        self.flags & MHD_VOLUME != 0
    }

    pub fn has_archive_comment(&self) -> bool {
        self.flags & MHD_COMMENT != 0
    }

    pub fn has_packed_comment(&self) -> bool {
        self.flags & MHD_PACK_COMMENT != 0
    }

    pub fn is_solid(&self) -> bool {
        self.flags & MHD_SOLID != 0
    }

    pub fn has_authenticity_verification(&self) -> bool {
        self.flags & MHD_AV != 0
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
    pub fn parse(input: &[u8]) -> Result<Self> {
        let data: Arc<[u8]> = Arc::from(input.to_vec().into_boxed_slice());
        Self::parse_shared(data)
    }

    pub fn parse_owned(input: Vec<u8>) -> Result<Self> {
        Self::parse_shared(Arc::from(input.into_boxed_slice()))
    }

    pub fn parse_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = Arc::new(path.as_ref().to_path_buf());
        let mut file = File::open(path.as_ref())?;
        let len = file.metadata()?.len();
        let scan_len = len.min(SFX_SCAN_LIMIT as u64) as usize;
        let mut scan = vec![0; scan_len];
        file.read_exact(&mut scan)?;
        let sig = find_archive_start(&scan, SFX_SCAN_LIMIT).ok_or(Error::UnsupportedSignature)?;
        if sig.family != ArchiveFamily::Rar13 {
            return Err(Error::UnsupportedSignature);
        }
        Self::parse_seekable(file, len, sig.offset, ArchiveSource::File(path))
    }

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
        Self::parse_seekable(file, len, signature.offset, ArchiveSource::File(path))
    }

    fn parse_shared(input: Arc<[u8]>) -> Result<Self> {
        let sig = find_archive_start(&input, SFX_SCAN_LIMIT).ok_or(Error::UnsupportedSignature)?;
        if sig.family != ArchiveFamily::Rar13 {
            return Err(Error::UnsupportedSignature);
        }

        let archive = &input[sig.offset..];
        let main = MainHeader::parse(archive)?;
        let mut pos = main.head_size as usize;
        let mut entries = Vec::new();

        while pos < archive.len() {
            if archive.len() - pos < FILE_HEAD_BASE_SIZE {
                break;
            }

            let (header, name, extra, consumed) = FileHeader::parse(&archive[pos..])?;
            let data_start = pos + consumed;
            let data_end =
                data_start
                    .checked_add(header.pack_size as usize)
                    .ok_or(Error::InvalidHeader(
                        "RAR 1.3 file data size overflows usize",
                    ))?;
            if data_end > archive.len() {
                return Err(Error::TooShort);
            }

            entries.push(Entry {
                header,
                name,
                extra,
                packed_range: sig.offset + data_start..sig.offset + data_end,
            });
            pos = data_end;
        }

        Ok(Self {
            sfx_offset: sig.offset,
            main,
            entries,
            source: ArchiveSource::Memory(input),
        })
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
        mut cipher: Rar13Cipher,
        out: &mut impl Write,
    ) -> Result<()> {
        let mut buffer = [0u8; COPY_BUFFER_SIZE];
        match &self.source {
            ArchiveSource::Memory(data) => {
                let data = data.get(range).ok_or(Error::TooShort)?;
                for chunk in data.chunks(COPY_BUFFER_SIZE) {
                    buffer[..chunk.len()].copy_from_slice(chunk);
                    for byte in &mut buffer[..chunk.len()] {
                        *byte = cipher.decrypt_byte(*byte);
                    }
                    out.write_all(&buffer[..chunk.len()])?;
                }
            }
            ArchiveSource::File(path) => {
                let mut file = File::open(path.as_ref())?;
                file.seek(SeekFrom::Start(range.start as u64))?;
                let mut remaining = range.len();
                while remaining > 0 {
                    let to_read = remaining.min(buffer.len());
                    file.read_exact(&mut buffer[..to_read])?;
                    for byte in &mut buffer[..to_read] {
                        *byte = cipher.decrypt_byte(*byte);
                    }
                    out.write_all(&buffer[..to_read])?;
                    remaining -= to_read;
                }
            }
        }
        Ok(())
    }

    /// Streams extracted entries to caller-provided writers.
    pub fn extract_to<F>(&self, password: Option<&[u8]>, mut open: F) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        let mut unpack15 = Unpack15::new();
        let mut extracted_count = 0usize;
        for entry in &self.entries {
            if entry.is_split_before() || entry.is_split_after() {
                return Err(Error::InvalidHeader(
                    "RAR 1.3 split entry requires multivolume extraction",
                ));
            }
            let meta = entry.metadata();
            if meta.is_directory {
                let _ = open(&meta)?;
                extracted_count += 1;
                continue;
            }
            let mut writer = open(&meta)?;
            if entry.is_stored() && !entry.is_encrypted() {
                entry
                    .write_stored_to(self, password, &mut writer)
                    .map_err(|error| entry.entry_error("extracting", error))?;
            } else {
                entry
                    .write_compressed_to(
                        self,
                        password,
                        &mut unpack15,
                        self.main.is_solid() && extracted_count != 0,
                        &mut writer,
                    )
                    .map_err(|error| entry.entry_error("extracting", error))?;
            }
            extracted_count += 1;
        }
        Ok(())
    }

    pub fn archive_comment(&self) -> Result<Option<Vec<u8>>> {
        if !self.main.has_archive_comment() {
            return Ok(None);
        }

        let length = read_u16(&self.main.extra, 0)? as usize;
        if self.main.has_packed_comment() {
            if length < 2 {
                return Err(Error::InvalidHeader(
                    "RAR 1.3 packed archive comment is shorter than size field",
                ));
            }
            let unpacked_len = read_u16(&self.main.extra, 2)? as usize;
            let packed_len = length - 2;
            let packed_start = 4usize;
            let packed_end = packed_start
                .checked_add(packed_len)
                .ok_or(Error::InvalidHeader(
                    "RAR 1.3 archive comment size overflows",
                ))?;
            if packed_end > self.main.extra.len() {
                return Err(Error::TooShort);
            }

            let mut packed = self.main.extra[packed_start..packed_end].to_vec();
            Rar13Cipher::new_comment().decrypt_in_place(&mut packed);
            return Ok(Some(unpack15_decode(&packed, unpacked_len)?));
        }

        let comment_start = 2usize;
        let comment_end = comment_start
            .checked_add(length)
            .ok_or(Error::InvalidHeader(
                "RAR 1.3 archive comment size overflows",
            ))?;
        if comment_end > self.main.extra.len() {
            return Err(Error::TooShort);
        }
        Ok(Some(self.main.extra[comment_start..comment_end].to_vec()))
    }

    pub fn authenticity_verification(&self) -> Result<Option<AuthenticityVerification>> {
        if !self.main.has_authenticity_verification() {
            return Ok(None);
        }
        let size = read_u16(&self.main.extra, 0)?;
        if size < RAR13_AV_PREFIX.len() as u16 {
            return Err(Error::InvalidHeader("RAR 1.3 AV payload is too short"));
        }
        let payload_end = 2usize
            .checked_add(size as usize)
            .ok_or(Error::InvalidHeader("RAR 1.3 AV payload size overflows"))?;
        if payload_end > self.main.extra.len() {
            return Err(Error::TooShort);
        }
        let prefix_bytes = self
            .main
            .extra
            .get(2..2 + RAR13_AV_PREFIX.len())
            .ok_or(Error::TooShort)?;
        let prefix: [u8; 6] = prefix_bytes
            .try_into()
            .expect("RAR 1.3 AV prefix slice has fixed length");
        if &prefix != RAR13_AV_PREFIX {
            return Err(Error::InvalidHeader("RAR 1.3 AV prefix mismatch"));
        }
        Ok(Some(AuthenticityVerification {
            size,
            prefix,
            cipher_body: self.main.extra[2 + RAR13_AV_PREFIX.len()..payload_end].to_vec(),
        }))
    }

    pub fn authenticity_verification_status(&self) -> Result<AuthenticityVerificationStatus> {
        Ok(if self.authenticity_verification()?.is_some() {
            AuthenticityVerificationStatus::StructurallyPresent
        } else {
            AuthenticityVerificationStatus::Absent
        })
    }
}

impl Entry {
    pub fn name_bytes(&self) -> &[u8] {
        &self.name
    }

    /// Returns the entry name with invalid UTF-8 replaced for display only.
    ///
    /// Use [`Self::name_bytes`] when exact archive bytes matter.
    pub fn name_lossy(&self) -> String {
        String::from_utf8_lossy(&self.name).into_owned()
    }

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

    pub fn file_comment(&self) -> Result<Option<Vec<u8>>> {
        if !self.has_file_comment() {
            return Ok(None);
        }
        let length = read_u16(&self.extra, 0)? as usize;
        let comment_start = 2usize;
        let comment_end = comment_start
            .checked_add(length)
            .ok_or(Error::InvalidHeader("RAR 1.3 file comment size overflows"))?;
        if comment_end > self.extra.len() {
            return Err(Error::TooShort);
        }
        Ok(Some(self.extra[comment_start..comment_end].to_vec()))
    }

    pub fn is_stored(&self) -> bool {
        self.header.method == METHOD_STORE
    }

    pub fn packed_data<'a>(&self, archive: &'a Archive) -> Result<&'a [u8]> {
        match &archive.source {
            ArchiveSource::Memory(data) => {
                data.get(self.packed_range.clone()).ok_or(Error::TooShort)
            }
            ArchiveSource::File(_) => Err(Error::InvalidHeader(
                "RAR 1.3 file-backed packed data requires owned read",
            )),
        }
    }

    pub fn write_packed_data(&self, archive: &Archive, out: &mut impl Write) -> Result<()> {
        archive.copy_range_to(self.packed_range.clone(), out)
    }

    pub fn verify_checksum(&self, data: &[u8]) -> Result<()> {
        let actual = file_checksum(data);
        if actual == self.header.file_crc {
            Ok(())
        } else {
            Err(Error::CrcMismatch {
                expected: self.header.file_crc,
                actual,
            })
        }
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
pub fn extract_volumes_to<F>(
    volumes: &[Archive],
    password: Option<&[u8]>,
    mut open: F,
) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
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

    fn write_to<F>(
        self,
        volumes: &[Archive],
        final_entry: &Entry,
        password: Option<&[u8]>,
        unpack15: &mut Unpack15,
        solid: bool,
        open: &mut F,
    ) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
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

pub fn file_checksum(input: &[u8]) -> u16 {
    let mut checksum = Rar13Checksum::new();
    checksum.update(input);
    checksum.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vendor::rars::codec::rar13::{LongLz, find_long_lz};
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    struct CollectWriter(Rc<RefCell<Vec<u8>>>);

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct CollectedEntry {
        name: Vec<u8>,
        data: Vec<u8>,
        file_time: u32,
        file_attr: u8,
        is_directory: bool,
    }

    impl Write for CollectWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn collect_extract(archive: &Archive, password: Option<&[u8]>) -> Result<Vec<CollectedEntry>> {
        let entries = RefCell::new(Vec::new());
        archive.extract_to(password, |meta| {
            let data = Rc::new(RefCell::new(Vec::new()));
            entries.borrow_mut().push((meta.clone(), Rc::clone(&data)));
            Ok(Box::new(CollectWriter(data)))
        })?;
        Ok(entries
            .into_inner()
            .into_iter()
            .map(|(meta, data)| CollectedEntry {
                name: meta.name,
                data: data.borrow().clone(),
                file_time: meta.file_time,
                file_attr: meta.file_attr,
                is_directory: meta.is_directory,
            })
            .collect())
    }

    fn collect_extract_volumes(
        volumes: &[Archive],
        password: Option<&[u8]>,
    ) -> Result<Vec<CollectedEntry>> {
        let entries = RefCell::new(Vec::new());
        extract_volumes_to(volumes, password, |meta| {
            let data = Rc::new(RefCell::new(Vec::new()));
            entries.borrow_mut().push((meta.clone(), Rc::clone(&data)));
            Ok(Box::new(CollectWriter(data)))
        })?;
        Ok(entries
            .into_inner()
            .into_iter()
            .map(|(meta, data)| CollectedEntry {
                name: meta.name,
                data: data.borrow().clone(),
                file_time: meta.file_time,
                file_attr: meta.file_attr,
                is_directory: meta.is_directory,
            })
            .collect())
    }

    fn synthetic_log_payload(lines: usize) -> Vec<u8> {
        let mut data = Vec::new();
        for index in 0..lines {
            data.extend_from_slice(
                format!(
                    "2026-05-12T12:{:02}:{:02}.000Z INFO worker-{:02} request_id={:04x}-{:05} path=/api/v1/items/{} status={} elapsed_ms={} bytes={} message=processed archive chunk retry={} user=service-{}\n",
                    index % 60,
                    (index * 7) % 60,
                    index % 16,
                    index % 10000,
                    (index * 17) % 100000,
                    index % 2048,
                    200 + (index % 5),
                    (index * 37) % 5000,
                    (index * 911) % 65536,
                    index % 3,
                    index % 32
                )
                .as_bytes(),
            );
        }
        data
    }

    #[test]
    fn rejects_malformed_main_header_boundaries() {
        assert_eq!(MainHeader::parse(b"RE~"), Err(Error::TooShort));

        let mut too_small = Vec::from(&b"RE~^"[..]);
        too_small.extend_from_slice(&6u16.to_le_bytes());
        too_small.push(0x80);
        assert_eq!(
            MainHeader::parse(&too_small),
            Err(Error::InvalidHeader(
                "RAR 1.3 main header is shorter than 7 bytes"
            ))
        );

        let mut truncated_extra = Vec::from(&b"RE~^"[..]);
        truncated_extra.extend_from_slice(&8u16.to_le_bytes());
        truncated_extra.push(0x80);
        assert_eq!(MainHeader::parse(&truncated_extra), Err(Error::TooShort));

        assert!(matches!(
            Archive::parse(b"Rar!\x1a\x07\x00"),
            Err(Error::UnsupportedSignature)
        ));
    }

    #[test]
    fn rejects_file_header_shorter_than_its_name() {
        let mut bytes = Vec::from(&b"RE~^"[..]);
        bytes.extend_from_slice(&7u16.to_le_bytes());
        bytes.push(0x80);
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&(FILE_HEAD_BASE_SIZE as u16).to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.push(0x20);
        bytes.push(0);
        bytes.push(DEFAULT_UNP_VER);
        bytes.push(10);
        bytes.push(METHOD_STORE);

        assert!(matches!(
            Archive::parse(&bytes),
            Err(Error::InvalidHeader(
                "RAR 1.3 file header is shorter than its name"
            ))
        ));
    }

    #[test]
    fn rejects_malformed_comment_extensions() {
        let packed_too_short = Archive {
            sfx_offset: 0,
            main: MainHeader {
                flags: MHD_COMMENT | MHD_PACK_COMMENT,
                head_size: MAIN_HEAD_SIZE,
                extra: 1u16.to_le_bytes().to_vec(),
            },
            entries: Vec::new(),
            source: ArchiveSource::Memory(Arc::new([])),
        };
        assert_eq!(
            packed_too_short.archive_comment(),
            Err(Error::InvalidHeader(
                "RAR 1.3 packed archive comment is shorter than size field"
            ))
        );

        let unpacked_too_short = Archive {
            sfx_offset: 0,
            main: MainHeader {
                flags: MHD_COMMENT,
                head_size: MAIN_HEAD_SIZE,
                extra: 4u16.to_le_bytes().to_vec(),
            },
            entries: Vec::new(),
            source: ArchiveSource::Memory(Arc::new([])),
        };
        assert_eq!(unpacked_too_short.archive_comment(), Err(Error::TooShort));
    }

    #[test]
    fn rejects_malformed_av_extensions() {
        let too_short = Archive {
            sfx_offset: 0,
            main: MainHeader {
                flags: MHD_AV,
                head_size: MAIN_HEAD_SIZE,
                extra: 5u16.to_le_bytes().to_vec(),
            },
            entries: Vec::new(),
            source: ArchiveSource::Memory(Arc::new([])),
        };
        assert_eq!(
            too_short.authenticity_verification(),
            Err(Error::InvalidHeader("RAR 1.3 AV payload is too short"))
        );

        let bad_prefix = Archive {
            sfx_offset: 0,
            main: MainHeader {
                flags: MHD_AV,
                head_size: MAIN_HEAD_SIZE,
                extra: {
                    let mut extra = 6u16.to_le_bytes().to_vec();
                    extra.extend_from_slice(b"badbad");
                    extra
                },
            },
            entries: Vec::new(),
            source: ArchiveSource::Memory(Arc::new([])),
        };
        assert_eq!(
            bad_prefix.authenticity_verification(),
            Err(Error::InvalidHeader("RAR 1.3 AV prefix mismatch"))
        );
    }

    fn short_lz_resistant_prefix(len: usize) -> Vec<u8> {
        let mut data = Vec::with_capacity(len);
        while data.len() < len {
            let next = (0u8..=u8::MAX)
                .find(|&candidate| {
                    if data.len() < 2 {
                        return true;
                    }
                    let start = data.len().saturating_sub(256);
                    !data[start..].windows(3).any(|window| {
                        window == [data[data.len() - 2], data[data.len() - 1], candidate]
                    })
                })
                .expect("byte alphabet can avoid local 3-byte repeats");
            data.push(next);
        }
        data
    }

    #[test]
    fn file_checksum_matches_rar13_algorithm() {
        assert_eq!(file_checksum(b""), 0x0000);
        assert_eq!(file_checksum(b"123456789"), 0xc78a);
    }

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

    fn parse_volumes(bytes: &[Vec<u8>]) -> Vec<Archive> {
        bytes.iter().map(|b| Archive::parse(b).unwrap()).collect()
    }

    #[test]
    fn parse_path_rejects_files_without_rar13_signature() {
        let dir =
            std::env::temp_dir().join(format!("rars-rar13-parse-path-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("not_a_rar.bin");
        std::fs::write(&path, [0u8; 64]).unwrap();

        let err = Archive::parse_path(&path).unwrap_err();
        assert_eq!(err, Error::UnsupportedSignature);

        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
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
