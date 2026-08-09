//! Vendored: the read half of `rars` — RAR 1.3 through RAR 7, in pure Rust.
//!
//! The facade over the version-specific format modules: detects archive
//! families, exposes common member metadata, and streams extraction to
//! caller-provided writers without buffering whole archives in memory.
//!
//! Upstream, what was cut and every deliberate change: `VENDORED.md` beside
//! this file. Writing, archive repair and the nightly-only SIMD paths are
//! gone — the engine extracts and lists, and never creates an archive.

pub mod codec;
pub mod crc32;
pub mod crypto;
pub mod detect;
pub mod error;
pub mod features;
mod io_util;
pub mod rar13;
pub mod rar15_40;
pub mod rar50;
mod source;
pub mod version;
mod volume_extract;

pub use detect::{ArchiveSignature, SFX_SCAN_LIMIT, detect_archive_family, find_archive_start};
pub use error::{Error, Result};
pub use features::FeatureSet;
use std::io::{Read, Write};
use std::path::Path;
pub use version::{ArchiveFamily, ArchiveVersion};

#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
/// Options used while parsing or extracting archives.
pub struct ArchiveReadOptions<'a> {
    /// Password bytes used for encrypted headers or payloads.
    pub password: Option<&'a [u8]>,
    /// Optional RAR 5 whole-member buffered decode limit.
    ///
    /// Filtered RAR 5 members need whole-member transforms. Compressed members
    /// above this limit use the streaming path and reject filtered streams
    /// with an unsupported-feature error instead of buffering the full member.
    pub rar50_buffered_decode_limit: Option<u64>,
}

impl<'a> ArchiveReadOptions<'a> {
    /// Creates read options without a password.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates read options with a password.
    pub fn with_password(password: &'a [u8]) -> Self {
        Self {
            password: Some(password),
            ..Self::default()
        }
    }

    /// Creates read options with an optional password.
    pub fn with_optional_password(password: Option<&'a [u8]>) -> Self {
        Self {
            password,
            ..Self::default()
        }
    }

    /// Sets the RAR 5 whole-member buffered decode limit.
    pub fn with_rar50_buffered_decode_limit(mut self, limit: u64) -> Self {
        self.rar50_buffered_decode_limit = Some(limit);
        self
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// A parsed RAR archive, preserving the concrete archive family.
pub enum Archive {
    /// RAR 1.3/1.4 archive.
    Rar13(rar13::Archive),
    /// RAR 1.5 through RAR 4.x archive.
    Rar15To40(rar15_40::Archive),
    /// RAR 5.0 or later archive, including RAR 7 archives.
    Rar50Plus(rar50::Archive),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// Metadata supplied to streaming extraction callbacks.
pub struct ExtractedEntryMeta {
    /// Raw entry name bytes as stored by the archive family.
    pub name: Vec<u8>,
    /// DOS/FAT timestamp when the archive family exposes one.
    pub file_time: u32,
    /// File attributes widened to a common integer type.
    pub file_attr: u64,
    /// Whether the entry is a directory.
    pub is_directory: bool,
}

impl ExtractedEntryMeta {
    /// Creates common metadata for extraction callbacks.
    pub fn new(name: Vec<u8>, file_time: u32, file_attr: u64, is_directory: bool) -> Self {
        Self {
            name,
            file_time,
            file_attr,
            is_directory,
        }
    }

    /// Raw entry name bytes as stored by the archive family.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name
    }

    /// Returns the entry name with invalid UTF-8 replaced for display only.
    ///
    /// Use [`Self::name_bytes`] when exact archive bytes matter.
    pub fn name_lossy(&self) -> String {
        String::from_utf8_lossy(&self.name).into_owned()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// Common member view plus family-specific detail.
pub struct ArchiveMember {
    /// Metadata shared across archive families.
    pub meta: ArchiveMemberMeta,
    /// Extra metadata that is meaningful only for one archive family.
    pub detail: ArchiveMemberDetail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// Family-independent metadata for a file-like archive member.
pub struct ArchiveMemberMeta {
    /// Archive family that produced this member.
    pub family: ArchiveFamily,
    /// Raw entry name bytes as stored by the archive.
    pub name: Vec<u8>,
    /// Packed payload size in bytes.
    pub packed_size: u64,
    /// Unpacked file size in bytes.
    pub unpacked_size: u64,
    /// DOS/FAT timestamp when present.
    pub file_time: Option<u32>,
    /// File attributes widened to a common integer type.
    pub file_attr: u64,
    /// Host OS discriminator when present in the archive format.
    pub host_os: Option<u64>,
    /// Whether the member is a directory.
    pub is_directory: bool,
    /// Whether the member payload is encrypted.
    pub is_encrypted: bool,
    /// Whether the member payload is stored without compression.
    pub is_stored: bool,
    /// Whether the member continues from a previous volume.
    pub is_split_before: bool,
    /// Whether the member continues into the next volume.
    pub is_split_after: bool,
}

impl ArchiveMemberMeta {
    /// Raw member name bytes as stored by the archive family.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name
    }

    /// Returns the member name with invalid UTF-8 replaced for display only.
    ///
    /// Use [`Self::name_bytes`] when exact archive bytes matter.
    pub fn name_lossy(&self) -> String {
        String::from_utf8_lossy(&self.name).into_owned()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// Family-specific member metadata.
pub enum ArchiveMemberDetail {
    /// RAR 1.3/1.4 member fields.
    #[non_exhaustive]
    Rar13 {
        /// Compression method byte from the file header.
        method: u8,
        /// Minimum unpacker version byte from the file header.
        unpack_version: u8,
        /// Legacy 16-bit file checksum.
        file_checksum: u16,
        /// Whether the member carries a file-comment extension.
        has_file_comment: bool,
    },
    /// RAR 1.5 through RAR 4.x member fields.
    #[non_exhaustive]
    Rar15To40 {
        /// Compression method byte from the file header.
        method: u8,
        /// Minimum unpacker version byte from the file header.
        unpack_version: u8,
        /// Stored CRC-32 of the unpacked data.
        crc32: u32,
        /// Whether this member participates in a solid stream.
        solid: bool,
        /// Per-file salt when file encryption is used.
        salt: Option<[u8; 8]>,
        /// Whether the member carries a file-comment extension.
        has_file_comment: bool,
    },
    /// RAR 5.0 and later member fields.
    #[non_exhaustive]
    Rar50Plus {
        /// Raw compression-info field from the RAR5 file header.
        compression_info: u64,
        /// Stored CRC-32 when present.
        crc32: Option<u32>,
        /// Strong file hash when present.
        hash: Option<ArchiveMemberHash>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// Strong hash metadata attached to an archive member.
pub enum ArchiveMemberHash {
    /// RAR5 BLAKE2sp file hash.
    Blake2sp([u8; 32]),
    /// Unknown hash record retained for inspection.
    Other { hash_type: u64, data: Vec<u8> },
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Lazy iterator returned by [`Archive::members`].
pub struct ArchiveMembers<'a> {
    inner: ArchiveMembersInner<'a>,
    index: usize,
}

#[derive(Debug, Clone)]
enum ArchiveMembersInner<'a> {
    Rar13(&'a [rar13::Entry]),
    Rar15To40(&'a [rar15_40::Block]),
    Rar50Plus(&'a [rar50::Block]),
}

impl Iterator for ArchiveMembers<'_> {
    type Item = ArchiveMember;

    fn next(&mut self) -> Option<Self::Item> {
        match self.inner {
            ArchiveMembersInner::Rar13(entries) => {
                let entry = entries.get(self.index)?;
                self.index += 1;
                Some(rar13_member(entry))
            }
            ArchiveMembersInner::Rar15To40(blocks) => {
                while let Some(block) = blocks.get(self.index) {
                    self.index += 1;
                    if let rar15_40::Block::File(file) = block {
                        return Some(rar15_40_member(file));
                    }
                }
                None
            }
            ArchiveMembersInner::Rar50Plus(blocks) => {
                while let Some(block) = blocks.get(self.index) {
                    self.index += 1;
                    if let rar50::Block::File(file) = block {
                        return Some(rar50_member(file));
                    }
                }
                None
            }
        }
    }
}

impl Archive {
    /// Returns the detected archive family.
    pub fn family(&self) -> ArchiveFamily {
        match self {
            Self::Rar13(_) => ArchiveFamily::Rar13,
            Self::Rar15To40(_) => ArchiveFamily::Rar15To40,
            Self::Rar50Plus(_) => ArchiveFamily::Rar50Plus,
        }
    }

    /// Returns the byte offset where the RAR archive begins after any SFX stub.
    pub fn sfx_offset(&self) -> usize {
        match self {
            Self::Rar13(archive) => archive.sfx_offset,
            Self::Rar15To40(archive) => archive.sfx_offset,
            Self::Rar50Plus(archive) => archive.sfx_offset,
        }
    }

    /// Iterates over file-like members using a common cross-version metadata view.
    pub fn members(&self) -> ArchiveMembers<'_> {
        match self {
            Self::Rar13(archive) => ArchiveMembers {
                inner: ArchiveMembersInner::Rar13(&archive.entries),
                index: 0,
            },
            Self::Rar15To40(archive) => ArchiveMembers {
                inner: ArchiveMembersInner::Rar15To40(&archive.blocks),
                index: 0,
            },
            Self::Rar50Plus(archive) => ArchiveMembers {
                inner: ArchiveMembersInner::Rar50Plus(&archive.blocks),
                index: 0,
            },
        }
    }

    /// Streams extracted entries to caller-provided writers.
    pub fn extract_to<F>(&self, password: Option<&[u8]>, open: F) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        self.extract_to_with_options(read_options(password), open)
    }

    /// Streams extracted entries to caller-provided writers with read options.
    pub fn extract_to_with_options<F>(
        &self,
        options: ArchiveReadOptions<'_>,
        mut open: F,
    ) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
    {
        match self {
            Self::Rar13(archive) => {
                archive.extract_to(options.password, |meta| open(&rar13_meta(meta)))
            }
            Self::Rar15To40(archive) => {
                archive.extract_to(options, |meta| open(&rar15_40_meta(meta)))
            }
            Self::Rar50Plus(archive) => archive.extract_to(options, |meta| open(&rar50_meta(meta))),
        }
    }

    /// Returns the concrete RAR 1.3/1.4 archive when this archive has that family.
    pub fn as_rar13(&self) -> Option<&rar13::Archive> {
        match self {
            Self::Rar13(archive) => Some(archive),
            Self::Rar15To40(_) => None,
            Self::Rar50Plus(_) => None,
        }
    }

    /// Returns the concrete RAR 1.5 through RAR 4.x archive when applicable.
    pub fn as_rar15_40(&self) -> Option<&rar15_40::Archive> {
        match self {
            Self::Rar13(_) => None,
            Self::Rar15To40(archive) => Some(archive),
            Self::Rar50Plus(_) => None,
        }
    }

    /// Returns the concrete RAR 5.0 or later archive when applicable.
    pub fn as_rar50(&self) -> Option<&rar50::Archive> {
        match self {
            Self::Rar13(_) | Self::Rar15To40(_) => None,
            Self::Rar50Plus(archive) => Some(archive),
        }
    }
}

fn rar13_member(entry: &rar13::Entry) -> ArchiveMember {
    ArchiveMember {
        meta: ArchiveMemberMeta {
            family: ArchiveFamily::Rar13,
            name: entry.name.clone(),
            packed_size: u64::from(entry.header.pack_size),
            unpacked_size: u64::from(entry.header.unp_size),
            file_time: Some(entry.header.file_time),
            file_attr: u64::from(entry.header.file_attr),
            host_os: None,
            is_directory: entry.is_directory(),
            is_encrypted: entry.is_encrypted(),
            is_stored: entry.is_stored(),
            is_split_before: entry.is_split_before(),
            is_split_after: entry.is_split_after(),
        },
        detail: ArchiveMemberDetail::Rar13 {
            method: entry.header.method,
            unpack_version: entry.header.unp_ver,
            file_checksum: entry.header.file_crc,
            has_file_comment: entry.has_file_comment(),
        },
    }
}

fn rar15_40_member(file: &rar15_40::FileHeader) -> ArchiveMember {
    ArchiveMember {
        meta: ArchiveMemberMeta {
            family: ArchiveFamily::Rar15To40,
            name: file.name.clone(),
            packed_size: file.pack_size,
            unpacked_size: file.unp_size,
            file_time: Some(file.file_time),
            file_attr: u64::from(file.attr),
            host_os: Some(u64::from(file.host_os)),
            is_directory: file.is_directory(),
            is_encrypted: file.is_encrypted(),
            is_stored: file.is_stored(),
            is_split_before: file.is_split_before(),
            is_split_after: file.is_split_after(),
        },
        detail: ArchiveMemberDetail::Rar15To40 {
            method: file.method,
            unpack_version: file.unp_ver,
            crc32: file.file_crc,
            solid: file.is_solid(),
            salt: file.salt,
            has_file_comment: file.has_file_comment(),
        },
    }
}

fn rar50_member(file: &rar50::FileHeader) -> ArchiveMember {
    ArchiveMember {
        meta: ArchiveMemberMeta {
            family: ArchiveFamily::Rar50Plus,
            name: file.name.clone(),
            packed_size: file.packed_size(),
            unpacked_size: file.unpacked_size,
            file_time: file.mtime,
            file_attr: file.attributes,
            host_os: Some(file.host_os),
            is_directory: file.is_directory(),
            is_encrypted: file.encrypted,
            is_stored: file.is_stored(),
            is_split_before: file.is_split_before(),
            is_split_after: file.is_split_after(),
        },
        detail: ArchiveMemberDetail::Rar50Plus {
            compression_info: file.compression_info,
            crc32: file.data_crc32,
            hash: file.hash.as_ref().map(rar50_member_hash),
        },
    }
}

fn rar50_member_hash(hash: &rar50::FileHash) -> ArchiveMemberHash {
    match hash.hash_type {
        0 if hash.data.len() == 32 => {
            let mut data = [0; 32];
            data.copy_from_slice(&hash.data);
            ArchiveMemberHash::Blake2sp(data)
        }
        _ => ArchiveMemberHash::Other {
            hash_type: hash.hash_type,
            data: hash.data.clone(),
        },
    }
}

#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
/// Archive reader facade with signature-based dispatch.
pub struct ArchiveReader;

impl ArchiveReader {
    /// Detects the archive signature in a byte slice.
    pub fn detect(input: &[u8]) -> Result<ArchiveSignature> {
        detect_archive_family(input).ok_or(Error::UnsupportedSignature)
    }

    /// Parses an archive from memory with default read options.
    pub fn read(input: &[u8]) -> Result<Archive> {
        Self::read_with_options(input, ArchiveReadOptions::default())
    }

    /// Parses an archive from an owned memory buffer with default read options.
    pub fn read_owned(input: Vec<u8>) -> Result<Archive> {
        Self::read_owned_with_options(input, ArchiveReadOptions::default())
    }

    /// Parses an archive from memory using explicit read options.
    pub fn read_with_options(input: &[u8], options: ArchiveReadOptions<'_>) -> Result<Archive> {
        let signature =
            find_archive_start(input, SFX_SCAN_LIMIT).ok_or(Error::UnsupportedSignature)?;
        match signature.family {
            ArchiveFamily::Rar13 => Ok(Archive::Rar13(rar13::Archive::parse(input)?)),
            ArchiveFamily::Rar15To40 => Ok(Archive::Rar15To40(
                rar15_40::Archive::parse_with_options(input, options)?,
            )),
            ArchiveFamily::Rar50Plus => Ok(Archive::Rar50Plus(rar50::Archive::parse_with_options(
                input, options,
            )?)),
        }
    }

    /// Parses an archive from an owned memory buffer using explicit read options.
    pub fn read_owned_with_options(
        input: Vec<u8>,
        options: ArchiveReadOptions<'_>,
    ) -> Result<Archive> {
        let signature =
            find_archive_start(&input, SFX_SCAN_LIMIT).ok_or(Error::UnsupportedSignature)?;
        match signature.family {
            ArchiveFamily::Rar13 => Ok(Archive::Rar13(rar13::Archive::parse_owned(input)?)),
            ArchiveFamily::Rar15To40 => Ok(Archive::Rar15To40(
                rar15_40::Archive::parse_owned_with_options(input, options)?,
            )),
            ArchiveFamily::Rar50Plus => Ok(Archive::Rar50Plus(
                rar50::Archive::parse_owned_with_options(input, options)?,
            )),
        }
    }

    /// Parses an archive from a path with default read options.
    pub fn read_path(path: impl AsRef<Path>) -> Result<Archive> {
        Self::read_path_with_options(path, ArchiveReadOptions::default())
    }

    /// Parses an archive from a path using explicit read options.
    pub fn read_path_with_options(
        path: impl AsRef<Path>,
        options: ArchiveReadOptions<'_>,
    ) -> Result<Archive> {
        let path = path.as_ref();
        let mut file = std::fs::File::open(path)?;
        let len = file.metadata()?.len();
        let mut scan = vec![0; len.min(SFX_SCAN_LIMIT as u64) as usize];
        file.read_exact(&mut scan)?;
        let signature =
            find_archive_start(&scan, SFX_SCAN_LIMIT).ok_or(Error::UnsupportedSignature)?;
        match signature.family {
            ArchiveFamily::Rar13 => Ok(Archive::Rar13(rar13::Archive::parse_path_with_signature(
                path, signature,
            )?)),
            ArchiveFamily::Rar15To40 => Ok(Archive::Rar15To40(
                rar15_40::Archive::parse_path_with_signature(path, signature, options)?,
            )),
            ArchiveFamily::Rar50Plus => Ok(Archive::Rar50Plus(
                rar50::Archive::parse_path_with_signature(path, signature, options)?,
            )),
        }
    }
}

fn read_options(password: Option<&[u8]>) -> ArchiveReadOptions<'_> {
    match password {
        Some(password) => ArchiveReadOptions::with_password(password),
        None => ArchiveReadOptions::new(),
    }
}

/// Streams a multivolume archive set to caller-provided writers.
pub fn extract_volumes_to<F>(archives: &[Archive], password: Option<&[u8]>, open: F) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
{
    extract_volumes_to_with_options(archives, read_options(password), open)
}

/// Streams a multivolume archive set to caller-provided writers with read options.
pub fn extract_volumes_to_with_options<F>(
    archives: &[Archive],
    options: ArchiveReadOptions<'_>,
    mut open: F,
) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write>>,
{
    let Some(first) = archives.first() else {
        return Err(Error::InvalidHeader("volume set is empty"));
    };

    match first.family() {
        ArchiveFamily::Rar13 => {
            let typed = rar13_volumes(archives)?;
            rar13::extract_volumes_to(&typed, options.password, |meta| open(&rar13_meta(meta)))
        }
        ArchiveFamily::Rar15To40 => {
            let typed = rar15_40_volumes(archives)?;
            rar15_40::extract_volumes_to(&typed, options, |meta| open(&rar15_40_meta(meta)))
        }
        ArchiveFamily::Rar50Plus => {
            let typed = rar50_volumes(archives)?;
            rar50::extract_volumes_to(&typed, options, |meta| open(&rar50_meta(meta)))
        }
    }
}

fn rar13_meta(meta: &rar13::ExtractedEntryMeta) -> ExtractedEntryMeta {
    ExtractedEntryMeta {
        name: meta.name.clone(),
        file_time: meta.file_time,
        file_attr: u64::from(meta.file_attr),
        is_directory: meta.is_directory,
    }
}

fn rar15_40_meta(meta: &rar15_40::ExtractedEntryMeta) -> ExtractedEntryMeta {
    ExtractedEntryMeta {
        name: meta.name.clone(),
        file_time: meta.file_time,
        file_attr: u64::from(meta.attr),
        is_directory: meta.is_directory,
    }
}

fn rar50_meta(meta: &rar50::ExtractedEntryMeta) -> ExtractedEntryMeta {
    ExtractedEntryMeta {
        name: meta.name.clone(),
        file_time: meta.file_time,
        file_attr: meta.attr,
        is_directory: meta.is_directory,
    }
}

fn rar13_volumes(archives: &[Archive]) -> Result<Vec<rar13::Archive>> {
    archives
        .iter()
        .map(|archive| match archive {
            Archive::Rar13(archive) => Ok(archive.clone()),
            Archive::Rar15To40(_) | Archive::Rar50Plus(_) => {
                Err(Error::InvalidHeader("mixed archive families in volume set"))
            }
        })
        .collect()
}

fn rar15_40_volumes(archives: &[Archive]) -> Result<Vec<rar15_40::Archive>> {
    archives
        .iter()
        .map(|archive| match archive {
            Archive::Rar15To40(archive) => Ok(archive.clone()),
            Archive::Rar13(_) | Archive::Rar50Plus(_) => {
                Err(Error::InvalidHeader("mixed archive families in volume set"))
            }
        })
        .collect()
}

fn rar50_volumes(archives: &[Archive]) -> Result<Vec<rar50::Archive>> {
    archives
        .iter()
        .map(|archive| match archive {
            Archive::Rar50Plus(archive) => Ok(archive.clone()),
            Archive::Rar13(_) | Archive::Rar15To40(_) => {
                Err(Error::InvalidHeader("mixed archive families in volume set"))
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::path::{Path, PathBuf};
    use std::rc::Rc;

    struct CollectWriter {
        data: Rc<RefCell<Vec<u8>>>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct CollectedEntry {
        name: Vec<u8>,
        data: Vec<u8>,
        file_time: u32,
        file_attr: u64,
        is_directory: bool,
    }

    fn deterministic_noise(len: usize) -> Vec<u8> {
        let mut state = 0x1234_5678u32;
        (0..len)
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (state >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn extracted_entry_meta_exposes_raw_and_lossy_names() {
        let meta = ExtractedEntryMeta {
            name: vec![0xff, b'.', b't', b'x', b't'],
            file_time: 0,
            file_attr: 0,
            is_directory: false,
        };

        assert_eq!(meta.name_bytes(), [0xff, b'.', b't', b'x', b't']);
        assert_eq!(meta.name_lossy(), "\u{fffd}.txt");
    }

    impl Write for CollectWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.data.borrow_mut().extend_from_slice(buf);
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
            Ok(Box::new(CollectWriter { data }))
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

    fn collect_rar15_40(archive: &rar15_40::Archive) -> Result<Vec<CollectedEntry>> {
        let entries = RefCell::new(Vec::new());
        archive.extract_to(ArchiveReadOptions::default(), |meta| {
            let data = Rc::new(RefCell::new(Vec::new()));
            entries.borrow_mut().push((meta.clone(), Rc::clone(&data)));
            Ok(Box::new(CollectWriter { data }))
        })?;
        Ok(entries
            .into_inner()
            .into_iter()
            .map(|(meta, data)| CollectedEntry {
                name: meta.name,
                data: data.borrow().clone(),
                file_time: meta.file_time,
                file_attr: u64::from(meta.attr),
                is_directory: meta.is_directory,
            })
            .collect())
    }

    fn collect_rar15_40_volumes(
        archives: &[rar15_40::Archive],
        password: Option<&[u8]>,
    ) -> Result<Vec<CollectedEntry>> {
        let entries = RefCell::new(Vec::new());
        rar15_40::extract_volumes_to(archives, read_options(password), |meta| {
            let data = Rc::new(RefCell::new(Vec::new()));
            entries.borrow_mut().push((meta.clone(), Rc::clone(&data)));
            Ok(Box::new(CollectWriter { data }))
        })?;
        Ok(entries
            .into_inner()
            .into_iter()
            .map(|(meta, data)| CollectedEntry {
                name: meta.name,
                data: data.borrow().clone(),
                file_time: meta.file_time,
                file_attr: u64::from(meta.attr),
                is_directory: meta.is_directory,
            })
            .collect())
    }

    fn collect_rar50_volumes(
        archives: &[rar50::Archive],
        password: Option<&[u8]>,
    ) -> Result<Vec<CollectedEntry>> {
        let entries = RefCell::new(Vec::new());
        rar50::extract_volumes_to(archives, read_options(password), |meta| {
            let data = Rc::new(RefCell::new(Vec::new()));
            entries.borrow_mut().push((meta.clone(), Rc::clone(&data)));
            Ok(Box::new(CollectWriter { data }))
        })?;
        Ok(entries
            .into_inner()
            .into_iter()
            .map(|(meta, data)| CollectedEntry {
                name: meta.name,
                data: data.borrow().clone(),
                file_time: meta.file_time,
                file_attr: meta.attr,
                is_directory: meta.is_directory,
            })
            .collect())
    }

    fn rar13_options(target: ArchiveVersion) -> rar13::WriterOptions {
        rar13::WriterOptions::new(target, FeatureSet::store_only())
    }

    fn rar15_options(target: ArchiveVersion) -> rar15_40::WriterOptions {
        rar15_options_with_features(target, FeatureSet::store_only())
    }

    fn rar15_options_with_features(
        target: ArchiveVersion,
        features: FeatureSet,
    ) -> rar15_40::WriterOptions {
        rar15_40::WriterOptions::new(target, features)
    }
}
