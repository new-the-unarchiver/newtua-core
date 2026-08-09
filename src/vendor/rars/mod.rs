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

pub use detect::{SFX_SCAN_LIMIT, find_archive_start};
pub use error::{Error, Result};

use std::io::Read;
use std::path::Path;
pub use version::ArchiveFamily;

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
    /// Creates read options with an optional password.
    pub fn with_optional_password(password: Option<&'a [u8]>) -> Self {
        Self {
            password,
            ..Self::default()
        }
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
