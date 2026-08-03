//! ALZip (`.alz`) from `newtua-alz` — ESTsoft's Korean archiver. Standard
//! index-extract container with optional ZipCrypto encryption.

use crate::archive::{FormatId, OpenOptions};
use crate::error::Error;
use std::io::Cursor;

use super::{EntryMeta, dos_date_to_systime, legacy_std_handler};

use newtua_alz::{AlzArchive, PasswordStatus};

legacy_std_handler! {
    /// ALZip (`.alz`). Multi-volume sets aren't reconstructed here (single-file
    /// `open` only); a `.alz` first volume opens its own leading member.
    AlzHandler, AlzBackend,
    id: FormatId::Alz,
    archive: AlzArchive,
    exts: [".alz"],
    recognize: AlzArchive::recognize,
    open: |b, o: &OpenOptions| match o.password.as_deref() {
        Some(p) => AlzArchive::open_with_password(Cursor::new(b), p.as_bytes()),
        None => AlzArchive::open(Cursor::new(b)),
    },
    // The record's MS-DOS timestamp packs the date word above the time word.
    metas: |a| a.entries().iter()
        .map(|e| EntryMeta {
            raw: e.name().to_vec(),
            is_dir: e.is_dir(),
            size: e.size(),
            is_encrypted: e.is_encrypted(),
            is_resource_fork: false,
            modified: dos_date_to_systime((e.dostime() >> 16) as u16, e.dostime() as u16),
        })
        .collect(),
    // Judged from the first encrypted member's ZipCrypto check byte, decoding
    // nothing — the same bargain `format/zip.rs` makes, and the reason a wrong
    // password stops the extraction before the first file is written.
    verify: |a| match a.password_status() {
        PasswordStatus::NotEncrypted | PasswordStatus::Correct => Ok(()),
        PasswordStatus::Missing => Err(Error::Encrypted),
        PasswordStatus::Wrong => Err(Error::WrongPassword),
    },
}
