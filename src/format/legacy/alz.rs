//! ALZip (`.alz`) from `newtua-alz` — ESTsoft's Korean archiver. Standard
//! index-extract container with optional ZipCrypto encryption.

use crate::archive::{FormatId, OpenOptions};
use std::io::Cursor;

use super::{EntryMeta, legacy_std_handler};

use newtua_alz::AlzArchive;

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
    metas: |a| a.entries().iter()
        .map(|e| EntryMeta { raw: e.name().to_vec(), is_dir: e.is_dir(), size: e.size(), is_encrypted: e.is_encrypted() })
        .collect(),
}
