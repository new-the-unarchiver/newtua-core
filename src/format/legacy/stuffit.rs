//! StuffIt family from `newtua-stuffit`: classic StuffIt, StuffIt 5, StuffItX.
//! All standard index-extract containers with real directories. Detection is
//! content-first — the three signatures are distinct, so a `.sit` file routes
//! to classic or SIT5 by `recognize` with no extension tie-break needed.

use crate::archive::{FormatId, OpenOptions};
use std::io::Cursor;

use super::{EntryMeta, legacy_std_handler, mac_date_to_systime};

use newtua_stuffit::sit5::StuffIt5Archive;
use newtua_stuffit::sitx::SitxArchive;
use newtua_stuffit::stuffit::StuffItArchive;

// Classic StuffIt and SIT5 store a file as two streams — data fork and
// resource fork — under one name, told apart by `is_resource_fork()`. Losing
// that flag loses the fork, and with it most of a picture or an application;
// see `Entry::is_resource_fork`. StuffItX has no forks and no dates.

legacy_std_handler! {
    /// StuffIt classic (`.sit`) — the dominant classic-Mac archiver.
    StuffItHandler, StuffItBackend,
    id: FormatId::StuffIt,
    archive: StuffItArchive,
    exts: [],
    recognize: StuffItArchive::recognize,
    open: |b, _o| StuffItArchive::open(Cursor::new(b)),
    metas: |a| a.entries().iter()
        .map(|e| EntryMeta::named(e.name(), e.is_directory(), e.size())
            .resource_fork(e.is_resource_fork())
            .at(mac_date_to_systime(e.modification_date())))
        .collect(),
}

legacy_std_handler! {
    /// StuffIt 5 (`.sit`) — later container, optionally RC4/MD5-encrypted.
    StuffIt5Handler, StuffIt5Backend,
    id: FormatId::StuffIt5,
    archive: StuffIt5Archive,
    exts: [],
    recognize: StuffIt5Archive::recognize,
    open: |b, o: &OpenOptions| match o.password.as_deref() {
        Some(p) => StuffIt5Archive::open_with_password(Cursor::new(b), p.as_bytes()),
        None => StuffIt5Archive::open(Cursor::new(b)),
    },
    metas: |a| a.entries().iter()
        .map(|e| EntryMeta::named(e.name(), e.is_directory(), e.size())
            .resource_fork(e.is_resource_fork())
            .at(mac_date_to_systime(e.modification_date())))
        .collect(),
}

legacy_std_handler! {
    /// StuffItX (`.sitx`) — range-coded successor (parses from an owned buffer).
    StuffItXHandler, StuffItXBackend,
    id: FormatId::StuffItX,
    archive: SitxArchive,
    exts: [],
    recognize: SitxArchive::recognize,
    open: |b, _o| SitxArchive::open(b),
    metas: |a| a.entries().iter().map(|e| EntryMeta::named(e.name(), e.is_directory(), e.size())).collect(),
}
