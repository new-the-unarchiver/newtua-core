//! Classic Macintosh formats from `newtua-mac`: BinHex, MacBinary,
//! AppleSingle/AppleDouble, Compact Pro, PackIt. All are standard
//! index-extract containers; detection is content-first (each has a reliable
//! in-header `recognize`), so no extension fallbacks.
//!
//! Every one of these formats stores a file as **two** streams — the data fork
//! and the resource fork — and reports them as two entries sharing one name.
//! Which of the two an entry is comes from `is_resource_fork()`, and it has to
//! travel all the way to extraction: for a picture or an application the
//! resource fork is most of the file, and for some files it is the whole file.
//! See `Entry::is_resource_fork`.

use crate::archive::{FormatId, OpenOptions};
use std::io::Cursor;

use super::{EntryMeta, applesingle_date_to_systime, legacy_std_handler, mac_date_to_systime};

use newtua_mac::applesingle::AppleSingleArchive;
use newtua_mac::binhex::BinHexArchive;
use newtua_mac::compactpro::CompactProArchive;
use newtua_mac::macbinary::MacBinaryArchive;
use newtua_mac::packit::PackItArchive;

legacy_std_handler! {
    /// BinHex 4.0 (`.hqx`) — 7-bit ASCII transport encoding with resource forks.
    /// Carries no timestamps of its own.
    BinHexHandler, BinHexBackend,
    id: FormatId::BinHex,
    archive: BinHexArchive,
    exts: [],
    recognize: BinHexArchive::recognize,
    open: |b, _o| BinHexArchive::open(Cursor::new(b)),
    metas: |a| a.entries().iter()
        .map(|e| EntryMeta::file(e.name(), e.size()).resource_fork(e.is_resource_fork()))
        .collect(),
}

legacy_std_handler! {
    /// MacBinary I/II/III (`.bin`) — resource-fork container. Detected by its
    /// 128-byte header (recognize-only; `.bin` is too generic to key on).
    MacBinaryHandler, MacBinaryBackend,
    id: FormatId::MacBinary,
    archive: MacBinaryArchive,
    exts: [],
    recognize: MacBinaryArchive::recognize,
    open: |b, _o| MacBinaryArchive::open(Cursor::new(b)),
    metas: |a| a.entries().iter()
        .map(|e| EntryMeta::file(e.name(), e.size())
            .resource_fork(e.is_resource_fork())
            .at(mac_date_to_systime(e.modification_date())))
        .collect(),
}

legacy_std_handler! {
    /// AppleSingle / AppleDouble — fork-preserving encoding (magic
    /// `0x00051600`/`0x00051607`). Dates count from 2000, not from 1904.
    AppleSingleHandler, AppleSingleBackend,
    id: FormatId::AppleSingle,
    archive: AppleSingleArchive,
    exts: [],
    recognize: AppleSingleArchive::recognize,
    open: |b, _o| AppleSingleArchive::open(Cursor::new(b)),
    metas: |a| a.entries().iter()
        .map(|e| EntryMeta::file(e.name(), e.size())
            .resource_fork(e.is_resource_fork())
            .at(applesingle_date_to_systime(e.modification_date())))
        .collect(),
}

legacy_std_handler! {
    /// Compact Pro (`.cpt`) — early-90s Mac archiver (has real directories).
    CompactProHandler, CompactProBackend,
    id: FormatId::CompactPro,
    archive: CompactProArchive,
    exts: [".cpt"],
    recognize: CompactProArchive::recognize,
    open: |b, _o| CompactProArchive::open(Cursor::new(b)),
    metas: |a| a.entries().iter()
        .map(|e| EntryMeta::named(e.name(), e.is_directory(), e.size())
            .resource_fork(e.is_resource_fork())
            .at(mac_date_to_systime(e.modification_date())))
        .collect(),
}

legacy_std_handler! {
    /// PackIt (`.pit`) — early Mac archiver, optionally password-protected.
    PackItHandler, PackItBackend,
    id: FormatId::PackIt,
    archive: PackItArchive,
    exts: [".pit"],
    recognize: PackItArchive::recognize,
    open: |b, o: &OpenOptions| match o.password.as_deref() {
        Some(p) => PackItArchive::open_with_password(Cursor::new(b), p.as_bytes()),
        None => PackItArchive::open(Cursor::new(b)),
    },
    metas: |a| a.entries().iter()
        .map(|e| EntryMeta::file(e.name(), e.size())
            .resource_fork(e.is_resource_fork())
            .at(mac_date_to_systime(e.modification_date())))
        .collect(),
}
