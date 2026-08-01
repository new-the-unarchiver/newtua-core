//! cpio, newc variant (`070701`) — SVR4 "new ASCII", what GNU and BSD
//! `cpio -o -H newc` write, and what a Linux initramfs is made of.
//!
//! The records are built here rather than committed as fixtures: the interesting
//! cases are names in legacy encodings and names whose length forces padding,
//! and both are a few bytes of setup each.
//!
//! Layout of one record, which is what these helpers encode:
//!
//! ```text
//! 110 bytes  header: "070701" + 13 fields of 8 ASCII hex digits
//!  namesize  name, NUL-terminated, `namesize` counting the NUL
//!   0..3     NULs, until 110 + namesize is a multiple of four
//!  filesize  body
//!   0..3     NULs, until filesize is a multiple of four
//! ```

use newtua_core::archive::{EntryKind, FormatId, OpenOptions};
use newtua_core::detect::open;
use std::io::Write as _;
use std::path::Path;

const HEADER_LEN: usize = 110;

const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;

/// NULs needed after `len` to reach the next multiple of four.
fn pad4(len: usize) -> usize {
    (4 - (len % 4)) % 4
}

/// One newc record. `extra_nuls` appends further NULs to the name *inside*
/// `namesize` — what `dracut-cpio` does when it pads a name out to a block
/// boundary.
pub(crate) fn newc_record_padded(
    name: &[u8],
    mode: u32,
    body: &[u8],
    extra_nuls: usize,
) -> Vec<u8> {
    let namesize = name.len() + 1 + extra_nuls;
    let mut rec = Vec::new();
    rec.extend_from_slice(b"070701");
    // ino, mode, uid, gid, nlink, mtime, filesize, devmajor, devminor,
    // rdevmajor, rdevminor, namesize, check.
    let fields: [u64; 13] = [
        1,
        u64::from(mode),
        0,
        0,
        1,
        1,
        body.len() as u64,
        0,
        0,
        0,
        0,
        namesize as u64,
        0,
    ];
    for f in fields {
        rec.extend_from_slice(format!("{f:08x}").as_bytes());
    }
    assert_eq!(rec.len(), HEADER_LEN);
    rec.extend_from_slice(name);
    rec.resize(rec.len() + 1 + extra_nuls, 0);
    rec.resize(rec.len() + pad4(HEADER_LEN + namesize), 0);
    rec.extend_from_slice(body);
    rec.resize(rec.len() + pad4(body.len()), 0);
    rec
}

pub(crate) fn newc_record(name: &[u8], mode: u32, body: &[u8]) -> Vec<u8> {
    newc_record_padded(name, mode, body, 0)
}

/// The closing record every newc archive ends with.
pub(crate) fn newc_trailer() -> Vec<u8> {
    newc_record(b"TRAILER!!!", 0, b"")
}

/// Write `bytes` where `detect::open` can reach them.
pub(crate) fn as_file(bytes: &[u8]) -> tempfile::TempPath {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(bytes).unwrap();
    tmp.into_temp_path()
}

/// Names in a legacy encoding: the archive must open, the paths must decode,
/// and `path_raw` must hold the archive's exact bytes.
///
/// Three encodings, one shape. Each is opened twice: once with the encoding
/// named (the paths are then exact) and once without (only the opening and the
/// raw bytes are claimed — which encoding the detector lands on is its own
/// business, and the point of the ticket is that the archive opens at all).
fn legacy_names_case(label: &str, raw: &[&[u8]], decoded: &[&str]) {
    let mut archive = Vec::new();
    for (i, name) in raw.iter().enumerate() {
        archive.extend_from_slice(&newc_record(
            name,
            S_IFREG | 0o644,
            format!("body {i}\n").as_bytes(),
        ));
    }
    archive.extend_from_slice(&newc_trailer());
    let path = as_file(&archive);

    let opts = OpenOptions {
        encoding_override: Some(label.to_string()),
        ..OpenOptions::default()
    };
    let mut reader =
        open(&path, &opts).unwrap_or_else(|e| panic!("{label} archive must open: {e}"));
    assert_eq!(reader.format(), FormatId::Cpio);
    let entries = reader.entries().expect("entries").to_vec();
    assert_eq!(entries.len(), raw.len());
    for (i, want) in decoded.iter().enumerate() {
        assert_eq!(entries[i].path, Path::new(want), "{label}: path {i}");
        assert_eq!(entries[i].path_raw, raw[i], "{label}: raw bytes {i}");
    }

    let mut body = Vec::new();
    reader.read_entry(0, &mut body).expect("read_entry 0");
    assert_eq!(body, b"body 0\n");

    // Without the label the archive still opens, and the raw bytes are still
    // the archive's own.
    let mut auto = open(&path, &OpenOptions::default())
        .unwrap_or_else(|e| panic!("{label} archive must open undeclared too: {e}"));
    let entries = auto.entries().expect("entries").to_vec();
    assert_eq!(entries.len(), raw.len());
    for (i, want) in raw.iter().enumerate() {
        assert_eq!(
            &entries[i].path_raw, want,
            "{label}: raw bytes {i}, no label"
        );
    }
}

/// Russian names in CP1251 — the case the ticket was filed for. Before this
/// parser existed the whole archive failed to open.
#[test]
fn newc_cp1251_names_open_and_decode() {
    // "отчет.txt", "письмо.txt", "документ.txt" in windows-1251.
    legacy_names_case(
        "windows-1251",
        &[
            &[0xEE, 0xF2, 0xF7, 0xE5, 0xF2, b'.', b't', b'x', b't'],
            &[0xEF, 0xE8, 0xF1, 0xFC, 0xEC, 0xEE, b'.', b't', b'x', b't'],
            &[
                0xE4, 0xEE, 0xEA, 0xF3, 0xEC, 0xE5, 0xED, 0xF2, b'.', b't', b'x', b't',
            ],
        ],
        &["отчет.txt", "письмо.txt", "документ.txt"],
    );
}

/// Japanese names in Shift-JIS.
#[test]
fn newc_shift_jis_names_open_and_decode() {
    // "日本.txt" = 93 FA 96 7B, "東京.txt" = 93 8C 8B 9E.
    legacy_names_case(
        "shift_jis",
        &[
            &[0x93, 0xFA, 0x96, 0x7B, b'.', b't', b'x', b't'],
            &[0x93, 0x8C, 0x8B, 0x9E, b'.', b't', b'x', b't'],
        ],
        &["日本.txt", "東京.txt"],
    );
}

/// French names in Latin-1.
#[test]
fn newc_latin1_names_open_and_decode() {
    // "café.txt", "élève.txt" in windows-1252 / latin1.
    legacy_names_case(
        "windows-1252",
        &[
            &[b'c', b'a', b'f', 0xE9, b'.', b't', b'x', b't'],
            &[0xE9, b'l', 0xE8, b'v', b'e', b'.', b't', b'x', b't'],
        ],
        &["café.txt", "élève.txt"],
    );
}

/// Alignment is the one thing newc has and odc does not, so it gets a test of
/// its own: a name and a body that each need padding, and a record after them
/// whose content proves the walk did not drift.
#[test]
fn newc_padding_keeps_the_next_record_in_place() {
    // 110 + 7 = 117 → three NULs after the name; a 3-byte body → one after it.
    let mut archive = newc_record(b"ab.txt", S_IFREG | 0o644, b"odd");
    archive.extend_from_slice(&newc_record(b"second.bin", S_IFREG | 0o600, b"SECOND"));
    archive.extend_from_slice(&newc_trailer());
    let path = as_file(&archive);

    let mut reader = open(&path, &OpenOptions::default()).expect("open padded newc");
    let entries = reader.entries().expect("entries").to_vec();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].path, Path::new("ab.txt"));
    assert_eq!(entries[1].path, Path::new("second.bin"));

    let mut out = Vec::new();
    reader.read_entry(0, &mut out).expect("read_entry 0");
    assert_eq!(out, b"odd", "the body must not carry its padding");
    out.clear();
    reader.read_entry(1, &mut out).expect("read_entry 1");
    assert_eq!(out, b"SECOND", "the second record drifted");
}

/// A name padded with NULs past its terminator keeps the path it had before:
/// the previous parser trimmed every trailing NUL, and so does this one.
#[test]
fn newc_extra_nuls_in_a_name_are_trimmed() {
    let mut archive = newc_record_padded(b"a.txt", S_IFREG | 0o644, b"hi", 5);
    archive.extend_from_slice(&newc_trailer());
    let path = as_file(&archive);

    let mut reader = open(&path, &OpenOptions::default()).expect("open dracut-style newc");
    let entries = reader.entries().expect("entries").to_vec();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path, Path::new("a.txt"));
    assert_eq!(entries[0].path_raw, b"a.txt");

    let mut out = Vec::new();
    reader.read_entry(0, &mut out).expect("read_entry 0");
    assert_eq!(out, b"hi");
}

/// Directories and symlinks survive the walk, and the file after them is found.
#[test]
fn newc_keeps_dirs_and_symlinks() {
    const S_IFDIR: u32 = 0o040000;
    let mut archive = newc_record(b"sub", S_IFDIR | 0o755, b"");
    archive.extend_from_slice(&newc_record(b"sub/link", S_IFLNK | 0o777, b"a.txt"));
    archive.extend_from_slice(&newc_record(b"a.txt", S_IFREG | 0o644, b"one\n"));
    archive.extend_from_slice(&newc_trailer());
    let path = as_file(&archive);

    let mut reader = open(&path, &OpenOptions::default()).expect("open newc tree");
    let entries = reader.entries().expect("entries").to_vec();
    assert_eq!(entries.len(), 3);
    assert!(matches!(entries[0].kind, EntryKind::Dir));
    assert!(matches!(
        &entries[1].kind,
        EntryKind::Symlink { target } if target == Path::new("a.txt")
    ));

    let mut out = Vec::new();
    reader.read_entry(2, &mut out).expect("read_entry 2");
    assert_eq!(out, b"one\n");
}

/// A `filesize` larger than the file itself is an error at open time, not an
/// allocation of the claimed size.
#[test]
fn newc_oversized_filesize_returns_error() {
    let mut archive = newc_record(b"a.txt", S_IFREG | 0o644, b"tiny");
    archive[54..62].copy_from_slice(b"ffffffff"); // filesize ≈ 4 GB
    archive.extend_from_slice(&newc_trailer());
    let path = as_file(&archive);

    let result = open(&path, &OpenOptions::default());
    assert!(
        matches!(result, Err(newtua_core::error::Error::Corrupt(_))),
        "expected Corrupt for an oversized filesize, got {:?}",
        result.map(|_| "Ok")
    );
}

/// Garbage where the hex digits belong is an error, never a silently wrong
/// number and never a panic.
#[test]
fn newc_garbage_hex_fields_return_error() {
    let mut archive = newc_record(b"a.txt", S_IFREG | 0o644, b"tiny");
    archive[94..102].copy_from_slice(b"zzzzzzzz"); // namesize
    archive.extend_from_slice(&newc_trailer());
    let path = as_file(&archive);

    let result = open(&path, &OpenOptions::default());
    assert!(
        matches!(result, Err(newtua_core::error::Error::Corrupt(_))),
        "expected Corrupt for garbage hex fields, got {:?}",
        result.map(|_| "Ok")
    );
}
