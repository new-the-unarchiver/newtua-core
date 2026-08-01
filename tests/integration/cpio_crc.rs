//! cpio, crc variant (`070702`) — what `cpio -o -H crc` writes: the newc record
//! layout down to the byte, with the one field newc leaves zero filled in.
//!
//! That field, despite the variant's name, holds no CRC: it is the sum of the
//! body's bytes truncated to 32 bits. The records are built here rather than
//! committed as fixtures, so the checksum can be forged on purpose — which is
//! the only way to test that a mismatch is refused.
//!
//! What these tests pin down:
//!
//! * the variant opens at all (it used to be refused as "not implemented");
//! * a matching checksum reads silently;
//! * a mismatched one is an error **at read time**, not at open time — building
//!   the listing must never read a body;
//! * the compression layer routes a crc archive to the handler, so a `.cpio.gz`
//!   of this variant expands instead of staying one opaque entry.

use newtua_core::archive::OpenOptions;
use newtua_core::archive::{EntryKind, FormatId};
use newtua_core::detect::open;
use std::path::Path;

use crate::cpio_newc::as_file;

const HEADER_LEN: usize = 110;

const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;

/// NULs needed after `len` to reach the next multiple of four.
fn pad4(len: usize) -> usize {
    (4 - (len % 4)) % 4
}

/// The variant's checksum: every byte of the body, added up as unsigned, kept
/// to 32 bits.
fn body_checksum(body: &[u8]) -> u32 {
    body.iter()
        .fold(0u32, |acc, b| acc.wrapping_add(u32::from(*b)))
}

/// One crc record. `check` overrides the checksum written into the header,
/// which is how the mismatch tests forge one; `None` writes the true sum.
fn crc_record_with_check(name: &[u8], mode: u32, body: &[u8], check: Option<u32>) -> Vec<u8> {
    let namesize = name.len() + 1;
    let mut rec = Vec::new();
    rec.extend_from_slice(b"070702");
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
        u64::from(check.unwrap_or_else(|| body_checksum(body))),
    ];
    for f in fields {
        rec.extend_from_slice(format!("{f:08x}").as_bytes());
    }
    assert_eq!(rec.len(), HEADER_LEN);
    rec.extend_from_slice(name);
    rec.push(0);
    rec.resize(rec.len() + pad4(HEADER_LEN + namesize), 0);
    rec.extend_from_slice(body);
    rec.resize(rec.len() + pad4(body.len()), 0);
    rec
}

fn crc_record(name: &[u8], mode: u32, body: &[u8]) -> Vec<u8> {
    crc_record_with_check(name, mode, body, None)
}

/// The closing record every crc archive ends with.
fn crc_trailer() -> Vec<u8> {
    crc_record(b"TRAILER!!!", 0, b"")
}

/// A small tree, with a body of high bytes so a sum that read them as signed
/// would not match.
fn sample_tree() -> (Vec<u8>, Vec<u8>) {
    let high: Vec<u8> = (0..300u32).map(|i| (i % 256) as u8).collect();
    let mut archive = crc_record(b"sub", S_IFDIR | 0o755, b"");
    archive.extend_from_slice(&crc_record(b"sub/link", S_IFLNK | 0o777, b"a.bin"));
    archive.extend_from_slice(&crc_record(b"a.bin", S_IFREG | 0o644, &high));
    archive.extend_from_slice(&crc_record(b"b.txt", S_IFREG | 0o600, b"second\n"));
    archive.extend_from_slice(&crc_trailer());
    (archive, high)
}

/// The variant opens, lists and reads: entries, kinds, modes and body bytes.
#[test]
fn crc_archive_lists_and_reads() {
    let (archive, high) = sample_tree();
    let path = as_file(&archive);

    let mut reader = open(&path, &OpenOptions::default()).expect("open a crc archive");
    assert_eq!(reader.format(), FormatId::Cpio);

    let entries = reader.entries().expect("entries").to_vec();
    assert_eq!(entries.len(), 4);
    assert!(matches!(entries[0].kind, EntryKind::Dir));
    assert!(matches!(
        &entries[1].kind,
        EntryKind::Symlink { target } if target == Path::new("a.bin")
    ));
    assert_eq!(entries[2].path, Path::new("a.bin"));
    assert_eq!(entries[2].size, high.len() as u64);
    assert_eq!(entries[2].mode, Some(S_IFREG | 0o644));
    assert_eq!(entries[3].path, Path::new("b.txt"));

    let mut out = Vec::new();
    reader.read_entry(2, &mut out).expect("read a.bin");
    assert_eq!(out, high, "a matching checksum must read silently");
    out.clear();
    reader.read_entry(3, &mut out).expect("read b.txt");
    assert_eq!(out, b"second\n");
}

/// A forged checksum is refused — and only when the body is read. Opening the
/// archive and listing it must still succeed, because a listing never reads a
/// body and so has nothing to verify.
#[test]
fn crc_mismatch_is_an_error_at_read_not_at_open() {
    let body = b"the quick brown fox";
    let mut archive = crc_record_with_check(
        b"tampered.txt",
        S_IFREG | 0o644,
        body,
        Some(body_checksum(body) ^ 0xFF),
    );
    archive.extend_from_slice(&crc_record(b"intact.txt", S_IFREG | 0o644, b"fine\n"));
    archive.extend_from_slice(&crc_trailer());
    let path = as_file(&archive);

    let mut reader =
        open(&path, &OpenOptions::default()).expect("a bad checksum must not block opening");
    let entries = reader.entries().expect("entries").to_vec();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].path, Path::new("tampered.txt"));

    let result = reader.read_entry(0, &mut Vec::new());
    match result {
        Err(newtua_core::error::Error::Corrupt(msg)) => {
            assert!(msg.contains("tampered.txt"), "entry must be named: {msg}");
            assert!(msg.contains("checksum"), "{msg}");
        }
        other => panic!(
            "expected Corrupt for a mismatched checksum, got {:?}",
            other.map(|()| "Ok")
        ),
    }

    // The record after the bad one is unaffected.
    let mut out = Vec::new();
    reader.read_entry(1, &mut out).expect("read intact.txt");
    assert_eq!(out, b"fine\n");
}

/// The compression layer looks for tar and then for cpio inside a decompressed
/// stream, and the cpio check has to claim the same variants the handler opens.
/// A crc archive inside gzip must therefore expand into its entries, not stay
/// one opaque blob.
#[test]
fn crc_cpio_inside_gzip_expands_to_its_entries() {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write as _;

    let (archive, high) = sample_tree();
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&archive).unwrap();
    let gz = encoder.finish().unwrap();
    let path = as_file(&gz);

    let mut reader = open(&path, &OpenOptions::default()).expect("open a gzipped crc archive");
    assert_eq!(
        reader.format(),
        FormatId::Cpio,
        "the crc archive stayed a single compressed entry"
    );
    let entries = reader.entries().expect("entries").to_vec();
    assert_eq!(entries.len(), 4);
    assert_eq!(entries[2].path, Path::new("a.bin"));

    let mut out = Vec::new();
    reader.read_entry(2, &mut out).expect("read a.bin");
    assert_eq!(out, high);
}
