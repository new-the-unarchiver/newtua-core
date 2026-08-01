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
//!
//! Two committed fixtures come from the real producer instead, because a
//! hand-built record can only ever confirm what its builder already believes.
//! `/usr/bin/cpio` on macOS is bsdcpio and answers `No such format 'crc'`, so
//! these were made with **GNU cpio 2.15** (homebrew, keg-only,
//! `/opt/homebrew/opt/cpio/bin/cpio`):
//!
//! ```text
//! # cpio_crc_gnu.cpio — a regular file, a file of bytes above 0x7F, a
//! # directory, a nested file and a symlink
//! printf 'hello crc\n' > a.txt
//! printf '\xff\xfe\x80\x7f\x00\x01\xaa\x55' > high.bin
//! mkdir dir && printf 'nested\n' > dir/b.txt
//! ln -s a.txt link
//! printf 'a.txt\nhigh.bin\ndir\ndir/b.txt\nlink\n' \
//!     | /opt/homebrew/opt/cpio/bin/cpio -o -H crc > cpio_crc_gnu.cpio
//!
//! # cpio_crc_gnu_hardlink.cpio — two names of one inode, plus a third file
//! printf 'hello crc\n' > a.txt && ln a.txt hard.txt && printf 'other\n' > c.txt
//! printf 'a.txt\nhard.txt\nc.txt\n' \
//!     | /opt/homebrew/opt/cpio/bin/cpio -o -H crc > cpio_crc_gnu_hardlink.cpio
//! ```

use newtua_core::archive::OpenOptions;
use newtua_core::archive::{ArchiveReader, EntryKind, FormatId};
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

// ── The real producer: GNU cpio 2.15 ─────────────────────────────────────────

fn fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Find one entry by path and return its index, or say what was there instead.
fn index_of(reader: &mut Box<dyn ArchiveReader>, path: &str) -> usize {
    let entries = reader.entries().expect("entries");
    entries
        .iter()
        .position(|e| e.path == Path::new(path))
        .unwrap_or_else(|| {
            panic!(
                "{path} missing; got {:?}",
                entries.iter().map(|e| &e.path).collect::<Vec<_>>()
            )
        })
}

/// Read one entry by path and return its body.
fn body_of(reader: &mut Box<dyn ArchiveReader>, path: &str) -> Vec<u8> {
    let idx = index_of(reader, path);
    let mut out = Vec::new();
    reader.read_entry(idx, &mut out).expect("read_entry");
    out
}

/// The raw `check` field, `filesize` and body of one record, read straight out
/// of the archive bytes — deliberately not through the crate under test, so a
/// test can state what GNU cpio really wrote.
fn raw_record(archive: &[u8], want: &[u8]) -> (u32, u64, Vec<u8>) {
    let mut pos = 0usize;
    loop {
        let header = &archive[pos..pos + HEADER_LEN];
        assert_eq!(&header[..6], b"070702", "record at {pos} is not crc");
        let field = |i: usize| {
            let text = std::str::from_utf8(&header[6 + 8 * i..14 + 8 * i]).expect("hex field");
            u64::from_str_radix(text, 16).expect("hex field")
        };
        let filesize = field(6) as usize;
        let namesize = field(11) as usize;
        let check = field(12) as u32;
        let name_end = pos + HEADER_LEN + namesize;
        let name = archive[pos + HEADER_LEN..name_end]
            .strip_suffix(b"\0")
            .expect("names are NUL-terminated");
        let body_start = name_end + pad4(HEADER_LEN + namesize);
        assert_ne!(
            name, b"TRAILER!!!",
            "no record named {want:?} in the archive"
        );
        if name == want {
            return (
                check,
                filesize as u64,
                archive[body_start..body_start + filesize].to_vec(),
            );
        }
        pos = body_start + filesize + pad4(filesize);
    }
}

/// A genuine `cpio -o -H crc` archive, read end to end: paths, kinds, modes,
/// every body byte for byte, and the symlink's target.
#[test]
fn gnu_crc_archive_lists_and_reads_byte_for_byte() {
    let mut reader = open(&fixture("cpio_crc_gnu.cpio"), &OpenOptions::default())
        .expect("open a real GNU cpio crc archive");
    assert_eq!(reader.format(), FormatId::Cpio);

    let entries = reader.entries().expect("entries").to_vec();
    let paths: Vec<&Path> = entries.iter().map(|e| e.path.as_path()).collect();
    assert_eq!(
        paths,
        [
            Path::new("a.txt"),
            Path::new("high.bin"),
            Path::new("dir"),
            Path::new("dir/b.txt"),
            Path::new("link"),
        ],
        "GNU cpio packs the names in the order they were fed to it"
    );

    // Modes, straight out of the headers: 100644 for the files, 40755 for the
    // directory, 120755 for the symlink.
    assert_eq!(entries[0].mode, Some(0o100644));
    assert_eq!(entries[1].mode, Some(0o100644));
    assert_eq!(entries[2].mode, Some(0o040755));
    assert_eq!(entries[3].mode, Some(0o100644));
    assert_eq!(entries[4].mode, Some(0o120755));

    assert!(matches!(entries[0].kind, EntryKind::File));
    assert!(matches!(entries[2].kind, EntryKind::Dir));
    assert!(
        matches!(&entries[4].kind, EntryKind::Symlink { target } if target == Path::new("a.txt")),
        "the symlink's target must survive: {:?}",
        entries[4].kind
    );

    // Every body, byte for byte. `high.bin` is the one that matters most: its
    // bytes above 0x7F only add up to the 1020 the header claims if they are
    // summed unsigned.
    assert_eq!(body_of(&mut reader, "a.txt"), b"hello crc\n");
    assert_eq!(
        body_of(&mut reader, "high.bin"),
        [0xFF, 0xFE, 0x80, 0x7F, 0x00, 0x01, 0xAA, 0x55]
    );
    assert_eq!(body_of(&mut reader, "dir/b.txt"), b"nested\n");
    // A directory has no body and reading it is not an error.
    assert!(body_of(&mut reader, "dir").is_empty());
}

/// **GNU cpio 2.15 writes a zero `check` field for everything that is not a
/// regular file** — a symlink included, even though its body is not empty at
/// all: it holds the target. Verified on the committed fixture, whose `link`
/// record declares `check = 0` over a five-byte body that sums to 495.
///
/// Reading such an archive must therefore never hold a symlink's body against
/// the header's checksum. Today it cannot: the parser hands symlink targets out
/// of the listing and gives the entry no body to read. This test is what turns
/// red if that ever changes — a "fix" that starts verifying symlinks would make
/// us reject archives from the reference implementation.
#[test]
fn gnu_crc_zeroes_the_checksum_of_a_symlink() {
    let archive = std::fs::read(fixture("cpio_crc_gnu.cpio")).expect("read the fixture");

    let (check, filesize, body) = raw_record(&archive, b"link");
    assert_eq!(check, 0, "GNU cpio zeroes the checksum of a symlink");
    assert_eq!(body, b"a.txt", "the body is the link target, not nothing");
    assert_eq!(filesize, 5);
    assert_eq!(
        body_checksum(&body),
        495,
        "the body really would sum to something other than the zero in the header"
    );

    // A regular file in the same archive does carry its sum, so the zero above
    // is the producer's rule about symlinks, not a producer that never fills
    // the field in.
    let (file_check, _, file_body) = raw_record(&archive, b"a.txt");
    assert_eq!(file_check, body_checksum(&file_body));
    assert_eq!(file_check, 886);

    // And the archive opens and reads through, symlink and all.
    let mut reader = open(&fixture("cpio_crc_gnu.cpio"), &OpenOptions::default())
        .expect("a zero checksum on a symlink must not stop the archive from opening");
    let idx = index_of(&mut reader, "link");
    let mut out = Vec::new();
    reader
        .read_entry(idx, &mut out)
        .expect("a symlink must not be checked against the zero in its header");
    assert!(out.is_empty(), "a symlink has no body to hand out");
    assert_eq!(body_of(&mut reader, "a.txt"), b"hello crc\n");
}

/// Hard links, as GNU cpio writes them: one inode under two names, the body
/// stored with the **last** name only and the earlier ones left with
/// `filesize = 0` and `check = 0`.
///
/// What this pins down is that such an archive reads without error — the
/// zero-length member's empty body does add up to the zero its header claims,
/// so the crc check passes. What it also records is the gap: we do not
/// reconstruct hard links, so the first name comes back empty rather than
/// carrying the content stored under the second. If that is ever fixed, this
/// test is where the change becomes visible.
#[test]
fn gnu_crc_hardlink_members_read_without_error() {
    let archive = std::fs::read(fixture("cpio_crc_gnu_hardlink.cpio")).expect("read the fixture");
    // The producer's layout, read from the bytes: the first name is a stub.
    let (first_check, first_size, _) = raw_record(&archive, b"a.txt");
    assert_eq!((first_check, first_size), (0, 0));
    let (last_check, last_size, last_body) = raw_record(&archive, b"hard.txt");
    assert_eq!((last_check, last_size), (886, 10));
    assert_eq!(last_body, b"hello crc\n");

    let mut reader = open(
        &fixture("cpio_crc_gnu_hardlink.cpio"),
        &OpenOptions::default(),
    )
    .expect("open a crc archive with a hard link");
    let entries = reader.entries().expect("entries").to_vec();
    let paths: Vec<&Path> = entries.iter().map(|e| e.path.as_path()).collect();
    assert_eq!(
        paths,
        [
            Path::new("a.txt"),
            Path::new("hard.txt"),
            Path::new("c.txt")
        ],
        "both names of the inode are listed, plus the unrelated file"
    );

    // The name the body was stored under reads it back.
    assert_eq!(body_of(&mut reader, "hard.txt"), b"hello crc\n");
    assert_eq!(body_of(&mut reader, "c.txt"), b"other\n");
    // The other name reads back empty: its record really holds no bytes and we
    // do not follow the inode to the one that does. Not an error — a known gap.
    assert!(
        body_of(&mut reader, "a.txt").is_empty(),
        "hard links are not reconstructed; the stub member is empty"
    );
    assert_eq!(entries[0].size, 0);
}
