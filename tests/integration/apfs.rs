//! APFS integration tests (#21c). Three fixtures:
//!
//! - `apfs_zlib.dmg` — a UDIF DMG wrapping an APFS volume (`hdiutil -fs APFS
//!   -format UDZO`), holding `hello.txt`/`sub/nested.txt`. Proves the DMG
//!   volume locator's APFS branch and closes the `report-21b` hole (a DMG
//!   with an APFS volume inside used to fail with `UnknownFormat`).
//! - `apfs_bare.img` — a raw APFS container carve (block 0 = NXSB, no
//!   partition wrapper), vendored from `apfs-core`'s own committed, real
//!   macOS-authored (`hdiutil`+`ditto`) test fixture (see
//!   `crates/apfs-core/tests/data/README.md`, fixture `apfs_content.bin`).
//!   Covers the standalone handler, decmpfs, and symlinks — content already
//!   cross-checked there against `fls`/`istat`/`shasum`/`readlink`.
//! - `apfs_decmpfs.img` — a carve of the corpus reference `apfs_decmpfs.dmg`,
//!   whose every file was compressed by `afsctool` on a real mounted volume.
//!   It holds both storage forms of the `com.apple.decmpfs` xattr — embedded
//!   for the two short files, spilled into its own stream for the two long
//!   ones — which is the pair our own fixtures used to lack entirely. The
//!   sizes it is checked against are the sizes of the payload files that went
//!   *into* the image, so the oracle is construction, not our own reader.

use std::path::Path;

use newtua_core::archive::{ArchiveReader, EntryKind, FormatId, OpenOptions};
use newtua_core::detect::open;
use newtua_core::error::Error;

fn fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn body_of(reader: &mut dyn ArchiveReader, name: &str) -> Vec<u8> {
    let idx = {
        let entries = reader.entries().expect("entries");
        entries
            .iter()
            .position(|e| e.path == Path::new(name))
            .unwrap_or_else(|| panic!("entry {name} not found"))
    };
    let mut body = Vec::new();
    reader.read_entry(idx, &mut body).expect("read_entry");
    body
}

// ── DMG-with-APFS (main path): closes the report-21b hole ──────────────────

#[test]
fn dmg_with_apfs_volume_lists_and_extracts_known_files() {
    let mut reader = open(&fixture("apfs_zlib.dmg"), &OpenOptions::default())
        .expect("open apfs_zlib.dmg (proves DMG volume locator's APFS branch)");
    assert_eq!(reader.format(), FormatId::Dmg);

    let entries = reader.entries().expect("entries").to_vec();
    let hello = entries
        .iter()
        .find(|e| e.path == Path::new("hello.txt"))
        .expect("hello.txt present");
    assert_eq!(hello.kind, EntryKind::File);
    assert_eq!(hello.size, 11);

    let nested = entries
        .iter()
        .find(|e| e.path == Path::new("sub/nested.txt"))
        .expect("sub/nested.txt present");
    assert_eq!(nested.kind, EntryKind::File);
    assert_eq!(nested.size, 12);

    let sub = entries
        .iter()
        .find(|e| e.path == Path::new("sub"))
        .expect("sub dir present");
    assert_eq!(sub.kind, EntryKind::Dir);

    assert_eq!(body_of(reader.as_mut(), "hello.txt"), b"hello apfs\n");
    assert_eq!(body_of(reader.as_mut(), "sub/nested.txt"), b"nested file\n");
}

#[test]
fn dmg_with_apfs_dir_read_is_empty() {
    let mut reader = open(&fixture("apfs_zlib.dmg"), &OpenOptions::default()).expect("open");
    let idx = reader
        .entries()
        .expect("entries")
        .iter()
        .position(|e| e.path == Path::new("sub"))
        .expect("sub dir");
    let mut body = Vec::new();
    reader.read_entry(idx, &mut body).expect("read dir");
    assert!(body.is_empty(), "directory body must be empty");
}

// ── standalone bare container ────────────────────────────────────────────

#[test]
fn apfs_bare_opens_standalone_and_lists_known_files() {
    let mut reader =
        open(&fixture("apfs_bare.img"), &OpenOptions::default()).expect("open apfs_bare.img");
    assert_eq!(reader.format(), FormatId::Apfs);

    let entries = reader.entries().expect("entries").to_vec();
    let plain = entries
        .iter()
        .find(|e| e.path == Path::new("plain.txt"))
        .expect("plain.txt present");
    assert_eq!(plain.kind, EntryKind::File);
    assert_eq!(plain.size, 35);

    let beth = entries
        .iter()
        .find(|e| e.path == Path::new("Dir1/Beth.txt"))
        .expect("Dir1/Beth.txt present");
    assert_eq!(beth.kind, EntryKind::File);
    assert_eq!(beth.size, 33);

    assert_eq!(
        body_of(reader.as_mut(), "plain.txt"),
        b"APFS P4 plain file. Hello extents.\n"
    );
    assert_eq!(
        body_of(reader.as_mut(), "Dir1/Beth.txt"),
        b"Beth target content for symlink.\n"
    );
}

// ── decmpfs: the key #21c capability (empty body under HFS+/#21a) ──────────

#[test]
fn apfs_bare_decmpfs_file_reads_full_content() {
    let mut reader = open(&fixture("apfs_bare.img"), &OpenOptions::default()).expect("open");

    // The listed size must be the logical one, not the inode's nothing. Same
    // ground truth as the hash below: `apfs-core`'s README records the file as
    // 180 000 bytes.
    let listed = reader
        .entries()
        .expect("entries")
        .iter()
        .find(|e| e.path == Path::new("compressed.txt"))
        .expect("compressed.txt present")
        .size;
    assert_eq!(listed, 180_000, "decmpfs file must not list as zero bytes");

    let body = body_of(reader.as_mut(), "compressed.txt");
    assert_eq!(body.len(), 180_000, "decmpfs must decode the FULL content");

    // SHA-256 over the transparently-decompressed bytes, matching the
    // ground truth in `crates/apfs-core/tests/data/README.md` (macOS
    // `shasum -a 256` over the same file, post-decmpfs).
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let digest = hasher.finalize();
    assert_eq!(
        format!("{digest:x}"),
        "3f58a41850c1096de883ada14c98c2375a85b473c80ccbef03c9e72c113abc78"
    );
}

// ── symlinks ─────────────────────────────────────────────────────────────

#[test]
fn apfs_bare_symlink_target_matches_readlink_oracle() {
    let mut reader = open(&fixture("apfs_bare.img"), &OpenOptions::default()).expect("open");
    let entries = reader.entries().expect("entries");
    let link = entries
        .iter()
        .find(|e| e.path == Path::new("symlink_to_beth"))
        .expect("symlink_to_beth present");
    match &link.kind {
        EntryKind::Symlink { target } => {
            assert_eq!(target.as_path(), Path::new("Dir1/Beth.txt"));
        }
        other => panic!("expected Symlink, got {other:?}"),
    }
}

// ── edge cases ───────────────────────────────────────────────────────────

#[test]
fn read_entry_out_of_range_is_invalid_index() {
    let mut reader = open(&fixture("apfs_bare.img"), &OpenOptions::default()).expect("open");
    let n = reader.entries().expect("entries").len();
    let mut sink = Vec::new();
    let err = reader
        .read_entry(n + 100, &mut sink)
        .expect_err("out-of-range index must error");
    assert!(
        matches!(err, Error::InvalidIndex(_)),
        "expected InvalidIndex, got {err:?}"
    );
}

#[test]
fn probe_recognizes_apfs_extension_without_magic() {
    let handlers = newtua_core::detect::registry();
    let apfs_probe = handlers
        .iter()
        .find(|h| h.id() == FormatId::Apfs)
        .expect("ApfsHandler registered");
    assert_eq!(
        apfs_probe.probe(&[0u8; 512], Some("volume.apfs")),
        newtua_core::archive::Confidence::MAGIC
    );
    assert_eq!(
        apfs_probe.probe(&[0u8; 512], Some("image.hfs")),
        newtua_core::archive::Confidence::NONE
    );
}

#[test]
fn file_without_nxsb_magic_is_unknown_format() {
    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let path = tmp_dir.path().join("garbage.apfs");
    std::fs::write(&path, [0u8; 100]).expect("write garbage");

    let err = open(&path, &OpenOptions::default())
        .err()
        .expect("must error");
    assert!(matches!(err, Error::UnknownFormat), "got {err:?}");
}

#[test]
fn nxsb_magic_but_corrupt_body_is_corrupt_not_panic() {
    let mut bytes = vec![0u8; 4096];
    bytes[32..36].copy_from_slice(b"NXSB"); // magic present, everything else garbage
    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let path = tmp_dir.path().join("bad_body.apfs");
    std::fs::write(&path, &bytes).expect("write");

    let err = open(&path, &OpenOptions::default())
        .err()
        .expect("must error, not panic");
    assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
}

// ── decmpfs sizes: the listing used to report zero for every compressed file ─

/// Every file in `apfs_decmpfs.img` is decmpfs-compressed, so none of them has
/// an ordinary data stream and the inode reports no size at all. Until the
/// logical size was taken from the decmpfs header instead, all four listed as
/// zero bytes long while extracting correctly — a listing that contradicted the
/// extraction.
///
/// The expected numbers are the sizes of the payload files the corpus fed to
/// `afsctool`, not numbers this crate produced.
#[test]
fn apfs_decmpfs_sizes_match_the_uncompressed_payload() {
    let mut reader =
        open(&fixture("apfs_decmpfs.img"), &OpenOptions::default()).expect("open apfs_decmpfs.img");
    assert_eq!(reader.format(), FormatId::Apfs);

    // (path, size of the file that went into the image)
    let expected: [(&str, u64); 4] = [
        ("big.txt", 65_529),
        ("привет.txt", 22),
        ("nested/deep/tiny.bin", 256),
        ("hello.txt", 15),
    ];

    let entries = reader.entries().expect("entries").to_vec();
    for (name, want) in expected {
        let entry = entries
            .iter()
            .find(|e| e.path == Path::new(name))
            .unwrap_or_else(|| panic!("{name} present"));
        assert_eq!(entry.kind, EntryKind::File);
        assert_eq!(entry.size, want, "{name}: listed size");
    }

    // And the listing must agree with what extraction actually writes — that
    // is the pair the defect broke.
    for (name, want) in expected {
        let body = body_of(reader.as_mut(), name);
        assert_eq!(body.len() as u64, want, "{name}: extracted length");
    }
}

/// A directory keeps a zero size even though its inode carries flags of its
/// own: the size lookup must stay confined to files.
#[test]
fn apfs_decmpfs_directories_have_no_size() {
    let mut reader = open(&fixture("apfs_decmpfs.img"), &OpenOptions::default()).expect("open");
    let entries = reader.entries().expect("entries").to_vec();
    for name in ["nested", "nested/deep"] {
        let dir = entries
            .iter()
            .find(|e| e.path == Path::new(name))
            .unwrap_or_else(|| panic!("{name} present"));
        assert_eq!(dir.kind, EntryKind::Dir);
        assert_eq!(dir.size, 0, "{name}");
    }
}

// ── POSIX permissions ────────────────────────────────────────────────────────

/// The inode's mode reaches `Entry`. It used to be dropped even though the same
/// field was already being read one line above, to tell a directory from a
/// symlink — so a closed directory came out public and a script lost its
/// execute bit.
///
/// The expected values are macOS's own, read from the mounted image:
///   hdiutil attach -nobrowse -readonly tests/fixtures/apfs_zlib.dmg
///   stat -f '%Sp %N' /Volumes/TEST/…
/// which reports `drwxr-xr-x` for `sub` and `-rw-r--r--` for the two files.
#[test]
fn apfs_reports_posix_modes() {
    let mut reader = open(&fixture("apfs_zlib.dmg"), &OpenOptions::default()).expect("open");
    let entries = reader.entries().expect("entries").to_vec();

    let mode_of = |name: &str| {
        entries
            .iter()
            .find(|e| e.path == Path::new(name))
            .unwrap_or_else(|| panic!("{name} missing: {entries:#?}"))
            .mode
    };

    assert_eq!(mode_of("sub").map(|m| m & 0o7777), Some(0o755));
    assert_eq!(mode_of("hello.txt").map(|m| m & 0o7777), Some(0o644));
    assert_eq!(mode_of("sub/nested.txt").map(|m| m & 0o7777), Some(0o644));

    // The type bits ride along, as with cpio, HFS+, ISO and WIM.
    assert_eq!(mode_of("sub").map(|m| m & 0o170000), Some(0o040000));
    assert_eq!(mode_of("hello.txt").map(|m| m & 0o170000), Some(0o100000));
}
