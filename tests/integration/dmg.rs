use std::path::Path;
use std::process::Command;

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
            .position(|e| e.path.to_string_lossy() == name)
            .unwrap_or_else(|| panic!("entry {name} not found"))
    };
    let mut body = Vec::new();
    reader.read_entry(idx, &mut body).expect("read_entry");
    body
}

/// Assert the standard fixture content (`hello.txt` / `sub/nested.txt`,
/// generated from the same `src/` tree across all codec variants — see
/// `task-21b-udif-container.md` §9.1) is present with the right sizes/kinds
/// and extracts to the exact bytes.
fn assert_standard_fixture_content(path: &std::path::Path) {
    let mut reader = open(path, &OpenOptions::default())
        .unwrap_or_else(|e| panic!("open {}: {e}", path.display()));
    assert_eq!(reader.format(), FormatId::Dmg);

    let entries = reader.entries().expect("entries").to_vec();
    let hello = entries
        .iter()
        .find(|e| e.path.to_string_lossy() == "hello.txt")
        .expect("hello.txt present");
    assert_eq!(hello.kind, EntryKind::File);
    assert_eq!(hello.size, 10);

    let nested = entries
        .iter()
        .find(|e| e.path.to_string_lossy() == "sub/nested.txt")
        .expect("sub/nested.txt present");
    assert_eq!(nested.kind, EntryKind::File);
    assert_eq!(nested.size, 12);

    let sub = entries
        .iter()
        .find(|e| e.path.to_string_lossy() == "sub")
        .expect("sub dir present");
    assert_eq!(sub.kind, EntryKind::Dir);

    assert_eq!(body_of(reader.as_mut(), "hello.txt"), b"hello dmg\n");
    assert_eq!(body_of(reader.as_mut(), "sub/nested.txt"), b"nested file\n");
}

// ── open + list + extract, one per committed codec fixture ─────────────────
//
// All five share the same HFS+ payload (§9.1); each proves a distinct chunk
// decode path end-to-end through the real container (koly -> plist -> blkx ->
// mish -> chunk decode -> raw image -> GPT-partition scan -> HFS+).

#[test]
fn dmg_zlib_lists_and_extracts_known_files() {
    assert_standard_fixture_content(&fixture("dmg_zlib.dmg"));
}

#[test]
fn dmg_bzip2_lists_and_extracts_known_files() {
    assert_standard_fixture_content(&fixture("dmg_bzip2.dmg"));
}

#[test]
fn dmg_lzfse_lists_and_extracts_known_files() {
    assert_standard_fixture_content(&fixture("dmg_lzfse.dmg"));
}

#[test]
fn dmg_lzma_lists_and_extracts_known_files() {
    assert_standard_fixture_content(&fixture("dmg_lzma.dmg"));
}

#[test]
fn dmg_adc_lists_and_extracts_known_files() {
    assert_standard_fixture_content(&fixture("dmg_adc.dmg"));
}

#[test]
fn dmg_dir_read_is_empty() {
    let mut reader = open(&fixture("dmg_zlib.dmg"), &OpenOptions::default()).expect("open");
    let idx = reader
        .entries()
        .expect("entries")
        .iter()
        .position(|e| e.path.to_string_lossy() == "sub")
        .expect("sub dir");
    let mut body = Vec::new();
    reader.read_entry(idx, &mut body).expect("read dir");
    assert!(body.is_empty(), "directory body must be empty");
}

#[test]
fn read_entry_out_of_range_is_invalid_index() {
    let mut reader = open(&fixture("dmg_zlib.dmg"), &OpenOptions::default()).expect("open");
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
fn probe_recognizes_dmg_extension_without_magic() {
    let handlers = newtua_core::detect::registry();
    let dmg_probe = handlers
        .iter()
        .find(|h| h.id() == FormatId::Dmg)
        .expect("DmgHandler registered");
    for name in ["image.dmg", "Image.DMG"] {
        assert_eq!(
            dmg_probe.probe(&[0u8; 512], Some(name)),
            newtua_core::archive::Confidence::MAGIC,
            "extension {name}"
        );
    }
    assert_eq!(
        dmg_probe.probe(&[0u8; 512], Some("image.hfs")),
        newtua_core::archive::Confidence::NONE
    );
}

// ── edge / malicious inputs ─────────────────────────────────────────────────

#[test]
fn short_file_named_dmg_is_unknown_format() {
    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let path = tmp_dir.path().join("short.dmg");
    std::fs::write(&path, [0u8; 100]).expect("write short file");

    let err = open(&path, &OpenOptions::default())
        .err()
        .expect("must error");
    assert!(matches!(err, Error::UnknownFormat), "got {err:?}");
}

#[test]
fn file_without_koly_magic_is_unknown_format() {
    let bytes = std::fs::read(fixture("dmg_zlib.dmg")).expect("read fixture");
    let mut corrupted = bytes.clone();
    let len = corrupted.len();
    corrupted[len - 512..len - 508].copy_from_slice(b"NOPE"); // clobber koly magic
    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let path = tmp_dir.path().join("bad_koly.dmg");
    std::fs::write(&path, &corrupted).expect("write corrupted");

    let err = open(&path, &OpenOptions::default())
        .err()
        .expect("must error");
    assert!(matches!(err, Error::UnknownFormat), "got {err:?}");
}

#[test]
fn truncated_data_fork_does_not_panic() {
    let bytes = std::fs::read(fixture("dmg_zlib.dmg")).expect("read fixture");
    // Keep the koly trailer + plist intact (both live in the tail of the
    // file), but chop the data fork the plist's blkx chunks point into.
    let truncated = &bytes[..100];
    let koly = &bytes[bytes.len() - 512..];
    let mut broken = truncated.to_vec();
    broken.extend_from_slice(koly);
    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let path = tmp_dir.path().join("truncated.dmg");
    std::fs::write(&path, &broken).expect("write truncated");

    // The koly trailer's own offsets no longer point at valid data (file is
    // far shorter than xml_offset+xml_length) -- must be a clean error, not a
    // panic, regardless of which stage first notices.
    let result = open(&path, &OpenOptions::default());
    assert!(result.is_err(), "expected Err for truncated dmg, got Ok");
}

// ── synthetic DMG builder (malformed-input tests below) ─────────────────────
//
// Byte layout mirrors `format/dmg.rs`'s `parse_mish`/`parse_koly` exactly
// (task §6.1/§6.3, all fields big-endian): mish header up to offset 0xCC,
// then one 40-byte `BLKXChunkEntry` per chunk (entry_type@0, sector_number@8,
// sector_count@16, compressed_offset@24, compressed_length@32, relative to
// the entry's own start).

const MISH_CHUNKS_OFFSET: usize = 0xCC;
const CHUNK_ENTRY_SIZE: usize = 40;

fn synthetic_mish(
    sector_number: u64,
    sector_count: u64,
    chunks: &[(u32, u64, u64, u64, u64)], // (entry_type, sector_number, sector_count, compressed_offset, compressed_length)
) -> Vec<u8> {
    let mut buf = vec![0u8; MISH_CHUNKS_OFFSET + chunks.len() * CHUNK_ENTRY_SIZE];
    buf[0x00..0x04].copy_from_slice(b"mish");
    buf[0x04..0x08].copy_from_slice(&1u32.to_be_bytes()); // version
    buf[0x08..0x10].copy_from_slice(&sector_number.to_be_bytes());
    buf[0x10..0x18].copy_from_slice(&sector_count.to_be_bytes());
    // data_offset (0x18..0x20) left zeroed -- not exercised here.
    buf[0xC8..0xCC].copy_from_slice(&(chunks.len() as u32).to_be_bytes());
    for (i, &(entry_type, c_sector, c_count, c_off, c_len)) in chunks.iter().enumerate() {
        let off = MISH_CHUNKS_OFFSET + i * CHUNK_ENTRY_SIZE;
        buf[off..off + 4].copy_from_slice(&entry_type.to_be_bytes());
        buf[off + 8..off + 16].copy_from_slice(&c_sector.to_be_bytes());
        buf[off + 16..off + 24].copy_from_slice(&c_count.to_be_bytes());
        buf[off + 24..off + 32].copy_from_slice(&c_off.to_be_bytes());
        buf[off + 32..off + 40].copy_from_slice(&c_len.to_be_bytes());
    }
    buf
}

/// Assemble a full synthetic `.dmg` file: a one-`blkx` plist wrapping `mish`,
/// plus a koly trailer pointing at it (`DataForkOffset` = 0). Returns the raw
/// bytes, ready to write to a temp path.
fn build_synthetic_dmg(mish: &[u8]) -> Vec<u8> {
    use base64::Engine as _;
    let mish_b64 = base64::engine::general_purpose::STANDARD.encode(mish);
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>resource-fork</key>
    <dict>
        <key>blkx</key>
        <array>
            <dict>
                <key>CFName</key><string>whole disk</string>
                <key>Data</key><data>{mish_b64}</data>
            </dict>
        </array>
    </dict>
</dict>
</plist>"#
    )
    .into_bytes();

    let mut koly = vec![0u8; 512];
    koly[0x00..0x04].copy_from_slice(b"koly");
    // data_fork_offset (0x18..0x20) left zeroed.
    koly[0xD8..0xE0].copy_from_slice(&0u64.to_be_bytes()); // xml_offset
    koly[0xE0..0xE8].copy_from_slice(&(plist.len() as u64).to_be_bytes()); // xml_length

    let mut file_bytes = plist;
    file_bytes.extend_from_slice(&koly);
    file_bytes
}

#[test]
fn dmg_without_hfsplus_inside_is_clean_error() {
    // One ZERO_FILL chunk covering 8 sectors -- the assembled raw image stays
    // all-zero, so no HFS+ volume header is ever found. Exercises the "not
    // found" tail of the locate-HFS+ scan without needing a real APFS image
    // (out of scope, #21c).
    let mish = synthetic_mish(0, 8, &[(0x0000_0000, 0, 8, 0, 0)]);
    let file_bytes = build_synthetic_dmg(&mish);

    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let path = tmp_dir.path().join("no_hfs.dmg");
    std::fs::write(&path, &file_bytes).expect("write");

    let err = open(&path, &OpenOptions::default())
        .err()
        .expect("must error, not panic");
    assert!(
        matches!(err, Error::UnknownFormat | Error::Corrupt(_)),
        "got {err:?}"
    );
}

#[test]
fn unknown_chunk_entry_type_is_corrupt() {
    // A bogus entry type, not in the known table (§7.1).
    let mish = synthetic_mish(0, 1, &[(0x1234_5678, 0, 1, 0, 0)]);
    let file_bytes = build_synthetic_dmg(&mish);

    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let path = tmp_dir.path().join("bad_chunk_type.dmg");
    std::fs::write(&path, &file_bytes).expect("write");

    let err = open(&path, &OpenOptions::default())
        .err()
        .expect("must error");
    assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
}

// ── crafted length fields: must fail cleanly, never abort/panic ──────────────
//
// The koly/mish length fields are attacker-controlled and feed allocations and
// sector arithmetic directly. A crafted huge value must yield a clean `Corrupt`,
// not an uncatchable OOM abort (huge `Vec`) or a debug overflow panic. Each test
// would kill the process before the hardening in `format/dmg.rs` (checked math +
// file-size-bounded allocations); passing proves it fails cleanly instead.

#[test]
fn crafted_huge_xml_length_is_error_not_abort() {
    // koly with xml_length = u64::MAX over a tiny file.
    let plist = b"<plist></plist>".to_vec();
    let mut koly = vec![0u8; 512];
    koly[0x00..0x04].copy_from_slice(b"koly");
    koly[0xD8..0xE0].copy_from_slice(&0u64.to_be_bytes()); // xml_offset
    koly[0xE0..0xE8].copy_from_slice(&u64::MAX.to_be_bytes()); // xml_length
    let mut file_bytes = plist;
    file_bytes.extend_from_slice(&koly);

    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let path = tmp_dir.path().join("huge_xml.dmg");
    std::fs::write(&path, &file_bytes).expect("write");

    let err = open(&path, &OpenOptions::default())
        .err()
        .expect("must error, not abort");
    assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
}

#[test]
fn crafted_huge_sector_count_is_error_not_panic() {
    // A mish claiming u64::MAX sectors -> raw image size overflows.
    let mish = synthetic_mish(0, u64::MAX, &[]);
    let file_bytes = build_synthetic_dmg(&mish);

    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let path = tmp_dir.path().join("huge_sectors.dmg");
    std::fs::write(&path, &file_bytes).expect("write");

    let err = open(&path, &OpenOptions::default())
        .err()
        .expect("must error, not panic");
    assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
}

#[test]
fn crafted_huge_compressed_length_is_error_not_abort() {
    // A zlib chunk whose compressed_length (u64::MAX) far exceeds the file.
    let mish = synthetic_mish(0, 1, &[(0x8000_0005, 0, 1, 0, u64::MAX)]);
    let file_bytes = build_synthetic_dmg(&mish);

    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let path = tmp_dir.path().join("huge_comp.dmg");
    std::fs::write(&path, &file_bytes).expect("write");

    let err = open(&path, &OpenOptions::default())
        .err()
        .expect("must error, not abort");
    assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
}

/// Cross-check against `7zz` when present on the system (dev-only oracle, per
/// `_protocol.md`). Skips (prints and returns) when the binary isn't found.
#[test]
fn dmg_zlib_matches_7zz_oracle() {
    if Command::new("7zz").arg("--help").output().is_err() {
        println!("skipping dmg_zlib_matches_7zz_oracle: 7zz not found");
        return;
    }
    let out_dir = tempfile::tempdir().expect("tempdir");
    let status = Command::new("7zz")
        .arg("e")
        .arg(fixture("dmg_zlib.dmg"))
        .arg("TEST/hello.txt")
        .arg(format!("-o{}", out_dir.path().display()))
        .arg("-y")
        .status()
        .expect("run 7zz e");
    assert!(status.success(), "7zz e failed");

    let expected = std::fs::read(out_dir.path().join("hello.txt")).expect("read 7zz output");
    let mut reader = open(&fixture("dmg_zlib.dmg"), &OpenOptions::default()).expect("open");
    assert_eq!(body_of(reader.as_mut(), "hello.txt"), expected);
}
