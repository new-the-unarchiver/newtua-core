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

#[test]
fn hfs_ci_lists_known_files() {
    let mut reader = open(&fixture("hfs_ci.hfs"), &OpenOptions::default()).expect("open hfs_ci");
    assert_eq!(reader.format(), FormatId::HfsPlus);
    let entries = reader.entries().expect("entries");

    let hello = entries
        .iter()
        .find(|e| e.path.to_string_lossy() == "hello.txt")
        .expect("hello.txt present");
    assert_eq!(hello.kind, EntryKind::File);
    assert_eq!(hello.size, 11);

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
}

#[test]
fn hfs_ci_extracts_file_contents() {
    let mut reader = open(&fixture("hfs_ci.hfs"), &OpenOptions::default()).expect("open hfs_ci");
    assert_eq!(body_of(reader.as_mut(), "hello.txt"), b"hello hfs+\n");
    assert_eq!(body_of(reader.as_mut(), "sub/nested.txt"), b"nested file\n");
}

#[test]
fn hfs_ci_dir_read_is_empty() {
    let mut reader = open(&fixture("hfs_ci.hfs"), &OpenOptions::default()).expect("open hfs_ci");
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
fn hfs_cs_hfsx_opens_and_lists_known_files() {
    let mut reader = open(&fixture("hfs_cs.hfs"), &OpenOptions::default()).expect("open hfs_cs");
    assert_eq!(reader.format(), FormatId::HfsPlus);
    let entries = reader.entries().expect("entries");
    assert!(
        entries
            .iter()
            .any(|e| e.path.to_string_lossy() == "hello.txt" && e.size == 11)
    );
    assert!(
        entries
            .iter()
            .any(|e| e.path.to_string_lossy() == "sub/nested.txt" && e.size == 12)
    );
    assert_eq!(body_of(reader.as_mut(), "hello.txt"), b"hello hfs+\n");
}

#[test]
fn probe_recognizes_extensions_without_magic() {
    let entries = newtua_core::detect::registry();
    let hfs_probe = entries
        .iter()
        .find(|h| h.id() == FormatId::HfsPlus)
        .expect("HfsPlusHandler registered");
    for name in ["image.hfs", "image.hfsplus", "image.HFSX"] {
        assert_eq!(
            hfs_probe.probe(&[0u8; 512], Some(name)),
            newtua_core::archive::Confidence::MAGIC,
            "extension {name}"
        );
    }
    assert_eq!(
        hfs_probe.probe(&[0u8; 512], Some("image.dmg")),
        newtua_core::archive::Confidence::NONE
    );
}

#[test]
fn read_entry_out_of_range_is_invalid_index() {
    let mut reader = open(&fixture("hfs_ci.hfs"), &OpenOptions::default()).expect("open hfs_ci");
    let n = reader.entries().expect("entries").len();
    let mut sink = Vec::new();
    let err = reader
        .read_entry(n + 100, &mut sink)
        .expect_err("out-of-range index must error");
    assert!(
        matches!(err, Error::InvalidIndex(_)),
        "expected InvalidIndex"
    );
}

#[test]
fn truncated_image_does_not_panic() {
    let bytes = std::fs::read(fixture("hfs_ci.hfs")).expect("read fixture");
    let truncated = &bytes[..600]; // shorter than the volume header at offset 1024
    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let path = tmp_dir.path().join("truncated.hfs");
    std::fs::write(&path, truncated).expect("write truncated");

    let result = open(&path, &OpenOptions::default());
    assert!(result.is_err(), "expected Err for truncated image, got Ok");
}

#[test]
fn bad_signature_is_unknown_format() {
    let bytes = std::fs::read(fixture("hfs_ci.hfs")).expect("read fixture");
    let mut corrupted = bytes.clone();
    corrupted[1024..1026].copy_from_slice(&[0, 0]); // neither H+ nor HX
    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let path = tmp_dir.path().join("bad_sig.hfs");
    std::fs::write(&path, &corrupted).expect("write corrupted");

    let result = open(&path, &OpenOptions::default());
    let is_unknown_format = matches!(result, Err(Error::UnknownFormat));
    assert!(is_unknown_format, "expected UnknownFormat");
}

/// The compressible source `ditto --hfsCompression` encoded into
/// `hfs_decmpfs.hfs`'s `bigfile.txt`. Regenerated deterministically here
/// instead of committing a second large blob for comparison.
fn decmpfs_source_bytes() -> Vec<u8> {
    b"The quick brown fox jumps over the lazy dog. ".repeat(4000)
}

#[test]
fn decmpfs_file_decompresses_fully() {
    let mut reader =
        open(&fixture("hfs_decmpfs.hfs"), &OpenOptions::default()).expect("open hfs_decmpfs");
    let entries = reader.entries().expect("entries");
    let bigfile = entries
        .iter()
        .find(|e| e.path.to_string_lossy() == "bigfile.txt")
        .expect("bigfile.txt present");
    assert_eq!(bigfile.kind, EntryKind::File);

    let expected = decmpfs_source_bytes();
    let body = body_of(reader.as_mut(), "bigfile.txt");
    assert_eq!(
        body.len(),
        expected.len(),
        "decmpfs must decode to the full original length, not an empty/partial body"
    );
    assert_eq!(
        body, expected,
        "decmpfs output must match the original file byte-for-byte"
    );
}

#[test]
fn symlink_is_typed_and_targets_original() {
    let mut reader =
        open(&fixture("hfs_decmpfs.hfs"), &OpenOptions::default()).expect("open hfs_decmpfs");
    let target = {
        let entries = reader.entries().expect("entries");
        let link = entries
            .iter()
            .find(|e| e.path.to_string_lossy() == "link_to_bigfile")
            .expect("link_to_bigfile present");
        match &link.kind {
            EntryKind::Symlink { target } => target.to_string_lossy().into_owned(),
            other => panic!("expected Symlink, got {other:?}"),
        }
    };
    assert_eq!(target, "bigfile.txt");
    // A symlink has no extractable body (its "content" is the target path).
    assert!(
        body_of(reader.as_mut(), "link_to_bigfile").is_empty(),
        "symlink body must be empty, not the target's data fork"
    );
}

#[test]
fn undecodable_decmpfs_is_corrupt_not_empty() {
    // Corrupt the `com.apple.decmpfs` xattr's `compression_type` field (the
    // 4 bytes right after the 'fpmc' magic) to an undocumented value, so
    // `hfsplus_forensic::read_file` fails loud (`None`) instead of returning
    // any body. `hfsplus.rs::read_entry` must map that to `Corrupt`, never a
    // silent empty/wrong extraction (the exact #21a bug #21a2 exists to fix).
    let mut bytes = std::fs::read(fixture("hfs_decmpfs.hfs")).expect("read fixture");
    let magic = b"fpmc";
    let pos = bytes
        .windows(magic.len())
        .position(|w| w == magic)
        .expect("decmpfs magic 'fpmc' present in fixture");
    // compression_type is the 4 bytes (LE) right after the 4-byte magic.
    bytes[pos + 4..pos + 8].copy_from_slice(&255u32.to_le_bytes());

    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let path = tmp_dir.path().join("corrupted_decmpfs.hfs");
    std::fs::write(&path, &bytes).expect("write corrupted");

    let mut reader = open(&path, &OpenOptions::default()).expect("open corrupted image");
    let idx = reader
        .entries()
        .expect("entries")
        .iter()
        .position(|e| e.path.to_string_lossy() == "bigfile.txt")
        .expect("bigfile.txt present");
    let mut sink = Vec::new();
    let err = reader
        .read_entry(idx, &mut sink)
        .expect_err("undecodable decmpfs must error, not return a body");
    assert!(
        matches!(err, Error::Corrupt(_)),
        "expected Corrupt, got {err:?}"
    );
    assert!(sink.is_empty(), "no partial body may leak out on error");
}

/// Cross-check against `7zz` when present on the system (dev-only oracle, per
/// `_protocol.md`). Skips (prints and returns) when the binary isn't found.
#[test]
fn hfs_ci_matches_7zz_oracle() {
    if Command::new("7zz").arg("--help").output().is_err() {
        println!("skipping hfs_ci_matches_7zz_oracle: 7zz not found");
        return;
    }
    let out_dir = tempfile::tempdir().expect("tempdir");
    let status = Command::new("7zz")
        .arg("e")
        .arg(fixture("hfs_ci.hfs"))
        .arg("TEST/hello.txt")
        .arg(format!("-o{}", out_dir.path().display()))
        .arg("-y")
        .status()
        .expect("run 7zz e");
    assert!(status.success(), "7zz e failed");

    let expected = std::fs::read(out_dir.path().join("hello.txt")).expect("read 7zz output");
    let mut reader = open(&fixture("hfs_ci.hfs"), &OpenOptions::default()).expect("open hfs_ci");
    assert_eq!(body_of(reader.as_mut(), "hello.txt"), expected);
}
