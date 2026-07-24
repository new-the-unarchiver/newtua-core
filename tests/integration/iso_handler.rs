/// Integration tests for the ISO 9660 format handler.
///
/// Fixtures:
///   `tests/fixtures/sample.iso`   — Joliet-only, no Rock Ridge; created with pycdlib
///     hello.txt  (10 bytes: "hello iso\n")
///     sub/       (directory)
///     sub/inner.txt  (7 bytes: "nested\n")
///
///   `tests/fixtures/susp_er0.iso` — hdiutil makehybrid (ISO + Rock Ridge / SUSP IEEE_P1282);
///     triggers an `unimplemented!()` panic inside cdfs when traversed without the
///     catch_unwind guard.
use std::io::Cursor;
use std::path::Path;

use newtua_core::archive::{ArchiveReader, EntryKind, FormatId, OpenOptions};
use newtua_core::detect;
use newtua_core::error::Error;

fn fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Write `fixture(src)`'s bytes into a temp file named `dst` and open it.
fn open_renamed(
    src: &str,
    dst: &str,
) -> (
    tempfile::TempDir,
    newtua_core::error::Result<Box<dyn ArchiveReader>>,
) {
    let bytes = std::fs::read(fixture(src)).expect("read fixture");
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(dst);
    std::fs::write(&path, &bytes).expect("write renamed");
    let r = detect::open(&path, &OpenOptions::default());
    (dir, r)
}

#[test]
fn iso_content_under_wrong_extension_is_detected_by_content() {
    // A real ISO renamed away from `.iso`: the CD001 signature lives at 0x8001,
    // past the registry's 512-byte header peek, so detection must fall back to a
    // content probe rather than trusting the extension.
    let (_d, r) = open_renamed("sample.iso", "renamed.bin");
    let mut reader = r.expect("mislabeled iso must be detected by content");
    assert_eq!(reader.format(), FormatId::Iso);
    assert_eq!(reader.entries().expect("entries").len(), 3);
}

#[test]
fn other_format_named_iso_is_not_shadowed_by_iso_handler() {
    // A SquashFS image mislabeled with a `.iso` extension must open as SquashFS.
    // IsoHandler used to claim any `.iso` at full confidence, then fail its
    // CD001 check and mask the genuine content handler.
    let (_d, r) = open_renamed("tree-gzip.squashfs", "mislabeled.iso");
    let mut reader = r.expect("squashfs named .iso must open as squashfs");
    assert_eq!(reader.format(), FormatId::Squashfs);
    assert!(!reader.entries().expect("entries").is_empty());
}

#[test]
fn open_lists_root_file_and_subdirectory() {
    let opts = OpenOptions::default();
    let mut reader = detect::open(&fixture("sample.iso"), &opts).expect("open sample.iso");

    assert_eq!(reader.format(), FormatId::Iso);

    let entries = reader.entries().expect("entries");

    // There must be at least 3 entries: hello.txt, sub/, sub/inner.txt
    assert!(
        entries.len() >= 3,
        "expected at least 3 entries, got {}",
        entries.len()
    );

    // Find hello.txt
    let hello = entries
        .iter()
        .find(|e| e.path.to_str().unwrap_or("") == "hello.txt")
        .expect("hello.txt not found in entries");
    assert_eq!(hello.kind, EntryKind::File);
    assert_eq!(hello.size, 10, "hello.txt should be 10 bytes");

    // Find the sub directory
    let sub = entries
        .iter()
        .find(|e| e.path.to_str().unwrap_or("") == "sub")
        .expect("sub/ directory not found in entries");
    assert_eq!(sub.kind, EntryKind::Dir);

    // Find sub/inner.txt
    let inner = entries
        .iter()
        .find(|e| e.path == Path::new("sub/inner.txt"))
        .expect("sub/inner.txt not found in entries");
    assert_eq!(inner.kind, EntryKind::File);
    assert_eq!(inner.size, 7, "sub/inner.txt should be 7 bytes");
}

#[test]
fn read_root_file_content() {
    let opts = OpenOptions::default();
    let mut reader = detect::open(&fixture("sample.iso"), &opts).expect("open sample.iso");

    let entries = reader.entries().expect("entries");
    let idx = entries
        .iter()
        .position(|e| e.path.to_str().unwrap_or("") == "hello.txt")
        .expect("hello.txt not found");

    let mut buf = Vec::new();
    reader
        .read_entry(idx, &mut buf)
        .expect("read_entry hello.txt");
    assert_eq!(buf, b"hello iso\n");
}

#[test]
fn read_nested_file_content() {
    let opts = OpenOptions::default();
    let mut reader = detect::open(&fixture("sample.iso"), &opts).expect("open sample.iso");

    let entries = reader.entries().expect("entries");
    let idx = entries
        .iter()
        .position(|e| e.path == Path::new("sub/inner.txt"))
        .expect("sub/inner.txt not found");

    let mut buf = Vec::new();
    reader
        .read_entry(idx, &mut buf)
        .expect("read_entry sub/inner.txt");
    assert_eq!(buf, b"nested\n");
}

#[test]
fn invalid_index_returns_error() {
    let opts = OpenOptions::default();
    let mut reader = detect::open(&fixture("sample.iso"), &opts).expect("open sample.iso");
    let _entries = reader.entries().expect("entries");

    let result = reader.read_entry(9999, &mut Vec::new());
    assert!(
        matches!(result, Err(Error::InvalidIndex(9999))),
        "expected InvalidIndex, got: {result:?}"
    );
}

#[test]
fn fake_iso_file_returns_unknown_format() {
    use newtua_core::archive::FormatHandler;
    use newtua_core::archive::Source;
    use newtua_core::format::IsoHandler;

    // A file named .iso but without CD001 at 0x8001 → UnknownFormat
    // Create a buffer of 40960 bytes (> 0x8001+5) filled with zeros.
    let garbage = vec![0u8; 40960];
    let cursor = Cursor::new(garbage);
    let src = Source::Seekable {
        inner: Box::new(cursor),
        path: None,
    };
    let opts = OpenOptions::default();
    let result = IsoHandler.open(src, &opts);
    assert!(
        matches!(result, Err(Error::UnknownFormat)),
        "expected UnknownFormat for garbage .iso"
    );
}

/// Regression: opening an ISO produced by `hdiutil makehybrid` (Rock Ridge / SUSP
/// IEEE_P1282) must NOT panic the test process — it must return `Err` instead.
///
/// Fixture `susp_er0.iso` was created with:
///   mkdir -p /tmp/susproot && printf 'x\n' > /tmp/susproot/f.txt
///   hdiutil makehybrid -iso -o /tmp/susp_rr.iso /tmp/susproot
///
/// Without the catch_unwind guard, cdfs calls `unimplemented!()` in its SUSP parser
/// when it encounters the IEEE_P1282 Rock Ridge extension record, crashing the process.
#[test]
fn susp_er0_iso_returns_err_not_panic() {
    let path = fixture("susp_er0.iso");
    let opts = OpenOptions::default();
    let result = detect::open(&path, &opts);
    assert!(
        result.is_err(),
        "expected Err for susp_er0.iso (cdfs panics on SUSP IEEE_P1282), got Ok"
    );
    // Verify it is specifically a Corrupt error (from the catch_unwind guard),
    // not some other variant like UnknownFormat or Io.
    assert!(
        matches!(result, Err(Error::Corrupt(_))),
        "expected Err(Corrupt) for susp_er0.iso"
    );
}

/// Fix 2 regression: calling read_entry for the same file index twice must return
/// identical, complete bytes both times.
///
/// ISOFile::read() always creates a fresh ISOFileReader starting at seek=0, so
/// repeated reads are expected to work — this test locks in that guarantee.
#[test]
fn read_entry_twice_returns_identical_complete_bytes() {
    let opts = OpenOptions::default();
    let mut reader = detect::open(&fixture("sample.iso"), &opts).expect("open sample.iso");

    let entries = reader.entries().expect("entries");
    let idx = entries
        .iter()
        .position(|e| e.path.to_str().unwrap_or("") == "hello.txt")
        .expect("hello.txt not found");

    let mut buf1 = Vec::new();
    reader.read_entry(idx, &mut buf1).expect("first read_entry");

    let mut buf2 = Vec::new();
    reader
        .read_entry(idx, &mut buf2)
        .expect("second read_entry");

    assert_eq!(buf1, b"hello iso\n", "first read returned wrong content");
    assert_eq!(
        buf1, buf2,
        "second read returned different bytes than the first"
    );
}
