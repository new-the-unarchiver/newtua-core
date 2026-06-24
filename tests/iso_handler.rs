/// Integration tests for the ISO 9660 format handler.
///
/// Fixture: `tests/fixtures/sample.iso`
/// Created with pycdlib (Joliet-only, no Rock Ridge) containing:
///   hello.txt  (10 bytes: "hello iso\n")
///   sub/       (directory)
///   sub/inner.txt  (7 bytes: "nested\n")
use std::io::Cursor;
use std::path::Path;

use newtua_core::archive::{EntryKind, FormatId, OpenOptions};
use newtua_core::detect;
use newtua_core::error::Error;

fn fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
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
        .find(|e| e.path.to_str().unwrap_or("") == "sub/inner.txt")
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
        .position(|e| e.path.to_str().unwrap_or("") == "sub/inner.txt")
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
