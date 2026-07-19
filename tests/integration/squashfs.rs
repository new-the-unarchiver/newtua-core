use newtua_core::archive::{ArchiveReader, EntryKind, FormatId, OpenOptions};
use newtua_core::detect::open;
use std::path::Path;

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
fn squashfs_reports_format_and_lists_tree() {
    let mut reader =
        open(&fixture("tree-gzip.squashfs"), &OpenOptions::default()).expect("open squashfs");
    assert_eq!(reader.format(), FormatId::Squashfs);
    let entries = reader.entries().expect("entries");
    let names: Vec<String> = entries
        .iter()
        .map(|e| e.path.to_string_lossy().into_owned())
        .collect();
    assert!(names.iter().any(|n| n == "hello.txt"), "names: {names:?}");
    assert!(names.iter().any(|n| n == "sub"), "names: {names:?}");
    assert!(
        names.iter().any(|n| n == "sub/nested.txt"),
        "names: {names:?}"
    );
    assert!(names.iter().any(|n| n == "link"), "names: {names:?}");
    // No leading '/', no special nodes.
    assert!(
        !names.iter().any(|n| n.starts_with('/')),
        "names: {names:?}"
    );
    let sub = entries
        .iter()
        .find(|e| e.path.to_string_lossy() == "sub")
        .unwrap();
    assert_eq!(sub.kind, EntryKind::Dir);
}

#[test]
fn squashfs_symlink_target() {
    let mut reader =
        open(&fixture("tree-gzip.squashfs"), &OpenOptions::default()).expect("open squashfs");
    let entries = reader.entries().expect("entries");
    let link = entries
        .iter()
        .find(|e| e.path.to_string_lossy() == "link")
        .expect("link entry");
    match &link.kind {
        EntryKind::Symlink { target } => {
            assert_eq!(target.as_path(), Path::new("sub/nested.txt"))
        }
        other => panic!("expected symlink, got {other:?}"),
    }
}

#[test]
fn squashfs_extracts_file() {
    let mut reader =
        open(&fixture("tree-gzip.squashfs"), &OpenOptions::default()).expect("open squashfs");
    assert_eq!(
        body_of(reader.as_mut(), "hello.txt"),
        b"hello from squashfs\n"
    );
}

#[test]
fn squashfs_dir_read_is_empty() {
    let mut reader =
        open(&fixture("tree-gzip.squashfs"), &OpenOptions::default()).expect("open squashfs");
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
fn squashfs_all_compressors_extract() {
    for c in ["gzip", "xz", "zstd", "lz4", "lzo"] {
        let name = format!("tree-{c}.squashfs");
        let mut reader = open(&fixture(&name), &OpenOptions::default())
            .unwrap_or_else(|e| panic!("open {name}: {e:?}"));
        assert_eq!(reader.format(), FormatId::Squashfs, "compressor {c}");
        assert_eq!(
            body_of(reader.as_mut(), "hello.txt"),
            b"hello from squashfs\n",
            "compressor {c}"
        );
        assert_eq!(
            body_of(reader.as_mut(), "sub/nested.txt"),
            b"nested file\n",
            "compressor {c}"
        );
    }
}

#[test]
fn squashfs_read_entry_out_of_range_is_invalid_index() {
    let mut reader =
        open(&fixture("tree-gzip.squashfs"), &OpenOptions::default()).expect("open squashfs");
    let n = reader.entries().expect("entries").len();
    let mut sink = Vec::new();
    let err = reader
        .read_entry(n + 100, &mut sink)
        .expect_err("out-of-range index must error");
    assert!(
        matches!(err, newtua_core::error::Error::InvalidIndex(_)),
        "expected InvalidIndex"
    );
}

#[test]
fn squashfs_corrupt_is_corrupt() {
    let result = open(&fixture("corrupt.squashfs"), &OpenOptions::default());
    assert!(
        matches!(result, Err(newtua_core::error::Error::Corrupt(_))),
        "expected Err(Corrupt), got something else"
    );
}
