use newtua_core::archive::{FormatId, OpenOptions};
use newtua_core::detect::open;
use std::path::Path;

fn fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// A single-file `.lz4` opens as one entry named after the stripped filename.
#[test]
fn dot_lz4_single_file() {
    let mut reader = open(&fixture("hello.txt.lz4"), &OpenOptions::default()).expect("open .lz4");
    assert_eq!(reader.format(), FormatId::Raw);

    let entries = reader.entries().expect("entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path.to_string_lossy(), "hello.txt");

    let mut body = Vec::new();
    reader.read_entry(0, &mut body).expect("read_entry 0");
    assert_eq!(body, b"hello from lz4\n");
}

/// A `.tar.lz4` is decompressed and handed to the tar handler.
#[test]
fn tar_dot_lz4_lists_members() {
    let mut reader =
        open(&fixture("payload.tar.lz4"), &OpenOptions::default()).expect("open .tar.lz4");
    assert_eq!(reader.format(), FormatId::Tar);

    let entries = reader.entries().expect("entries");
    let names: Vec<String> = entries
        .iter()
        .map(|e| e.path.to_string_lossy().into_owned())
        .collect();
    assert!(names.contains(&"a.txt".to_string()), "got {names:?}");
    assert!(names.contains(&"b.txt".to_string()), "got {names:?}");

    let idx = entries
        .iter()
        .position(|e| e.path.to_string_lossy() == "a.txt")
        .unwrap();
    let mut body = Vec::new();
    reader.read_entry(idx, &mut body).expect("read a.txt");
    assert_eq!(body, b"one\n");
}
