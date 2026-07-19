use newtua_core::archive::{FormatId, OpenOptions};
use newtua_core::detect::open;
use std::path::Path;

fn fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// A single-file `.br` opens as one entry named after the stripped filename.
#[test]
fn dot_br_single_file() {
    let mut reader = open(&fixture("hello.txt.br"), &OpenOptions::default()).expect("open .br");
    assert_eq!(reader.format(), FormatId::Raw);

    let entries = reader.entries().expect("entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path.to_string_lossy(), "hello.txt");

    let mut body = Vec::new();
    reader.read_entry(0, &mut body).expect("read_entry 0");
    assert_eq!(body, b"hello from brotli\n");
}

/// A `.tar.br` is decompressed and handed to the tar handler.
#[test]
fn tar_dot_br_lists_members() {
    let mut reader =
        open(&fixture("payload.tar.br"), &OpenOptions::default()).expect("open .tar.br");
    assert_eq!(reader.format(), FormatId::Tar);

    // Collect indices while `entries` borrow is live; release before read_entry calls.
    let (idx, idx_b) = {
        let entries = reader.entries().expect("entries");
        let names: Vec<String> = entries
            .iter()
            .map(|e| e.path.to_string_lossy().into_owned())
            .collect();
        assert!(names.contains(&"a.txt".to_string()), "got {names:?}");
        assert!(names.contains(&"b.txt".to_string()), "got {names:?}");

        let idx = entries
            .iter()
            .position(|e| e.path == Path::new("a.txt"))
            .unwrap();
        let idx_b = entries
            .iter()
            .position(|e| e.path == Path::new("b.txt"))
            .unwrap();
        (idx, idx_b)
    };

    let mut body = Vec::new();
    reader.read_entry(idx, &mut body).expect("read a.txt");
    assert_eq!(body, b"one\n");

    // Also assert b.txt's body (not just its presence).
    let mut body_b = Vec::new();
    reader.read_entry(idx_b, &mut body_b).expect("read b.txt");
    assert_eq!(body_b, b"two\n");
}
