use newtua_core::archive::{FormatId, OpenOptions};
use newtua_core::detect::open;
use std::path::Path;

fn fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Opens the committed `cpio_newc.cpio` fixture, verifies the entry list
/// and extracts the single file body.
#[test]
fn cpio_newc_list_and_extract() {
    let path = fixture("cpio_newc.cpio");
    let opts = OpenOptions::default();
    let mut reader = open(&path, &opts).expect("open cpio_newc.cpio");

    assert_eq!(reader.format(), FormatId::Cpio);

    let entries = reader.entries().expect("entries");
    // The fixture contains exactly one file: a.txt (6 bytes: "hello\n")
    assert_eq!(entries.len(), 1, "expected 1 entry, got {}", entries.len());

    let e = &entries[0];
    assert_eq!(e.path.to_string_lossy(), "a.txt");
    assert_eq!(e.size, 6, "expected 6 bytes");
    assert!(!e.is_encrypted);
    assert!(e.mode.is_some());

    // Extract and verify body.
    let mut body = Vec::new();
    reader.read_entry(0, &mut body).expect("read_entry 0");
    assert_eq!(body, b"hello\n");
}

/// `read_entry` with an out-of-range index returns `InvalidIndex`, never panics.
#[test]
fn cpio_read_entry_out_of_range() {
    let path = fixture("cpio_newc.cpio");
    let opts = OpenOptions::default();
    let mut reader = open(&path, &opts).expect("open cpio_newc.cpio");
    reader.entries().expect("entries");

    let result = reader.read_entry(99, &mut std::io::sink());
    assert!(
        matches!(result, Err(newtua_core::error::Error::InvalidIndex(99))),
        "expected InvalidIndex(99), got {:?}",
        result
    );
}

/// A buffer starting with the cpio newc magic but containing no TRAILER entry
/// must return an error, not a panic.
#[test]
fn truncated_cpio_returns_error() {
    use std::io::Write as _;

    // Build a valid newc header for one file but then truncate the archive
    // (no TRAILER record). We build the archive in memory and write to a
    // temp file so that `detect::open` can open it.
    let data: &[u8] = b"hi";
    let output: Vec<u8> = Vec::new();
    let builder = cpio::NewcBuilder::new("hi.txt")
        .mode(0o100644)
        .ino(1)
        .nlink(1);
    let mut writer = builder.write(output, data.len() as u32);
    writer.write_all(data).unwrap();
    let truncated = writer.finish().unwrap();
    // truncated contains the entry but NO trailer

    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(&truncated).unwrap();
    let tmp_path = tmp.into_temp_path();

    let opts = OpenOptions::default();
    let result = open(&tmp_path, &opts);
    // Must return some Err — either Corrupt or Io — never panic.
    assert!(
        result.is_err(),
        "expected an error for truncated cpio, got Ok"
    );
}
