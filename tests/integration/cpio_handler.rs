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

/// Regression: `read_entry` on a symlink must return zero bytes, not the
/// first regular file's bytes.  Previously the offsets table stored
/// `(0, target_len)` for symlinks; `size != 0` caused the seek+copy branch to
/// run from offset 0 of the temp file, returning the first file's content.
#[test]
fn cpio_symlink_read_entry_is_empty() {
    use crate::cpio_newc::{as_file, newc_record, newc_trailer};

    // Build an in-memory newc archive:
    //   entry 0 — regular file "file.txt" with body b"REGULAR"
    //   entry 1 — symlink "link.txt" -> "file.txt" (target is 8 bytes)
    let mut output = newc_record(b"file.txt", 0o100644, b"REGULAR");
    output.extend_from_slice(&newc_record(b"link.txt", 0o120644, b"file.txt"));
    output.extend_from_slice(&newc_trailer());

    // Persist to a temp file so `detect::open` can read it.
    let tmp_path = as_file(&output);

    let opts = newtua_core::archive::OpenOptions::default();
    let mut reader =
        newtua_core::detect::open(&tmp_path, &opts).expect("open synthetic symlink cpio");

    let entries = reader.entries().expect("entries");
    assert_eq!(entries.len(), 2, "expected 2 entries");

    // Verify regular file reads back correctly.
    let mut file_body = Vec::new();
    reader.read_entry(0, &mut file_body).expect("read_entry 0");
    assert_eq!(file_body, b"REGULAR", "regular file body mismatch");

    // Symlink entry must yield zero bytes — regression for the bug where
    // size == target_len caused the temp-file seek+copy branch to fire.
    let mut link_body = Vec::new();
    reader
        .read_entry(1, &mut link_body)
        .expect("read_entry 1 (symlink)");
    assert!(
        link_body.is_empty(),
        "expected empty output for symlink read_entry, got {} bytes: {:?}",
        link_body.len(),
        link_body
    );
}

/// A buffer starting with the cpio newc magic but containing no TRAILER entry
/// must return an error, not a panic.
#[test]
fn truncated_cpio_returns_error() {
    use crate::cpio_newc::{as_file, newc_record};

    // Build a valid newc header for one file but then truncate the archive
    // (no TRAILER record). We build the archive in memory and write to a
    // temp file so that `detect::open` can open it.
    let truncated = newc_record(b"hi.txt", 0o100644, b"hi");
    // `truncated` contains the entry but NO trailer.

    let tmp_path = as_file(&truncated);

    let opts = OpenOptions::default();
    let result = open(&tmp_path, &opts);
    // Must return some Err — either Corrupt or Io — never panic.
    assert!(
        result.is_err(),
        "expected an error for truncated cpio, got Ok"
    );
}
