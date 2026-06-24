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
    use cpio::NewcBuilder;
    use cpio::newc::trailer;
    use std::io::Write as _;

    // Build an in-memory newc archive:
    //   entry 0 — regular file "file.txt" with body b"REGULAR"
    //   entry 1 — symlink "link.txt" -> "file.txt" (target is 8 bytes)
    let body: &[u8] = b"REGULAR";
    let output: Vec<u8> = Vec::new();

    // Regular file entry.
    let builder = NewcBuilder::new("file.txt").ino(1).nlink(1).mode(0o100644);
    let mut w = builder.write(output, body.len() as u32);
    w.write_all(body).unwrap();
    let output = w.finish().unwrap();

    // Symlink entry — body is the link target string.
    let target: &[u8] = b"file.txt";
    let builder = NewcBuilder::new("link.txt")
        .ino(2)
        .nlink(1)
        .mode(0o100644)
        .set_mode_file_type(cpio::newc::ModeFileType::Symlink);
    let mut w = builder.write(output, target.len() as u32);
    w.write_all(target).unwrap();
    let output = w.finish().unwrap();

    // Write the TRAILER record.
    let output = trailer(output).unwrap();

    // Persist to a temp file so `detect::open` can read it.
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(&output).unwrap();
    let tmp_path = tmp.into_temp_path();

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
