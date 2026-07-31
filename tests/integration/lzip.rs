//! lzip (`.lz`) — LZMA1 in lzip's own framing, single- and multi-member.
//!
//! Fixtures are produced by the reference tool Keka ships, `lzip 1.26`, not by
//! an encoder of ours (we have none). Run from a directory under `$HOME`:
//! lzip's own sandbox refuses to work inside `/tmp`.
//!
//! ```text
//! K="/Applications/Keka.app/Contents/MacOS/Keka --ignore-file-access --cli"
//! gzip -dc tests/fixtures/payload.tar.Z > payload.tar   # same tar as the
//!                                                       # other compressors'
//! printf 'hello from lzip\n' > hello.txt
//! printf 'member one\n' > one.txt
//! printf 'member two\n' > two.txt
//! $K lzip -k hello.txt payload.tar one.txt two.txt
//! cat one.txt.lz two.txt.lz > multi.txt.lz
//! ```
//!
//! `hello.txt.lz` and the two members of `multi.txt.lz` code a 4 KiB
//! dictionary; `payload.tar.lz` codes 7168 bytes — not a power of two, which is
//! exactly the case the synthesized "alone" header has to round up.

use newtua_core::archive::{FormatId, OpenOptions};
use newtua_core::detect::open;
use std::io::Write;
use std::path::Path;

fn fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// A single-file `.lz` opens as one entry named after the stripped filename.
#[test]
fn dot_lz_single_file() {
    let mut reader = open(&fixture("hello.txt.lz"), &OpenOptions::default()).expect("open .lz");
    assert_eq!(reader.format(), FormatId::Raw);

    let entries = reader.entries().expect("entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path.to_string_lossy(), "hello.txt");

    let mut body = Vec::new();
    reader.read_entry(0, &mut body).expect("read_entry 0");
    assert_eq!(body, b"hello from lzip\n");
}

/// A `.tar.lz` is decompressed and handed to the tar handler.
#[test]
fn tar_dot_lz_lists_members() {
    let mut reader =
        open(&fixture("payload.tar.lz"), &OpenOptions::default()).expect("open .tar.lz");
    assert_eq!(reader.format(), FormatId::Tar);

    let (idx_a, idx_b) = {
        let entries = reader.entries().expect("entries");
        let names: Vec<String> = entries
            .iter()
            .map(|e| e.path.to_string_lossy().into_owned())
            .collect();
        assert!(names.contains(&"a.txt".to_string()), "got {names:?}");
        assert!(names.contains(&"b.txt".to_string()), "got {names:?}");

        let idx_a = entries
            .iter()
            .position(|e| e.path == Path::new("a.txt"))
            .unwrap();
        let idx_b = entries
            .iter()
            .position(|e| e.path == Path::new("b.txt"))
            .unwrap();
        (idx_a, idx_b)
    };

    let mut body = Vec::new();
    reader.read_entry(idx_a, &mut body).expect("read a.txt");
    assert_eq!(body, b"one\n");

    let mut body_b = Vec::new();
    reader.read_entry(idx_b, &mut body_b).expect("read b.txt");
    assert_eq!(body_b, b"two\n");
}

/// A multi-member `.lz` yields the contents of **every** member.
///
/// lzip files concatenate like gzip's, and a single-member decoder would return
/// only "member one\n" — a success that silently drops half the data. This is
/// the test that pins the member loop.
#[test]
fn multi_member_dot_lz_yields_every_member() {
    let mut reader = open(&fixture("multi.txt.lz"), &OpenOptions::default()).expect("open .lz");
    assert_eq!(reader.format(), FormatId::Raw);

    let entries = reader.entries().expect("entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path.to_string_lossy(), "multi.txt");

    let mut body = Vec::new();
    reader.read_entry(0, &mut body).expect("read_entry 0");
    assert_eq!(body, b"member one\nmember two\n");
}

/// A truncated `.lz` must fail with an error — never panic, never hang.
#[test]
fn truncated_dot_lz_errors() {
    let full = std::fs::read(fixture("hello.txt.lz")).expect("read fixture");
    // Keep the 6-byte header so detection still fires, then cut the LZMA
    // payload in half: the end-of-stream marker never arrives.
    let cut = 6 + (full.len() - 6) / 2;
    let mut tmp = tempfile::Builder::new()
        .suffix(".lz")
        .tempfile()
        .expect("tempfile");
    tmp.write_all(&full[..cut]).expect("write truncated");
    tmp.flush().expect("flush");

    let res = open(tmp.path(), &OpenOptions::default());
    assert!(res.is_err(), "truncated .lz must not open successfully");
}

/// A `.lz` whose second member is cut off must fail rather than quietly
/// returning just the first member's bytes.
#[test]
fn dot_lz_with_a_truncated_second_member_errors() {
    let full = std::fs::read(fixture("multi.txt.lz")).expect("read fixture");
    // The first member is 48 bytes (its trailer says so); keep it whole and
    // leave the second one a stump.
    let mut tmp = tempfile::Builder::new()
        .suffix(".lz")
        .tempfile()
        .expect("tempfile");
    tmp.write_all(&full[..48 + 20]).expect("write truncated");
    tmp.flush().expect("flush");

    let res = open(tmp.path(), &OpenOptions::default());
    assert!(
        res.is_err(),
        "a .lz whose trailing member is truncated must not open successfully"
    );
}

/// A `.lz` whose compressed body is garbage must fail, not panic.
#[test]
fn corrupt_dot_lz_errors() {
    let mut bytes = std::fs::read(fixture("hello.txt.lz")).expect("read fixture");
    // Keep the header so detection fires; overwrite the rest with garbage.
    for b in bytes.iter_mut().skip(6) {
        *b = 0xFF;
    }
    let mut tmp = tempfile::Builder::new()
        .suffix(".lz")
        .tempfile()
        .expect("tempfile");
    tmp.write_all(&bytes).expect("write corrupt");
    tmp.flush().expect("flush");

    let res = open(tmp.path(), &OpenOptions::default());
    assert!(res.is_err(), "corrupt .lz must not open successfully");
}

/// Detection is by content, so the extension is not what carries it: the same
/// bytes under a `.bin` name still open as lzip.
#[test]
fn lzip_content_is_detected_without_the_extension() {
    let bytes = std::fs::read(fixture("hello.txt.lz")).expect("read fixture");
    let mut tmp = tempfile::Builder::new()
        .suffix(".bin")
        .tempfile()
        .expect("tempfile");
    tmp.write_all(&bytes).expect("write");
    tmp.flush().expect("flush");

    let mut reader = open(tmp.path(), &OpenOptions::default()).expect("open renamed .lz");
    assert_eq!(reader.format(), FormatId::Raw);
    let mut body = Vec::new();
    reader.read_entry(0, &mut body).expect("read_entry 0");
    assert_eq!(body, b"hello from lzip\n");
}
