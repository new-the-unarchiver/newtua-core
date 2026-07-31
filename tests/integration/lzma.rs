//! Bare LZMA (`.lzma`) — the alone/legacy LZMA1 container, no magic of its own.
//!
//! Fixtures are produced by the reference tool `xz` (XZ Utils 5.8.3), not by our
//! own encoder:
//!
//! ```text
//! printf 'hello from lzma\n' > hello.txt
//! printf 'one\n' > tree/a.txt; printf 'two\n' > tree/b.txt
//! tar -cf payload.tar -C tree a.txt b.txt
//! xz --format=lzma -k -c hello.txt   > hello.txt.lzma
//! xz --format=lzma -k -c payload.tar > payload.tar.lzma
//! ```
//!
//! (`payload.tar` here is byte-identical to the one behind the other compressor
//! fixtures — it was recovered with `gzip -dc payload.tar.Z > payload.tar`.)

use newtua_core::archive::{FormatId, OpenOptions};
use newtua_core::detect::open;
use std::io::Write;
use std::path::Path;

fn fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// A single-file `.lzma` opens as one entry named after the stripped filename.
#[test]
fn dot_lzma_single_file() {
    let mut reader = open(&fixture("hello.txt.lzma"), &OpenOptions::default()).expect("open .lzma");
    assert_eq!(reader.format(), FormatId::Raw);

    let entries = reader.entries().expect("entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path.to_string_lossy(), "hello.txt");

    let mut body = Vec::new();
    reader.read_entry(0, &mut body).expect("read_entry 0");
    assert_eq!(body, b"hello from lzma\n");
}

/// A `.tar.lzma` is decompressed and handed to the tar handler.
#[test]
fn tar_dot_lzma_lists_members() {
    let mut reader =
        open(&fixture("payload.tar.lzma"), &OpenOptions::default()).expect("open .tar.lzma");
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

/// The same bytes under a different name must stay unknown.
///
/// LZMA1 has no reliable signature — its first byte is just a packed set of
/// coder properties, and any file could start that way. Detecting it by content
/// would misclassify arbitrary data, so detection is by extension only. This
/// test is the guard against someone "helpfully" adding a magic branch later.
#[test]
fn lzma_content_without_the_extension_stays_unknown() {
    let bytes = std::fs::read(fixture("hello.txt.lzma")).expect("read fixture");
    let mut tmp = tempfile::Builder::new()
        .suffix(".bin")
        .tempfile()
        .expect("tempfile");
    tmp.write_all(&bytes).expect("write");
    tmp.flush().expect("flush");

    let res = open(tmp.path(), &OpenOptions::default());
    assert!(
        res.is_err(),
        "LZMA content without a .lzma extension must not be detected"
    );
}

/// A truncated `.lzma` must fail with an error — never panic, never hang.
#[test]
fn truncated_dot_lzma_errors() {
    let full = std::fs::read(fixture("hello.txt.lzma")).expect("read fixture");
    // Keep the 13-byte alone header so the payload starts decoding, then cut:
    // the decoder hits EOF before the end-of-stream marker.
    let mut tmp = tempfile::Builder::new()
        .suffix(".lzma")
        .tempfile()
        .expect("tempfile");
    tmp.write_all(&full[..13 + (full.len() - 13) / 2])
        .expect("write truncated");
    tmp.flush().expect("flush");

    let res = open(tmp.path(), &OpenOptions::default());
    assert!(res.is_err(), "truncated .lzma must not open successfully");
}
