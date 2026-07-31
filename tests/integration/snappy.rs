//! Framed Snappy (`.sz`) — the format Keka calls SNAPPY.
//!
//! Fixtures are produced by the reference tool Keka ships (`snzip 1.0.5`,
//! default format `framing2`), not by our own encoder:
//!
//! ```text
//! printf 'hello from snappy\n' > hello.txt
//! printf 'one\n' > tree/a.txt; printf 'two\n' > tree/b.txt
//! /Applications/Keka.app/Contents/MacOS/Keka --ignore-file-access --cli \
//!     tar -cf - -C tree a.txt b.txt > payload.tar
//! /Applications/Keka.app/Contents/MacOS/Keka --ignore-file-access --cli \
//!     snzip -c hello.txt > hello.txt.sz
//! /Applications/Keka.app/Contents/MacOS/Keka --ignore-file-access --cli \
//!     snzip -c payload.tar > payload.tar.sz
//! ```

use newtua_core::archive::{FormatId, OpenOptions};
use newtua_core::detect::open;
use std::io::Write;
use std::path::Path;

fn fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// A single-file `.sz` opens as one entry named after the stripped filename.
#[test]
fn dot_sz_single_file() {
    let mut reader = open(&fixture("hello.txt.sz"), &OpenOptions::default()).expect("open .sz");
    assert_eq!(reader.format(), FormatId::Raw);

    let entries = reader.entries().expect("entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path.to_string_lossy(), "hello.txt");

    let mut body = Vec::new();
    reader.read_entry(0, &mut body).expect("read_entry 0");
    assert_eq!(body, b"hello from snappy\n");
}

/// A `.tar.sz` is decompressed and handed to the tar handler.
#[test]
fn tar_dot_sz_lists_members() {
    let mut reader =
        open(&fixture("payload.tar.sz"), &OpenOptions::default()).expect("open .tar.sz");
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

/// A truncated `.sz` must fail with an error — never panic, never hang.
#[test]
fn truncated_dot_sz_errors() {
    let full = std::fs::read(fixture("hello.txt.sz")).expect("read fixture");
    // Keep the stream-identifier chunk (10 bytes) so detection still fires,
    // then cut the body in half: the frame decoder hits EOF mid-chunk.
    let cut = 10 + (full.len() - 10) / 2;
    let mut tmp = tempfile::Builder::new()
        .suffix(".sz")
        .tempfile()
        .expect("tempfile");
    tmp.write_all(&full[..cut]).expect("write truncated");
    tmp.flush().expect("flush");

    let res = open(tmp.path(), &OpenOptions::default());
    assert!(res.is_err(), "truncated .sz must not open successfully");
}

/// A `.sz` whose chunk payload is garbage must fail, not panic.
#[test]
fn corrupt_dot_sz_errors() {
    let mut bytes = std::fs::read(fixture("hello.txt.sz")).expect("read fixture");
    // Overwrite everything past the stream-identifier chunk with garbage.
    for b in bytes.iter_mut().skip(10) {
        *b = 0xFF;
    }
    let mut tmp = tempfile::Builder::new()
        .suffix(".sz")
        .tempfile()
        .expect("tempfile");
    tmp.write_all(&bytes).expect("write corrupt");
    tmp.flush().expect("flush");

    let res = open(tmp.path(), &OpenOptions::default());
    assert!(res.is_err(), "corrupt .sz must not open successfully");
}
