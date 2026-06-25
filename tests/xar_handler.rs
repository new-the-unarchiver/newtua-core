//! XAR (.xar/.pkg) integration tests. XAR is built by default (in-house reader).

use newtua_core::archive::{EntryKind, FormatId};
use newtua_core::detect::open;
use newtua_core::format::XarHandler;
use newtua_core::{Error, FormatHandler, OpenOptions, Source};
use std::path::Path;

/// Path to the committed fixture created with:
///   cd /tmp && printf 'hi from xar\n' > f.txt
///   xar -cf <fixture_path> f.txt
fn fixture() -> &'static Path {
    Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/sample.xar"
    ))
}

// ── Integration: open via detect::open ────────────────────────────────────────

#[test]
fn detects_and_opens_xar_fixture() {
    let mut ar = open(fixture(), &OpenOptions::default()).unwrap();
    assert_eq!(ar.format(), FormatId::Xar);

    let entries = ar.entries().unwrap();
    assert!(
        !entries.is_empty(),
        "expected at least one entry in fixture"
    );
}

#[test]
fn lists_known_member() {
    let mut ar = open(fixture(), &OpenOptions::default()).unwrap();
    let entries = ar.entries().unwrap();

    // The fixture was created with a single file "f.txt"
    let file_entry = entries
        .iter()
        .find(|e| e.path.to_str().unwrap_or("") == "f.txt")
        .expect("f.txt not found in fixture entries");

    assert_eq!(file_entry.kind, EntryKind::File);
    assert!(!file_entry.is_encrypted);
}

#[test]
fn reads_exact_bytes_from_fixture() {
    let mut ar = open(fixture(), &OpenOptions::default()).unwrap();
    let entries = ar.entries().unwrap();

    let idx = entries
        .iter()
        .position(|e| e.path.to_str().unwrap_or("") == "f.txt")
        .expect("f.txt not in entries");

    let mut out = Vec::new();
    ar.read_entry(idx, &mut out).unwrap();
    assert_eq!(out, b"hi from xar\n", "decompressed content mismatch");
}

// ── Integration: nested tree (full paths, dirs, nested read, symlink) ────────

/// `nested.xar` built with /usr/bin/xar from: top.txt, sub/{a.txt,b.txt},
/// link.txt → top.txt. Exercises full-path reconstruction (zar's top-level-only
/// API could not do this), directory entries, nested-file reads, and symlinks.
fn nested_fixture() -> &'static Path {
    Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/nested.xar"
    ))
}

#[test]
fn nested_full_paths_and_kinds() {
    let mut ar = open(nested_fixture(), &OpenOptions::default()).unwrap();
    assert_eq!(ar.format(), FormatId::Xar);
    let entries = ar.entries().unwrap();

    let by_path = |p: &str| entries.iter().find(|e| e.path.to_str() == Some(p));

    // Nested files carry their full path, not just the leaf name.
    assert_eq!(
        by_path("sub/a.txt").map(|e| &e.kind),
        Some(&EntryKind::File)
    );
    assert_eq!(
        by_path("sub/b.txt").map(|e| &e.kind),
        Some(&EntryKind::File)
    );
    assert_eq!(by_path("top.txt").map(|e| &e.kind), Some(&EntryKind::File));

    // The directory is its own entry.
    assert_eq!(by_path("sub").map(|e| &e.kind), Some(&EntryKind::Dir));

    // The symlink exposes its target.
    match by_path("link.txt").map(|e| &e.kind) {
        Some(EntryKind::Symlink { target }) => assert_eq!(target, Path::new("top.txt")),
        other => panic!("link.txt should be a symlink to top.txt, got {other:?}"),
    }
}

#[test]
fn nested_reads_file_inside_directory() {
    let mut ar = open(nested_fixture(), &OpenOptions::default()).unwrap();
    let idx = {
        let entries = ar.entries().unwrap();
        entries
            .iter()
            .position(|e| e.path.to_str() == Some("sub/a.txt"))
            .expect("sub/a.txt not found")
    };
    let mut out = Vec::new();
    ar.read_entry(idx, &mut out).unwrap();
    assert_eq!(out, b"aaa\n", "nested file body mismatch");
}

// ── Unit: open via XarHandler directly ───────────────────────────────────────

#[test]
fn xar_handler_open_and_read() {
    let src = Source::path(fixture()).unwrap();
    let mut ar = XarHandler.open(src, &OpenOptions::default()).unwrap();

    let entries = ar.entries().unwrap();
    assert!(!entries.is_empty());

    let idx = entries
        .iter()
        .position(|e| e.path.to_str().unwrap_or("") == "f.txt")
        .unwrap();

    let mut out = Vec::new();
    ar.read_entry(idx, &mut out).unwrap();
    assert_eq!(out, b"hi from xar\n");
}

#[test]
fn read_entry_out_of_range_returns_invalid_index() {
    let src = Source::path(fixture()).unwrap();
    let mut ar = XarHandler.open(src, &OpenOptions::default()).unwrap();
    ar.entries().unwrap();

    let mut out = Vec::new();
    let err = ar.read_entry(9999, &mut out).unwrap_err();
    assert!(matches!(err, Error::InvalidIndex(9999)));
}

// ── Edge: stream source is rejected ──────────────────────────────────────────

#[test]
fn stream_source_returns_unsupported() {
    use newtua_core::archive::Source;
    use std::io::Cursor;

    let data = std::fs::read(fixture()).unwrap();
    let stream_src = Source::Stream {
        inner: Box::new(Cursor::new(data)),
        path: None,
    };

    let result = XarHandler.open(stream_src, &OpenOptions::default());
    assert!(
        matches!(result, Err(Error::Unsupported { .. })),
        "expected Unsupported error for stream source"
    );
}

// ── Edge: truncated / garbage input ─────────────────────────────────────────

/// Build a minimal XAR header (28 bytes, big-endian) with the given
/// `toc_length_compressed` value followed by `toc_length_uncompressed` and
/// checksum algorithm, then append `extra_bytes`.
///
/// The header `size` field is set to 28 (the minimum valid value); the reader
/// rejects anything smaller as `Corrupt`.
fn make_xar_header(toc_compressed_len: u64, extra_bytes: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"xar!"); // magic (4 bytes)
    buf.extend_from_slice(&28u16.to_be_bytes()); // size = 28 (2 bytes)
    buf.extend_from_slice(&1u16.to_be_bytes()); // version = 1 (2 bytes)
    buf.extend_from_slice(&toc_compressed_len.to_be_bytes()); // toc_compressed (8 bytes)
    buf.extend_from_slice(&0u64.to_be_bytes()); // toc_uncompressed (8 bytes)
    buf.extend_from_slice(&1u32.to_be_bytes()); // checksum = SHA1 (4 bytes)
    buf.extend_from_slice(extra_bytes);
    buf
}

#[test]
fn garbage_toc_returns_error_not_panic() {
    use newtua_core::archive::Source;
    use std::io::Cursor;

    // Valid header claiming a 16-byte TOC, followed by 16 bytes of garbage
    // zlib data. The zlib decoder will return an error — not a panic.
    let data = make_xar_header(
        16,
        &[
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77,
        ],
    );
    let src = Source::Seekable {
        inner: Box::new(Cursor::new(data)),
        path: None,
    };

    let result = XarHandler.open(src, &OpenOptions::default());
    assert!(result.is_err(), "expected Err on garbage XAR TOC, got Ok");
}

#[test]
fn truncated_after_header_returns_error_not_panic() {
    use newtua_core::archive::Source;
    use std::io::Cursor;

    // Valid header claiming a 100-byte TOC, but no bytes follow — truncated.
    let data = make_xar_header(100, &[]);
    let src = Source::Seekable {
        inner: Box::new(Cursor::new(data)),
        path: None,
    };

    let result = XarHandler.open(src, &OpenOptions::default());
    assert!(result.is_err(), "expected Err on truncated XAR, got Ok");
}
