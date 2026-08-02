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
        .find(|e| e.path == Path::new("f.txt"))
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
        .position(|e| e.path == Path::new("f.txt"))
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

    let by_path = |p: &str| entries.iter().find(|e| e.path == Path::new(p));

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
            .position(|e| e.path == Path::new("sub/a.txt"))
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

// ── D7 regression: a base64-encoded name is decoded, and safely ─────────────

/// `base64_name.xar` was built with the system `xar` 1.8 (a corpus reference,
/// not our own writer — see the `oracle-independence` rule): it holds four
/// files, one of them `привет.txt`. Real `xar` encodes any non-ASCII name to
/// base64 (`<name enctype="base64">0L/RgNC40LLQtdGCLnR4dA==</name>`) and never
/// decodes it back — XADMaster does not either, and shows the base64 string.
/// That is our floor, not our ceiling: we decode, so the listing carries the
/// real name. Decoding also disposes of the incidental bug the encoded form
/// had: the base64 alphabet includes `/`, and the TOC gives one path component
/// per `<file>`, so a literal `0L/RgNC...` split off a spurious `0L` directory.
fn base64_name_fixture() -> &'static Path {
    Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/base64_name.xar"
    ))
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// The fixture's four members: path, byte count, sha256 of the content.
const BASE64_FIXTURE_MEMBERS: [(&str, usize, &str); 4] = [
    (
        "hello.txt",
        15,
        "d8bfbcfd8b1bce61f3abbd65de37d13f354e2c73c7a6d5f362353317c2ffce42",
    ),
    (
        "привет.txt",
        22,
        "f509c862e2613c56f3b322e4b080e013ece8259a549ffd81113a335b67a840ca",
    ),
    (
        "nested/deep/tiny.bin",
        256,
        "1455fb514dcd6af818919b765a99cbebf7d91d7994341cc1d4f350ecc65e0a36",
    ),
    (
        "big.txt",
        65_529,
        "df1515a6fad9ce2f8141ff97f1e14ca7873ca48e50a95185efd64a55df216bec",
    ),
];

#[test]
fn base64_encoded_name_is_decoded() {
    let mut ar = open(base64_name_fixture(), &OpenOptions::default()).unwrap();
    let entries = ar.entries().unwrap();
    let paths: Vec<_> = entries.iter().map(|e| e.path.clone()).collect();

    // The encoded member is listed under its real name.
    assert!(
        paths.contains(&Path::new("привет.txt").to_path_buf()),
        "expected the decoded name in the listing, got {paths:?}"
    );
    // Neither the base64 string nor the `0L` directory a literal `/` would
    // have split off is anywhere in the listing.
    assert!(
        paths.iter().all(|p| p != Path::new("0L")),
        "the base64 '/' must never become a path separator: {paths:?}"
    );
    assert!(
        !paths
            .iter()
            .any(|p| p.to_string_lossy().contains("RgNC40LLQtdGCLnR4dA")),
        "the base64 string must not survive into a name: {paths:?}"
    );
    // The three plain-ASCII members are unaffected.
    for name in ["hello.txt", "big.txt", "nested/deep/tiny.bin"] {
        assert!(
            paths.contains(&Path::new(name).to_path_buf()),
            "{name} missing from {paths:?}"
        );
    }
}

/// Decoding the name must not disturb the bodies: every member still reads back
/// byte-for-byte. Sizes and hashes were taken from the files the fixture was
/// built from, not from this reader.
#[test]
fn base64_name_fixture_members_read_back_intact() {
    let mut ar = open(base64_name_fixture(), &OpenOptions::default()).unwrap();
    for (name, size, sha) in BASE64_FIXTURE_MEMBERS {
        let idx = {
            let entries = ar.entries().unwrap();
            entries
                .iter()
                .position(|e| e.path == Path::new(name))
                .unwrap_or_else(|| panic!("{name} not found in the listing"))
        };
        let mut out = Vec::new();
        ar.read_entry(idx, &mut out).unwrap();
        assert_eq!(out.len(), size, "{name}: wrong byte count");
        assert_eq!(sha256_hex(&out), sha, "{name}: content mismatch");
    }
}

/// End to end: the decoded name lands on disk as `привет.txt`, and no `0L`
/// directory is created. Unix-only because the pre-fix behaviour wrote a name
/// holding `:`, which Windows will not accept, and because this is the platform
/// where a bare `/` in a name splits a directory in the first place.
#[cfg(unix)]
#[test]
fn base64_encoded_name_extracts_under_its_real_name() {
    use newtua_core::{ExtractOptions, extract_all};

    let mut ar = open(base64_name_fixture(), &OpenOptions::default()).unwrap();
    let dest = tempfile::tempdir().unwrap();
    extract_all(
        &mut *ar,
        &mut ExtractOptions {
            dest: dest.path().to_path_buf(),
            wrapper_name: None,
            strict: false,
            preserve: false,
            selection: None,
            progress: None,
            keep_macos_metadata: false,
        },
    )
    .unwrap();

    assert!(
        !dest.path().join("0L").exists(),
        "extraction must not create a directory named '0L' on disk"
    );
    for (name, size, sha) in BASE64_FIXTURE_MEMBERS {
        let on_disk = std::fs::read(dest.path().join(name))
            .unwrap_or_else(|e| panic!("{name} not extracted: {e}"));
        assert_eq!(on_disk.len(), size, "{name}: wrong byte count on disk");
        assert_eq!(
            sha256_hex(&on_disk),
            sha,
            "{name}: content mismatch on disk"
        );
    }
}

/// The reason decoding has to happen *before* the traversal check: an attacker
/// can put `../evil` in base64 just as easily as in plain text. Checking the
/// TOC string first would wave it through, and only `safe_join` would stand
/// between the archive and the parent directory.
///
/// The archive is built here rather than committed: a fixture that actually
/// attacks the checkout is not something to leave lying in `tests/fixtures`.
#[test]
fn base64_traversal_name_never_escapes_the_destination() {
    use newtua_core::{ExtractOptions, extract_all};

    // "Li4vZXZpbA==" is base64 for "../evil".
    let evil = b"pwned\n";
    let good = b"harmless\n";
    let toc = format!(
        "<xar><toc>\
         <file id=\"1\"><name enctype=\"base64\">Li4vZXZpbA==</name><type>file</type>\
         <data><offset>0</offset><length>{}</length><size>{}</size>\
         <encoding style=\"application/octet-stream\"/></data></file>\
         <file id=\"2\"><name>ok.txt</name><type>file</type>\
         <data><offset>{}</offset><length>{}</length><size>{}</size>\
         <encoding style=\"application/octet-stream\"/></data></file>\
         </toc></xar>",
        evil.len(),
        evil.len(),
        evil.len(),
        good.len(),
        good.len()
    );
    let mut heap = Vec::new();
    heap.extend_from_slice(evil);
    heap.extend_from_slice(good);
    let archive = build_xar(&toc, &heap);

    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("out");
    std::fs::create_dir(&dest).unwrap();

    let path = tmp.path().join("traversal.xar");
    std::fs::write(&path, &archive).unwrap();
    let mut ar = open(&path, &OpenOptions::default()).unwrap();

    // The escaping name never reaches the listing at all.
    let paths: Vec<_> = ar
        .entries()
        .unwrap()
        .iter()
        .map(|e| e.path.clone())
        .collect();
    assert_eq!(paths, vec![Path::new("ok.txt").to_path_buf()]);

    extract_all(
        &mut *ar,
        &mut ExtractOptions {
            dest: dest.clone(),
            wrapper_name: None,
            strict: false,
            preserve: false,
            selection: None,
            progress: None,
            keep_macos_metadata: false,
        },
    )
    .unwrap();

    // Nothing was written beside the destination — the archive's own directory.
    assert!(
        !tmp.path().join("evil").exists(),
        "a base64-encoded '../evil' escaped the destination directory"
    );
    assert!(!dest.join("evil").exists());
    assert_eq!(std::fs::read(dest.join("ok.txt")).unwrap(), good);
}

/// Assemble a XAR: 28-byte header, zlib-compressed TOC, then the heap.
fn build_xar(toc_xml: &str, heap: &[u8]) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use std::io::Write as _;

    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(toc_xml.as_bytes()).unwrap();
    let toc_comp = enc.finish().unwrap();

    let mut buf = make_xar_header(toc_comp.len() as u64, &toc_comp);
    buf.extend_from_slice(heap);
    buf
}
