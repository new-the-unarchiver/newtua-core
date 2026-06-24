/// Tests for `.zipx` (WinZip advanced compression) support in the existing
/// zip handler.  The fixtures were generated with:
///   python3 -c "open('/tmp/lzma_payload.txt','wb').write(('lzma zipx payload\n'*200).encode())"
///   7zz a -tzip -mm=LZMA    crates/newtua-core/tests/fixtures/lzma.zipx     /tmp/lzma_payload.txt
///   python3 -c "open('/tmp/bzip2_payload.txt','wb').write(('bzip2 zipx payload\n'*200).encode())"
///   7zz a -tzip -mm=BZip2   crates/newtua-core/tests/fixtures/bzip2.zipx    /tmp/bzip2_payload.txt
///   python3 -c "open('/tmp/ppmd_payload.txt','wb').write(('ppmd zipx payload\n'*200).encode())"
///   7zz a -tzip -mm=PPMd    crates/newtua-core/tests/fixtures/ppmd.zipx     /tmp/ppmd_payload.txt
///   python3 -c "open('/tmp/xz_payload.txt','wb').write(('xz zipx payload\n'*200).encode())"
///   7zz a -tzip -mm=Xz      crates/newtua-core/tests/fixtures/xz.zipx       /tmp/xz_payload.txt
///   python3 -c "open('/tmp/d64_payload.txt','wb').write(('deflate64 payload\n'*200).encode())"
///   7zz a -tzip -mm=Deflate64 crates/newtua-core/tests/fixtures/deflate64.zipx /tmp/d64_payload.txt
use newtua_core::archive::FormatId;
use newtua_core::{Error, OpenOptions, open};
use std::path::Path;

fn fixture(name: &str) -> std::path::PathBuf {
    Path::new("tests/fixtures").join(name)
}

// ── LZMA: listing works, extraction is reported Unsupported ─────────────────
//
// NOTE: The zip crate 2.4.2 uses lzma_rs with UnpackedSize::ReadFromHeader,
// but the ZIP LZMA format (APPNOTE.TXT) does not include the 8-byte size field
// before the compressed payload — the 5-byte LZMA properties are followed
// immediately by EOS-terminated compressed data.  This mismatch causes lzma_rs
// to misinterpret the first bytes of compressed data as the size, producing
// "LZ distance beyond output size" errors.  The `lzma` feature is enabled (so
// listing works), but `read_entry` returns Error::Unsupported for LZMA members
// rather than leaking that misleading IO error — until the zip crate fixes its
// ZIP-LZMA decoder (or we upgrade to a version that does).

#[test]
fn lzma_zipx_lists_entries() {
    // Listing must succeed even when extraction is unsupported.
    let mut ar = open(&fixture("lzma.zipx"), &OpenOptions::default()).unwrap();
    let entries = ar.entries().unwrap();
    assert_eq!(entries.len(), 1, "expected exactly one entry in lzma.zipx");
    assert_eq!(
        ar.format(),
        FormatId::Zip,
        "format must be Zip, not a new FormatId"
    );
}

#[test]
fn lzma_zipx_read_entry_is_unsupported_not_io() {
    // The broken ZIP-LZMA decoder must surface as Unsupported, not a cryptic IO
    // error, mirroring how PPMd is reported.
    let mut ar = open(&fixture("lzma.zipx"), &OpenOptions::default()).unwrap();
    ar.entries().unwrap();
    let mut out = Vec::new();
    let err = ar.read_entry(0, &mut out).unwrap_err();
    assert!(
        matches!(err, newtua_core::Error::Unsupported { .. }),
        "expected Unsupported, got {err:?}"
    );
}

// ── BZip2 happy path ──────────────────────────────────────────────────────────

#[test]
fn bzip2_zipx_lists_entries() {
    let mut ar = open(&fixture("bzip2.zipx"), &OpenOptions::default()).unwrap();
    let entries = ar.entries().unwrap();
    assert_eq!(entries.len(), 1, "expected exactly one entry in bzip2.zipx");
    assert_eq!(ar.format(), FormatId::Zip);
}

#[test]
fn bzip2_zipx_extracts_correct_bytes() {
    let expected: Vec<u8> = "bzip2 zipx payload\n".repeat(200).into_bytes();
    let mut ar = open(&fixture("bzip2.zipx"), &OpenOptions::default()).unwrap();
    ar.entries().unwrap();
    let mut out = Vec::new();
    ar.read_entry(0, &mut out).unwrap();
    assert_eq!(out, expected);
}

// ── XZ happy path ─────────────────────────────────────────────────────────────

#[test]
fn xz_zipx_lists_entries() {
    let mut ar = open(&fixture("xz.zipx"), &OpenOptions::default()).unwrap();
    let entries = ar.entries().unwrap();
    assert_eq!(entries.len(), 1, "expected exactly one entry in xz.zipx");
    assert_eq!(ar.format(), FormatId::Zip);
}

#[test]
fn xz_zipx_extracts_correct_bytes() {
    let expected: Vec<u8> = "xz zipx payload\n".repeat(200).into_bytes();
    let mut ar = open(&fixture("xz.zipx"), &OpenOptions::default()).unwrap();
    ar.entries().unwrap();
    let mut out = Vec::new();
    ar.read_entry(0, &mut out).unwrap();
    assert_eq!(out, expected);
}

// ── Deflate64 happy path ──────────────────────────────────────────────────────

#[test]
fn deflate64_zipx_lists_entries() {
    let mut ar = open(&fixture("deflate64.zipx"), &OpenOptions::default()).unwrap();
    let entries = ar.entries().unwrap();
    assert_eq!(
        entries.len(),
        1,
        "expected exactly one entry in deflate64.zipx"
    );
    assert_eq!(ar.format(), FormatId::Zip);
}

#[test]
fn deflate64_zipx_extracts_correct_bytes() {
    let expected: Vec<u8> = "deflate64 payload\n".repeat(200).into_bytes();
    let mut ar = open(&fixture("deflate64.zipx"), &OpenOptions::default()).unwrap();
    ar.entries().unwrap();
    let mut out = Vec::new();
    ar.read_entry(0, &mut out).unwrap();
    assert_eq!(out, expected);
}

// ── PPMd → must surface as Error::Unsupported, not Corrupt or a panic ────────

#[test]
fn ppmd_zipx_listing_succeeds() {
    // Listing (entries()) must work even for PPMd — the header is readable.
    let mut ar = open(&fixture("ppmd.zipx"), &OpenOptions::default()).unwrap();
    let entries = ar.entries().unwrap();
    assert_eq!(entries.len(), 1, "expected exactly one entry in ppmd.zipx");
    assert_eq!(ar.format(), FormatId::Zip);
}

#[test]
fn ppmd_zipx_read_entry_is_unsupported_not_corrupt() {
    // PPMd (method 98) has no decoder in the zip crate; must return
    // Error::Unsupported, never Error::Corrupt or a panic.
    let mut ar = open(&fixture("ppmd.zipx"), &OpenOptions::default()).unwrap();
    ar.entries().unwrap();
    let mut out = Vec::new();
    let err = ar.read_entry(0, &mut out).unwrap_err();
    assert!(
        matches!(err, Error::Unsupported { .. }),
        "expected Error::Unsupported for PPMd, got: {err:?}"
    );
}
