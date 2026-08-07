/// Integration tests for multi-volume archive opening.
///
/// Test A — generic byte-split (`.001`/`.002` scheme):
///   Build a real ZIP, split it in half, call `open("…/archive.zip.001")`, and
///   verify that all entries and their content are accessible.
///
/// Test B — `zip -s` split volumes (`name.z01`, …, `name.zip`):
///   The entry point is the LAST file, because the central directory lives
///   there. Fixtures were produced by Info-ZIP `zip -s 64k`; `split64.*`
///   additionally carries `-fz` (forced zip64), so it exercises the zip64
///   end-of-central-directory record and locator.
///
/// Test C — RAR native multi-volume (`name.partN.rar`):
///   Fixtures created with:
///     content.txt (4000 random bytes) →
///       `rar a -m0 -v2k mv.rar content.txt`
///   Results in mv.part1.rar / mv.part2.rar / mv.part3.rar.
///   Opening part1 should list 1 entry and extract the full file.
use newtua_core::{OpenOptions, open};
use std::io::Write;
use std::path::Path;

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Build a small in-memory ZIP with two entries ("a.txt" and "b.txt").
fn make_zip_bytes() -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let opts: zip::write::FileOptions<()> = zip::write::FileOptions::default();
        w.start_file("a.txt", opts).unwrap();
        w.write_all(b"hello from a").unwrap();
        let opts: zip::write::FileOptions<()> = zip::write::FileOptions::default();
        w.start_file("b.txt", opts).unwrap();
        w.write_all(b"hello from b").unwrap();
        w.finish().unwrap();
    }
    buf
}

// ── Test A: generic .001/.002 split ─────────────────────────────────────────

#[test]
fn split_zip_opens_via_001_suffix() {
    let dir = tempfile::tempdir().unwrap();

    // Write a complete ZIP to disk.
    let zip_bytes = make_zip_bytes();
    let total = zip_bytes.len();
    assert!(total >= 4, "fixture too small");

    // Split into two roughly equal halves.
    let half = total / 2;
    std::fs::write(dir.path().join("archive.zip.001"), &zip_bytes[..half]).unwrap();
    std::fs::write(dir.path().join("archive.zip.002"), &zip_bytes[half..]).unwrap();

    // open() on the .001 member should reconstruct and parse the ZIP.
    let path = dir.path().join("archive.zip.001");
    let mut ar = open(&path, &OpenOptions::default()).unwrap();

    let entries = ar.entries().unwrap();
    let names: Vec<_> = entries
        .iter()
        .map(|e| e.path.to_str().unwrap().to_string())
        .collect();
    assert!(
        names.contains(&"a.txt".to_string()),
        "expected a.txt in entries, got: {names:?}"
    );
    assert!(
        names.contains(&"b.txt".to_string()),
        "expected b.txt in entries, got: {names:?}"
    );

    // Extract entry "a.txt" (index 0) and verify content.
    let a_idx = entries
        .iter()
        .position(|e| e.path == Path::new("a.txt"))
        .unwrap();
    let mut out = Vec::new();
    ar.read_entry(a_idx, &mut out).unwrap();
    assert_eq!(out, b"hello from a");
}

/// Opening a single `.001` file (no `.002` sibling) falls back to normal open.
#[test]
fn single_001_file_no_sibling_opens_normally() {
    let dir = tempfile::tempdir().unwrap();
    let zip_bytes = make_zip_bytes();
    // Write only the .001 — no .002 sibling.
    let path = dir.path().join("lone.zip.001");
    std::fs::write(&path, &zip_bytes).unwrap();

    let mut ar = open(&path, &OpenOptions::default()).unwrap();
    let entries = ar.entries().unwrap();
    assert_eq!(entries.len(), 2);
}

// ── Test B: `zip -s` split volumes ──────────────────────────────────────────

const SPLIT_Z01: &[u8] = include_bytes!("../fixtures/split.z01");
const SPLIT_ZIP: &[u8] = include_bytes!("../fixtures/split.zip");
const SPLIT64_Z01: &[u8] = include_bytes!("../fixtures/split64.z01");
const SPLIT64_ZIP: &[u8] = include_bytes!("../fixtures/split64.zip");

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// Read the entry named `name` and return its bytes.
fn body_of(ar: &mut dyn newtua_core::ArchiveReader, name: &str) -> Vec<u8> {
    let idx = ar
        .entries()
        .unwrap()
        .iter()
        .position(|e| e.path == Path::new(name))
        .unwrap_or_else(|| panic!("no entry {name}"));
    let mut out = Vec::new();
    ar.read_entry(idx, &mut out).unwrap();
    out
}

/// A `zip -s` set must open from its LAST volume (`.zip`) and yield the exact
/// original bytes of every entry.
///
/// The expected tree and its hashes come from the files that went into the
/// archive, not from this crate's reader: `big.txt` lives on volume 0, the
/// other five entries on volume 1, so every kind of cross-volume offset is
/// exercised at once.
#[test]
fn split_zip_z01_scheme_opens_from_last_volume() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("split.z01"), SPLIT_Z01).unwrap();
    std::fs::write(dir.path().join("split.zip"), SPLIT_ZIP).unwrap();

    let mut ar = open(&dir.path().join("split.zip"), &OpenOptions::default()).unwrap();
    let names: Vec<String> = ar
        .entries()
        .unwrap()
        .iter()
        .map(|e| e.path.to_string_lossy().into_owned())
        .collect();
    assert_eq!(names.len(), 6, "expected six entries, got: {names:?}");
    for expected in [
        "hello.txt",
        "привет.txt",
        "nested/",
        "nested/deep/",
        "nested/deep/tiny.bin",
        "big.txt",
    ] {
        assert!(
            names.iter().any(|n| n == expected),
            "missing {expected} in {names:?}"
        );
    }

    for (name, size, sha) in [
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
            // On volume 0 — its local header offset only becomes valid after
            // the volumes are concatenated.
            "big.txt",
            65_529,
            "df1515a6fad9ce2f8141ff97f1e14ca7873ca48e50a95185efd64a55df216bec",
        ),
    ] {
        let body = body_of(ar.as_mut(), name);
        assert_eq!(body.len(), size, "wrong size for {name}");
        assert_eq!(sha256_hex(&body), sha, "wrong content for {name}");
    }
}

/// The same scheme with a zip64 trailer: the end-of-central-directory record
/// and its locator must be rewritten too, and the per-entry zip64 extra fields
/// (here: the uncompressed size) must survive the rewrite untouched.
#[test]
fn split_zip64_scheme_opens_from_last_volume() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("split64.z01"), SPLIT64_Z01).unwrap();
    std::fs::write(dir.path().join("split64.zip"), SPLIT64_ZIP).unwrap();

    let mut ar = open(&dir.path().join("split64.zip"), &OpenOptions::default()).unwrap();
    assert_eq!(ar.entries().unwrap().len(), 2);

    // payload.bin starts on volume 0, note.txt on volume 1.
    let payload = body_of(ar.as_mut(), "payload.bin");
    assert_eq!(payload.len(), 70_000);
    assert_eq!(
        sha256_hex(&payload),
        "d1c6be6b733581dc3ebb28a111a115399fcca53a6b287825cc98793ca35b7828"
    );
    let note = body_of(ar.as_mut(), "note.txt");
    assert_eq!(note, b"zip64 split volume test\n");
}

/// Regression guard: an ordinary single-volume zip must go through the old
/// path untouched — no siblings, no joining, no rewriting.
#[test]
fn plain_zip_without_volumes_is_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("plain.zip");
    std::fs::write(&path, make_zip_bytes()).unwrap();

    let mut ar = open(&path, &OpenOptions::default()).unwrap();
    assert_eq!(ar.entries().unwrap().len(), 2);
    let mut out = Vec::new();
    ar.read_entry(0, &mut out).unwrap();
    assert_eq!(out, b"hello from a");
}

/// A stray `.z01` next to a perfectly normal zip must not turn it into a
/// multi-volume set: the decision is made by the archive's own end record
/// (volume numbers zero), not by what the neighbouring file is called.
#[test]
fn plain_zip_ignores_a_stray_z01_neighbour() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("plain.zip");
    std::fs::write(&path, make_zip_bytes()).unwrap();
    std::fs::write(dir.path().join("plain.z01"), b"not a volume at all").unwrap();

    let mut ar = open(&path, &OpenOptions::default()).unwrap();
    assert_eq!(ar.entries().unwrap().len(), 2);
}

/// A volume missing from the set is an error, not a half-read archive.
#[test]
fn split_zip_with_a_missing_volume_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    // Only the last volume: `.z01` is replaced by a decoy so the scheme is
    // recognised, but the byte count can never line up.
    std::fs::write(dir.path().join("split.zip"), SPLIT_ZIP).unwrap();
    std::fs::write(dir.path().join("split.z01"), b"truncated").unwrap();

    let Err(err) = open(&dir.path().join("split.zip"), &OpenOptions::default()) else {
        panic!("a set with a bogus volume must not open");
    };
    assert!(
        !matches!(err, newtua_core::Error::UnknownFormat),
        "expected a specific failure, got {err}"
    );
}

// ── Test C: RAR native multi-volume ─────────────────────────────────────────

// Fixtures: mv.part1.rar, mv.part2.rar, mv.part3.rar
// Content:  content.txt — 4000 random bytes (stored verbatim, -m0)
const RAR_PART1: &[u8] = include_bytes!("../fixtures/mv.part1.rar");
const RAR_PART2: &[u8] = include_bytes!("../fixtures/mv.part2.rar");
const RAR_PART3: &[u8] = include_bytes!("../fixtures/mv.part3.rar");
const EXPECTED_CONTENT: &[u8] = include_bytes!("../fixtures/mv_content.txt");

/// Listing a native multi-volume RAR must succeed and return the correct entry
/// metadata.  The unrar 0.5.8 library is able to list without crossing volume
/// boundaries, so this should not crash.
#[test]
fn rar_native_multivolume_listing_works() {
    let dir = tempfile::tempdir().unwrap();

    // Write all three volumes into the same temp dir so the unrar library
    // can locate siblings when it scans next to the first volume path.
    std::fs::write(dir.path().join("mv.part1.rar"), RAR_PART1).unwrap();
    std::fs::write(dir.path().join("mv.part2.rar"), RAR_PART2).unwrap();
    std::fs::write(dir.path().join("mv.part3.rar"), RAR_PART3).unwrap();

    let part1 = dir.path().join("mv.part1.rar");
    let mut ar = open(&part1, &OpenOptions::default()).unwrap();

    let entries = ar.entries().unwrap();
    assert_eq!(entries.len(), 1, "expected 1 entry across volumes");
    assert_eq!(
        entries[0].path.to_str().unwrap(),
        "content.txt",
        "unexpected entry name"
    );
    assert_eq!(
        entries[0].size,
        EXPECTED_CONTENT.len() as u64,
        "entry size should match original"
    );
}

/// Extraction from a native multi-volume RAR must succeed and yield bytes
/// that exactly match the original content file.
///
/// Implementation note: the in-memory `read()` path used to SIGABRT here when
/// the payload crossed a volume boundary, and the handler had to detour through
/// `extract_to(temp_file)` on disk. The cause — a null pointer dereferenced in
/// the `UCM_PROCESSDATA` callback — is patched in `newtua-unrar`, so the detour
/// is gone and this test now guards the plain path. All volume parts must exist
/// in the same directory as part1 so that libunrar can locate them
/// automatically.
#[test]
fn rar_native_multivolume_extraction_works() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("mv.part1.rar"), RAR_PART1).unwrap();
    std::fs::write(dir.path().join("mv.part2.rar"), RAR_PART2).unwrap();
    std::fs::write(dir.path().join("mv.part3.rar"), RAR_PART3).unwrap();

    let part1 = dir.path().join("mv.part1.rar");
    let mut ar = open(&part1, &OpenOptions::default()).unwrap();

    // Listing must succeed first.
    let entries = ar.entries().unwrap();
    assert_eq!(entries.len(), 1, "expected 1 entry across volumes");

    // Extraction must yield bytes identical to the original content.
    let mut out = Vec::new();
    ar.read_entry(0, &mut out)
        .expect("multi-volume extraction must not fail");
    assert_eq!(
        out, EXPECTED_CONTENT,
        "extracted bytes must match original content"
    );
}
