/// Integration tests for multi-volume archive opening.
///
/// Test A — generic byte-split (`.001`/`.002` scheme):
///   Build a real ZIP, split it in half, call `open("…/archive.zip.001")`, and
///   verify that all entries and their content are accessible.
///
/// Test B — RAR native multi-volume (`name.partN.rar`):
///   Fixtures created with:
///     content.txt (4000 random bytes) →
///       `rar a -m0 -v2k mv.rar content.txt`
///   Results in mv.part1.rar / mv.part2.rar / mv.part3.rar.
///   Opening part1 should list 1 entry and extract the full file.
use newtua_core::{OpenOptions, open};
use std::io::Write;

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
    let names: Vec<_> = entries.iter().map(|e| e.path.to_str().unwrap().to_string()).collect();
    assert!(
        names.contains(&"a.txt".to_string()),
        "expected a.txt in entries, got: {names:?}"
    );
    assert!(
        names.contains(&"b.txt".to_string()),
        "expected b.txt in entries, got: {names:?}"
    );

    // Extract entry "a.txt" (index 0) and verify content.
    let a_idx = entries.iter().position(|e| e.path.to_str() == Some("a.txt")).unwrap();
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

// ── Test B: RAR native multi-volume ─────────────────────────────────────────

// Fixtures: mv.part1.rar, mv.part2.rar, mv.part3.rar
// Content:  content.txt — 4000 random bytes (stored verbatim, -m0)
const RAR_PART1: &[u8] = include_bytes!("fixtures/mv.part1.rar");
const RAR_PART2: &[u8] = include_bytes!("fixtures/mv.part2.rar");
const RAR_PART3: &[u8] = include_bytes!("fixtures/mv.part3.rar");
const EXPECTED_CONTENT: &[u8] = include_bytes!("fixtures/mv_content.txt");

// RED: unrar crate 0.5.8 crashes (SIGABRT / null-ptr UB) when read_entry()
// crosses a volume boundary. The listing succeeds but extraction aborts.
// Tracked as: unrar crate limitation — multi-volume processing is unsupported.
// This test is marked #[ignore] to prevent the SIGABRT from killing the whole
// test binary. Once the unrar crate is updated or worked around, re-enable.
#[test]
#[ignore = "unrar 0.5.8 crashes (SIGABRT) on cross-volume extraction — tracked as RAR-MV-UB"]
fn rar_native_multivolume_lists_and_extracts() {
    let dir = tempfile::tempdir().unwrap();

    // Write all three volumes into the same temp dir so the unrar library
    // can locate siblings by scanning next to the first volume path.
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
    assert_eq!(entries[0].size, EXPECTED_CONTENT.len() as u64);

    let mut out = Vec::new();
    ar.read_entry(0, &mut out).unwrap();
    assert_eq!(out, EXPECTED_CONTENT, "extracted bytes differ from original");
}
