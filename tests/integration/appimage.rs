//! End-to-end tests for the AppImage handler.
//!
//! AppImage fixtures are assembled at runtime: a hand-built 128-byte ELF64
//! prefix (e_shoff=64, e_shentsize=64, e_shnum=1 → fs offset 128) prepended to a
//! committed inner filesystem (`tree-*.squashfs` for Type 2, `sample.iso` for
//! Type 1). This keeps the ELF layout visible in code and avoids committing
//! blobs that merely concatenate existing fixtures.
use std::io::Write;
use std::path::Path;

use newtua_core::archive::{ArchiveReader, EntryKind, FormatId, OpenOptions};
use newtua_core::detect::open;
use newtua_core::error::Error;

fn fixture_bytes(name: &str) -> Vec<u8> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("read fixture {name}: {e}"))
}

/// 128-byte little-endian ELF64 AppImage prefix; fs offset = 64 + 64·1 = 128.
fn elf64_prefix(ai_type: u8) -> Vec<u8> {
    let mut h = vec![0u8; 128];
    h[0..4].copy_from_slice(b"\x7fELF");
    h[4] = 2; // ELFCLASS64
    h[5] = 1; // ELFDATA2LSB
    h[6] = 1; // EI_VERSION
    h[8] = b'A';
    h[9] = b'I';
    h[10] = ai_type;
    h[16..18].copy_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
    h[18..20].copy_from_slice(&0x3eu16.to_le_bytes()); // e_machine = EM_X86_64
    h[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
    h[40..48].copy_from_slice(&64u64.to_le_bytes()); // e_shoff = 64
    h[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize = 64
    h[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize = 64
    h[60..62].copy_from_slice(&1u16.to_le_bytes()); // e_shnum = 1
    h
}

/// Build a `.appimage` temp file = ELF prefix + `inner` filesystem bytes.
fn build_appimage(inner: &[u8], ai_type: u8) -> tempfile::NamedTempFile {
    let mut bytes = elf64_prefix(ai_type);
    bytes.extend_from_slice(inner);
    let mut tmp = tempfile::Builder::new()
        .suffix(".appimage")
        .tempfile()
        .expect("temp");
    tmp.write_all(&bytes).expect("write");
    tmp.flush().expect("flush");
    tmp
}

fn body_of(reader: &mut dyn ArchiveReader, name: &str) -> Vec<u8> {
    let idx = {
        let entries = reader.entries().expect("entries");
        entries
            .iter()
            .position(|e| e.path.to_string_lossy() == name)
            .unwrap_or_else(|| panic!("entry {name} not found"))
    };
    let mut body = Vec::new();
    reader.read_entry(idx, &mut body).expect("read_entry");
    body
}

#[test]
fn type2_squashfs_gzip_lists_and_extracts() {
    let app = build_appimage(&fixture_bytes("tree-gzip.squashfs"), 2);
    let mut reader = open(app.path(), &OpenOptions::default()).expect("open appimage");
    assert_eq!(reader.format(), FormatId::AppImage);

    let names: Vec<String> = reader
        .entries()
        .expect("entries")
        .iter()
        .map(|e| e.path.to_string_lossy().into_owned())
        .collect();
    assert!(names.iter().any(|n| n == "hello.txt"), "names: {names:?}");
    assert!(
        names.iter().any(|n| n == "sub/nested.txt"),
        "names: {names:?}"
    );

    assert_eq!(
        body_of(reader.as_mut(), "hello.txt"),
        b"hello from squashfs\n"
    );
}

#[test]
fn type2_squashfs_xz_extracts() {
    // Exercises the XzViaXz2 path (#18) reached through AppImage dispatch.
    let app = build_appimage(&fixture_bytes("tree-xz.squashfs"), 2);
    let mut reader = open(app.path(), &OpenOptions::default()).expect("open appimage xz");
    assert_eq!(reader.format(), FormatId::AppImage);
    assert_eq!(body_of(reader.as_mut(), "sub/nested.txt"), b"nested file\n");
}

#[test]
fn type1_iso_lists_and_extracts() {
    let app = build_appimage(&fixture_bytes("sample.iso"), 1);
    let mut reader = open(app.path(), &OpenOptions::default()).expect("open appimage iso");
    assert_eq!(reader.format(), FormatId::AppImage);

    let entries = reader.entries().expect("entries");
    let hello = entries
        .iter()
        .find(|e| e.path.to_string_lossy() == "hello.txt")
        .expect("hello.txt");
    assert_eq!(hello.kind, EntryKind::File);
    assert_eq!(body_of(reader.as_mut(), "hello.txt"), b"hello iso\n");
    assert_eq!(body_of(reader.as_mut(), "sub/inner.txt"), b"nested\n");
}

#[test]
fn detected_by_extension_when_ai_marker_zeroed() {
    // AI type byte zeroed → magic fails, but the `.appimage` name still detects,
    // and dispatch by the actual `hsqs` bytes still opens it as Type 2.
    let app = build_appimage(&fixture_bytes("tree-gzip.squashfs"), 0);
    let mut reader = open(app.path(), &OpenOptions::default()).expect("open by extension");
    assert_eq!(reader.format(), FormatId::AppImage);
    assert_eq!(
        body_of(reader.as_mut(), "hello.txt"),
        b"hello from squashfs\n"
    );
}

#[test]
fn garbage_filesystem_is_corrupt() {
    // Valid ELF prefix, but the payload is neither squashfs nor iso.
    let app = build_appimage(&[0x5Au8; 64], 2);
    match open(app.path(), &OpenOptions::default()) {
        Err(Error::Corrupt(_)) => {}
        Err(e) => panic!("expected Corrupt error, got {e:?}"),
        Ok(_) => panic!("expected Corrupt error, got Ok"),
    }
}
