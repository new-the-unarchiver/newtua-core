use newtua_core::archive::{EntryKind, FormatId, OpenOptions};
use newtua_core::detect::open;
use std::path::Path;

fn fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Opens the committed `minimal.rpm` fixture (gzip-compressed cpio payload),
/// verifies the entry list and extracts the known file body.
///
/// The fixture is `minimal-1.0-1.noarch.rpm`, built with `rpmbuild` on this
/// dev machine.  It contains exactly one file:
///   `/usr/share/minimal/hello.txt`  — 18 bytes — content: `-n hello from rpm\n`
///
/// The `-n` prefix is an artefact of the macOS `/bin/sh` `echo -n` handling
/// in the rpmbuild environment; the exact bytes were confirmed with `xxd`.
#[test]
fn rpm_list_and_extract() {
    let path = fixture("minimal.rpm");
    let opts = OpenOptions::default();
    let mut reader = open(&path, &opts).expect("open minimal.rpm");

    // The top-level format ID must be Rpm, not Cpio.
    assert_eq!(reader.format(), FormatId::Rpm);

    let entries = reader.entries().expect("entries");

    // The fixture contains one file entry (plus possibly directory entries).
    // Find the hello.txt entry.
    let hello_idx = entries
        .iter()
        .position(|e| {
            e.path.to_string_lossy().contains("hello.txt") && matches!(e.kind, EntryKind::File)
        })
        .expect("hello.txt not found in entries");

    let e = &entries[hello_idx];
    assert!(
        e.path.to_string_lossy().ends_with("hello.txt"),
        "unexpected path: {}",
        e.path.display()
    );
    assert_eq!(e.size, 18, "expected 18 bytes, got {}", e.size);
    assert!(!e.is_encrypted);

    // Extract and verify the file body.
    let mut body = Vec::new();
    reader
        .read_entry(hello_idx, &mut body)
        .expect("read_entry for hello.txt");
    assert_eq!(
        body, b"-n hello from rpm\n",
        "content mismatch: got {:?}",
        body
    );
}

/// `read_entry` with an out-of-range index must return `InvalidIndex`.
#[test]
fn rpm_read_entry_out_of_range() {
    let path = fixture("minimal.rpm");
    let opts = OpenOptions::default();
    let mut reader = open(&path, &opts).expect("open minimal.rpm");
    reader.entries().expect("entries");

    let result = reader.read_entry(9999, &mut std::io::sink());
    assert!(
        matches!(result, Err(newtua_core::error::Error::InvalidIndex(9999))),
        "expected InvalidIndex(9999), got {:?}",
        result
    );
}

/// Probe positive: the minimal.rpm starts with the RPM lead magic.
#[test]
fn rpm_probe_detects_magic() {
    use newtua_core::archive::Confidence;
    use newtua_core::archive::FormatHandler;
    use newtua_core::format::rpm::RpmHandler;

    let magic = &[0xED_u8, 0xAB, 0xEE, 0xDB, 0x03, 0x00, 0x00, 0x01];
    assert_eq!(RpmHandler.probe(magic, None), Confidence::MAGIC);
}
