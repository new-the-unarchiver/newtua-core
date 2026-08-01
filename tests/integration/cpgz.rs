//! cpio inside a compressor — the `.cpgz` that macOS Archive Utility produces.
//!
//! After the compression layer unpacks a file to a temp file, the content is
//! checked for tar and then for cpio. Nothing else: a `.zip.gz` must still come
//! out as one entry, which the last test here nails down.
//!
//! Fixtures (bsdcpio 3.5.3 / libarchive 3.7.4, the `cpio` shipped with macOS):
//!
//! ```text
//! mkdir tree && printf 'one\n' > tree/a.txt && printf 'two\n' > tree/b.txt
//! (cd tree && printf 'a.txt\nb.txt\n' | cpio -o --format newc) > tree.cpio
//! gzip -n -c tree.cpio > tree.cpgz
//! xz -c tree.cpio > tree.cpio.xz
//!
//! mkdir z && printf 'inner\n' > z/inner.txt
//! (cd z && zip -q -X ../payload.zip inner.txt)
//! gzip -n -c payload.zip > payload.zip.gz
//! ```

use newtua_core::archive::{FormatId, OpenOptions};
use newtua_core::detect::open;
use std::path::Path;

fn fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Read the two fixture members back and check names and bodies.
fn assert_tree_cpio(reader: &mut Box<dyn newtua_core::archive::ArchiveReader>) {
    assert_eq!(reader.format(), FormatId::Cpio);

    let (idx_a, idx_b) = {
        let entries = reader.entries().expect("entries");
        assert_eq!(entries.len(), 2, "expected 2 cpio entries");
        let idx_a = entries
            .iter()
            .position(|e| e.path == Path::new("a.txt"))
            .expect("a.txt missing");
        let idx_b = entries
            .iter()
            .position(|e| e.path == Path::new("b.txt"))
            .expect("b.txt missing");
        (idx_a, idx_b)
    };

    let mut body = Vec::new();
    reader.read_entry(idx_a, &mut body).expect("read a.txt");
    assert_eq!(body, b"one\n");

    let mut body_b = Vec::new();
    reader.read_entry(idx_b, &mut body_b).expect("read b.txt");
    assert_eq!(body_b, b"two\n");
}

/// A `.cpgz` lists the files that were packed, under their own names — not one
/// entry called `tree.cpgz`.
#[test]
fn cpgz_expands_to_its_cpio_entries() {
    let mut reader = open(&fixture("tree.cpgz"), &OpenOptions::default()).expect("open .cpgz");
    assert_tree_cpio(&mut reader);
}

/// The check lives after the compression layer, so it is not gzip-specific:
/// the same cpio inside xz behaves identically.
#[test]
fn cpio_inside_xz_expands_the_same_way() {
    let mut reader =
        open(&fixture("tree.cpio.xz"), &OpenOptions::default()).expect("open .cpio.xz");
    assert_tree_cpio(&mut reader);
}

/// Regression guard for the deliberate narrowness of the change: only tar and
/// cpio are looked for after decompression. A zip inside gzip must stay exactly
/// what it is today — one entry holding the raw `.zip` bytes — and must not
/// start being expanded through the format registry.
#[test]
fn zip_inside_gzip_stays_one_entry() {
    let mut reader =
        open(&fixture("payload.zip.gz"), &OpenOptions::default()).expect("open .zip.gz");
    assert_eq!(reader.format(), FormatId::Raw);

    let entries = reader.entries().expect("entries");
    assert_eq!(entries.len(), 1, "expected the zip to stay a single entry");
    assert_eq!(entries[0].path.to_string_lossy(), "payload.zip");

    // The one entry is the untouched zip file, byte for byte.
    let mut body = Vec::new();
    reader.read_entry(0, &mut body).expect("read_entry 0");
    assert!(body.starts_with(b"PK\x03\x04"), "expected raw zip bytes");
}
