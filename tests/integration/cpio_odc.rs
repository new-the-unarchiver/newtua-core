//! cpio, odc variant (`070707`) — the one macOS actually writes.
//!
//! `ditto` is the engine behind Archive Utility, and it emits odc, not newc:
//!
//! ```text
//! $ ditto -c src out.cpio && head -c 6 out.cpio
//! 070707
//! ```
//!
//! Fixtures (macOS 15, system `ditto`; `src/a.txt` = "one\n",
//! `src/sub/b.txt` = "two two\n"):
//!
//! ```text
//! mkdir -p src/sub && printf 'one\n' > src/a.txt && printf 'two two\n' > src/sub/b.txt
//!
//! # cpio_odc.cpio / tree_odc.cpgz — without the AppleDouble sidecars
//! ditto --norsrc --noextattr --noqtn --noacl -c src cpio_odc.cpio
//! gzip -n -c cpio_odc.cpio > tree_odc.cpgz
//!
//! # tree_odc_sidecars.cpgz — a plain `ditto -c`, exactly as Archive Utility
//! # runs it: the `._*` AppleDouble members are part of the stream
//! ditto -c src out.cpio
//! gzip -n -c out.cpio > tree_odc_sidecars.cpgz
//! ```

use newtua_core::archive::{ArchiveReader, EntryKind, FormatId, OpenOptions};
use newtua_core::detect::open;
use std::io::Write as _;
use std::path::Path;

fn fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Read one entry by path and return its body.
fn body_of(reader: &mut Box<dyn ArchiveReader>, path: &str) -> Vec<u8> {
    let idx = {
        let entries = reader.entries().expect("entries");
        entries
            .iter()
            .position(|e| e.path == Path::new(path))
            .unwrap_or_else(|| {
                panic!(
                    "{path} missing; got {:?}",
                    entries.iter().map(|e| &e.path).collect::<Vec<_>>()
                )
            })
    };
    let mut out = Vec::new();
    reader.read_entry(idx, &mut out).expect("read_entry");
    out
}

/// The two files a `ditto`-made archive carries, with the nesting intact.
fn assert_ditto_tree(reader: &mut Box<dyn ArchiveReader>) {
    assert_eq!(reader.format(), FormatId::Cpio);
    assert_eq!(body_of(reader, "a.txt"), b"one\n");
    assert_eq!(body_of(reader, "sub/b.txt"), b"two two\n");
}

/// A bare odc `.cpio` opens directly through the registry, not only inside a
/// compressor.
#[test]
fn odc_cpio_lists_and_extracts() {
    let mut reader = open(&fixture("cpio_odc.cpio"), &OpenOptions::default()).expect("open odc");
    assert_ditto_tree(&mut reader);

    // Directory members keep their kind and their nesting shows up in the path.
    let entries = reader.entries().expect("entries");
    let sub = entries
        .iter()
        .find(|e| e.path == Path::new("sub"))
        .expect("sub/ missing");
    assert!(matches!(sub.kind, EntryKind::Dir), "sub must be a Dir");
    assert_eq!(sub.mode.map(|m| m & 0o7777), Some(0o755));

    let a = entries
        .iter()
        .find(|e| e.path == Path::new("a.txt"))
        .expect("a.txt missing");
    assert_eq!(a.size, 4);
    assert!(matches!(a.kind, EntryKind::File));
    assert!(a.modified.is_some(), "odc carries an mtime");
}

/// The point of the whole ticket: a `.cpgz` from `ditto` + `gzip` expands into
/// the files that were packed, not into one entry named `tree_odc.cpgz`.
#[test]
fn odc_cpgz_expands_to_its_entries() {
    let mut reader = open(&fixture("tree_odc.cpgz"), &OpenOptions::default()).expect("open .cpgz");
    assert_ditto_tree(&mut reader);
}

/// A plain `ditto -c` (no flags) — exactly what Archive Utility runs — also
/// packs `._*` AppleDouble sidecars. Listing shows them; extraction skips them
/// by default, so the user gets back the tree they packed.
#[test]
fn odc_cpgz_with_apple_sidecars_extracts_the_real_tree() {
    let path = fixture("tree_odc_sidecars.cpgz");
    let mut reader = open(&path, &OpenOptions::default()).expect("open sidecar .cpgz");
    assert_ditto_tree(&mut reader);

    let entries = reader.entries().expect("entries");
    assert!(
        entries.iter().any(|e| e.path == Path::new("._a.txt")),
        "the raw listing keeps the AppleDouble members"
    );

    let dest = tempfile::tempdir().unwrap();
    newtua_core::extract_all(
        &mut *reader,
        &mut newtua_core::ExtractOptions {
            dest: dest.path().to_path_buf(),
            wrapper_name: None,
            strict: true,
            preserve: false,
            selection: None,
            progress: None,
            keep_macos_metadata: false,
        },
    )
    .expect("extract_all");

    assert_eq!(std::fs::read(dest.path().join("a.txt")).unwrap(), b"one\n");
    assert_eq!(
        std::fs::read(dest.path().join("sub/b.txt")).unwrap(),
        b"two two\n"
    );
    assert!(
        !dest.path().join("._a.txt").exists(),
        "AppleDouble sidecars must not be written"
    );
}

/// An odc stream that ends before its trailer is an error, never a panic.
#[test]
fn truncated_odc_returns_error() {
    let full = std::fs::read(fixture("cpio_odc.cpio")).unwrap();
    // Cut mid-body of the last file, well past the first header.
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(&full[..full.len() / 2]).unwrap();
    let tmp_path = tmp.into_temp_path();

    let result = open(&tmp_path, &OpenOptions::default());
    assert!(
        matches!(result, Err(newtua_core::error::Error::Corrupt(_))),
        "expected Corrupt for a truncated odc, got {:?}",
        result.map(|_| "Ok")
    );
}

/// Garbage in the octal fields is rejected, not multiplied into a huge
/// allocation and not a panic. The header below has the odc magic and then
/// non-octal bytes where the sizes belong.
#[test]
fn odc_with_garbage_octal_fields_returns_error() {
    let mut header = Vec::new();
    header.extend_from_slice(b"070707");
    header.extend_from_slice(&[b'z'; 70]); // dev..filesize, all non-octal
    header.extend_from_slice(b"name\0");

    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(&header).unwrap();
    let tmp_path = tmp.into_temp_path();

    let result = open(&tmp_path, &OpenOptions::default());
    assert!(
        matches!(result, Err(newtua_core::error::Error::Corrupt(_))),
        "expected Corrupt for garbage octal fields, got {:?}",
        result.map(|_| "Ok")
    );
}

/// A header whose `filesize` claims far more than the file holds must fail
/// while streaming, not pre-allocate the claimed size.
#[test]
fn odc_with_oversized_filesize_returns_error() {
    let mut header = Vec::new();
    header.extend_from_slice(b"070707"); // magic
    header.extend_from_slice(b"000000"); // dev
    header.extend_from_slice(b"000001"); // ino
    header.extend_from_slice(b"100644"); // mode — regular file
    header.extend_from_slice(b"000000"); // uid
    header.extend_from_slice(b"000000"); // gid
    header.extend_from_slice(b"000001"); // nlink
    header.extend_from_slice(b"000000"); // rdev
    header.extend_from_slice(b"00000000000"); // mtime
    header.extend_from_slice(b"000006"); // namesize — "a.txt\0"
    header.extend_from_slice(b"77777777777"); // filesize — ~8 GB, absent
    assert_eq!(header.len(), 76);
    header.extend_from_slice(b"a.txt\0");
    header.extend_from_slice(b"tiny");

    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(&header).unwrap();
    let tmp_path = tmp.into_temp_path();

    let result = open(&tmp_path, &OpenOptions::default());
    assert!(
        matches!(result, Err(newtua_core::error::Error::Corrupt(_))),
        "expected Corrupt for an oversized filesize, got {:?}",
        result.map(|_| "Ok")
    );
}
