use ar::{GnuBuilder, Header};
use newtua_core::format::ArHandler;
use newtua_core::{Error, ExtractOptions, FormatHandler, OpenOptions, Source, extract_all};

/// Build a GNU-variant ar archive in a temp file. Using `GnuBuilder` exercises
/// both inline short names and the `//` long-name table (for names > 16 bytes).
/// Each tuple is (name, data, mode, mtime).
fn make_ar(files: &[(&str, &[u8], u32, u64)]) -> tempfile::NamedTempFile {
    let tmp = tempfile::Builder::new().suffix(".a").tempfile().unwrap();
    let ids: Vec<Vec<u8>> = files.iter().map(|f| f.0.as_bytes().to_vec()).collect();
    let file = std::fs::File::create(tmp.path()).unwrap();
    let mut builder = GnuBuilder::new(file, ids);
    for f in files {
        let mut header = Header::new(f.0.as_bytes().to_vec(), f.1.len() as u64);
        header.set_mode(f.2);
        header.set_mtime(f.3);
        builder.append(&header, f.1).unwrap();
    }
    builder.into_inner().unwrap();
    tmp
}

#[test]
fn lists_and_reads_ar() {
    let long_name = "this_is_a_very_long_member_name.txt"; // > 16 bytes -> `//` table
    let ar = make_ar(&[
        ("short.txt", b"short data", 0o644, 1_000_000_000),
        (long_name, b"long member data", 0o755, 1_700_000_000),
    ]);
    let src = Source::path(ar.path()).unwrap();
    let mut reader = ArHandler.open(src, &OpenOptions::default()).unwrap();

    let entries = reader.entries().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].path.to_str().unwrap(), "short.txt");
    assert_eq!(entries[1].path.to_str().unwrap(), long_name);
    assert_eq!(entries[0].size, 10);
    assert_eq!(entries[1].size, 16);
    assert_eq!(entries[0].mode, Some(0o644));
    assert_eq!(entries[1].mode, Some(0o755));
    assert!(entries[0].modified.is_some());

    let mut out = Vec::new();
    reader.read_entry(0, &mut out).unwrap();
    assert_eq!(out, b"short data");
    let mut out2 = Vec::new();
    reader.read_entry(1, &mut out2).unwrap();
    assert_eq!(out2, b"long member data");
}

#[test]
fn read_entry_out_of_range_errors() {
    let ar = make_ar(&[("a.txt", b"a", 0o644, 0)]);
    let src = Source::path(ar.path()).unwrap();
    let mut reader = ArHandler.open(src, &OpenOptions::default()).unwrap();
    reader.entries().unwrap();
    let mut out = Vec::new();
    let err = reader.read_entry(99, &mut out).unwrap_err();
    assert!(matches!(err, Error::InvalidIndex(99)));
}

#[test]
fn extracts_ar_to_dest() {
    let ar = make_ar(&[("a.txt", b"AAA", 0o644, 0), ("b.txt", b"BBB", 0o644, 0)]);
    let dest = tempfile::tempdir().unwrap();
    let src = Source::path(ar.path()).unwrap();
    let mut reader = ArHandler.open(src, &OpenOptions::default()).unwrap();
    extract_all(
        &mut *reader,
        &mut ExtractOptions {
            dest: dest.path().to_path_buf(),
            wrapper_name: Some("arc".into()),
            strict: false,
            preserve: false,
            selection: None,
            progress: None,
            keep_macos_metadata: false,
        },
    )
    .unwrap();
    // Members are flat (no common root), so they are wrapped in the "arc" folder.
    assert_eq!(
        std::fs::read(dest.path().join("arc/a.txt")).unwrap(),
        b"AAA"
    );
    assert_eq!(
        std::fs::read(dest.path().join("arc/b.txt")).unwrap(),
        b"BBB"
    );
}
