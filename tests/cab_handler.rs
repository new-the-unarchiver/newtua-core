use newtua_core::format::CabHandler;
use newtua_core::{Error, ExtractOptions, FormatHandler, OpenOptions, Source, extract_all};
use std::io::Write;

/// Build a single-folder MSZIP cabinet in a temp file. Files are written in the
/// order declared (the `cab` writer streams `next_file()` in that order).
fn make_cab(files: &[(&str, &[u8])]) -> tempfile::NamedTempFile {
    use cab::{CabinetBuilder, CompressionType};
    let tmp = tempfile::Builder::new().suffix(".cab").tempfile().unwrap();
    let mut builder = CabinetBuilder::new();
    {
        let folder = builder.add_folder(CompressionType::MsZip);
        for (name, _) in files {
            folder.add_file(*name);
        }
    }
    let file = std::fs::File::create(tmp.path()).unwrap();
    let mut cw = builder.build(file).unwrap();
    let mut data = files.iter();
    while let Some(mut w) = cw.next_file().unwrap() {
        w.write_all(data.next().unwrap().1).unwrap();
    }
    cw.finish().unwrap();
    tmp
}

#[test]
fn lists_and_reads_cab() {
    let cab = make_cab(&[("hello.txt", b"hello cab"), ("dir\\nested.txt", b"nested!")]);
    let src = Source::path(cab.path()).unwrap();
    let mut ar = CabHandler.open(src, &OpenOptions::default()).unwrap();

    let entries = ar.entries().unwrap();
    assert_eq!(entries.len(), 2);
    // backslash separators are normalized to forward slashes
    assert_eq!(entries[0].path.to_str().unwrap(), "hello.txt");
    assert_eq!(entries[1].path.to_str().unwrap(), "dir/nested.txt");
    assert_eq!(entries[0].size, 9);
    assert_eq!(entries[1].size, 7);

    let mut out = Vec::new();
    ar.read_entry(0, &mut out).unwrap();
    assert_eq!(out, b"hello cab");
    let mut out2 = Vec::new();
    ar.read_entry(1, &mut out2).unwrap();
    assert_eq!(out2, b"nested!");
}

#[test]
fn read_entry_out_of_range_errors() {
    let cab = make_cab(&[("a.txt", b"a")]);
    let src = Source::path(cab.path()).unwrap();
    let mut ar = CabHandler.open(src, &OpenOptions::default()).unwrap();
    ar.entries().unwrap();
    let mut out = Vec::new();
    let err = ar.read_entry(99, &mut out).unwrap_err();
    assert!(matches!(err, Error::InvalidIndex(99)));
}

#[test]
fn extracts_cab_to_dest() {
    let cab = make_cab(&[("data\\a.txt", b"A"), ("data\\b.txt", b"B")]);
    let dest = tempfile::tempdir().unwrap();
    let src = Source::path(cab.path()).unwrap();
    let mut ar = CabHandler.open(src, &OpenOptions::default()).unwrap();
    extract_all(
        &mut *ar,
        &mut ExtractOptions {
            dest: dest.path().to_path_buf(),
            wrapper_name: Some("arc".into()),
            strict: false,
            preserve: true,
            selection: None,
            progress: None,
            keep_macos_metadata: false,
        },
    )
    .unwrap();
    // "data" is the common root, so it is used as the folder (no extra wrapper)
    assert_eq!(std::fs::read(dest.path().join("data/a.txt")).unwrap(), b"A");
    assert_eq!(std::fs::read(dest.path().join("data/b.txt")).unwrap(), b"B");
}
