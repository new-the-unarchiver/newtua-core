use newtua_core::error::Error;
use newtua_core::format::TarHandler;
use newtua_core::{FormatHandler, OpenOptions, Source};

fn make_tar() -> tempfile::NamedTempFile {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let mut builder = tar::Builder::new(std::fs::File::create(tmp.path()).unwrap());
    let data = b"hello tar";
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, "dir/a.txt", &data[..])
        .unwrap();
    builder.finish().unwrap();
    tmp
}

#[test]
fn lists_tar_entries() {
    let tmp = make_tar();
    let h = TarHandler;
    let src = Source::path(tmp.path()).unwrap();
    let mut ar = h.open(src, &OpenOptions::default()).unwrap();
    let entries = ar.entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path.to_str().unwrap(), "dir/a.txt");
    assert_eq!(entries[0].size, 9);
}

#[test]
fn extracts_tar_entry_bytes() {
    let tmp = make_tar();
    let h = TarHandler;
    let src = Source::path(tmp.path()).unwrap();
    let mut ar = h.open(src, &OpenOptions::default()).unwrap();
    ar.entries().unwrap();
    let mut out = Vec::new();
    ar.read_entry(0, &mut out).unwrap();
    assert_eq!(out, b"hello tar");
}

#[test]
fn read_entry_out_of_range_returns_invalid_index() {
    let tmp = make_tar();
    let h = TarHandler;
    let src = Source::path(tmp.path()).unwrap();
    let mut ar = h.open(src, &OpenOptions::default()).unwrap();
    ar.entries().unwrap();
    let mut sink = Vec::new();
    let err = ar.read_entry(999, &mut sink).unwrap_err();
    assert!(
        matches!(err, Error::InvalidIndex(_)),
        "expected InvalidIndex, got: {err}"
    );
}

#[test]
fn corrupt_tar_errors() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), b"not a tar file at all, just text").unwrap();
    let h = TarHandler;
    let src = Source::path(tmp.path()).unwrap();
    // open считывает и индексирует; на мусоре tar отдаёт 0 записей либо ошибку.
    if let Ok(mut ar) = h.open(src, &OpenOptions::default()) {
        let entries = ar.entries().unwrap();
        assert!(entries.is_empty());
    }
}
