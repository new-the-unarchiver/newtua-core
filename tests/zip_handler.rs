use newtua_core::format::ZipHandler;
use newtua_core::{Error, FormatHandler, OpenOptions, Source};
use std::io::Write;

fn make_zip(password: Option<&str>) -> tempfile::NamedTempFile {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let file = std::fs::File::create(tmp.path()).unwrap();
    let mut w = zip::ZipWriter::new(file);
    let mut opts: zip::write::FileOptions<()> =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    if let Some(p) = password {
        opts = opts.with_aes_encryption(zip::AesMode::Aes256, p);
    }
    w.start_file("dir/a.txt", opts).unwrap();
    w.write_all(b"hello zip").unwrap();
    w.finish().unwrap();
    tmp
}

#[test]
fn lists_and_extracts_plain_zip() {
    let tmp = make_zip(None);
    let src = Source::path(tmp.path()).unwrap();
    let mut ar = ZipHandler.open(src, &OpenOptions::default()).unwrap();
    let entries = ar.entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path.to_str().unwrap(), "dir/a.txt");
    let mut out = Vec::new();
    ar.read_entry(0, &mut out).unwrap();
    assert_eq!(out, b"hello zip");
}

#[test]
fn encrypted_zip_requires_password() {
    let tmp = make_zip(Some("secret"));
    let src = Source::path(tmp.path()).unwrap();
    let mut ar = ZipHandler.open(src, &OpenOptions::default()).unwrap();
    ar.entries().unwrap();
    let mut out = Vec::new();
    let err = ar.read_entry(0, &mut out).unwrap_err();
    assert!(matches!(err, Error::Encrypted | Error::WrongPassword));
}

#[test]
fn encrypted_zip_extracts_with_password() {
    let tmp = make_zip(Some("secret"));
    let src = Source::path(tmp.path()).unwrap();
    let opts = OpenOptions { password: Some("secret".into()), encoding_override: None };
    let mut ar = ZipHandler.open(src, &opts).unwrap();
    ar.entries().unwrap();
    let mut out = Vec::new();
    ar.read_entry(0, &mut out).unwrap();
    assert_eq!(out, b"hello zip");
}

#[test]
fn wrong_password_reported() {
    let tmp = make_zip(Some("secret"));
    let src = Source::path(tmp.path()).unwrap();
    let opts = OpenOptions { password: Some("WRONG".into()), encoding_override: None };
    let mut ar = ZipHandler.open(src, &opts).unwrap();
    ar.entries().unwrap();
    let mut out = Vec::new();
    let err = ar.read_entry(0, &mut out).unwrap_err();
    assert!(matches!(err, Error::WrongPassword | Error::Encrypted));
}

#[test]
fn non_zip_open_errors() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), b"plain text").unwrap();
    let src = Source::path(tmp.path()).unwrap();
    assert!(ZipHandler.open(src, &OpenOptions::default()).is_err());
}
