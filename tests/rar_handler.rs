use newtua_core::format::RarHandler;
use newtua_core::{FormatHandler, OpenOptions, Source};

const FIXTURE: &[u8] = include_bytes!("fixtures/hello.rar");

#[test]
fn lists_and_extracts_rar() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), FIXTURE).unwrap();
    let src = Source::path(tmp.path()).unwrap();
    let mut ar = RarHandler.open(src, &OpenOptions::default()).unwrap();
    let entries = ar.entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path.to_str().unwrap(), "a.txt");
    let mut out = Vec::new();
    ar.read_entry(0, &mut out).unwrap();
    assert_eq!(out, b"hello rar");
}

const ENC_FIXTURE: &[u8] = include_bytes!("fixtures/secret.rar");

#[test]
fn wrong_password_errors() {
    use newtua_core::Error;
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), ENC_FIXTURE).unwrap();
    let src = Source::path(tmp.path()).unwrap();
    let opts = OpenOptions { password: Some("WRONG".into()), encoding_override: None };
    let mut ar = RarHandler.open(src, &opts).unwrap();
    ar.entries().unwrap();
    let mut out = Vec::new();
    let err = ar.read_entry(0, &mut out).unwrap_err();
    assert!(matches!(err, Error::WrongPassword | Error::Encrypted | Error::Corrupt(_)));
}
