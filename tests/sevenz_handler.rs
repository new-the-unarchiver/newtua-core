use newtua_core::format::SevenZHandler;
use newtua_core::{FormatHandler, OpenOptions, Source};

// Fixture: pre-built 7z archive with one entry "a.txt" = "hello 7z".
const FIXTURE: &[u8] = include_bytes!("fixtures/hello.7z");

// secret.7z MUST be created with header encryption enabled:
//   7zz a -ppw -mhe=on secret.7z a.txt
// Header encryption makes SevenZReader::new fail immediately on a wrong
// password. Without -mhe=on, sevenz-rust2 may return wrong data instead of
// an error, which would make the wrong-password test pass silently on bad output.
const ENC_FIXTURE: &[u8] = include_bytes!("fixtures/secret.7z");

#[test]
fn lists_and_extracts_7z() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), FIXTURE).unwrap();
    let src = Source::path(tmp.path()).unwrap();
    let mut ar = SevenZHandler.open(src, &OpenOptions::default()).unwrap();
    let entries = ar.entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path.to_str().unwrap(), "a.txt");
    let mut out = Vec::new();
    ar.read_entry(0, &mut out).unwrap();
    assert_eq!(out, b"hello 7z");
}

#[test]
fn wrong_password_errors() {
    use newtua_core::Error;
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), ENC_FIXTURE).unwrap();
    let src = Source::path(tmp.path()).unwrap();
    let opts = OpenOptions { password: Some("WRONG".into()), encoding_override: None };
    let res = SevenZHandler.open(src, &opts);
    assert!(matches!(res, Err(Error::WrongPassword) | Err(Error::Corrupt(_))));
}
