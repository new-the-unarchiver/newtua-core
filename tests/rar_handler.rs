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

// meta.rar: self-generated archive with known unix mode.
// Created with:
//   printf 'x' > f.txt && chmod 0755 f.txt
//   rar a meta.rar f.txt && rm f.txt
// (RAR 7.22, Host OS: Unix, Attributes: -rwxr-xr-x)
// file_attr = 0o100755 (full POSIX st_mode); file_attr & 0o7777 = 0o755.
const META_FIXTURE: &[u8] = include_bytes!("fixtures/meta.rar");

#[test]
fn rar_populates_mode_when_available() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), META_FIXTURE).unwrap();
    let src = Source::path(tmp.path()).unwrap();
    let mut ar = RarHandler.open(src, &OpenOptions::default()).unwrap();
    let entries = ar.entries().unwrap().to_vec();
    let f = entries
        .iter()
        .find(|e| e.path.to_str() == Some("f.txt"))
        .expect("f.txt not found in meta.rar");
    // The unrar crate exposes file_attr: u32 on FileHeader.
    // For Unix-created RARs, file_attr is the full POSIX st_mode (e.g. 0o100755).
    // We detect Unix attributes by checking the file-type nibble (S_IFREG/S_IFDIR/S_IFLNK),
    // then mask with 0o7777 to get permission bits only.
    assert_eq!(f.mode, Some(0o755));
}

// secret.rar: self-generated data-encrypted archive, password "pw".
// Created with: printf 'hello rar' > a.txt && rar a -ppw secret.rar a.txt && rm a.txt
// (RAR 7.22 no longer supports -ma4; produces RAR5 data-encrypted archive.)
// The archive lists without a password; extraction with a wrong password errors.
const ENC_FIXTURE: &[u8] = include_bytes!("fixtures/secret.rar");

#[test]
fn wrong_password_errors() {
    use newtua_core::Error;
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), ENC_FIXTURE).unwrap();
    let src = Source::path(tmp.path()).unwrap();
    let opts = OpenOptions {
        password: Some("WRONG".into()),
        encoding_override: None,
    };
    let mut ar = RarHandler.open(src, &opts).unwrap();
    ar.entries().unwrap();
    let mut out = Vec::new();
    let err = ar.read_entry(0, &mut out).unwrap_err();
    assert!(matches!(
        err,
        Error::WrongPassword | Error::Encrypted | Error::Corrupt(_)
    ));
}
