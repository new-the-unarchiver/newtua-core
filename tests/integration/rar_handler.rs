use newtua_core::format::RarHandler;
use newtua_core::{FormatHandler, OpenOptions, Source};
use std::path::Path;

const FIXTURE: &[u8] = include_bytes!("../fixtures/hello.rar");

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
const META_FIXTURE: &[u8] = include_bytes!("../fixtures/meta.rar");

#[test]
fn rar_populates_mode_when_available() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), META_FIXTURE).unwrap();
    let src = Source::path(tmp.path()).unwrap();
    let mut ar = RarHandler.open(src, &OpenOptions::default()).unwrap();
    let entries = ar.entries().unwrap().to_vec();
    let f = entries
        .iter()
        .find(|e| e.path == Path::new("f.txt"))
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
const ENC_FIXTURE: &[u8] = include_bytes!("../fixtures/secret.rar");

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

#[test]
fn verify_password_without_password_is_encrypted() {
    use newtua_core::Error;
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), ENC_FIXTURE).unwrap();
    let src = Source::path(tmp.path()).unwrap();
    let mut ar = RarHandler.open(src, &OpenOptions::default()).unwrap();
    // Listing works without a password; the guard comes from verify_password.
    ar.entries().unwrap();
    assert!(matches!(ar.verify_password(), Err(Error::Encrypted)));
}

#[test]
fn verify_password_with_wrong_password_errors() {
    use newtua_core::Error;
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), ENC_FIXTURE).unwrap();
    let src = Source::path(tmp.path()).unwrap();
    let opts = OpenOptions {
        password: Some("WRONG".into()),
        encoding_override: None,
    };
    let mut ar = RarHandler.open(src, &opts).unwrap();
    assert!(matches!(
        ar.verify_password(),
        Err(Error::WrongPassword) | Err(Error::Encrypted) | Err(Error::Corrupt(_))
    ));
}

#[test]
fn verify_password_with_correct_password_is_ok() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), ENC_FIXTURE).unwrap();
    let src = Source::path(tmp.path()).unwrap();
    let opts = OpenOptions {
        password: Some("pw".into()),
        encoding_override: None,
    };
    let mut ar = RarHandler.open(src, &opts).unwrap();
    assert!(ar.verify_password().is_ok());
}

// ── Timestamps ───────────────────────────────────────────────────────────────

/// RAR's date reaches the entry, read as local time.
///
/// `meta.rar` stores the packed MS-DOS pair `0x5CD538A6` — 2026-06-21 07:05:12
/// on the wall, with no timezone attached, exactly like zip's identical field.
/// So the instant depends on the machine running the test, and the assertions
/// are stated in a way that does not: the wall clock has to land within a
/// plausible zone offset of its UTC reading, and the seconds have to stay even.
///
/// `unar` reports 02:05:13Z for the same file — one second later — because RAR 5
/// *also* stores an exact instant, which the DOS field cannot express and which
/// we cannot reach; see the note in `format/rar.rs`.
#[test]
fn rar_reports_the_stored_modification_time_as_local() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), META_FIXTURE).unwrap();
    let src = Source::path(tmp.path()).unwrap();
    let mut ar = RarHandler.open(src, &OpenOptions::default()).unwrap();
    let e = &ar.entries().unwrap()[0];

    let secs = e
        .modified
        .expect("meta.rar carries a timestamp")
        .duration_since(std::time::UNIX_EPOCH)
        .expect("post-epoch")
        .as_secs();

    // 2026-06-21T07:05:12Z — the wall clock read as if it were UTC. A real
    // timezone moves this by at most fourteen hours in either direction.
    let wall_as_utc: i64 = 1_782_025_512;
    let offset = wall_as_utc - secs as i64;
    assert!(
        offset.abs() <= 14 * 3600,
        "expected the stored wall clock read locally; off by {offset} s"
    );
    assert_eq!(
        secs % 2,
        0,
        "the DOS field resolves to two seconds, so an odd second means a bug"
    );
}
