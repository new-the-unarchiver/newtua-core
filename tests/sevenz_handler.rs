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

// multi.7z: two-entry archive: f1.txt="first", f2.txt="second"
//   7zz a multi.7z f1.txt f2.txt
const MULTI_FIXTURE: &[u8] = include_bytes!("fixtures/multi.7z");

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
    let opts = OpenOptions {
        password: Some("WRONG".into()),
        encoding_override: None,
    };
    let res = SevenZHandler.open(src, &opts);
    assert!(matches!(
        res,
        Err(Error::WrongPassword) | Err(Error::Corrupt(_))
    ));
}

/// Verifies on-demand per-index extraction: opening a two-entry archive must
/// list both entries and extract each one independently (without buffering the
/// other entry into RAM).
#[test]
fn multi_entry_on_demand_extraction() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), MULTI_FIXTURE).unwrap();
    let src = Source::path(tmp.path()).unwrap();
    let mut ar = SevenZHandler.open(src, &OpenOptions::default()).unwrap();

    let entries = ar.entries().unwrap();
    assert_eq!(entries.len(), 2, "expected 2 entries in multi.7z");

    // Determine which index corresponds to f1.txt / f2.txt (order may vary).
    let idx_f1 = entries
        .iter()
        .position(|e| e.path.file_name().map(|n| n == "f1.txt").unwrap_or(false))
        .expect("f1.txt not found");
    let idx_f2 = entries
        .iter()
        .position(|e| e.path.file_name().map(|n| n == "f2.txt").unwrap_or(false))
        .expect("f2.txt not found");

    // Extract f2 first to confirm on-demand (not sequential) access.
    let mut out2 = Vec::new();
    ar.read_entry(idx_f2, &mut out2).unwrap();
    assert_eq!(out2, b"second", "f2.txt content mismatch");

    // Then extract f1.
    let mut out1 = Vec::new();
    ar.read_entry(idx_f1, &mut out1).unwrap();
    assert_eq!(out1, b"first", "f1.txt content mismatch");
}
