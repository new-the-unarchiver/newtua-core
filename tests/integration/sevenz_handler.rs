use newtua_core::format::SevenZHandler;
use newtua_core::{EntryKind, ExtractOptions, FormatHandler, OpenOptions, Source, extract_all};

// Fixture: pre-built 7z archive with one entry "a.txt" = "hello 7z".
const FIXTURE: &[u8] = include_bytes!("../fixtures/hello.7z");

// secret.7z MUST be created with header encryption enabled:
//   7zz a -ppw -mhe=on secret.7z a.txt
// Header encryption makes SevenZReader::new fail immediately on a wrong
// password. Without -mhe=on, sevenz-rust2 may return wrong data instead of
// an error, which would make the wrong-password test pass silently on bad output.
const ENC_FIXTURE: &[u8] = include_bytes!("../fixtures/secret.7z");

// multi.7z: two-entry archive: f1.txt="first", f2.txt="second"
//   7zz a multi.7z f1.txt f2.txt
const MULTI_FIXTURE: &[u8] = include_bytes!("../fixtures/multi.7z");

// secret_content.7z: CONTENT-only encryption (no -mhe), password "pw":
//   printf 'hello 7z' > a.txt && 7zz a -ppw secret_content.7z a.txt
// Header is plaintext, so open()/listing succeed without a password and the
// encrypted-extract guard must come from verify_password, not open().
const ENC_CONTENT_FIXTURE: &[u8] = include_bytes!("../fixtures/secret_content.7z");

#[test]
fn content_encrypted_lists_without_password() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), ENC_CONTENT_FIXTURE).unwrap();
    let src = Source::path(tmp.path()).unwrap();
    let mut ar = SevenZHandler.open(src, &OpenOptions::default()).unwrap();
    let entries = ar.entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].is_encrypted);
}

#[test]
fn content_encrypted_verify_without_password_is_encrypted() {
    use newtua_core::Error;
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), ENC_CONTENT_FIXTURE).unwrap();
    let src = Source::path(tmp.path()).unwrap();
    let mut ar = SevenZHandler.open(src, &OpenOptions::default()).unwrap();
    assert!(matches!(ar.verify_password(), Err(Error::Encrypted)));
}

#[test]
fn content_encrypted_verify_with_correct_password_is_ok() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), ENC_CONTENT_FIXTURE).unwrap();
    let src = Source::path(tmp.path()).unwrap();
    let opts = OpenOptions {
        password: Some("pw".into()),
        encoding_override: None,
    };
    let mut ar = SevenZHandler.open(src, &opts).unwrap();
    assert!(ar.verify_password().is_ok());
}

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

/// Opening an UNENCRYPTED archive with a spurious password must report
/// `is_encrypted == false` for every entry.  The old password-based hack
/// returned `true` here (regression test: RED before fix, GREEN after).
#[test]
fn unencrypted_archive_with_spurious_password_is_not_encrypted() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), FIXTURE).unwrap();
    let src = Source::path(tmp.path()).unwrap();
    let opts = OpenOptions {
        password: Some("spurious".into()),
        encoding_override: None,
    };
    let mut ar = SevenZHandler.open(src, &opts).unwrap();
    let entries = ar.entries().unwrap();
    assert!(!entries.is_empty());
    for entry in entries {
        assert!(
            !entry.is_encrypted,
            "plain archive entry must not be marked encrypted even when a password is supplied"
        );
    }
}

/// Opening an AES-encrypted archive (header-encrypted, -mhe=on) with the
/// correct password must report `is_encrypted == true` for every data entry.
#[test]
fn encrypted_archive_reports_is_encrypted_true() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), ENC_FIXTURE).unwrap();
    let src = Source::path(tmp.path()).unwrap();
    let opts = OpenOptions {
        password: Some("pw".into()),
        encoding_override: None,
    };
    let mut ar = SevenZHandler.open(src, &opts).unwrap();
    let entries = ar.entries().unwrap();
    assert!(!entries.is_empty());
    // Every entry in secret.7z is in an AES-encrypted folder.
    let data_entries: Vec<_> = entries.iter().filter(|e| !e.is_dir()).collect();
    assert!(!data_entries.is_empty(), "expected at least one file entry");
    for entry in data_entries {
        assert!(
            entry.is_encrypted,
            "encrypted archive entry must be marked encrypted"
        );
    }
}

/// Verifies that unix mode bits are extracted from 7z Windows attributes when the
/// unix-extension bit (0x8000) is set by the archiver (e.g. `7zz` on macOS/Linux).
/// The fixture meta.7z was built with `7zz a meta.7z f.txt` where `f.txt` had
/// mode 0755 — so `windows_attributes >> 16` should yield `0o100755` and the
/// permission bits `& 0o7777` should be `0o755`.
#[test]
fn sevenz_populates_mode_when_available() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), include_bytes!("../fixtures/meta.7z")).unwrap();
    let src = Source::path(tmp.path()).unwrap();
    let mut ar = SevenZHandler.open(src, &OpenOptions::default()).unwrap();
    let entries = ar.entries().unwrap().to_vec();
    let f = entries
        .iter()
        .find(|e| e.path.to_str() == Some("f.txt"))
        .unwrap();
    assert_eq!(f.mode, Some(0o755));
}

/// Verifies that the symlink entry in symlink.7z has its target populated at
/// listing time (open() reads the symlink content and sets the real target).
#[cfg(unix)]
#[test]
fn sevenz_symlink_target_populated() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), include_bytes!("../fixtures/symlink.7z")).unwrap();
    let src = Source::path(tmp.path()).unwrap();
    let mut ar = SevenZHandler.open(src, &OpenOptions::default()).unwrap();
    let entries = ar.entries().unwrap();
    let slink = entries
        .iter()
        .find(|e| e.path.file_name().map(|n| n == "slink").unwrap_or(false))
        .expect("entry 'slink' not found in symlink.7z");
    assert_eq!(
        slink.kind,
        EntryKind::Symlink {
            target: std::path::PathBuf::from("target.txt"),
        },
        "symlink target must be 'target.txt', got {:?}",
        slink.kind
    );
}

/// Verifies that extracting symlink.7z creates a real on-disk symlink pointing
/// to "target.txt" (end-to-end: open -> entries -> extract_all -> read_link).
#[cfg(unix)]
#[test]
fn sevenz_symlink_extracted_correctly() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), include_bytes!("../fixtures/symlink.7z")).unwrap();
    let src = Source::path(tmp.path()).unwrap();
    let mut ar = SevenZHandler.open(src, &OpenOptions::default()).unwrap();
    let dest = tempfile::tempdir().unwrap();
    extract_all(
        &mut *ar,
        &mut ExtractOptions {
            dest: dest.path().to_path_buf(),
            wrapper_name: None,
            strict: true,
            preserve: false,
            selection: None,
            progress: None,
            keep_macos_metadata: false,
        },
    )
    .unwrap();
    assert_eq!(
        std::fs::read_link(dest.path().join("slink")).unwrap(),
        std::path::PathBuf::from("target.txt"),
        "extracted symlink must point to 'target.txt'"
    );
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

// Regression (found by the fuzz harness): a 63-byte 7z with a malformed start
// header made sevenz-rust2 fall back to a tail-scan recovery and request a
// ~412 GB allocation, killing the process. Our start-header guard must reject
// it cleanly. If the guard regresses, this test OOMs/aborts instead of failing.
const MALFORMED_OOM_FIXTURE: &[u8] = include_bytes!("../fixtures/malformed_oom.7z");

#[test]
fn malformed_header_is_rejected_not_oom() {
    use newtua_core::Error;
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), MALFORMED_OOM_FIXTURE).unwrap();
    let src = Source::path(tmp.path()).unwrap();
    match SevenZHandler.open(src, &OpenOptions::default()) {
        Ok(_) => panic!("malformed 7z must be rejected, not opened"),
        Err(Error::Corrupt(_)) => {}
        Err(e) => panic!("expected Corrupt, got {e:?}"),
    }
}
