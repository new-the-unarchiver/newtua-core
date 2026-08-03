use newtua_core::format::SevenZHandler;
use newtua_core::{FormatHandler, OpenOptions, Source};
// Used only by the symlink tests below, which are Unix-only.
#[cfg(unix)]
use newtua_core::{EntryKind, ExtractOptions, extract_all};
use std::path::Path;

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
        .find(|e| e.path == Path::new("f.txt"))
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
        .find(|e| e.path.file_name() == Some(Path::new("slink").as_os_str()))
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
        .position(|e| e.path.file_name() == Some(Path::new("f1.txt").as_os_str()))
        .expect("f1.txt not found");
    let idx_f2 = entries
        .iter()
        .position(|e| e.path.file_name() == Some(Path::new("f2.txt").as_os_str()))
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

// no_stream_entries.7z: эталон из корпуса, собранный настоящим упаковщиком.
// Внутри — два каталога (записи БЕЗ потока данных) и четыре файла:
//   nested/, nested/deep/, hello.txt, привет.txt, nested/deep/tiny.bin, big.txt
// Именно записи без потока ломали выбор по позиции: `for_each_entries` отдаёт
// сперва файлы с данными, потом каталоги, а заголовок хранит другой порядок.
// Регрессия D1: в big.txt попадало содержимое tiny.bin, в hello.txt —
// содержимое привет.txt, и всё это БЕЗ ошибки.
const NO_STREAM_FIXTURE: &[u8] = include_bytes!("../fixtures/no_stream_entries.7z");

/// sha256 в виде строки — сверяем содержимое, а не только имена и количество:
/// проверка «записей столько, ошибок нет» этот дефект и пропустила в релиз.
fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

// Путь внутри архива, размер, sha256 содержимого.
const NO_STREAM_EXPECTED: &[(&str, usize, &str)] = &[
    (
        "hello.txt",
        15,
        "d8bfbcfd8b1bce61f3abbd65de37d13f354e2c73c7a6d5f362353317c2ffce42",
    ),
    (
        "привет.txt",
        22,
        "f509c862e2613c56f3b322e4b080e013ece8259a549ffd81113a335b67a840ca",
    ),
    (
        "nested/deep/tiny.bin",
        256,
        "1455fb514dcd6af818919b765a99cbebf7d91d7994341cc1d4f350ecc65e0a36",
    ),
    (
        "big.txt",
        65_529,
        "df1515a6fad9ce2f8141ff97f1e14ca7873ca48e50a95185efd64a55df216bec",
    ),
];

/// Главный тест дефекта D1: содержимое КАЖДОГО файла эталона должно совпасть
/// побайтно (сверяем sha256), когда в архиве есть записи без потока данных.
#[test]
fn no_stream_entries_read_entry_returns_own_content() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), NO_STREAM_FIXTURE).unwrap();
    let src = Source::path(tmp.path()).unwrap();
    let mut ar = SevenZHandler.open(src, &OpenOptions::default()).unwrap();

    let entries = ar.entries().unwrap().to_vec();
    assert_eq!(entries.len(), 6, "ожидались 4 файла и 2 каталога");

    for (path, size, sha) in NO_STREAM_EXPECTED {
        let idx = entries
            .iter()
            .position(|e| e.path == Path::new(path))
            .unwrap_or_else(|| panic!("запись {path} не найдена"));
        assert_eq!(entries[idx].size, *size as u64, "{path}: размер в описи");

        let mut out = Vec::new();
        ar.read_entry(idx, &mut out).unwrap();
        assert_eq!(out.len(), *size, "{path}: прочитано байт");
        assert_eq!(
            sha256_hex(&out),
            *sha,
            "{path}: прочитано содержимое ДРУГОЙ записи"
        );
    }

    // Каталоги остаются каталогами и не приносят чужих байтов.
    for dir in ["nested", "nested/deep"] {
        let e = entries
            .iter()
            .find(|e| e.path == Path::new(dir))
            .unwrap_or_else(|| panic!("каталог {dir} не найден"));
        assert!(e.is_dir(), "{dir} должен быть каталогом");
    }
}

/// То же самое, но через полную распаковку на диск: то, что попадает в файлы,
/// обязано совпадать с эталоном — именно этот путь и подменял данные молча.
#[cfg(unix)]
#[test]
fn no_stream_entries_extract_all_writes_correct_content() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), NO_STREAM_FIXTURE).unwrap();
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

    for (path, size, sha) in NO_STREAM_EXPECTED {
        let on_disk = dest.path().join(path);
        let data = std::fs::read(&on_disk)
            .unwrap_or_else(|e| panic!("{path} не распакован: {e} ({on_disk:?})"));
        assert_eq!(data.len(), *size, "{path}: размер на диске");
        assert_eq!(sha256_hex(&data), *sha, "{path}: на диск легли чужие байты");
    }
    assert!(dest.path().join("nested/deep").is_dir());
}

/// Символьная ссылка ищется тем же ключом. В symlink.7z записей без потока нет,
/// поэтому сама по себе она не ломалась, — тест закрепляет, что переход на поиск
/// по имени её не сломал: цель читается у ссылки, а не у соседней записи.
#[cfg(unix)]
#[test]
fn symlink_target_read_by_name_not_position() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), include_bytes!("../fixtures/symlink.7z")).unwrap();
    let src = Source::path(tmp.path()).unwrap();
    let mut ar = SevenZHandler.open(src, &OpenOptions::default()).unwrap();
    let entries = ar.entries().unwrap().to_vec();

    let slink = entries
        .iter()
        .find(|e| e.path == Path::new("slink"))
        .expect("slink не найден");
    assert_eq!(
        slink.kind,
        EntryKind::Symlink {
            target: std::path::PathBuf::from("target.txt"),
        }
    );

    // И обычный сосед по архиву читается своим содержимым, а не содержимым ссылки.
    let idx = entries
        .iter()
        .position(|e| e.path == Path::new("target.txt"))
        .expect("target.txt не найден");
    let mut out = Vec::new();
    ar.read_entry(idx, &mut out).unwrap();
    assert_eq!(out.len() as u64, entries[idx].size);
    assert_ne!(out, b"target.txt", "прочитано тело ссылки вместо файла");
}

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

// ── Timestamps ───────────────────────────────────────────────────────────────

const META_FIXTURE: &[u8] = include_bytes!("../fixtures/meta.7z");

fn open_meta() -> Box<dyn newtua_core::ArchiveReader> {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), META_FIXTURE).unwrap();
    let src = Source::path(tmp.path()).unwrap();
    SevenZHandler.open(src, &OpenOptions::default()).unwrap()
}

/// 7z stores the modification time as a Windows FILETIME — an absolute instant,
/// so this is the same answer in any timezone. `unar` extracts `meta.7z` to a
/// file stamped 2026-06-21 01:45:04 UTC; we must agree to the second.
#[test]
fn sevenz_reports_the_stored_modification_time() {
    let mut ar = open_meta();
    let e = &ar.entries().unwrap()[0];
    let secs = e
        .modified
        .expect("meta.7z carries a timestamp")
        .duration_since(std::time::UNIX_EPOCH)
        .expect("post-epoch")
        .as_secs();
    assert_eq!(secs, 1_782_006_304, "2026-06-21T01:45:04Z expected");
}

/// The flag matters: in 7z the timestamp is optional, and the raw field of an
/// entry that carries none reads as the year 1601, not as "unknown". A file
/// stamped 1601 is worse than one with no date at all, so an entry without the
/// flag must report `None` — never an instant from before the archive format
/// existed.
#[test]
fn sevenz_never_reports_the_filetime_zero_point() {
    for fixture in [META_FIXTURE, FIXTURE] {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), fixture).unwrap();
        let src = Source::path(tmp.path()).unwrap();
        let mut ar = SevenZHandler.open(src, &OpenOptions::default()).unwrap();
        for e in ar.entries().unwrap() {
            if let Some(t) = e.modified {
                let secs = t
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("no entry may predate the Unix epoch")
                    .as_secs();
                assert!(
                    secs > 946_684_800,
                    "{:?}: {secs} looks like the FILETIME zero point leaking out",
                    e.path
                );
            }
        }
    }
}
