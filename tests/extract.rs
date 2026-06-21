use newtua_core::{ExtractOptions, OpenOptions, extract_all, open};
use std::io::Write;
use std::time::{Duration, SystemTime};

fn e(path: &str, is_dir: bool) -> newtua_core::Entry {
    newtua_core::Entry {
        path_raw: path.as_bytes().to_vec(),
        path: std::path::PathBuf::from(path),
        kind: if is_dir {
            newtua_core::EntryKind::Dir
        } else {
            newtua_core::EntryKind::File
        },
        size: 0,
        mode: None,
        is_encrypted: false,
        modified: None,
    }
}

fn make_zip(entries: &[(&str, &[u8])]) -> tempfile::NamedTempFile {
    let tmp = tempfile::Builder::new().suffix(".zip").tempfile().unwrap();
    let mut w = zip::ZipWriter::new(std::fs::File::create(tmp.path()).unwrap());
    for (name, data) in entries {
        let o: zip::write::FileOptions<()> = zip::write::FileOptions::default();
        w.start_file(*name, o).unwrap();
        w.write_all(data).unwrap();
    }
    w.finish().unwrap();
    tmp
}

#[test]
fn extracts_files_to_dest() {
    let zip = make_zip(&[("root/a.txt", b"A"), ("root/b.txt", b"B")]);
    let dest = tempfile::tempdir().unwrap();
    let mut ar = open(zip.path(), &OpenOptions::default()).unwrap();
    let report = extract_all(
        &mut *ar,
        &ExtractOptions {
            dest: dest.path().to_path_buf(),
            wrapper_name: Some("arc".into()),
            strict: false,
            preserve: true,
        },
    )
    .unwrap();
    assert_eq!(report.extracted, 2);
    // единый общий корень "root" → без обёртки
    assert!(!report.wrapped);
    assert_eq!(std::fs::read(dest.path().join("root/a.txt")).unwrap(), b"A");
    assert_eq!(std::fs::read(dest.path().join("root/b.txt")).unwrap(), b"B");
}

#[test]
fn wraps_when_no_common_root() {
    let zip = make_zip(&[("a.txt", b"A"), ("b.txt", b"B")]);
    let dest = tempfile::tempdir().unwrap();
    let mut ar = open(zip.path(), &OpenOptions::default()).unwrap();
    let report = extract_all(
        &mut *ar,
        &ExtractOptions {
            dest: dest.path().to_path_buf(),
            wrapper_name: Some("myarc".into()),
            strict: false,
            preserve: true,
        },
    )
    .unwrap();
    assert!(report.wrapped);
    assert_eq!(report.extracted, 2);
    // содержимое внутри обёртки myarc/
    assert_eq!(
        std::fs::read(dest.path().join("myarc/a.txt")).unwrap(),
        b"A"
    );
    assert_eq!(
        std::fs::read(dest.path().join("myarc/b.txt")).unwrap(),
        b"B"
    );
}

#[test]
fn common_root_detected() {
    use newtua_core::common_root;
    let zip = make_zip(&[("top/a", b"1"), ("top/b", b"2")]);
    let mut ar = open(zip.path(), &OpenOptions::default()).unwrap();
    let entries = ar.entries().unwrap();
    assert_eq!(common_root(entries), Some("top".to_string()));
}

#[test]
fn no_common_root_when_mixed() {
    use newtua_core::common_root;
    let zip = make_zip(&[("a/x", b"1"), ("b/y", b"2")]);
    let mut ar = open(zip.path(), &OpenOptions::default()).unwrap();
    assert_eq!(common_root(ar.entries().unwrap()), None);
}

#[test]
fn zip_slip_entry_is_skipped_in_non_strict() {
    // Архив с вредоносным путём ../evil.txt
    let tmp = tempfile::Builder::new().suffix(".zip").tempfile().unwrap();
    {
        let mut w = zip::ZipWriter::new(std::fs::File::create(tmp.path()).unwrap());
        let o: zip::write::FileOptions<()> = zip::write::FileOptions::default();
        w.start_file("../evil.txt", o).unwrap();
        w.write_all(b"pwn").unwrap();
        w.finish().unwrap();
    }
    let dest = tempfile::tempdir().unwrap();
    let mut ar = open(tmp.path(), &OpenOptions::default()).unwrap();
    let report = extract_all(
        &mut *ar,
        &ExtractOptions {
            dest: dest.path().to_path_buf(),
            wrapper_name: None,
            strict: false,
            preserve: true,
        },
    )
    .unwrap();
    assert_eq!(report.extracted, 0);
    assert_eq!(report.failed.len(), 1);
    // файл за пределами dest не создан
    assert!(!dest.path().parent().unwrap().join("evil.txt").exists());
}

#[test]
fn strict_aborts_on_zip_slip() {
    use newtua_core::Error;
    let tmp = tempfile::Builder::new().suffix(".zip").tempfile().unwrap();
    {
        let mut w = zip::ZipWriter::new(std::fs::File::create(tmp.path()).unwrap());
        let o: zip::write::FileOptions<()> = zip::write::FileOptions::default();
        w.start_file("../evil.txt", o).unwrap();
        w.write_all(b"pwn").unwrap();
        w.finish().unwrap();
    }
    let dest = tempfile::tempdir().unwrap();
    let mut ar = open(tmp.path(), &OpenOptions::default()).unwrap();
    let err = extract_all(
        &mut *ar,
        &ExtractOptions {
            dest: dest.path().to_path_buf(),
            wrapper_name: None,
            strict: true,
            preserve: true,
        },
    )
    .unwrap_err();
    assert!(matches!(err, Error::PathTraversal(_)));
}

#[test]
fn common_root_with_explicit_dir_entry() {
    use newtua_core::common_root;
    let entries = vec![
        e("root", true),
        e("root/a.txt", false),
        e("root/b.txt", false),
    ];
    assert_eq!(common_root(&entries), Some("root".to_string()));
}

#[test]
fn common_root_single_file_is_none() {
    use newtua_core::common_root;
    let entries = vec![e("s.txt", false)];
    assert_eq!(common_root(&entries), None);
}

#[test]
fn common_root_single_nested_file() {
    use newtua_core::common_root;
    let entries = vec![e("root/a.txt", false)];
    assert_eq!(common_root(&entries), Some("root".to_string()));
}

#[test]
fn common_root_single_bare_dir() {
    use newtua_core::common_root;
    let entries = vec![e("root", true)];
    assert_eq!(common_root(&entries), Some("root".to_string()));
}

#[test]
fn restores_file_mtime_by_default() {
    // tar with a known mtime on a file under a common root (no wrapper)
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let known = 1_600_000_000u64; // 2020-09-13
    {
        let mut b = tar::Builder::new(std::fs::File::create(tmp.path()).unwrap());
        let data = b"x";
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_mtime(known);
        h.set_cksum();
        b.append_data(&mut h, "root/a.txt", &data[..]).unwrap();
        let mut h2 = tar::Header::new_gnu();
        h2.set_size(1);
        h2.set_mode(0o644);
        h2.set_mtime(known);
        h2.set_cksum();
        b.append_data(&mut h2, "root/b.txt", &b"y"[..]).unwrap();
        b.finish().unwrap();
    }
    let dest = tempfile::tempdir().unwrap();
    let mut ar = newtua_core::open(tmp.path(), &newtua_core::OpenOptions::default()).unwrap();
    newtua_core::extract_all(&mut *ar, &newtua_core::ExtractOptions {
        dest: dest.path().to_path_buf(), wrapper_name: None, strict: false, preserve: true,
    }).unwrap();

    let meta = std::fs::metadata(dest.path().join("root/a.txt")).unwrap();
    let mtime = meta.modified().unwrap();
    let expected = SystemTime::UNIX_EPOCH + Duration::from_secs(known);
    let diff = mtime.duration_since(expected).or_else(|_| expected.duration_since(mtime)).unwrap();
    assert!(diff < Duration::from_secs(2), "mtime not restored: {diff:?}");
}

#[test]
fn no_preserve_skips_mtime() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let known = 1_600_000_000u64;
    {
        let mut b = tar::Builder::new(std::fs::File::create(tmp.path()).unwrap());
        let mut h = tar::Header::new_gnu();
        h.set_size(1); h.set_mode(0o644); h.set_mtime(known); h.set_cksum();
        b.append_data(&mut h, "root/a.txt", &b"x"[..]).unwrap();
        let mut h2 = tar::Header::new_gnu();
        h2.set_size(1); h2.set_mode(0o644); h2.set_mtime(known); h2.set_cksum();
        b.append_data(&mut h2, "root/b.txt", &b"y"[..]).unwrap();
        b.finish().unwrap();
    }
    let dest = tempfile::tempdir().unwrap();
    let mut ar = newtua_core::open(tmp.path(), &newtua_core::OpenOptions::default()).unwrap();
    newtua_core::extract_all(&mut *ar, &newtua_core::ExtractOptions {
        dest: dest.path().to_path_buf(), wrapper_name: None, strict: false, preserve: false,
    }).unwrap();
    let mtime = std::fs::metadata(dest.path().join("root/a.txt")).unwrap().modified().unwrap();
    let expected = SystemTime::UNIX_EPOCH + Duration::from_secs(known);
    // With preserve=false the file keeps "now", far from 2020.
    assert!(mtime.duration_since(expected).unwrap() > Duration::from_secs(60 * 60 * 24));
}
