use newtua_core::{ExtractOptions, OpenOptions, extract_all, open};
use std::io::Write;

fn zip_three() -> tempfile::NamedTempFile {
    let tmp = tempfile::Builder::new().suffix(".zip").tempfile().unwrap();
    let mut w = zip::ZipWriter::new(std::fs::File::create(tmp.path()).unwrap());
    let o: zip::write::FileOptions<()> = zip::write::FileOptions::default();
    for (name, body) in [
        ("root/a.txt", b"aaaa".as_slice()),
        ("root/b.txt", b"bb"),
        ("root/c.txt", b"ccc"),
    ] {
        w.start_file(name, o).unwrap();
        w.write_all(body).unwrap();
    }
    w.finish().unwrap();
    tmp
}

#[test]
fn selection_extracts_only_chosen_indices() {
    let zip = zip_three();
    let dest = tempfile::tempdir().unwrap();
    let mut ar = open(zip.path(), &OpenOptions::default()).unwrap();
    // entries() order matches insertion: 0=a, 1=b, 2=c. Select a and c.
    let mut opts = ExtractOptions {
        dest: dest.path().to_path_buf(),
        wrapper_name: None,
        strict: false,
        preserve: true,
        selection: Some(vec![0, 2]),
        progress: None,
    };
    let report = extract_all(&mut *ar, &mut opts).unwrap();
    assert_eq!(report.extracted, 2);
    assert!(dest.path().join("root/a.txt").exists());
    assert!(!dest.path().join("root/b.txt").exists());
    assert!(dest.path().join("root/c.txt").exists());
}

#[test]
fn empty_selection_extracts_nothing() {
    let zip = zip_three();
    let dest = tempfile::tempdir().unwrap();
    let mut ar = open(zip.path(), &OpenOptions::default()).unwrap();
    let mut opts = ExtractOptions {
        dest: dest.path().to_path_buf(),
        wrapper_name: None,
        strict: false,
        preserve: true,
        selection: Some(vec![]),
        progress: None,
    };
    let report = extract_all(&mut *ar, &mut opts).unwrap();
    assert_eq!(report.extracted, 0);
    assert!(!dest.path().join("root").exists());
}
