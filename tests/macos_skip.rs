use newtua_core::{ExtractOptions, OpenOptions, extract_all, open};
use std::io::Write;

fn make_zip(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("t.zip");
    let f = std::fs::File::create(&path).unwrap();
    let mut z = zip::ZipWriter::new(f);
    let opts: zip::write::FileOptions<()> = zip::write::FileOptions::default();
    for name in ["keep.txt", "._keep.txt", ".DS_Store"] {
        z.start_file(name, opts).unwrap();
        z.write_all(b"x").unwrap();
    }
    z.finish().unwrap();
    path
}

#[test]
fn extract_skips_macos_metadata_by_default() {
    let tmp = tempfile::tempdir().unwrap();
    let zip = make_zip(tmp.path());
    let out = tmp.path().join("out");
    let mut ar = open(&zip, &OpenOptions::default()).unwrap();
    let mut opts = ExtractOptions {
        dest: out.clone(),
        wrapper_name: None,
        strict: false,
        preserve: true,
        selection: None,
        progress: None,
        keep_macos_metadata: false,
    };
    let report = extract_all(&mut *ar, &mut opts).unwrap();
    assert_eq!(report.extracted, 1);
    assert!(out.join("keep.txt").exists());
    assert!(!out.join("._keep.txt").exists());
    assert!(!out.join(".DS_Store").exists());
}

#[test]
fn extract_keeps_macos_metadata_when_requested() {
    let tmp = tempfile::tempdir().unwrap();
    let zip = make_zip(tmp.path());
    let out = tmp.path().join("out");
    let mut ar = open(&zip, &OpenOptions::default()).unwrap();
    let mut opts = ExtractOptions {
        dest: out.clone(),
        wrapper_name: None,
        strict: false,
        preserve: true,
        selection: None,
        progress: None,
        keep_macos_metadata: true,
    };
    let report = extract_all(&mut *ar, &mut opts).unwrap();
    assert_eq!(report.extracted, 3);
    assert!(out.join("._keep.txt").exists());
}
