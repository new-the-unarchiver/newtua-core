use newtua_core::archive::{FormatId, OpenOptions};
use newtua_core::detect::open;
use std::path::Path;

fn fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn body_of(reader: &mut dyn newtua_core::archive::ArchiveReader, name: &str) -> Vec<u8> {
    let idx = {
        let entries = reader.entries().expect("entries");
        entries
            .iter()
            .position(|e| e.path.to_string_lossy() == name)
            .unwrap_or_else(|| panic!("entry {name} not found"))
    };
    let mut body = Vec::new();
    reader.read_entry(idx, &mut body).expect("read_entry");
    body
}

#[test]
fn conda_reports_conda_and_lists_inner_files() {
    let mut reader = open(&fixture("pkg.conda"), &OpenOptions::default()).expect("open conda");
    assert_eq!(reader.format(), FormatId::Conda);
    let names: Vec<String> = reader
        .entries()
        .expect("entries")
        .iter()
        .map(|e| e.path.to_string_lossy().into_owned())
        .collect();
    // Виден файл из pkg-члена и файл из info-члена; самих *.tar.zst и
    // metadata.json среди записей нет.
    assert!(
        names
            .iter()
            .any(|n| n == "lib/python3.12/site-packages/foo/__init__.py")
    );
    assert!(names.iter().any(|n| n == "info/index.json"));
    assert!(!names.iter().any(|n| n.ends_with(".tar.zst")));
    assert!(!names.iter().any(|n| n == "metadata.json"));
}

#[test]
fn conda_extracts_pkg_file() {
    let mut reader = open(&fixture("pkg.conda"), &OpenOptions::default()).expect("open conda");
    assert_eq!(
        body_of(
            reader.as_mut(),
            "lib/python3.12/site-packages/foo/__init__.py"
        ),
        b"print('hi from foo')\n"
    );
}

#[test]
fn conda_extracts_info_file() {
    let mut reader = open(&fixture("pkg.conda"), &OpenOptions::default()).expect("open conda");
    assert_eq!(
        body_of(reader.as_mut(), "info/index.json"),
        b"{\"name\": \"foo\", \"version\": \"1.0\"}\n"
    );
}

#[test]
fn conda_without_tar_zst_is_corrupt() {
    let result = open(&fixture("notar.conda"), &OpenOptions::default());
    assert!(
        matches!(result, Err(newtua_core::error::Error::Corrupt(_))),
        "expected Err(Corrupt), got something else"
    );
}
