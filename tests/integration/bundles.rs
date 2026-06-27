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
fn apk_reports_apk_and_extracts() {
    let mut reader = open(&fixture("app.apk"), &OpenOptions::default()).expect("open apk");
    assert_eq!(reader.format(), FormatId::Apk);
    assert_eq!(body_of(reader.as_mut(), "classes.dex"), b"hello apk\n");
}

#[test]
fn epub_reports_epub_and_extracts() {
    let mut reader = open(&fixture("book.epub"), &OpenOptions::default()).expect("open epub");
    assert_eq!(reader.format(), FormatId::Epub);
    assert_eq!(body_of(reader.as_mut(), "OEBPS/ch1.html"), b"hello epub\n");
}

#[test]
fn docx_reports_docx_and_extracts() {
    let mut reader = open(&fixture("doc.docx"), &OpenOptions::default()).expect("open docx");
    assert_eq!(reader.format(), FormatId::Docx);
    assert_eq!(
        body_of(reader.as_mut(), "word/document.xml"),
        b"hello docx\n"
    );
}
