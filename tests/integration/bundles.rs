//! Zip-бандлы: одно и то же содержимое, разный рапортуемый подтип.
//!
//! Фикстуры `webapp.war` / `app.appx` / `ext.xpi` / `plain.zip` порождены так:
//!
//! ```sh
//! mkdir -p war/WEB-INF appx xpi plain
//! printf 'hello war\n'  > war/WEB-INF/web.xml
//! printf 'hello appx\n' > appx/AppxManifest.xml
//! printf 'hello xpi\n'  > xpi/manifest.json
//! printf 'hello zip\n'  > plain/a.txt
//! (cd war  && zip -q -X -r ../webapp.war WEB-INF)
//! (cd appx && zip -q -X ../app.appx AppxManifest.xml)
//! (cd xpi  && zip -q -X ../ext.xpi manifest.json)
//! (cd plain && zip -q -X ../plain.zip a.txt)
//! ```

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
            .position(|e| e.path == Path::new(name))
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

#[test]
fn war_reports_war_and_extracts() {
    let mut reader = open(&fixture("webapp.war"), &OpenOptions::default()).expect("open war");
    assert_eq!(reader.format(), FormatId::War);
    assert_eq!(body_of(reader.as_mut(), "WEB-INF/web.xml"), b"hello war\n");
}

#[test]
fn appx_reports_appx_and_extracts() {
    let mut reader = open(&fixture("app.appx"), &OpenOptions::default()).expect("open appx");
    assert_eq!(reader.format(), FormatId::Appx);
    assert_eq!(
        body_of(reader.as_mut(), "AppxManifest.xml"),
        b"hello appx\n"
    );
}

#[test]
fn xpi_reports_xpi_and_extracts() {
    let mut reader = open(&fixture("ext.xpi"), &OpenOptions::default()).expect("open xpi");
    assert_eq!(reader.format(), FormatId::Xpi);
    assert_eq!(body_of(reader.as_mut(), "manifest.json"), b"hello xpi\n");
}

/// Защита от перехвата: новые строки таблицы бандлов не должны утаскивать
/// обычный `.zip` в чужой подтип.
#[test]
fn plain_zip_still_reports_zip() {
    let mut reader = open(&fixture("plain.zip"), &OpenOptions::default()).expect("open zip");
    assert_eq!(reader.format(), FormatId::Zip);
    assert_eq!(body_of(reader.as_mut(), "a.txt"), b"hello zip\n");
}

#[test]
fn crx3_reports_crx_and_extracts() {
    let mut reader = open(&fixture("ext.crx"), &OpenOptions::default()).expect("open crx3");
    assert_eq!(reader.format(), FormatId::Crx);
    assert_eq!(body_of(reader.as_mut(), "background.js"), b"hello crx\n");
}

#[test]
fn crx2_reports_crx_and_extracts() {
    let mut reader = open(&fixture("ext2.crx"), &OpenOptions::default()).expect("open crx2");
    assert_eq!(reader.format(), FormatId::Crx);
    assert_eq!(body_of(reader.as_mut(), "background.js"), b"hello crx\n");
}
