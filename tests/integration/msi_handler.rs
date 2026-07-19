//! Integration tests for the MSI installer format handler. Always compiled.
//!

use std::io::{Cursor, Write};
use std::path::Path;

use newtua_core::{OpenOptions, detect};

// ── Fixture helpers ────────────────────────────────────────────────────────────

/// Build a tiny uncompressed CAB in memory containing one file.
fn make_cab_bytes(file_name: &str, content: &[u8]) -> Vec<u8> {
    let buf = Cursor::new(Vec::<u8>::new());
    let mut builder = cab::CabinetBuilder::new();
    {
        let folder = builder.add_folder(cab::CompressionType::None);
        folder.add_file(file_name);
    }
    let mut cw = builder.build(buf).unwrap();
    if let Some(mut fw) = cw.next_file().unwrap() {
        fw.write_all(content).unwrap();
    }
    let cursor = cw.finish().unwrap();
    cursor.into_inner()
}

/// Create a minimal MSI fixture on disk.
///
/// The MSI has:
/// - A `Media` table with columns (DiskId PK int16, LastSequence int16,
///   DiskPrompt nullable text, Cabinet nullable text, VolumeLabel nullable
///   text, Source nullable text) — matching the real MSI Media table schema.
/// - One Media row: DiskId=1, LastSequence=1, Cabinet="#cabstream".
/// - A CFB binary stream named `cabstream` holding a valid CAB.
///
/// Returns a `NamedTempFile` so the MSI file stays alive for the test.
/// The standard MSI `Media`-table schema: DiskId (PK int16), LastSequence
/// (int16), DiskPrompt / Cabinet / VolumeLabel / Source (nullable strings).
fn media_columns() -> Vec<msi::Column> {
    vec![
        msi::Column::build("DiskId").primary_key().int16(),
        msi::Column::build("LastSequence").int16(),
        msi::Column::build("DiskPrompt").nullable().text_string(64),
        msi::Column::build("Cabinet").nullable().text_string(255),
        msi::Column::build("VolumeLabel").nullable().text_string(32),
        msi::Column::build("Source").nullable().id_string(72),
    ]
}

fn make_msi_fixture(file_name: &str, content: &[u8]) -> tempfile::NamedTempFile {
    let cab_bytes = make_cab_bytes(file_name, content);

    let tmp = tempfile::Builder::new()
        .suffix(".msi")
        .tempfile()
        .expect("create temp msi file");

    // We need a Read+Write+Seek backing. Open the temp file for RW.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(tmp.path())
        .expect("open temp msi file for rw");

    let mut package =
        msi::Package::create(msi::PackageType::Installer, file).expect("create msi package");

    package
        .create_table("Media", media_columns())
        .expect("create Media table");

    // Insert one row: DiskId=1, LastSequence=1, Cabinet="#cabstream",
    // all nullable columns are Null.
    let query = msi::Insert::into("Media").row(vec![
        msi::Value::from(1i16),         // DiskId
        msi::Value::from(1i16),         // LastSequence
        msi::Value::Null,               // DiskPrompt
        msi::Value::from("#cabstream"), // Cabinet (embedded stream)
        msi::Value::Null,               // VolumeLabel
        msi::Value::Null,               // Source
    ]);
    package.insert_rows(query).expect("insert Media row");

    // Write the CAB bytes as a CFB binary stream named "cabstream".
    {
        let mut stream = package
            .write_stream("cabstream")
            .expect("create cab stream");
        stream
            .write_all(&cab_bytes)
            .expect("write cab bytes to stream");
    }

    package.flush().expect("flush msi package");

    tmp
}

/// A single embedded-cab entry: stream name, file name inside the cab, content.
struct CabEntry<'a> {
    stream_name: &'a str,
    file_name: &'a str,
    content: &'a [u8],
}

/// Create an MSI fixture containing multiple embedded CAB streams.
///
/// Each `CabEntry` in `cabs` contributes one Media row (`Cabinet =
/// "#<stream_name>"`) and one CFB stream holding a tiny uncompressed CAB with a
/// single file.  DiskId values are 1-based sequential integers.
///
/// Returns a `NamedTempFile` so the file stays alive for the test.
fn make_multi_cab_msi_fixture(cabs: &[CabEntry<'_>]) -> tempfile::NamedTempFile {
    let tmp = tempfile::Builder::new()
        .suffix(".msi")
        .tempfile()
        .expect("create temp msi file");

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(tmp.path())
        .expect("open temp msi file for rw");

    let mut package =
        msi::Package::create(msi::PackageType::Installer, file).expect("create msi package");

    package
        .create_table("Media", media_columns())
        .expect("create Media table");

    for (i, cab) in cabs.iter().enumerate() {
        let disk_id = (i + 1) as i16;
        let cabinet_value = format!("#{}", cab.stream_name);
        let query = msi::Insert::into("Media").row(vec![
            msi::Value::from(disk_id),
            msi::Value::from(disk_id), // LastSequence
            msi::Value::Null,
            msi::Value::from(cabinet_value.as_str()),
            msi::Value::Null,
            msi::Value::Null,
        ]);
        package.insert_rows(query).expect("insert Media row");

        // Write the CAB bytes as a CFB stream.
        let cab_bytes = make_cab_bytes(cab.file_name, cab.content);
        let mut stream = package
            .write_stream(cab.stream_name)
            .expect("create cab stream");
        stream
            .write_all(&cab_bytes)
            .expect("write cab bytes to stream");
    }

    package.flush().expect("flush msi package");

    tmp
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[test]
fn msi_lists_embedded_file() {
    let content = b"Hello from MSI!";
    let msi_file = make_msi_fixture("hello.txt", content);

    let mut reader =
        detect::open(msi_file.path(), &OpenOptions::default()).expect("open msi via detect::open");

    let entries = reader.entries().expect("list entries");
    assert_eq!(entries.len(), 1, "expected one entry in the embedded CAB");
    assert_eq!(
        entries[0].path.to_str().unwrap(),
        "hello.txt",
        "entry path should be hello.txt"
    );
    assert_eq!(entries[0].size, content.len() as u64, "size should match");
}

#[test]
fn msi_reads_embedded_file_content() {
    let content = b"Hello from MSI!";
    let msi_file = make_msi_fixture("hello.txt", content);

    let mut reader =
        detect::open(msi_file.path(), &OpenOptions::default()).expect("open msi via detect::open");

    reader.entries().expect("list entries");

    let mut out = Vec::new();
    reader.read_entry(0, &mut out).expect("read_entry(0)");
    assert_eq!(out, content, "extracted content must match original");
}

#[test]
fn msi_read_entry_out_of_range_errors() {
    let msi_file = make_msi_fixture("a.txt", b"data");

    let mut reader =
        detect::open(msi_file.path(), &OpenOptions::default()).expect("open msi via detect::open");

    reader.entries().expect("list entries");

    let mut out = Vec::new();
    let err = reader.read_entry(99, &mut out).unwrap_err();
    assert!(
        matches!(err, newtua_core::Error::InvalidIndex(99)),
        "expected InvalidIndex(99), got {err:?}"
    );
}

#[test]
fn msi_empty_media_table_gives_zero_entries() {
    // Create an MSI with a Media table but no rows → zero entries.
    let tmp = tempfile::Builder::new()
        .suffix(".msi")
        .tempfile()
        .expect("create temp msi file");

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(tmp.path())
        .expect("open temp msi file for rw");

    let mut package =
        msi::Package::create(msi::PackageType::Installer, file).expect("create msi package");

    package
        .create_table("Media", media_columns())
        .expect("create Media table");
    // No rows inserted.
    package.flush().expect("flush");
    drop(package);

    let mut reader =
        detect::open(tmp.path(), &OpenOptions::default()).expect("open empty-media msi");

    let entries = reader.entries().expect("list entries");
    assert_eq!(entries.len(), 0, "no rows → no entries");
}

// ── Multi-cab tests ────────────────────────────────────────────────────────────

/// A single-cab MSI must NOT prefix entry paths with the stream name.
#[test]
fn msi_single_cab_no_prefix() {
    let content = b"Hello from MSI!";
    let msi_file = make_msi_fixture("hello.txt", content);

    let mut reader =
        detect::open(msi_file.path(), &OpenOptions::default()).expect("open msi via detect::open");

    let entries = reader.entries().expect("list entries");
    assert_eq!(entries.len(), 1);
    // With only one embedded cab, NO stream-name prefix must be applied.
    assert_eq!(
        entries[0].path.to_str().unwrap(),
        "hello.txt",
        "single-cab entry must not be prefixed"
    );
}

/// An MSI with two embedded CAB streams must prefix each entry with its stream
/// name so files from different cabs are uniquely identified.
///
/// Prefix scheme (from the handler source):
///   `PathBuf::from(stream_name).join(entry.path)` → `stream_name/filename`
#[test]
fn msi_multi_cab_entries_are_prefixed() {
    let cabs = [
        CabEntry {
            stream_name: "media1",
            file_name: "a.txt",
            content: b"AAA",
        },
        CabEntry {
            stream_name: "media2",
            file_name: "b.txt",
            content: b"BBB",
        },
    ];
    let msi_file = make_multi_cab_msi_fixture(&cabs);

    let mut reader =
        detect::open(msi_file.path(), &OpenOptions::default()).expect("open multi-cab msi");

    let entries = reader.entries().expect("list entries");
    assert_eq!(entries.len(), 2, "expected two entries (one per cab)");

    // Entries are in insertion order: media1/a.txt then media2/b.txt.
    assert_eq!(
        entries[0].path,
        Path::new("media1/a.txt"),
        "first entry must be prefixed with 'media1'"
    );
    assert_eq!(
        entries[1].path,
        Path::new("media2/b.txt"),
        "second entry must be prefixed with 'media2'"
    );
}

/// `read_entry` for a multi-cab MSI must return the correct bytes from each
/// respective embedded cab.
#[test]
fn msi_multi_cab_read_entry_routes_correctly() {
    let cabs = [
        CabEntry {
            stream_name: "media1",
            file_name: "a.txt",
            content: b"AAA",
        },
        CabEntry {
            stream_name: "media2",
            file_name: "b.txt",
            content: b"BBB",
        },
    ];
    let msi_file = make_multi_cab_msi_fixture(&cabs);

    let mut reader =
        detect::open(msi_file.path(), &OpenOptions::default()).expect("open multi-cab msi");

    reader.entries().expect("list entries");

    let mut out0 = Vec::new();
    reader.read_entry(0, &mut out0).expect("read_entry(0)");
    assert_eq!(out0, b"AAA", "entry 0 (media1/a.txt) must contain AAA");

    let mut out1 = Vec::new();
    reader.read_entry(1, &mut out1).expect("read_entry(1)");
    assert_eq!(out1, b"BBB", "entry 1 (media2/b.txt) must contain BBB");
}

// ── Resolution fixtures (File/Component/Directory tables) ────────────────────────

/// Build an uncompressed CAB containing several files (name → content).
fn make_cab_bytes_multi(files: &[(&str, &[u8])]) -> Vec<u8> {
    let buf = Cursor::new(Vec::<u8>::new());
    let mut builder = cab::CabinetBuilder::new();
    {
        let folder = builder.add_folder(cab::CompressionType::None);
        for (name, _) in files {
            folder.add_file(*name);
        }
    }
    let mut cw = builder.build(buf).unwrap();
    for (_, content) in files {
        if let Some(mut fw) = cw.next_file().unwrap() {
            fw.write_all(content).unwrap();
        }
    }
    cw.finish().unwrap().into_inner()
}

struct DirRow<'a> {
    key: &'a str,
    parent: Option<&'a str>,
    default_dir: &'a str,
}
struct FileRow<'a> {
    file_key: &'a str,
    component: &'a str,
    file_name: &'a str,
    content: &'a [u8],
}

/// Create an MSI with one embedded CAB (stream "cab") plus Directory, Component,
/// and File tables. Each File's CAB member name IS its `File` key.
fn make_resolved_msi(
    dirs: &[DirRow<'_>],
    components: &[(&str, &str)], // (Component, Directory_)
    files: &[FileRow<'_>],
) -> tempfile::NamedTempFile {
    let tmp = tempfile::Builder::new().suffix(".msi").tempfile().unwrap();
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(tmp.path())
        .unwrap();
    let mut package = msi::Package::create(msi::PackageType::Installer, file).unwrap();

    // Media + the single embedded CAB stream.
    package.create_table("Media", media_columns()).unwrap();
    package
        .insert_rows(msi::Insert::into("Media").row(vec![
            msi::Value::from(1i16),
            msi::Value::from(files.len() as i16),
            msi::Value::Null,
            msi::Value::from("#cab"),
            msi::Value::Null,
            msi::Value::Null,
        ]))
        .unwrap();

    // Directory table.
    package
        .create_table(
            "Directory",
            vec![
                msi::Column::build("Directory").primary_key().id_string(72),
                msi::Column::build("Directory_Parent")
                    .nullable()
                    .id_string(72),
                msi::Column::build("DefaultDir").text_string(255),
            ],
        )
        .unwrap();
    for d in dirs {
        package
            .insert_rows(msi::Insert::into("Directory").row(vec![
                msi::Value::from(d.key),
                match d.parent {
                    Some(p) => msi::Value::from(p),
                    None => msi::Value::Null,
                },
                msi::Value::from(d.default_dir),
            ]))
            .unwrap();
    }

    // Component table.
    package
        .create_table(
            "Component",
            vec![
                msi::Column::build("Component").primary_key().id_string(72),
                msi::Column::build("Directory_").id_string(72),
            ],
        )
        .unwrap();
    for (comp, dir_) in components {
        package
            .insert_rows(
                msi::Insert::into("Component")
                    .row(vec![msi::Value::from(*comp), msi::Value::from(*dir_)]),
            )
            .unwrap();
    }

    // File table.
    package
        .create_table(
            "File",
            vec![
                msi::Column::build("File").primary_key().id_string(72),
                msi::Column::build("Component_").id_string(72),
                msi::Column::build("FileName").text_string(255),
            ],
        )
        .unwrap();
    for f in files {
        package
            .insert_rows(msi::Insert::into("File").row(vec![
                msi::Value::from(f.file_key),
                msi::Value::from(f.component),
                msi::Value::from(f.file_name),
            ]))
            .unwrap();
    }

    // Embedded CAB stream: member names are the File keys.
    let cab_files: Vec<(&str, &[u8])> = files.iter().map(|f| (f.file_key, f.content)).collect();
    let cab_bytes = make_cab_bytes_multi(&cab_files);
    {
        let mut stream = package.write_stream("cab").unwrap();
        stream.write_all(&cab_bytes).unwrap();
    }

    package.flush().unwrap();
    tmp
}

#[test]
fn msi_resolves_nested_install_path() {
    let dirs = [
        DirRow {
            key: "TARGETDIR",
            parent: None,
            default_dir: "SourceDir",
        },
        DirRow {
            key: "ProgramFilesFolder",
            parent: Some("TARGETDIR"),
            default_dir: "ProgramFilesFolder",
        },
        DirRow {
            key: "MyApp",
            parent: Some("ProgramFilesFolder"),
            default_dir: "APP|MyApp",
        },
        DirRow {
            key: "Sub",
            parent: Some("MyApp"),
            default_dir: "SUB|sub",
        },
    ];
    let comps = [("cmp", "Sub")];
    let files = [FileRow {
        file_key: "fl_hello",
        component: "cmp",
        file_name: "HELLO~1.TXT|hello.txt",
        content: b"hi",
    }];
    let msi_file = make_resolved_msi(&dirs, &comps, &files);

    let mut reader = detect::open(msi_file.path(), &OpenOptions::default()).unwrap();
    let entries = reader.entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].path,
        Path::new("ProgramFilesFolder/MyApp/sub/hello.txt")
    );

    let mut out = Vec::new();
    reader.read_entry(0, &mut out).unwrap();
    assert_eq!(out, b"hi");
}

#[test]
fn msi_resolution_drops_dot_directory() {
    let dirs = [
        DirRow {
            key: "TARGETDIR",
            parent: None,
            default_dir: "SourceDir",
        },
        DirRow {
            key: "INSTALLDIR",
            parent: Some("TARGETDIR"),
            default_dir: ".",
        },
        DirRow {
            key: "Bin",
            parent: Some("INSTALLDIR"),
            default_dir: "bin",
        },
    ];
    let comps = [("cmp", "Bin")];
    let files = [FileRow {
        file_key: "fl_app",
        component: "cmp",
        file_name: "app.exe",
        content: b"X",
    }];
    let msi_file = make_resolved_msi(&dirs, &comps, &files);

    let mut reader = detect::open(msi_file.path(), &OpenOptions::default()).unwrap();
    let entries = reader.entries().unwrap();
    // INSTALLDIR has DefaultDir "." → contributes no segment.
    assert_eq!(entries[0].path, Path::new("bin/app.exe"));
}

#[test]
fn msi_unknown_file_key_falls_back_to_member_name() {
    // CAB has two members ("known", "orphan") but the File table lists only
    // "known"; the unlisted "orphan" member keeps its CAB name. Built inline
    // because the CAB must hold a member absent from the File table.
    let tmp = tempfile::Builder::new().suffix(".msi").tempfile().unwrap();
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(tmp.path())
        .unwrap();
    let mut package = msi::Package::create(msi::PackageType::Installer, file).unwrap();
    package.create_table("Media", media_columns()).unwrap();
    package
        .insert_rows(msi::Insert::into("Media").row(vec![
            msi::Value::from(1i16),
            msi::Value::from(2i16),
            msi::Value::Null,
            msi::Value::from("#cab"),
            msi::Value::Null,
            msi::Value::Null,
        ]))
        .unwrap();
    package
        .create_table(
            "Directory",
            vec![
                msi::Column::build("Directory").primary_key().id_string(72),
                msi::Column::build("Directory_Parent")
                    .nullable()
                    .id_string(72),
                msi::Column::build("DefaultDir").text_string(255),
            ],
        )
        .unwrap();
    package
        .insert_rows(msi::Insert::into("Directory").row(vec![
            msi::Value::from("TARGETDIR"),
            msi::Value::Null,
            msi::Value::from("SourceDir"),
        ]))
        .unwrap();
    package
        .insert_rows(msi::Insert::into("Directory").row(vec![
            msi::Value::from("Bin"),
            msi::Value::from("TARGETDIR"),
            msi::Value::from("bin"),
        ]))
        .unwrap();
    package
        .create_table(
            "Component",
            vec![
                msi::Column::build("Component").primary_key().id_string(72),
                msi::Column::build("Directory_").id_string(72),
            ],
        )
        .unwrap();
    package
        .insert_rows(
            msi::Insert::into("Component")
                .row(vec![msi::Value::from("cmp"), msi::Value::from("Bin")]),
        )
        .unwrap();
    package
        .create_table(
            "File",
            vec![
                msi::Column::build("File").primary_key().id_string(72),
                msi::Column::build("Component_").id_string(72),
                msi::Column::build("FileName").text_string(255),
            ],
        )
        .unwrap();
    package
        .insert_rows(msi::Insert::into("File").row(vec![
            msi::Value::from("known"),
            msi::Value::from("cmp"),
            msi::Value::from("known.txt"),
        ]))
        .unwrap();
    let cab_bytes = make_cab_bytes_multi(&[("known", b"K"), ("orphan", b"O")]);
    {
        let mut s = package.write_stream("cab").unwrap();
        s.write_all(&cab_bytes).unwrap();
    }
    package.flush().unwrap();

    let mut reader = detect::open(tmp.path(), &OpenOptions::default()).unwrap();
    let entries = reader.entries().unwrap();
    let paths: Vec<&Path> = entries.iter().map(|e| e.path.as_path()).collect();
    assert!(
        paths.contains(&Path::new("bin/known.txt")),
        "known file resolves; got {paths:?}"
    );
    assert!(
        paths.contains(&Path::new("orphan")),
        "orphan keeps CAB member name; got {paths:?}"
    );
}

#[test]
fn msi_directory_cycle_does_not_hang() {
    // Self-referential / cyclic Directory_Parent must not panic or hang.
    let dirs = [
        DirRow {
            key: "A",
            parent: Some("B"),
            default_dir: "A",
        },
        DirRow {
            key: "B",
            parent: Some("A"),
            default_dir: "B",
        },
    ];
    let comps = [("cmp", "A")];
    let files = [FileRow {
        file_key: "fl",
        component: "cmp",
        file_name: "f.txt",
        content: b"Z",
    }];
    let msi_file = make_resolved_msi(&dirs, &comps, &files);

    let mut reader = detect::open(msi_file.path(), &OpenOptions::default()).unwrap();
    let entries = reader.entries().unwrap();
    // Resolution terminates and yields a path ending in the file name.
    assert!(entries[0].path.to_str().unwrap().ends_with("f.txt"));
}
