use newtua_core::archive::{ArchiveReader, EntryKind, FormatId, OpenOptions};
use newtua_core::detect::open;
use newtua_core::error::Error;
use std::path::Path;
use std::process::Command;

fn fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn body_of(reader: &mut dyn ArchiveReader, name: &str) -> Vec<u8> {
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

/// Assert the standard `src/{a.txt,empty.txt,sub/,sub/b.txt}` tree (see
/// task_n_reports/task-20a-wim.md §7) is listed and extracts correctly.
fn assert_standard_tree(reader: &mut dyn ArchiveReader) {
    let entries = reader.entries().expect("entries");
    let names: Vec<String> = entries
        .iter()
        .map(|e| e.path.to_string_lossy().into_owned())
        .collect();
    assert!(names.iter().any(|n| n == "a.txt"), "names: {names:?}");
    assert!(names.iter().any(|n| n == "empty.txt"), "names: {names:?}");
    assert!(names.iter().any(|n| n == "sub"), "names: {names:?}");
    assert!(names.iter().any(|n| n == "sub/b.txt"), "names: {names:?}");
    assert!(
        !names.iter().any(|n| n.starts_with('/')),
        "no leading slash: {names:?}"
    );
    let sub = entries
        .iter()
        .find(|e| e.path.to_string_lossy() == "sub")
        .unwrap();
    assert_eq!(sub.kind, EntryKind::Dir);

    assert_eq!(body_of(reader, "a.txt"), b"hello wim\n");
    assert_eq!(body_of(reader, "sub/b.txt"), b"nested\n");

    let empty_idx = reader
        .entries()
        .unwrap()
        .iter()
        .position(|e| e.path.to_string_lossy() == "empty.txt")
        .unwrap();
    assert_eq!(reader.entries().unwrap()[empty_idx].size, 0);
    let mut body = Vec::new();
    reader.read_entry(empty_idx, &mut body).unwrap();
    assert!(body.is_empty());
}

#[test]
fn wim_none_reports_format_and_extracts_tree() {
    let mut reader = open(&fixture("wim_none.wim"), &OpenOptions::default()).expect("open wim");
    assert_eq!(reader.format(), FormatId::Wim);
    assert_standard_tree(reader.as_mut());
}

#[test]
fn wim_xpress_extracts_tree() {
    let mut reader =
        open(&fixture("wim_xpress.wim"), &OpenOptions::default()).expect("open wim xpress");
    assert_eq!(reader.format(), FormatId::Wim);
    assert_standard_tree(reader.as_mut());
}

#[test]
fn wim_lzx_extracts_tree() {
    let mut reader = open(&fixture("wim_lzx.wim"), &OpenOptions::default()).expect("open wim lzx");
    assert_eq!(reader.format(), FormatId::Wim);
    assert_standard_tree(reader.as_mut());
}

#[test]
fn wim_lzms_extracts_tree() {
    let mut reader =
        open(&fixture("wim_lzms.esd"), &OpenOptions::default()).expect("open wim lzms");
    assert_eq!(reader.format(), FormatId::Wim);
    assert_standard_tree(reader.as_mut());
}

#[test]
fn wim_corrupt_is_corrupt() {
    let result = open(&fixture("wim_corrupt.wim"), &OpenOptions::default());
    match result {
        Err(Error::Corrupt(_)) => {}
        Err(other) => panic!("expected Err(Corrupt), got Err({other:?})"),
        Ok(_) => panic!("expected Err(Corrupt), got Ok"),
    }
}

#[test]
fn wim_read_entry_out_of_range_is_invalid_index() {
    let mut reader = open(&fixture("wim_none.wim"), &OpenOptions::default()).expect("open wim");
    let n = reader.entries().expect("entries").len();
    let mut sink = Vec::new();
    let err = reader
        .read_entry(n + 100, &mut sink)
        .expect_err("out-of-range index must error");
    assert!(matches!(err, Error::InvalidIndex(_)), "got {err:?}");
}

#[test]
fn wim_detected_by_extension_alone() {
    // probe() must recognise `.wim` even without peeking the magic, matching
    // detect::open's registry path (the fixture does carry the real magic
    // too, but this exercises the same probe() the extension-only branch
    // would take for a headerless/renamed file).
    let entries = newtua_core::detect::registry();
    let wim_probe = entries
        .iter()
        .find(|h| h.id() == FormatId::Wim)
        .expect("WimHandler registered");
    assert_eq!(
        wim_probe.probe(b"\x00\x00\x00\x00", Some("install.wim")),
        newtua_core::archive::Confidence::MAGIC
    );
}

/// Cross-check against `wimlib-imagex apply` when the tool is present on the
/// system (dev-only oracle, per `_protocol.md`). Skips (prints and returns)
/// when the binary isn't found rather than failing the suite.
#[test]
fn wim_none_matches_wimlib_imagex_apply() {
    if Command::new("wimlib-imagex")
        .arg("--version")
        .output()
        .is_err()
    {
        println!("skipping wim_none_matches_wimlib_imagex_apply: wimlib-imagex not found");
        return;
    }
    let out_dir = tempfile::tempdir().expect("tempdir");
    let status = Command::new("wimlib-imagex")
        .arg("apply")
        .arg(fixture("wim_none.wim"))
        .arg(out_dir.path())
        .status()
        .expect("run wimlib-imagex apply");
    assert!(status.success(), "wimlib-imagex apply failed");

    let mut reader = open(&fixture("wim_none.wim"), &OpenOptions::default()).expect("open wim");
    for rel in ["a.txt", "sub/b.txt", "empty.txt"] {
        let expected = std::fs::read(out_dir.path().join(rel))
            .unwrap_or_else(|e| panic!("read reference {rel}: {e}"));
        assert_eq!(
            body_of(reader.as_mut(), rel),
            expected,
            "mismatch for {rel}"
        );
    }
}
