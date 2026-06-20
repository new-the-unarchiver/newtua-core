use newtua_core::{OpenOptions, open};
use std::io::Write;

#[test]
fn opens_plain_zip_by_magic() {
    let tmp = tempfile::Builder::new().suffix(".zip").tempfile().unwrap();
    {
        let mut w = zip::ZipWriter::new(std::fs::File::create(tmp.path()).unwrap());
        let o: zip::write::FileOptions<()> = zip::write::FileOptions::default();
        w.start_file("a.txt", o).unwrap();
        w.write_all(b"zip!").unwrap();
        w.finish().unwrap();
    }
    let mut ar = open(tmp.path(), &OpenOptions::default()).unwrap();
    assert_eq!(ar.entries().unwrap().len(), 1);
}

#[test]
fn opens_tar_gz() {
    // tar → gzip — regression: .tar.gz must still yield the inner tar entries
    let mut tar_bytes = Vec::new();
    {
        let mut b = tar::Builder::new(&mut tar_bytes);
        let data = b"inside";
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, "f.txt", &data[..]).unwrap();
        b.finish().unwrap();
    }
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&tar_bytes).unwrap();
    let gz_bytes = gz.finish().unwrap();

    let tmp = tempfile::Builder::new()
        .suffix(".tar.gz")
        .tempfile()
        .unwrap();
    std::fs::write(tmp.path(), gz_bytes).unwrap();

    let mut ar = open(tmp.path(), &OpenOptions::default()).unwrap();
    let entries = ar.entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path.to_str().unwrap(), "f.txt");
}

#[test]
fn unknown_format_errors() {
    use newtua_core::Error;
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), b"definitely not an archive").unwrap();
    let result = open(tmp.path(), &OpenOptions::default());
    assert!(result.is_err());
    let err = result.err().unwrap();
    assert!(matches!(err, Error::UnknownFormat));
}

/// Single compressed non-tar .gz file should yield exactly one entry whose name
/// is the stem (without the .gz extension) and whose content equals the payload.
#[test]
fn single_gz_non_tar_yields_one_entry() {
    let payload = b"just some bytes\n";

    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(payload).unwrap();
    let gz_bytes = gz.finish().unwrap();

    // Use a temp directory so we can name the file exactly "payload.txt.gz".
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("payload.txt.gz");
    std::fs::write(&path, gz_bytes).unwrap();

    let mut ar = open(&path, &OpenOptions::default()).unwrap();
    let entries = ar.entries().unwrap();
    assert_eq!(entries.len(), 1, "expected exactly 1 entry");

    let entry_name = entries[0].path.to_str().unwrap().to_string();
    assert_eq!(
        entry_name, "payload.txt",
        "unexpected entry name: {entry_name}"
    );

    // Extracted bytes must equal the original payload
    let mut out = Vec::new();
    ar.read_entry(0, &mut out).unwrap();
    assert_eq!(out, payload, "extracted content mismatch");
}

/// Single compressed non-tar .bz2 file should yield exactly one entry.
#[test]
fn single_bz2_non_tar_yields_one_entry() {
    let payload = b"bzip2 payload data\n";

    let mut enc = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
    enc.write_all(payload).unwrap();
    let bz2_bytes = enc.finish().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("notes.txt.bz2");
    std::fs::write(&path, bz2_bytes).unwrap();

    let mut ar = open(&path, &OpenOptions::default()).unwrap();
    let entries = ar.entries().unwrap();
    assert_eq!(entries.len(), 1, "expected exactly 1 entry");

    let entry_name = entries[0].path.to_str().unwrap().to_string();
    assert_eq!(
        entry_name, "notes.txt",
        "unexpected entry name: {entry_name}"
    );

    let mut out = Vec::new();
    ar.read_entry(0, &mut out).unwrap();
    assert_eq!(out, payload, "extracted content mismatch");
}

/// Single compressed non-tar .xz file should yield exactly one entry.
#[test]
fn single_xz_non_tar_yields_one_entry() {
    let payload = b"xz payload data\n";

    let mut enc = xz2::write::XzEncoder::new(Vec::new(), 6);
    enc.write_all(payload).unwrap();
    let xz_bytes = enc.finish().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data.bin.xz");
    std::fs::write(&path, xz_bytes).unwrap();

    let mut ar = open(&path, &OpenOptions::default()).unwrap();
    let entries = ar.entries().unwrap();
    assert_eq!(entries.len(), 1, "expected exactly 1 entry");

    let entry_name = entries[0].path.to_str().unwrap().to_string();
    assert_eq!(
        entry_name, "data.bin",
        "unexpected entry name: {entry_name}"
    );

    let mut out = Vec::new();
    ar.read_entry(0, &mut out).unwrap();
    assert_eq!(out, payload, "extracted content mismatch");
}

/// read_entry with out-of-range index on a single-file reader must return an error.
#[test]
fn single_gz_out_of_range_index_errors() {
    use newtua_core::Error;
    let payload = b"some data\n";

    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(payload).unwrap();
    let gz_bytes = gz.finish().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file.txt.gz");
    std::fs::write(&path, gz_bytes).unwrap();

    let mut ar = open(&path, &OpenOptions::default()).unwrap();
    let result = ar.read_entry(1, &mut Vec::new());
    assert!(
        matches!(result, Err(Error::InvalidIndex(1))),
        "expected InvalidIndex(1), got: {result:?}"
    );
}
