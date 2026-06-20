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

    // Named "payload.txt.gz" — expected entry name: "payload.txt"
    let tmp = tempfile::Builder::new()
        .prefix("payload.txt")
        .suffix(".gz")
        .tempfile()
        .unwrap();
    std::fs::write(tmp.path(), gz_bytes).unwrap();

    let mut ar = open(tmp.path(), &OpenOptions::default()).unwrap();
    let entries = ar.entries().unwrap();
    assert_eq!(entries.len(), 1, "expected exactly 1 entry");

    // Entry name must be stem without .gz
    let entry_name = entries[0].path.to_str().unwrap().to_string();
    assert!(
        entry_name.ends_with(".txt"),
        "expected stem ending with .txt, got: {entry_name}"
    );
    assert!(
        !entry_name.ends_with(".gz"),
        "entry name must not retain .gz, got: {entry_name}"
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

    let tmp = tempfile::Builder::new()
        .prefix("notes.txt")
        .suffix(".bz2")
        .tempfile()
        .unwrap();
    std::fs::write(tmp.path(), bz2_bytes).unwrap();

    let mut ar = open(tmp.path(), &OpenOptions::default()).unwrap();
    let entries = ar.entries().unwrap();
    assert_eq!(entries.len(), 1, "expected exactly 1 entry");

    let entry_name = entries[0].path.to_str().unwrap().to_string();
    assert!(
        !entry_name.ends_with(".bz2"),
        "entry name must not retain .bz2, got: {entry_name}"
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

    let tmp = tempfile::Builder::new()
        .prefix("data.bin")
        .suffix(".xz")
        .tempfile()
        .unwrap();
    std::fs::write(tmp.path(), xz_bytes).unwrap();

    let mut ar = open(tmp.path(), &OpenOptions::default()).unwrap();
    let entries = ar.entries().unwrap();
    assert_eq!(entries.len(), 1, "expected exactly 1 entry");

    let entry_name = entries[0].path.to_str().unwrap().to_string();
    assert!(
        !entry_name.ends_with(".xz"),
        "entry name must not retain .xz, got: {entry_name}"
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

    let tmp = tempfile::Builder::new()
        .prefix("file.txt")
        .suffix(".gz")
        .tempfile()
        .unwrap();
    std::fs::write(tmp.path(), gz_bytes).unwrap();

    let mut ar = open(tmp.path(), &OpenOptions::default()).unwrap();
    let result = ar.read_entry(1, &mut Vec::new());
    assert!(
        matches!(result, Err(Error::InvalidIndex(1))),
        "expected InvalidIndex(1), got: {result:?}"
    );
}
