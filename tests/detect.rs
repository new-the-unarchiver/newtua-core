use newtua_core::{open, OpenOptions};
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
    // tar → gzip
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

    let tmp = tempfile::Builder::new().suffix(".tar.gz").tempfile().unwrap();
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

/// Placeholder: single compressed non-tar file (e.g. file.gz containing plain data,
/// not a tar stream) is not supported in v1 — TarHandler will error on malformed tar.
/// Future work: detect and handle this case.
#[test]
#[ignore = "future work: single-file compressed archives (non-tar) not supported in v1"]
fn single_gz_non_tar_future_work() {
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(b"plain content, not a tar").unwrap();
    let gz_bytes = gz.finish().unwrap();

    let tmp = tempfile::Builder::new().suffix(".gz").tempfile().unwrap();
    std::fs::write(tmp.path(), gz_bytes).unwrap();

    // This would fail in v1 because we always feed gzip output to TarHandler.
    let _ = open(tmp.path(), &OpenOptions::default()).unwrap();
}
