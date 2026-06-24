use newtua_core::{OpenOptions, open};
use std::io::Write;
use std::path::Path;

/// Build a one-entry tar (`usr/bin/hello` = "deb payload") and return its bytes.
fn one_file_tar() -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut b = tar::Builder::new(&mut buf);
        let data = b"deb payload";
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, "usr/bin/hello", &data[..]).unwrap();
        b.finish().unwrap();
    }
    buf
}

/// Write a minimal .deb (ar: debian-binary + control.tar.gz stub + data member)
/// to `path`. `data_member` is the member name (e.g. "data.tar.gz");
/// `data_bytes` is its content (already compressed, or a raw tar).
fn write_deb(path: &Path, data_member: &str, data_bytes: &[u8]) {
    use ar::{GnuBuilder, Header};
    let names = vec![
        b"debian-binary".to_vec(),
        b"control.tar.gz".to_vec(),
        data_member.as_bytes().to_vec(),
    ];
    let file = std::fs::File::create(path).unwrap();
    let mut builder = GnuBuilder::new(file, names);

    let db = b"2.0\n";
    builder
        .append(
            &Header::new(b"debian-binary".to_vec(), db.len() as u64),
            &db[..],
        )
        .unwrap();
    let ctrl = b"control-stub";
    builder
        .append(
            &Header::new(b"control.tar.gz".to_vec(), ctrl.len() as u64),
            &ctrl[..],
        )
        .unwrap();
    builder
        .append(
            &Header::new(data_member.as_bytes().to_vec(), data_bytes.len() as u64),
            data_bytes,
        )
        .unwrap();
    builder.into_inner().unwrap();
}

/// Open the deb at `path` and assert the payload is the single `usr/bin/hello`
/// entry with content "deb payload".
fn assert_payload(path: &Path) {
    let mut ar = open(path, &OpenOptions::default()).unwrap();
    let entries = ar.entries().unwrap();
    assert_eq!(entries.len(), 1, "expected exactly 1 payload entry");
    assert_eq!(entries[0].path.to_str().unwrap(), "usr/bin/hello");

    let mut out = Vec::new();
    ar.read_entry(0, &mut out).unwrap();
    assert_eq!(out, b"deb payload");
}

#[test]
fn deb_data_tar_gz() {
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&one_file_tar()).unwrap();
    let data = gz.finish().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pkg.deb");
    write_deb(&path, "data.tar.gz", &data);
    assert_payload(&path);
}
