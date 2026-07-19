/// Integration tests for the WARC format handler.
///
/// Fixtures are built programmatically (WARC is plain text + gzip) — no
/// committed binary files are required.
use std::io::Write as _;
use std::path::Path;

use flate2::Compression;
use flate2::write::GzEncoder;
use newtua_core::archive::{FormatId, OpenOptions};
use newtua_core::detect::open;

// ── WARC building helpers ─────────────────────────────────────────────────────

/// Build a WARC record as a sequence of bytes.
///
/// WARC record format:
///
/// ```text
/// WARC/1.0\r\n
/// WARC-Type: <type>\r\n
/// WARC-Record-ID: <id>\r\n
/// Content-Length: <n>\r\n
/// [WARC-Target-URI: <uri>\r\n]
/// [WARC-Date: <date>\r\n]
/// \r\n
/// <body bytes (n bytes)>
/// \r\n\r\n
/// ```
fn build_warc_record(
    warc_type: &str,
    target_uri: Option<&str>,
    date: Option<&str>,
    body: &[u8],
) -> Vec<u8> {
    let mut record = Vec::new();
    write!(record, "WARC/1.0\r\n").unwrap();
    write!(record, "WARC-Type: {warc_type}\r\n").unwrap();
    write!(
        record,
        "WARC-Record-ID: <urn:uuid:00000000-0000-0000-0000-{warc_type:012}>\r\n"
    )
    .unwrap();
    write!(record, "Content-Length: {}\r\n", body.len()).unwrap();
    if let Some(uri) = target_uri {
        write!(record, "WARC-Target-URI: {uri}\r\n").unwrap();
    }
    if let Some(d) = date {
        write!(record, "WARC-Date: {d}\r\n").unwrap();
    }
    write!(record, "\r\n").unwrap();
    record.extend_from_slice(body);
    write!(record, "\r\n\r\n").unwrap();
    record
}

/// Build a complete multi-record WARC file in memory.
fn build_warc(records: &[Vec<u8>]) -> Vec<u8> {
    records.iter().flat_map(|r| r.iter().copied()).collect()
}

/// Gzip-compress each record individually and concatenate — this is the
/// `.warc.gz` per-record-gzip format.
fn build_warc_gz(records: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for rec in records {
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(rec).unwrap();
        let compressed = enc.finish().unwrap();
        out.extend_from_slice(&compressed);
    }
    out
}

/// Write bytes to a named-extension temp file and return the `TempPath`.
fn write_temp(data: &[u8], suffix: &str) -> tempfile::TempPath {
    let mut tmp = tempfile::Builder::new()
        .suffix(suffix)
        .tempfile()
        .expect("tempfile");
    tmp.write_all(data).expect("write");
    tmp.into_temp_path()
}

// ── Fixtures ──────────────────────────────────────────────────────────────────

/// Standard HTTP response body used across multiple tests.
const HTTP_BODY: &[u8] = b"<html><body>Hello world</body></html>";
const RESOURCE_BODY: &[u8] = b"\x89PNG\r\nfake-png-data";

fn make_records() -> [Vec<u8>; 3] {
    let http_response = {
        let mut b = Vec::new();
        b.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n");
        b.extend_from_slice(HTTP_BODY);
        b
    };

    [
        // warcinfo — must be excluded from entries
        build_warc_record(
            "warcinfo",
            None,
            Some("2023-01-01T00:00:00Z"),
            b"software: test\r\n",
        ),
        // response — HTTP headers must be stripped
        build_warc_record(
            "response",
            Some("http://example.com/page.html"),
            Some("2023-06-15T12:00:00Z"),
            &http_response,
        ),
        // resource — body verbatim
        build_warc_record(
            "resource",
            Some("http://example.com/data.bin"),
            Some("2023-06-15T12:01:00Z"),
            RESOURCE_BODY,
        ),
    ]
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Plain .warc: open via detect::open, check entry count, names, and bodies.
#[test]
fn warc_list_and_extract_plain() {
    let records = make_records();
    let warc_bytes = build_warc(&records);
    let tmp = write_temp(&warc_bytes, ".warc");

    let opts = OpenOptions::default();
    let mut reader = open(&tmp, &opts).expect("open .warc");

    assert_eq!(reader.format(), FormatId::Warc, "format should be Warc");

    let entries = reader.entries().expect("entries");

    // Only response and resource records are exposed; warcinfo is excluded.
    assert_eq!(
        entries.len(),
        2,
        "expected 2 entries (response + resource), got {}",
        entries.len()
    );

    // Verify derived paths from WARC-Target-URI.
    assert_eq!(
        entries[0].path,
        Path::new("example.com/page.html"),
        "response entry path"
    );
    assert_eq!(
        entries[1].path,
        Path::new("example.com/data.bin"),
        "resource entry path"
    );

    // response body: HTTP headers stripped, only HTML payload.
    let mut body0 = Vec::new();
    reader.read_entry(0, &mut body0).expect("read_entry 0");
    assert_eq!(
        body0, HTTP_BODY,
        "response body should have HTTP headers stripped"
    );

    // resource body: verbatim.
    let mut body1 = Vec::new();
    reader.read_entry(1, &mut body1).expect("read_entry 1");
    assert_eq!(body1, RESOURCE_BODY, "resource body should be verbatim");
}

/// .warc.gz: per-record gzip — detect::open must route to WARC (not SingleFileReader).
#[test]
fn warc_gz_opens_as_warc_not_gzip() {
    let records = make_records();
    let warc_gz_bytes = build_warc_gz(&records);
    let tmp = write_temp(&warc_gz_bytes, ".warc.gz");

    let opts = OpenOptions::default();
    let mut reader = open(&tmp, &opts).expect("open .warc.gz");

    assert_eq!(
        reader.format(),
        FormatId::Warc,
        ".warc.gz must open as WARC, not as a generic gzip/raw"
    );

    let entries = reader.entries().expect("entries");
    assert_eq!(
        entries.len(),
        2,
        "expected 2 entries from .warc.gz, got {}",
        entries.len()
    );

    assert_eq!(entries[0].path, Path::new("example.com/page.html"));
    assert_eq!(entries[1].path, Path::new("example.com/data.bin"));

    // Verify bodies are correct even after gzip decompression.
    let mut body0 = Vec::new();
    reader
        .read_entry(0, &mut body0)
        .expect("read_entry 0 from gz");
    assert_eq!(body0, HTTP_BODY);

    let mut body1 = Vec::new();
    reader
        .read_entry(1, &mut body1)
        .expect("read_entry 1 from gz");
    assert_eq!(body1, RESOURCE_BODY);
}

/// read_entry with an out-of-range index returns InvalidIndex, never panics.
#[test]
fn warc_read_entry_out_of_range() {
    let records = make_records();
    let warc_bytes = build_warc(&records);
    let tmp = write_temp(&warc_bytes, ".warc");

    let opts = OpenOptions::default();
    let mut reader = open(&tmp, &opts).expect("open .warc");
    reader.entries().expect("entries");

    let result = reader.read_entry(99, &mut std::io::sink());
    assert!(
        matches!(result, Err(newtua_core::error::Error::InvalidIndex(99))),
        "expected InvalidIndex(99), got {:?}",
        result
    );
}

/// A truncated / garbage .warc must return an error, not panic.
#[test]
fn warc_truncated_returns_error() {
    // Looks like WARC (starts with WARC/1.0) but is otherwise garbage.
    let garbage = b"WARC/1.0\r\nWARC-Type: response\r\nContent-Length: 999\r\n\r\nTRUNCATED";
    let tmp = write_temp(garbage, ".warc");

    let opts = OpenOptions::default();
    let result = open(&tmp, &opts);
    // The `warc` crate will return an error when it can't read the expected
    // 999 bytes of body — we map this to Error::Corrupt.
    assert!(
        result.is_err(),
        "expected an error for truncated/garbage WARC, got Ok"
    );
}

/// Duplicate URIs get disambiguated with -1, -2, … suffixes.
#[test]
fn warc_duplicate_uri_deduplication() {
    let records = [
        build_warc_record(
            "resource",
            Some("http://example.com/file.txt"),
            Some("2023-01-01T00:00:00Z"),
            b"first",
        ),
        build_warc_record(
            "resource",
            Some("http://example.com/file.txt"),
            Some("2023-01-01T00:00:01Z"),
            b"second",
        ),
    ];
    let warc_bytes = build_warc(&records);
    let tmp = write_temp(&warc_bytes, ".warc");

    let opts = OpenOptions::default();
    let mut reader = open(&tmp, &opts).expect("open duplicate-uri warc");
    let entries = reader.entries().expect("entries");

    assert_eq!(entries.len(), 2, "expected 2 entries");
    assert_eq!(entries[0].path, Path::new("example.com/file.txt"));
    // Second occurrence gets a -1 suffix.
    assert_eq!(entries[1].path, Path::new("example.com/file.txt-1"));

    let mut b0 = Vec::new();
    reader.read_entry(0, &mut b0).expect("read_entry 0");
    assert_eq!(b0, b"first");

    let mut b1 = Vec::new();
    reader.read_entry(1, &mut b1).expect("read_entry 1");
    assert_eq!(b1, b"second");
}
