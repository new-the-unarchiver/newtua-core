use newtua_core::Source;
use std::io::Write;

#[test]
fn peek_header_reads_and_rewinds() {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(b"PK\x03\x04rest-of-file").unwrap();
    tmp.flush().unwrap();

    let mut src = Source::path(tmp.path()).unwrap();
    let head = src.peek_header(4).unwrap();
    assert_eq!(&head, b"PK\x03\x04");
    // повторный peek даёт тот же результат (откат сработал)
    let head2 = src.peek_header(4).unwrap();
    assert_eq!(head, head2);
}

#[test]
fn peek_header_on_short_file_returns_available_bytes() {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(b"PK").unwrap();
    tmp.flush().unwrap();
    let mut src = Source::path(tmp.path()).unwrap();
    let head = src.peek_header(8).unwrap();
    assert_eq!(&head, b"PK");
}
