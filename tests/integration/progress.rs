use newtua_core::{ExtractOptions, Flow, OpenOptions, ProgressEvent, extract_all, open};
use std::io::Write;
use std::sync::{Arc, Mutex};

fn zip_two() -> tempfile::NamedTempFile {
    let tmp = tempfile::Builder::new().suffix(".zip").tempfile().unwrap();
    let mut w = zip::ZipWriter::new(std::fs::File::create(tmp.path()).unwrap());
    let o: zip::write::FileOptions<()> = zip::write::FileOptions::default();
    w.start_file("a.txt", o).unwrap();
    w.write_all(b"hello").unwrap();
    w.start_file("b.txt", o).unwrap();
    w.write_all(b"world!!").unwrap();
    w.finish().unwrap();
    tmp
}

#[test]
fn progress_reports_bytes_per_entry() {
    let zip = zip_two();
    let dest = tempfile::tempdir().unwrap();
    let mut ar = open(zip.path(), &OpenOptions::default()).unwrap();
    let log = Arc::new(Mutex::new(Vec::<(usize, u64)>::new()));
    let log2 = log.clone();
    let mut opts = ExtractOptions {
        dest: dest.path().to_path_buf(),
        wrapper_name: None,
        strict: false,
        preserve: true,
        selection: None,
        progress: Some(Box::new(move |ev| {
            if let ProgressEvent::Bytes { index, written } = ev {
                log2.lock().unwrap().push((index, written));
            }
            Flow::Continue
        })),
        keep_macos_metadata: false,
    };
    let report = extract_all(&mut *ar, &mut opts).unwrap();
    assert_eq!(report.extracted, 2);
    assert!(!report.aborted);
    // Sum of bytes per index equals each file's length (5 and 7).
    let log = log.lock().unwrap();
    let sum0: u64 = log.iter().filter(|(i, _)| *i == 0).map(|(_, n)| *n).sum();
    let sum1: u64 = log.iter().filter(|(i, _)| *i == 1).map(|(_, n)| *n).sum();
    assert_eq!(sum0, 5);
    assert_eq!(sum1, 7);
}

#[test]
fn abort_stops_and_marks_report() {
    let zip = zip_two();
    let dest = tempfile::tempdir().unwrap();
    let mut ar = open(zip.path(), &OpenOptions::default()).unwrap();
    let mut opts = ExtractOptions {
        dest: dest.path().to_path_buf(),
        wrapper_name: None,
        strict: false,
        preserve: true,
        selection: None,
        // Abort at the first EntryStart.
        progress: Some(Box::new(|ev| match ev {
            ProgressEvent::EntryStart { .. } => Flow::Abort,
            _ => Flow::Continue,
        })),
        keep_macos_metadata: false,
    };
    let report = extract_all(&mut *ar, &mut opts).unwrap();
    assert!(report.aborted);
    assert_eq!(report.extracted, 0);
    // Nothing was written.
    assert!(!dest.path().join("a.txt").exists());
}
