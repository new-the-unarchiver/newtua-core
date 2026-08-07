use newtua_core::format::CabHandler;
use newtua_core::{
    EntrySink, Error, ExtractOptions, FormatHandler, OpenOptions, SinkStep, Source, extract_all,
};
use std::io::Write;
use std::path::Path;

/// Build a single-folder MSZIP cabinet in a temp file. Files are written in the
/// order declared (the `cab` writer streams `next_file()` in that order).
///
/// The writer is upstream `cab`, a dev-dependency; the reader under test is the
/// vendored one in `src/vendor/cab/`. Keeping those two apart is the point — a
/// fixture built by the code that reads it can only prove self-consistency.
fn make_cab(files: &[(&str, &[u8])]) -> tempfile::NamedTempFile {
    make_cab_folders(&[files])
}

/// Build a cabinet with one CAB folder per slice. A folder is a solid stream,
/// so this is what puts the one-pass walk under test: several streams, each
/// needing its own decoder.
fn make_cab_folders(folders: &[&[(&str, &[u8])]]) -> tempfile::NamedTempFile {
    use cab::{CabinetBuilder, CompressionType};
    let tmp = tempfile::Builder::new().suffix(".cab").tempfile().unwrap();
    let mut builder = CabinetBuilder::new();
    for files in folders {
        let folder = builder.add_folder(CompressionType::MsZip);
        for (name, _) in *files {
            folder.add_file(*name);
        }
    }
    let file = std::fs::File::create(tmp.path()).unwrap();
    let mut cw = builder.build(file).unwrap();
    let mut data = folders.iter().flat_map(|f| f.iter());
    while let Some(mut w) = cw.next_file().unwrap() {
        w.write_all(data.next().unwrap().1).unwrap();
    }
    cw.finish().unwrap();
    tmp
}

/// Everything `read_entries` reported, as `(index, body)` pairs.
///
/// Deliberately not a `Vec<u8>` per index: the point of several of these tests
/// is *which* entry each body was attributed to, and a sink that only collected
/// bytes would pass even if two entries swapped names.
#[derive(Default)]
struct Collector {
    current: Option<usize>,
    got: Vec<(usize, Vec<u8>)>,
    /// Indices to answer `Skip` for.
    skip: Vec<usize>,
    /// Index after which to answer `Stop`.
    stop_before: Option<usize>,
}

impl EntrySink for Collector {
    fn begin(&mut self, idx: usize) -> newtua_core::Result<SinkStep> {
        if self.stop_before == Some(idx) {
            return Ok(SinkStep::Stop);
        }
        if self.skip.contains(&idx) {
            return Ok(SinkStep::Skip);
        }
        self.current = Some(idx);
        self.got.push((idx, Vec::new()));
        Ok(SinkStep::Body)
    }

    fn write_body(&mut self, buf: &[u8]) -> newtua_core::Result<()> {
        self.got.last_mut().unwrap().1.extend_from_slice(buf);
        Ok(())
    }

    fn end(&mut self, idx: usize, outcome: newtua_core::Result<()>) -> newtua_core::Result<bool> {
        assert_eq!(self.current, Some(idx), "end() came for a different entry");
        outcome.unwrap();
        Ok(true)
    }
}

#[test]
fn lists_and_reads_cab() {
    let cab = make_cab(&[("hello.txt", b"hello cab"), ("dir\\nested.txt", b"nested!")]);
    let src = Source::path(cab.path()).unwrap();
    let mut ar = CabHandler.open(src, &OpenOptions::default()).unwrap();

    let entries = ar.entries().unwrap();
    assert_eq!(entries.len(), 2);
    // backslash separators are normalized to forward slashes
    assert_eq!(entries[0].path.to_str().unwrap(), "hello.txt");
    assert_eq!(entries[1].path, Path::new("dir/nested.txt"));
    assert_eq!(entries[0].size, 9);
    assert_eq!(entries[1].size, 7);

    let mut out = Vec::new();
    ar.read_entry(0, &mut out).unwrap();
    assert_eq!(out, b"hello cab");
    let mut out2 = Vec::new();
    ar.read_entry(1, &mut out2).unwrap();
    assert_eq!(out2, b"nested!");
}

#[test]
fn read_entry_out_of_range_errors() {
    let cab = make_cab(&[("a.txt", b"a")]);
    let src = Source::path(cab.path()).unwrap();
    let mut ar = CabHandler.open(src, &OpenOptions::default()).unwrap();
    ar.entries().unwrap();
    let mut out = Vec::new();
    let err = ar.read_entry(99, &mut out).unwrap_err();
    assert!(matches!(err, Error::InvalidIndex(99)));
}

#[test]
fn extracts_cab_to_dest() {
    let cab = make_cab(&[("data\\a.txt", b"A"), ("data\\b.txt", b"B")]);
    let dest = tempfile::tempdir().unwrap();
    let src = Source::path(cab.path()).unwrap();
    let mut ar = CabHandler.open(src, &OpenOptions::default()).unwrap();
    extract_all(
        &mut *ar,
        &mut ExtractOptions {
            dest: dest.path().to_path_buf(),
            wrapper_name: Some("arc".into()),
            strict: false,
            preserve: true,
            selection: None,
            progress: None,
            keep_macos_metadata: false,
        },
    )
    .unwrap();
    // "data" is the common root, so it is used as the folder (no extra wrapper)
    assert_eq!(std::fs::read(dest.path().join("data/a.txt")).unwrap(), b"A");
    assert_eq!(std::fs::read(dest.path().join("data/b.txt")).unwrap(), b"B");
}

#[test]
fn batch_read_crosses_several_folders() {
    let cab = make_cab_folders(&[
        &[("one.txt", b"first"), ("two.txt", b"second")],
        &[("three.txt", b"third")],
        &[("four.txt", b"fourth"), ("five.txt", b"fifth")],
    ]);
    let src = Source::path(cab.path()).unwrap();
    let mut ar = CabHandler.open(src, &OpenOptions::default()).unwrap();
    assert_eq!(ar.entries().unwrap().len(), 5);

    let mut sink = Collector::default();
    ar.read_entries(&[0, 1, 2, 3, 4], &mut sink).unwrap();
    assert_eq!(
        sink.got,
        vec![
            (0, b"first".to_vec()),
            (1, b"second".to_vec()),
            (2, b"third".to_vec()),
            (3, b"fourth".to_vec()),
            (4, b"fifth".to_vec()),
        ]
    );
}

#[test]
fn batch_read_of_a_subset_skips_the_rest() {
    let cab = make_cab_folders(&[
        &[("a.txt", b"aaa"), ("b.txt", b"bbb"), ("c.txt", b"ccc")],
        &[("d.txt", b"ddd"), ("e.txt", b"eee")],
    ]);
    let src = Source::path(cab.path()).unwrap();
    let mut ar = CabHandler.open(src, &OpenOptions::default()).unwrap();
    ar.entries().unwrap();

    // The last file of one folder and the last of the other: both sit behind
    // files nobody asked for, which is exactly the case a forward-only walk has
    // to get right.
    let mut sink = Collector::default();
    ar.read_entries(&[2, 4], &mut sink).unwrap();
    assert_eq!(sink.got, vec![(2, b"ccc".to_vec()), (4, b"eee".to_vec())]);
}

#[test]
fn the_same_name_in_two_folders_stays_two_entries() {
    // Legal in CAB, and the old name-based lookup resolved both to the first
    // match — so one file was extracted twice and the other never appeared.
    let cab = make_cab_folders(&[
        &[("readme.txt", b"from folder one")],
        &[("readme.txt", b"from folder two")],
    ]);
    let src = Source::path(cab.path()).unwrap();
    let mut ar = CabHandler.open(src, &OpenOptions::default()).unwrap();
    let entries = ar.entries().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].path, entries[1].path);

    let mut first = Vec::new();
    ar.read_entry(0, &mut first).unwrap();
    let mut second = Vec::new();
    ar.read_entry(1, &mut second).unwrap();
    assert_eq!(first, b"from folder one");
    assert_eq!(second, b"from folder two");

    let mut sink = Collector::default();
    ar.read_entries(&[0, 1], &mut sink).unwrap();
    assert_eq!(
        sink.got,
        vec![
            (0, b"from folder one".to_vec()),
            (1, b"from folder two".to_vec()),
        ]
    );
}

#[test]
fn a_skipped_entry_does_not_disturb_the_walk() {
    let cab = make_cab(&[("a.txt", b"aaa"), ("b.txt", b"bbb"), ("c.txt", b"ccc")]);
    let src = Source::path(cab.path()).unwrap();
    let mut ar = CabHandler.open(src, &OpenOptions::default()).unwrap();
    ar.entries().unwrap();

    let mut sink = Collector {
        skip: vec![1],
        ..Default::default()
    };
    ar.read_entries(&[0, 1, 2], &mut sink).unwrap();
    assert_eq!(sink.got, vec![(0, b"aaa".to_vec()), (2, b"ccc".to_vec())]);
}

#[test]
fn stopping_leaves_the_earlier_entries_written() {
    let cab = make_cab(&[("a.txt", b"aaa"), ("b.txt", b"bbb"), ("c.txt", b"ccc")]);
    let src = Source::path(cab.path()).unwrap();
    let mut ar = CabHandler.open(src, &OpenOptions::default()).unwrap();
    ar.entries().unwrap();

    let mut sink = Collector {
        stop_before: Some(2),
        ..Default::default()
    };
    ar.read_entries(&[0, 1, 2], &mut sink).unwrap();
    assert_eq!(sink.got, vec![(0, b"aaa".to_vec()), (1, b"bbb".to_vec())]);
}

#[test]
fn extraction_across_folders_writes_every_file() {
    let cab = make_cab_folders(&[
        &[("data\\a.txt", b"A"), ("data\\b.txt", b"B")],
        &[("data\\c.txt", b"C")],
    ]);
    let dest = tempfile::tempdir().unwrap();
    let src = Source::path(cab.path()).unwrap();
    let mut ar = CabHandler.open(src, &OpenOptions::default()).unwrap();
    extract_all(
        &mut *ar,
        &mut ExtractOptions {
            dest: dest.path().to_path_buf(),
            wrapper_name: Some("arc".into()),
            strict: false,
            preserve: true,
            selection: None,
            progress: None,
            keep_macos_metadata: false,
        },
    )
    .unwrap();
    assert_eq!(std::fs::read(dest.path().join("data/a.txt")).unwrap(), b"A");
    assert_eq!(std::fs::read(dest.path().join("data/b.txt")).unwrap(), b"B");
    assert_eq!(std::fs::read(dest.path().join("data/c.txt")).unwrap(), b"C");
}
