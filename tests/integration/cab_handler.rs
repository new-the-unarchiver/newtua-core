use newtua_core::format::CabHandler;
use newtua_core::{
    EntrySink, Error, ExtractOptions, FormatHandler, OpenOptions, SinkStep, Source, extract_all,
};
use std::io::{Seek, SeekFrom, Write};
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

/// Mark folder `index` as Quantum-compressed, in place, without touching its
/// data — which stays MSZIP and will therefore not decode.
///
/// This is how "one folder is unreadable, the rest are not" gets tested at all:
/// nothing available writes a *broken* CAB folder on purpose. Since the Quantum
/// decoder arrived the mislabelled folder fails inside decoding rather than at
/// the door, which is the more interesting path — a real damaged archive fails
/// the same way.
///
/// Header geometry, from the CAB specification: the fixed header is 36 bytes
/// (and this builder sets no reserve areas and no previous/next cabinet names,
/// so nothing follows it), then one 8-byte folder entry each — `u32` first data
/// block offset, `u16` block count, `u16` compression.
fn mark_folder_quantum(cab: &tempfile::NamedTempFile, index: usize) {
    const HEADER_LEN: u64 = 36;
    const FOLDER_ENTRY_LEN: u64 = 8;
    const COMPRESSION_OFFSET: u64 = 6;
    // Quantum, level 7, memory 20 — the same bit pattern the vendored reader's
    // own unit test recognises.
    const QUANTUM_BITS: u16 = 0x1472;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(cab.path())
        .unwrap();
    let at = HEADER_LEN + FOLDER_ENTRY_LEN * index as u64 + COMPRESSION_OFFSET;
    file.seek(SeekFrom::Start(at)).unwrap();
    file.write_all(&QUANTUM_BITS.to_le_bytes()).unwrap();
}

/// Everything `read_entries` reported: the bodies that arrived, keyed by entry,
/// and the entries it refused.
///
/// Deliberately not a `Vec<u8>` per index: the point of several of these tests
/// is *which* entry each body was attributed to, and a sink that only collected
/// bytes would pass even if two entries swapped names.
#[derive(Default)]
struct Collector {
    current: Option<usize>,
    got: Vec<(usize, Vec<u8>)>,
    /// Entries whose `end` carried a failure. A refusal is a normal outcome of a
    /// batch pass — one unreadable file must not end the walk — so it is
    /// recorded rather than unwrapped.
    failed: Vec<usize>,
    /// Indices to answer `Skip` for.
    skip: Vec<usize>,
    /// Index to answer `Stop` for.
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
        if outcome.is_err() {
            self.failed.push(idx);
            self.got.retain(|(i, _)| *i != idx);
        }
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

#[test]
fn a_folder_whose_data_will_not_decode_fails_alone() {
    let cab = make_cab_folders(&[
        &[("readable.txt", b"this folder is MSZIP")],
        &[("locked.txt", b"this folder claims Quantum")],
        &[("also-readable.txt", b"and this one is MSZIP again")],
    ]);
    mark_folder_quantum(&cab, 1);

    let src = Source::path(cab.path()).unwrap();
    let mut ar = CabHandler.open(src, &OpenOptions::default()).unwrap();
    // Listing still works: names and sizes come from headers, which are not
    // compressed at all.
    let entries = ar.entries().unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[1].path, Path::new("locked.txt"));

    // The folder is labelled Quantum but holds MSZIP bytes, so the Quantum
    // decoder refuses them — a damaged archive, not an unsupported one.
    let err = ar.read_entry(1, &mut Vec::new()).unwrap_err();
    assert!(
        matches!(&err, Error::Corrupt(m) if m.contains("Quantum")),
        "ожидали отказ по испорченным данным, получили {err:?}"
    );

    // The batch pass reports that one refusal and keeps going.
    let mut sink = Collector::default();
    ar.read_entries(&[0, 1, 2], &mut sink).unwrap();
    assert_eq!(
        sink.got,
        vec![
            (0, b"this folder is MSZIP".to_vec()),
            (2, b"and this one is MSZIP again".to_vec()),
        ]
    );
    assert_eq!(sink.failed, vec![1]);
}

#[test]
fn extraction_reports_the_broken_folder_and_writes_the_rest() {
    let cab = make_cab_folders(&[
        &[("data\\ok.txt", b"written")],
        &[("data\\locked.txt", b"not written")],
    ]);
    mark_folder_quantum(&cab, 1);
    let dest = tempfile::tempdir().unwrap();
    let src = Source::path(cab.path()).unwrap();
    let mut ar = CabHandler.open(src, &OpenOptions::default()).unwrap();
    let report = extract_all(
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

    assert_eq!(
        std::fs::read(dest.path().join("data/ok.txt")).unwrap(),
        b"written"
    );
    // The refused entry leaves no file behind — a zero-length one wearing the
    // right name reads as success and is worse than the entry plainly missing.
    assert!(!dest.path().join("data/locked.txt").exists());
    assert_eq!(report.failed.len(), 1);
    assert_eq!(report.failed[0].0, Path::new("data/locked.txt"));
}

/// Replace `from` with `to` in the cabinet's bytes. Both must be the same
/// length, so nothing in the header moves.
///
/// This is how a non-UTF-8 name gets into a fixture at all: upstream's writer
/// takes a `&str`, and Rust has no way to hand it bytes that are not UTF-8
/// without undefined behaviour. Writing an ASCII placeholder and overwriting it
/// afterwards produces exactly the file a Windows packer would.
fn patch_bytes(cab: &tempfile::NamedTempFile, from: &[u8], to: &[u8]) {
    assert_eq!(from.len(), to.len(), "замена должна быть той же длины");
    let mut bytes = std::fs::read(cab.path()).unwrap();
    let at = bytes
        .windows(from.len())
        .position(|w| w == from)
        .expect("placeholder not found in the cabinet");
    bytes[at..at + to.len()].copy_from_slice(to);
    std::fs::write(cab.path(), bytes).unwrap();
}

#[test]
fn a_name_in_a_legacy_codepage_survives() {
    // CP1251 for "привет.txt" — a name a Windows packer writes with the UTF-8
    // flag clear. Read through `from_utf8_lossy`, as it was until 2026-08-07,
    // every one of those six bytes becomes U+FFFD and the name is gone for good.
    const CP1251: &[u8] = &[0xEF, 0xF0, 0xE8, 0xE2, 0xE5, 0xF2, b'.', b't', b'x', b't'];
    let cab = make_cab(&[("aaaaaa.txt", b"body")]);
    patch_bytes(&cab, b"aaaaaa.txt", CP1251);

    let src = Source::path(cab.path()).unwrap();
    let mut ar = CabHandler.open(src, &OpenOptions::default()).unwrap();
    let entries = ar.entries().unwrap();

    assert_eq!(entries[0].path_raw, CP1251, "сырые байты идут как есть");
    assert_eq!(entries[0].path, Path::new("привет.txt"));

    let mut out = Vec::new();
    ar.read_entry(0, &mut out).unwrap();
    assert_eq!(out, b"body");
}

#[test]
fn damage_in_a_later_block_is_reported_as_a_damaged_archive() {
    // A CAB data block holds at most 32 768 uncompressed bytes, so this file
    // spans two of them. Opening the folder decodes only the first; the second
    // is decoded while the body is poured out.
    let body: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();
    let cab = make_cab(&[("big.bin", &body)]);

    // Corrupt the tail — that is the second block's compressed data, and the
    // first block stays readable.
    let mut bytes = std::fs::read(cab.path()).unwrap();
    let tail = bytes.len() - 64;
    for b in &mut bytes[tail..] {
        *b ^= 0xFF;
    }
    std::fs::write(cab.path(), bytes).unwrap();

    let src = Source::path(cab.path()).unwrap();
    let mut ar = CabHandler.open(src, &OpenOptions::default()).unwrap();
    let err = ar.read_entry(0, &mut Vec::new()).unwrap_err();

    // `Error::Io` here would tell the person their disk is at fault for someone
    // else's damaged archive. Until this was fixed the promise held only for
    // one-block cabinets: the seek was classified, the body copy was not.
    assert!(
        matches!(&err, Error::Corrupt(_)),
        "ожидали «архив повреждён», получили {err:?}"
    );
}

// ── Quantum ──────────────────────────────────────────────────────────────────
//
// The three fixtures come from libmspack's own test suite (LGPL-2.1) and are
// the only Quantum cabinets to be had: nothing available writes the format, and
// the reference corpus holds none. The oracle for them is `cabextract`, which
// is libmspack — a different lineage from XADMaster, where our decoder is
// ported from, so agreement between the two means something.

/// One file per compression method: MSZIP, LZX and Quantum, 379 bytes in all.
const QUANTUM_MSZIP_LZX: &[u8] = include_bytes!("../fixtures/quantum_mszip_lzx.cab");
/// From CVE-2014-9556: a cabinet that sent the reference decoder into an
/// infinite loop.
const QUANTUM_CVE_2014_9556: &[u8] = include_bytes!("../fixtures/quantum_cve_2014_9556.cab");
/// From CVE-2018-18584: a block claiming the maximum size.
const QUANTUM_CVE_2018_18584: &[u8] = include_bytes!("../fixtures/quantum_cve_2018_18584.cab");

fn write_fixture(bytes: &[u8]) -> tempfile::NamedTempFile {
    let mut tmp = tempfile::Builder::new().suffix(".cab").tempfile().unwrap();
    tmp.write_all(bytes).unwrap();
    tmp.flush().unwrap();
    tmp
}

#[test]
fn quantum_decodes_beside_mszip_and_lzx() {
    let cab = write_fixture(QUANTUM_MSZIP_LZX);
    let src = Source::path(cab.path()).unwrap();
    let mut ar = CabHandler.open(src, &OpenOptions::default()).unwrap();

    let names: Vec<String> = ar
        .entries()
        .unwrap()
        .iter()
        .map(|e| e.path.to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["mszip.txt", "lzx.txt", "qtm.txt"]);

    // Byte for byte what `cabextract` produces from the same cabinet.
    let expected: [&[u8]; 3] = [
        b"If you can read this, the MSZIP decompressor is working!\n",
        b"-----------------------------------------------------------------\n\
          If you can read this, the LZX decompressor is working!\n\
          -----------------------------------------------------------------\n",
        b"If you can read this, the Quantum decompressor is working!\n",
    ];
    for (idx, want) in expected.iter().enumerate() {
        let mut got = Vec::new();
        ar.read_entry(idx, &mut got).unwrap();
        assert_eq!(&got, want, "запись {idx}");
    }
}

#[test]
fn quantum_survives_the_infinite_loop_sample() {
    // The archive declares a Quantum level of zero, which no cabinet may, so it
    // is turned away before a decoder is ever built. What matters is that it
    // returns at all.
    let cab = write_fixture(QUANTUM_CVE_2014_9556);
    let src = Source::path(cab.path()).unwrap();
    match CabHandler.open(src, &OpenOptions::default()) {
        Err(Error::Corrupt(m)) => assert!(m.contains("Quantum"), "неожиданная причина: {m}"),
        Err(other) => panic!("ожидали отказ по заголовку, получили {other:?}"),
        Ok(_) => panic!("испорченный архив открылся"),
    }
}

#[test]
fn quantum_refuses_the_max_size_block_sample_and_leaves_nothing_behind() {
    let cab = write_fixture(QUANTUM_CVE_2018_18584);
    let src = Source::path(cab.path()).unwrap();
    let mut ar = CabHandler.open(src, &OpenOptions::default()).unwrap();
    assert_eq!(ar.entries().unwrap().len(), 1);

    let err = ar.read_entry(0, &mut Vec::new()).unwrap_err();
    assert!(
        matches!(&err, Error::Corrupt(m) if m.contains("Quantum")),
        "ожидали отказ по испорченным данным, получили {err:?}"
    );

    // `cabextract` refuses this one too, but leaves a zero-length file wearing
    // the right name. Nothing is worse than that: it reads as success.
    let dest = tempfile::tempdir().unwrap();
    let src = Source::path(cab.path()).unwrap();
    let mut ar = CabHandler.open(src, &OpenOptions::default()).unwrap();
    let report = extract_all(
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
    assert_eq!(report.failed.len(), 1);
    assert!(!dest.path().join("arc/test1.bin").exists());
}
