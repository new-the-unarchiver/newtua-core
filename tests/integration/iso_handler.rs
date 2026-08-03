/// Integration tests for the ISO 9660 format handler.
///
/// Fixtures:
///   `tests/fixtures/sample.iso`   — Joliet-only, no Rock Ridge; created with pycdlib
///     hello.txt  (10 bytes: "hello iso\n")
///     sub/       (directory)
///     sub/inner.txt  (7 bytes: "nested\n")
///
///   `tests/fixtures/susp_er0.iso` — hdiutil makehybrid (ISO + Rock Ridge / SUSP IEEE_P1282);
///     triggers an `unimplemented!()` panic inside cdfs when traversed without the
///     catch_unwind guard.
use std::io::Cursor;
use std::path::Path;

use newtua_core::archive::{ArchiveReader, EntryKind, FormatId, OpenOptions};
use newtua_core::detect;
use newtua_core::error::Error;

fn fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Write `fixture(src)`'s bytes into a temp file named `dst` and open it.
fn open_renamed(
    src: &str,
    dst: &str,
) -> (
    tempfile::TempDir,
    newtua_core::error::Result<Box<dyn ArchiveReader>>,
) {
    let bytes = std::fs::read(fixture(src)).expect("read fixture");
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(dst);
    std::fs::write(&path, &bytes).expect("write renamed");
    let r = detect::open(&path, &OpenOptions::default());
    (dir, r)
}

#[test]
fn iso_content_under_wrong_extension_is_detected_by_content() {
    // A real ISO renamed away from `.iso`: the CD001 signature lives at 0x8001,
    // past the registry's 512-byte header peek, so detection must fall back to a
    // content probe rather than trusting the extension.
    let (_d, r) = open_renamed("sample.iso", "renamed.bin");
    let mut reader = r.expect("mislabeled iso must be detected by content");
    assert_eq!(reader.format(), FormatId::Iso);
    assert_eq!(reader.entries().expect("entries").len(), 3);
}

#[test]
fn other_format_named_iso_is_not_shadowed_by_iso_handler() {
    // A SquashFS image mislabeled with a `.iso` extension must open as SquashFS.
    // IsoHandler used to claim any `.iso` at full confidence, then fail its
    // CD001 check and mask the genuine content handler.
    let (_d, r) = open_renamed("tree-gzip.squashfs", "mislabeled.iso");
    let mut reader = r.expect("squashfs named .iso must open as squashfs");
    assert_eq!(reader.format(), FormatId::Squashfs);
    assert!(!reader.entries().expect("entries").is_empty());
}

#[test]
fn open_lists_root_file_and_subdirectory() {
    let opts = OpenOptions::default();
    let mut reader = detect::open(&fixture("sample.iso"), &opts).expect("open sample.iso");

    assert_eq!(reader.format(), FormatId::Iso);

    let entries = reader.entries().expect("entries");

    // There must be at least 3 entries: hello.txt, sub/, sub/inner.txt
    assert!(
        entries.len() >= 3,
        "expected at least 3 entries, got {}",
        entries.len()
    );

    // Find hello.txt
    let hello = entries
        .iter()
        .find(|e| e.path.to_str().unwrap_or("") == "hello.txt")
        .expect("hello.txt not found in entries");
    assert_eq!(hello.kind, EntryKind::File);
    assert_eq!(hello.size, 10, "hello.txt should be 10 bytes");

    // Find the sub directory
    let sub = entries
        .iter()
        .find(|e| e.path.to_str().unwrap_or("") == "sub")
        .expect("sub/ directory not found in entries");
    assert_eq!(sub.kind, EntryKind::Dir);

    // Find sub/inner.txt
    let inner = entries
        .iter()
        .find(|e| e.path == Path::new("sub/inner.txt"))
        .expect("sub/inner.txt not found in entries");
    assert_eq!(inner.kind, EntryKind::File);
    assert_eq!(inner.size, 7, "sub/inner.txt should be 7 bytes");
}

#[test]
fn read_root_file_content() {
    let opts = OpenOptions::default();
    let mut reader = detect::open(&fixture("sample.iso"), &opts).expect("open sample.iso");

    let entries = reader.entries().expect("entries");
    let idx = entries
        .iter()
        .position(|e| e.path.to_str().unwrap_or("") == "hello.txt")
        .expect("hello.txt not found");

    let mut buf = Vec::new();
    reader
        .read_entry(idx, &mut buf)
        .expect("read_entry hello.txt");
    assert_eq!(buf, b"hello iso\n");
}

#[test]
fn read_nested_file_content() {
    let opts = OpenOptions::default();
    let mut reader = detect::open(&fixture("sample.iso"), &opts).expect("open sample.iso");

    let entries = reader.entries().expect("entries");
    let idx = entries
        .iter()
        .position(|e| e.path == Path::new("sub/inner.txt"))
        .expect("sub/inner.txt not found");

    let mut buf = Vec::new();
    reader
        .read_entry(idx, &mut buf)
        .expect("read_entry sub/inner.txt");
    assert_eq!(buf, b"nested\n");
}

#[test]
fn invalid_index_returns_error() {
    let opts = OpenOptions::default();
    let mut reader = detect::open(&fixture("sample.iso"), &opts).expect("open sample.iso");
    let _entries = reader.entries().expect("entries");

    let result = reader.read_entry(9999, &mut Vec::new());
    assert!(
        matches!(result, Err(Error::InvalidIndex(9999))),
        "expected InvalidIndex, got: {result:?}"
    );
}

#[test]
fn fake_iso_file_returns_unknown_format() {
    use newtua_core::archive::FormatHandler;
    use newtua_core::archive::Source;
    use newtua_core::format::IsoHandler;

    // A file named .iso but without CD001 at 0x8001 → UnknownFormat
    // Create a buffer of 40960 bytes (> 0x8001+5) filled with zeros.
    let garbage = vec![0u8; 40960];
    let cursor = Cursor::new(garbage);
    let src = Source::Seekable {
        inner: Box::new(cursor),
        path: None,
    };
    let opts = OpenOptions::default();
    let result = IsoHandler.open(src, &opts);
    assert!(
        matches!(result, Err(Error::UnknownFormat)),
        "expected UnknownFormat for garbage .iso"
    );
}

/// Regression: opening an ISO produced by `hdiutil makehybrid` (Rock Ridge / SUSP
/// IEEE_P1282) must NOT panic the test process — it must return `Err` instead.
///
/// Fixture `susp_er0.iso` was created with:
///   mkdir -p /tmp/susproot && printf 'x\n' > /tmp/susproot/f.txt
///   hdiutil makehybrid -iso -o /tmp/susp_rr.iso /tmp/susproot
///
/// Without the catch_unwind guard, cdfs calls `unimplemented!()` in its SUSP parser
/// when it encounters the IEEE_P1282 Rock Ridge extension record, crashing the process.
#[test]
fn susp_er0_iso_returns_err_not_panic() {
    let path = fixture("susp_er0.iso");
    let opts = OpenOptions::default();
    let result = detect::open(&path, &opts);
    assert!(
        result.is_err(),
        "expected Err for susp_er0.iso (cdfs panics on SUSP IEEE_P1282), got Ok"
    );
    // Verify it is specifically a Corrupt error (from the catch_unwind guard),
    // not some other variant like UnknownFormat or Io.
    assert!(
        matches!(result, Err(Error::Corrupt(_))),
        "expected Err(Corrupt) for susp_er0.iso"
    );
}

/// Fix 2 regression: calling read_entry for the same file index twice must return
/// identical, complete bytes both times.
///
/// ISOFile::read() always creates a fresh ISOFileReader starting at seek=0, so
/// repeated reads are expected to work — this test locks in that guarantee.
#[test]
fn read_entry_twice_returns_identical_complete_bytes() {
    let opts = OpenOptions::default();
    let mut reader = detect::open(&fixture("sample.iso"), &opts).expect("open sample.iso");

    let entries = reader.entries().expect("entries");
    let idx = entries
        .iter()
        .position(|e| e.path.to_str().unwrap_or("") == "hello.txt")
        .expect("hello.txt not found");

    let mut buf1 = Vec::new();
    reader.read_entry(idx, &mut buf1).expect("first read_entry");

    let mut buf2 = Vec::new();
    reader
        .read_entry(idx, &mut buf2)
        .expect("second read_entry");

    assert_eq!(buf1, b"hello iso\n", "first read returned wrong content");
    assert_eq!(
        buf1, buf2,
        "second read returned different bytes than the first"
    );
}

// ── Rock Ridge permissions and per-record dates ──────────────────────────────

/// Seconds since the Unix epoch of an entry's `modified`, for comparing against
/// what an external reader reports.
fn mtime_secs(e: &newtua_core::archive::Entry) -> u64 {
    e.modified
        .expect("entry carries no mtime")
        .duration_since(std::time::UNIX_EPOCH)
        .expect("mtime is post-epoch")
        .as_secs()
}

/// `appimage_type1.AppImage` is an ISO 9660 image with Rock Ridge, so every
/// record carries a `PX` mode and a `TF` timestamp of its own. Files and
/// directories alike used to come out with `mode: None` and directories with no
/// date at all — an extracted `AppRun` lost its execute bit and every directory
/// was stamped with the moment of extraction.
///
/// The expected values are `xorriso`'s, not ours. Obtained with:
///   xorriso -osirrox on -indev <image> -extract / ref
///   TZ=UTC stat -f '%Sp %Sm %N' -t '%Y-%m-%d %H:%M:%S' ref/…
/// which restores `rwxrwxr-x` (files and directories) and dates that differ
/// between records: 03:39:02 for `.DirIcon`, 03:39:25 for `usr/`, 03:39:26 for
/// `AppRun`, all on 2016-01-09 UTC. That spread is the point — a single shared
/// date would pass a laxer assertion while proving nothing.
#[test]
fn rock_ridge_iso_reports_mode_and_per_record_dates() {
    let (_d, r) = open_renamed("appimage_type1.AppImage", "appimage.iso");
    let mut reader = r.expect("type-1 AppImage must open as an ISO");
    let entries = reader.entries().expect("entries");

    let by_path = |p: &str| {
        entries
            .iter()
            .find(|e| e.path == Path::new(p))
            .unwrap_or_else(|| panic!("{p} missing from the listing"))
    };

    for (path, mtime) in [
        (".DirIcon", 1_452_310_742),
        ("AppRun", 1_452_310_766),
        ("usr", 1_452_310_765),
        ("usr/bin", 1_452_310_765),
        ("usr/bin/xorriso", 1_452_310_766),
    ] {
        let e = by_path(path);
        assert_eq!(
            e.mode.map(|m| m & 0o7777),
            Some(0o775),
            "{path}: wrong permissions"
        );
        assert_eq!(mtime_secs(e), mtime, "{path}: wrong mtime");
    }

    // The type bits ride along with the permissions, the way cpio and HFS+ also
    // report them; `extract.rs::apply_mode` masks them off before use.
    assert_eq!(by_path("usr").mode.map(|m| m & 0o170000), Some(0o040000));
    assert_eq!(by_path("AppRun").mode.map(|m| m & 0o170000), Some(0o100000));
}

/// The other half of the same rule: `sample.iso` is Joliet-only, with no Rock
/// Ridge at all, so the image states no permissions. `None` is the honest
/// answer — inventing `0644` here would close a file the disc never said was
/// closed. Dates still come out, from the ISO 9660 recording timestamp, which is
/// all such an image has.
#[test]
fn iso_without_rock_ridge_reports_no_mode_but_still_reports_dates() {
    let opts = OpenOptions::default();
    let mut reader = detect::open(&fixture("sample.iso"), &opts).expect("open sample.iso");
    for e in reader.entries().expect("entries") {
        assert_eq!(e.mode, None, "{:?}: mode invented out of nothing", e.path);
        assert!(e.modified.is_some(), "{:?}: no recording date", e.path);
    }
}

// ── Runaway directory walks (D2) ─────────────────────────────────────────────
//
// The walk in `iso.rs` used to recurse with no depth cap and no memory of the
// extents it had already entered, skipping only the literal names "." and "..".
// A directory record that leads back where the walk came from therefore ran
// forever and overflowed the stack — an abort, not a panic, so nothing in the
// crate could catch it: the whole process died. These tests cover the three
// guards that replaced that: the empty-identifier filter, the depth cap, and the
// visited-extent set.

/// A real type-1 AppImage: an ELF runtime with an ISO 9660 filesystem behind it,
/// which `detect::open` routes here through the CD001 content probe. Its root
/// directory hands cdfs two records with an *empty* identifier — its own "." and
/// "..", which cdfs does not translate into dots. The old filter let them
/// through and the walk descended into the root again, forever.
///
/// The image is sound, so the fix is not an error: it is a correct listing.
#[test]
fn type1_appimage_named_iso_lists_instead_of_killing_the_process() {
    let (_d, r) = open_renamed("appimage_type1.AppImage", "appimage.iso");
    let mut reader = r.expect("type-1 AppImage must open as an ISO");
    assert_eq!(reader.format(), FormatId::Iso);
    let entries = reader.entries().expect("entries");

    // The real payload of AppImageExtract: a runtime, an icon, a .desktop file
    // and a usr/ tree. An exact count pins that we neither lose entries nor
    // invent them.
    assert_eq!(entries.len(), 12, "unexpected listing: {entries:#?}");
    for wanted in ["AppRun", "usr", "usr/bin/xorriso"] {
        assert!(
            entries.iter().any(|e| e.path == Path::new(wanted)),
            "{wanted} missing from the listing"
        );
    }

    // No entry may carry an empty final component — that is exactly what the
    // untranslated "." / ".." records used to produce ("usr/", "usr/bin/", …).
    for e in entries {
        assert!(
            !e.path.as_os_str().is_empty()
                && e.path
                    .file_name()
                    .is_some_and(|n| !n.is_empty() && n != "." && n != ".."),
            "self/parent record leaked into the listing: {:?}",
            e.path
        );
    }
}

// ── Synthetic images built from `sample.iso` ─────────────────────────────────
//
// Rather than ship new fixtures, these rewrite the real image: its directory
// records are copied verbatim and only the extent locations are changed, so cdfs
// parses the result exactly as it parses the original.

const BLOCK: usize = 2048;

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes(b[..4].try_into().expect("4 bytes"))
}

/// Both halves of a both-endian extent location live at record offsets 2 (LE)
/// and 6 (BE); cdfs reads the little-endian one, but write both so the image
/// stays well-formed.
fn set_extent(bytes: &mut [u8], rec: usize, lba: u32) {
    bytes[rec + 2..rec + 6].copy_from_slice(&lba.to_le_bytes());
    bytes[rec + 6..rec + 10].copy_from_slice(&lba.to_be_bytes());
}

/// LBA of the directory extent cdfs walks as the root: the Supplementary
/// (Joliet) volume descriptor's root record when the image has one — which
/// `sample.iso` does — otherwise the Primary's. The root record sits at offset
/// 156 of the descriptor.
fn root_extent(bytes: &[u8]) -> u32 {
    let (mut lba, mut primary, mut supplementary) = (16usize, None, None);
    loop {
        let s = &bytes[lba * BLOCK..(lba + 1) * BLOCK];
        match s[0] {
            1 => primary = Some(le32(&s[158..])),
            2 => supplementary = Some(le32(&s[158..])),
            255 => break,
            _ => {}
        }
        lba += 1;
    }
    supplementary.or(primary).expect("a volume descriptor")
}

/// Offset (in `bytes`) of the first real subdirectory record inside the
/// directory extent at `lba` — `sub/` in `sample.iso`. `.` and `..` are the
/// records whose identifier is the single byte 0x00 / 0x01; the directory flag
/// is bit 1 of the file-flags byte at record offset 25.
fn find_subdir_record(bytes: &[u8], lba: u32) -> usize {
    let base = lba as usize * BLOCK;
    let mut off = 0;
    while off < BLOCK {
        let len = bytes[base + off] as usize;
        if len == 0 {
            break;
        }
        let rec = &bytes[base + off..base + off + len];
        let id = &rec[33..33 + rec[32] as usize];
        if rec[25] & 0x02 != 0 && id != [0] && id != [1] {
            return base + off;
        }
        off += len;
    }
    panic!("no subdirectory record in extent {lba}");
}

/// `sample.iso` with its `sub/` record repointed at a freshly appended chain of
/// `depth` directories, one per extent, each named `sub` and each holding the
/// next. Distinct extents throughout, so the visited-extent set cannot
/// short-circuit the descent — only the depth cap can stop it.
fn iso_nested(depth: u32) -> Vec<u8> {
    let mut bytes = std::fs::read(fixture("sample.iso")).expect("read fixture");
    assert_eq!(bytes.len() % BLOCK, 0, "fixture must be block-aligned");

    let root = root_extent(&bytes);
    let root_base = root as usize * BLOCK;
    // `.` and `..` are the first two records of any directory extent; copy them
    // (and the `sub` record) rather than synthesising records by hand.
    let dot_len = bytes[root_base] as usize;
    let dotdot_len = bytes[root_base + dot_len] as usize;
    let dot = bytes[root_base..root_base + dot_len].to_vec();
    let dotdot = bytes[root_base + dot_len..root_base + dot_len + dotdot_len].to_vec();
    let sub_off = find_subdir_record(&bytes, root);
    let sub = bytes[sub_off..sub_off + bytes[sub_off] as usize].to_vec();

    let base = u32::try_from(bytes.len() / BLOCK).expect("lba fits u32");
    for i in 0..depth {
        let mut sector = Vec::with_capacity(BLOCK);
        sector.extend_from_slice(&dot);
        sector.extend_from_slice(&dotdot);
        if i + 1 < depth {
            sector.extend_from_slice(&sub);
        }
        set_extent(&mut sector, 0, base + i);
        set_extent(
            &mut sector,
            dot_len,
            if i == 0 { root } else { base + i - 1 },
        );
        if i + 1 < depth {
            set_extent(&mut sector, dot_len + dotdot_len, base + i + 1);
        }
        sector.resize(BLOCK, 0);
        bytes.extend_from_slice(&sector);
    }
    set_extent(&mut bytes, sub_off, base);
    bytes
}

/// Write `bytes` as an `.iso` into a temp dir and open it.
fn open_bytes_as_iso(
    bytes: &[u8],
) -> (
    tempfile::TempDir,
    newtua_core::error::Result<Box<dyn ArchiveReader>>,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("synthetic.iso");
    std::fs::write(&path, bytes).expect("write synthetic iso");
    let r = detect::open(&path, &OpenOptions::default());
    (dir, r)
}

/// Control for the test below: the same builder, at a depth no cap objects to,
/// must produce a walkable image. Without this, a rejection at depth 300 would
/// prove nothing — it could just as well mean the builder emits garbage.
#[test]
fn shallow_nested_iso_walks_every_level() {
    let (_d, r) = open_bytes_as_iso(&iso_nested(10));
    let mut reader = r.expect("a 10-level image must open");
    let entries = reader.entries().expect("entries");
    let deepest = "sub/".repeat(9) + "sub";
    assert!(
        entries.iter().any(|e| e.path == Path::new(&deepest)),
        "deepest level missing; got {:?}",
        entries.iter().map(|e| &e.path).collect::<Vec<_>>()
    );
}

/// 64 levels is past the 32-level cap, and every level sits in its own extent,
/// so nothing but the depth guard can stop the descent. Before the fix this
/// aborted the process; the assertion on the message is what keeps the test
/// honest — any *other* error would mean the guard never fired.
#[test]
fn deeply_nested_iso_is_rejected_by_the_depth_cap() {
    let (_d, r) = open_bytes_as_iso(&iso_nested(64));
    let err = r.err().expect("a 300-level image must be rejected");
    match err {
        Error::Corrupt(ref msg) => assert!(msg.contains("too deep"), "wrong Corrupt: {msg}"),
        other => panic!("expected Corrupt(\"…too deep\"), got {other:?}"),
    }
}

/// A directory record naming its own parent extent as its child: the cycle has
/// no bottom, and the names are ordinary, so neither the "."/".." filter nor the
/// depth cap sees anything odd until the stack is gone. The visited-extent set
/// is what ends it — the record is still listed, it is just not entered twice.
#[test]
fn self_referencing_directory_does_not_recurse_forever() {
    let mut bytes = std::fs::read(fixture("sample.iso")).expect("read fixture");
    let root = root_extent(&bytes);
    let sub_off = find_subdir_record(&bytes, root);
    set_extent(&mut bytes, sub_off, root); // sub/ now *is* the root

    let (_d, r) = open_bytes_as_iso(&bytes);
    let mut reader = r.expect("a self-referencing directory must not fail the open");
    let entries = reader.entries().expect("entries");
    assert!(
        entries.iter().any(|e| e.path == Path::new("sub")),
        "the looping record must still be listed"
    );
    // `Path::starts_with` compares whole components, so "sub" itself matches
    // "sub" — what must not appear is anything *below* it.
    assert!(
        !entries
            .iter()
            .any(|e| e.path.starts_with("sub") && e.path != Path::new("sub")),
        "the walk must not descend into an extent it already entered: {:?}",
        entries.iter().map(|e| &e.path).collect::<Vec<_>>()
    );
}
