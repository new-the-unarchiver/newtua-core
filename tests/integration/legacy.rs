//! End-to-end wiring tests for the `newtua-formats` legacy adapters
//! (`format/legacy/`). The upstream crates' own oracle tests prove decode
//! correctness (cross-checked against `unar`); these tests prove the core
//! adapters: detection routing, entry listing, and index extraction through
//! `LegacyReader`.
//!
//! ARC gives full end-to-end coverage across every method (stored, LZW,
//! Crunch, Crush, Squashed) and, since every legacy handler shares the same
//! `LegacyReader`/`legacy_std_handler!` path, exercises the wiring the other
//! `newtua-dos` containers (ARJ/Zoo/LBR/Crunch) reuse. Those four plus Squeeze
//! have no committed binary fixtures upstream (their oracle tests build inputs
//! programmatically), so here they are covered by detection + registration
//! smoke tests only — flagged in report-*.md.

use newtua_core::detect::registry;
use newtua_core::format::{
    ArcHandler, ArjHandler, CrunchHandler, LbrHandler, NsisHandler, SqueezeHandler, ZooHandler,
};
use newtua_core::{Confidence, FormatHandler, FormatId, OpenOptions};

fn fixture(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/legacy")
        .join(name)
}

/// Open a fixture through the full detection path (`newtua_core::open`).
fn open_detected(name: &str) -> Box<dyn newtua_core::ArchiveReader> {
    newtua_core::open(&fixture(name), &OpenOptions::default()).unwrap()
}

fn read(ar: &mut dyn newtua_core::ArchiveReader, idx: usize) -> Vec<u8> {
    let mut out = Vec::new();
    ar.read_entry(idx, &mut out).unwrap();
    out
}

// ---- ARC: full end-to-end via the detection path ----------------------------

#[test]
fn arc_detected_as_arc_format() {
    let ar = open_detected("multi.arc");
    assert_eq!(ar.format(), FormatId::Arc);
}

#[test]
fn arc_multi_lists_and_extracts_stored_members() {
    let mut ar = open_detected("multi.arc");
    let names: Vec<String> = ar
        .entries()
        .unwrap()
        .iter()
        .map(|e| e.path.to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["a", "p.txt", "s"]);
    assert_eq!(read(&mut *ar, 0), b"A");
    assert_eq!(read(&mut *ar, 1), b"abcdef");
    assert_eq!(read(&mut *ar, 2), b"A");
}

#[test]
fn arc_crunch_methods_extract_named_members() {
    let mut ar = open_detected("crunch.arc");
    let entries = ar.entries().unwrap().to_vec();
    assert_eq!(entries.len(), 4);
    assert_eq!(entries[0].path.to_str().unwrap(), "readme");
    assert_eq!(read(&mut *ar, 0), b"stored anchor");
    // c5.txt is a 65-byte run-pattern compressed with method 5 (no RLE90).
    assert_eq!(
        read(&mut *ar, 1),
        b"AAAAAAAAAA BBBBBBBBBB AAAAAAAAAA BBBBBBBBBB AAAAAAAAAA CCCCCCCCCC"
    );
}

#[test]
fn arc_crush_methods_extract_and_match_sizes() {
    let mut ar = open_detected("crush.arc");
    let entries = ar.entries().unwrap().to_vec();
    assert_eq!(
        entries
            .iter()
            .map(|e| e.path.to_str().unwrap())
            .collect::<Vec<_>>(),
        ["anchor", "small", "rep", "nolit", "repl"]
    );
    assert_eq!(read(&mut *ar, 0), b"A");
    // `rep` is "abc" repeated (168 bytes / 3).
    assert_eq!(read(&mut *ar, 2), b"abc".repeat(56));
    // Every member extracts to exactly its reported size.
    for (i, e) in entries.iter().enumerate() {
        assert_eq!(read(&mut *ar, i).len() as u64, e.size, "member {i}");
    }
}

/// The universal wiring invariant across every ARC fixture / method: each
/// member extracts, and its byte count equals the listed size.
#[test]
fn arc_every_member_extracts_to_its_size() {
    for name in [
        "multi.arc",
        "lzw.arc",
        "cmp.arc",
        "crunch.arc",
        "clear.arc",
        "crush.arc",
    ] {
        let mut ar = open_detected(name);
        let entries = ar.entries().unwrap().to_vec();
        assert!(!entries.is_empty(), "{name} listed no entries");
        for (i, e) in entries.iter().enumerate() {
            assert_eq!(read(&mut *ar, i).len() as u64, e.size, "{name} member {i}");
        }
    }
}

#[test]
fn arc_read_entry_out_of_range_is_invalid_index() {
    let mut ar = open_detected("multi.arc");
    ar.entries().unwrap();
    let err = ar.read_entry(99, &mut Vec::new()).unwrap_err();
    assert!(matches!(err, newtua_core::Error::InvalidIndex(99)));
}

// ---- Registration + detection smoke for the fixture-less dos formats ---------

/// All six newtua-dos formats are registered in the detection registry.
#[test]
fn dos_formats_are_registered() {
    let ids: Vec<FormatId> = registry().iter().map(|h| h.id()).collect();
    for id in [
        FormatId::Arj,
        FormatId::Zoo,
        FormatId::Lbr,
        FormatId::Crunch,
        FormatId::Arc,
        FormatId::Squeeze,
    ] {
        assert!(ids.contains(&id), "{id:?} not registered");
    }
}

/// All five newtua-mac formats are registered. No committed binary fixtures
/// exist upstream (their oracle tests build inputs in-process), so mac coverage
/// is registration-level; the extract wiring is the shared `LegacyReader` path
/// exercised end-to-end by ARC above.
#[test]
fn mac_formats_are_registered() {
    let ids: Vec<FormatId> = registry().iter().map(|h| h.id()).collect();
    for id in [
        FormatId::BinHex,
        FormatId::MacBinary,
        FormatId::AppleSingle,
        FormatId::CompactPro,
        FormatId::PackIt,
    ] {
        assert!(ids.contains(&id), "{id:?} not registered");
    }
}

/// All three StuffIt-family formats are registered (fixture-less upstream, so
/// registration-level like mac; extract wiring is the shared `LegacyReader`).
#[test]
fn stuffit_formats_are_registered() {
    let ids: Vec<FormatId> = registry().iter().map(|h| h.id()).collect();
    for id in [FormatId::StuffIt, FormatId::StuffIt5, FormatId::StuffItX] {
        assert!(ids.contains(&id), "{id:?} not registered");
    }
}

// ---- PowerPacker: full end-to-end via the detection path --------------------

/// PowerPacker carries no internal name — the single entry is named from the
/// source stem (`hello.pp` → `hello`) and decodes to the known payload.
#[test]
fn powerpacker_detects_lists_and_extracts() {
    let mut ar = open_detected("hello.pp");
    assert_eq!(ar.format(), FormatId::PowerPacker);
    let entries = ar.entries().unwrap().to_vec();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path.to_str().unwrap(), "hello");
    assert_eq!(read(&mut *ar, 0), b"Hello, PowerPacker!");
    // The reported size matches the decrunched length.
    assert_eq!(entries[0].size, 19);
}

/// The three Amiga formats are registered. PowerPacker has a real fixture
/// (tested above); LZX and DMS are registration-level (no committed fixtures).
#[test]
fn amiga_formats_are_registered() {
    let ids: Vec<FormatId> = registry().iter().map(|h| h.id()).collect();
    for id in [FormatId::PowerPacker, FormatId::Lzx, FormatId::Dms] {
        assert!(ids.contains(&id), "{id:?} not registered");
    }
}

/// ALZip and NSIS are registered. ALZ detects by recognize/`.alz`; NSIS is
/// dispatched by the `MZ` early branch in `detect::open`, so its handler probe
/// is `NONE` (no committed fixtures upstream — registration-level coverage).
#[test]
fn alz_and_nsis_are_registered() {
    let ids: Vec<FormatId> = registry().iter().map(|h| h.id()).collect();
    assert!(ids.contains(&FormatId::Alz));
    assert!(ids.contains(&FormatId::Nsis));
}

/// NSIS's handler probe never fires (dispatch is the `MZ` early branch).
#[test]
fn nsis_probe_is_none() {
    assert_eq!(
        NsisHandler.probe(b"MZ\x90\x00", Some("setup.exe")),
        Confidence::NONE
    );
}

/// Extension-detected formats (ARC, Squeeze) probe MAGIC on their extensions.
#[test]
fn ext_detected_formats_probe_by_extension() {
    assert_eq!(ArcHandler.probe(b"", Some("old.arc")), Confidence::MAGIC);
    assert_eq!(ArcHandler.probe(b"", Some("old.pak")), Confidence::MAGIC);
    assert_eq!(SqueezeHandler.probe(b"", Some("old.sq")), Confidence::MAGIC);
    // Squeeze also sniffs its `0x76 0xFF` lead magic.
    assert_eq!(SqueezeHandler.probe(&[0x76, 0xFF], None), Confidence::MAGIC);
}

/// Content-sniffed formats don't false-positive on a bare/mis-named input
/// (they carry no extension fallback, so garbage → NONE, no panic).
#[test]
fn content_sniffed_formats_reject_garbage() {
    let garbage = b"not an archive at all, just some text bytes here";
    assert_eq!(ArjHandler.probe(garbage, Some("x.arj")), Confidence::NONE);
    assert_eq!(ZooHandler.probe(garbage, Some("x.zoo")), Confidence::NONE);
    assert_eq!(LbrHandler.probe(garbage, Some("x.lbr")), Confidence::NONE);
    assert_eq!(CrunchHandler.probe(garbage, None), Confidence::NONE);
}

// ── Ресурсные вилки ───────────────────────────────────────────────────────

/// Собрать AppleSingle из секций `(id, байты)`. Раскладка та же, что у
/// upstream: магия, версия, шестнадцать нулей, число секций, таблица
/// дескрипторов, тела подряд. Идентификаторы: 1 — вилка данных, 2 — вилка
/// ресурсов, 3 — настоящее имя.
fn build_applesingle(sections: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let n = sections.len();
    let table = 26 + 12 * n;
    let mut out = vec![0u8; table];
    out[0..4].copy_from_slice(&0x0005_1600u32.to_be_bytes());
    out[4..8].copy_from_slice(&0x0002_0000u32.to_be_bytes());
    out[24..26].copy_from_slice(&(n as u16).to_be_bytes());
    let mut off = table;
    let mut body = Vec::new();
    for (i, (id, sec)) in sections.iter().enumerate() {
        let d = 26 + i * 12;
        out[d..d + 4].copy_from_slice(&id.to_be_bytes());
        out[d + 4..d + 8].copy_from_slice(&(off as u32).to_be_bytes());
        out[d + 8..d + 12].copy_from_slice(&(sec.len() as u32).to_be_bytes());
        body.extend_from_slice(sec);
        off += sec.len();
    }
    out.extend_from_slice(&body);
    out
}

/// Ресурсная вилка должна доехать до диска, а не потеряться по дороге.
///
/// У файла классического Mac два независимых содержимого: вилка данных и
/// вилка ресурсов. У картинки или программы в ресурсной вилке лежит почти
/// весь файл, а иногда и весь целиком. Форматы того времени отдают их двумя
/// записями с **одним именем**, и если признак вилки потерять, до диска
/// доедет только одна из двух — молча.
///
/// Здесь вилка ресурсов вчетверо больше вилки данных: если правка отвалится,
/// эти байты просто исчезнут.
#[test]
fn resource_fork_reaches_the_disk() {
    let data = b"the data fork".to_vec();
    let rsrc: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    let file = build_applesingle(&[
        (3, b"picture.pct".to_vec()),
        (1, data.clone()),
        (2, rsrc.clone()),
    ]);

    let tmp = tempfile::tempdir().expect("tempdir");
    let src = tmp.path().join("carrier.bin");
    std::fs::write(&src, &file).expect("write fixture");

    let mut ar = newtua_core::open(&src, &OpenOptions::default()).expect("open applesingle");

    // Обе вилки видны в листинге как две записи с одним именем, и различает их
    // только признак.
    let entries = ar.entries().expect("entries").to_vec();
    let forks: Vec<_> = entries.iter().filter(|e| e.is_resource_fork).collect();
    assert_eq!(forks.len(), 1, "ровно одна запись — ресурсная вилка");
    assert_eq!(forks[0].size, rsrc.len() as u64);
    let plain: Vec<_> = entries.iter().filter(|e| !e.is_resource_fork).collect();
    assert_eq!(plain.len(), 1, "и ровно одна — сам файл");
    assert_eq!(plain[0].path, forks[0].path, "имя у них общее");

    let dest = tmp.path().join("out");
    let mut xo = newtua_core::ExtractOptions {
        dest: dest.clone(),
        wrapper_name: None,
        strict: false,
        preserve: true,
        selection: None,
        progress: None,
        keep_macos_metadata: false,
    };
    let rep = newtua_core::extract_all(ar.as_mut(), &mut xo).expect("extract");
    assert!(
        rep.failed.is_empty(),
        "ничего не должно отказать: {:?}",
        rep.failed
    );

    let written = dest.join("picture.pct");
    assert_eq!(std::fs::read(&written).expect("данные на месте"), data);

    #[cfg(target_os = "macos")]
    {
        // На macOS вилка ложится внутрь самого файла — как её и клал упаковщик.
        let fork_path = written.join("..namedfork").join("rsrc");
        assert_eq!(
            std::fs::read(&fork_path).expect("вилка внутри файла"),
            rsrc,
            "ресурсная вилка должна дойти целиком"
        );
        assert!(
            !dest.join("._picture.pct").exists(),
            "рядом ничего лишнего появляться не должно"
        );
    }

    #[cfg(not(target_os = "macos"))]
    {
        // Там, где вилок нет, — контейнер AppleDouble, как его пишет сама
        // macOS: 38 байт заголовка, дальше байты вилки.
        let sidecar = std::fs::read(dest.join("._picture.pct")).expect("файл рядом");
        assert_eq!(
            &sidecar[0..4],
            &0x0005_1607u32.to_be_bytes(),
            "магия AppleDouble"
        );
        assert_eq!(&sidecar[4..8], &0x0002_0000u32.to_be_bytes(), "версия 2");
        assert_eq!(&sidecar[24..26], &1u16.to_be_bytes(), "одна секция");
        assert_eq!(
            &sidecar[26..30],
            &2u32.to_be_bytes(),
            "и это ресурсная вилка"
        );
        assert_eq!(
            &sidecar[38..],
            &rsrc[..],
            "байты вилки следом за заголовком"
        );
    }
}

// ---- StuffIt 5: encryption is announced, and checked before any writing -----
//
// `encrypted.sit` is a one-file StuffIt 5 archive (`secret.txt`, RC4 + MD5,
// password `opensesame`), built by the mirror builder in `newtua-stuffit`'s own
// `sit5_oracle` test — the same builder whose output `unar` extracts correctly,
// so the container is not merely self-consistent.

const SIT5_PASSWORD: &str = "opensesame";

fn extract_opts(dest: &std::path::Path) -> newtua_core::ExtractOptions {
    newtua_core::ExtractOptions {
        dest: dest.to_path_buf(),
        wrapper_name: Some("out".into()),
        strict: false,
        preserve: false,
        selection: None,
        progress: None,
        keep_macos_metadata: false,
    }
}

#[test]
fn encrypted_stuffit5_entries_are_marked_encrypted() {
    // Without this flag `extract_all` never calls `verify_password` at all, and
    // every guarantee below is silently inert.
    let mut ar = open_detected("encrypted.sit");
    assert_eq!(ar.format(), FormatId::StuffIt5);
    let entries = ar.entries().unwrap();
    assert!(
        entries.iter().any(|e| e.is_encrypted),
        "no entry reports encryption: {entries:#?}"
    );
}

#[test]
fn encrypted_stuffit5_without_password_writes_nothing() {
    let dest = tempfile::tempdir().unwrap();
    let mut ar = open_detected("encrypted.sit");
    let err = newtua_core::extract_all(&mut *ar, &mut extract_opts(dest.path())).unwrap_err();
    assert!(
        matches!(err, newtua_core::Error::Encrypted),
        "expected Encrypted, got {err:?}"
    );
    assert!(
        std::fs::read_dir(dest.path()).unwrap().next().is_none(),
        "a failed password check must leave the destination untouched"
    );
}

#[test]
fn encrypted_stuffit5_with_wrong_password_writes_nothing() {
    let dest = tempfile::tempdir().unwrap();
    let opts = OpenOptions {
        password: Some("WRONG".into()),
        encoding_override: None,
    };
    let mut ar = newtua_core::open(&fixture("encrypted.sit"), &opts).unwrap();
    let err = newtua_core::extract_all(&mut *ar, &mut extract_opts(dest.path())).unwrap_err();
    assert!(
        matches!(err, newtua_core::Error::WrongPassword),
        "expected WrongPassword, got {err:?}"
    );
    assert!(
        std::fs::read_dir(dest.path()).unwrap().next().is_none(),
        "a wrong password must leave the destination untouched"
    );
}

#[test]
fn encrypted_stuffit5_with_the_right_password_extracts() {
    // The control: without it, "writes nothing" could be satisfied by an
    // extractor that never writes anything at all.
    let dest = tempfile::tempdir().unwrap();
    let opts = OpenOptions {
        password: Some(SIT5_PASSWORD.into()),
        encoding_override: None,
    };
    let mut ar = newtua_core::open(&fixture("encrypted.sit"), &opts).unwrap();
    newtua_core::extract_all(&mut *ar, &mut extract_opts(dest.path())).unwrap();
    // The archive holds one loose entry, so `extract_all` wraps it in a folder
    // named after `wrapper_name`.
    assert_eq!(
        std::fs::read(dest.path().join("out/secret.txt")).unwrap(),
        b"classified payload\n"
    );
}
