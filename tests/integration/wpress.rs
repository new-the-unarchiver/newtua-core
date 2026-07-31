//! WPRESS (`.wpress`) — дамп сайта WordPress, который пишет плагин
//! All-in-One WP Migration: цепочка записей «заголовок фиксированной длины +
//! сырое содержимое», без сжатия.
//!
//! Фикстура `site.wpress` порождена скриптом ниже и **прочитана эталонным
//! распаковщиком Keka** (`kwet`) — он выдал ровно те же три файла с теми же
//! путями и байтами:
//!
//! ```sh
//! python3 - <<'PY'
//! NAME, SIZE, MTIME, PREFIX = 255, 14, 12, 4096
//! HDR = NAME + SIZE + MTIME + PREFIX          # 4377
//! def f(v, w): assert len(v) <= w; return v + b"\0" * (w - len(v))
//! def rec(name, prefix, data, mtime=1750000000):
//!     return (f(name.encode(), NAME) + f(str(len(data)).encode(), SIZE)
//!             + f(str(mtime).encode(), MTIME) + f(prefix.encode(), PREFIX) + data)
//! blob = b"".join([
//!     rec("readme.txt", ".", b"hello wpress\n"),
//!     rec("index.php", "wp-content", b"<?php echo 'hi';\n"),
//!     rec("style.css", "wp-content/themes/kek", b"body{color:red}\n"),
//! ]) + b"\0" * HDR
//! open("site.wpress", "wb").write(blob)
//! PY
//! /Applications/Keka.app/Contents/MacOS/Keka --ignore-file-access --cli kwet -o out site.wpress
//! ```

use std::io::Write;
use std::path::Path;

use newtua_core::archive::{ArchiveReader, EntryKind, FormatId, OpenOptions};
use newtua_core::detect::open;
use newtua_core::error::Error;
use newtua_core::extract::{ExtractOptions, extract_all};

const SITE: &[u8] = include_bytes!("../fixtures/site.wpress");

// ── Разбивка заголовка, подтверждённая эталоном ──────────────────────────────
//
// Смещения проверены на `kwet` (см. отчёт по тикету): файл, где каждое поле
// заполнено до последнего байта (имя 255 символов, размер 14 цифр, время
// 12 цифр), читается эталоном без ошибок, а многозаписный файл сходится по
// шагу 4377 байт.
const NAME_LEN: usize = 255;
const SIZE_LEN: usize = 14;
const MTIME_LEN: usize = 12;
const PREFIX_LEN: usize = 4096;
const HEADER_LEN: usize = NAME_LEN + SIZE_LEN + MTIME_LEN + PREFIX_LEN;

/// Собрать одну запись: заголовок + тело. Поля дополняются нулями справа.
/// `size` передаётся строкой отдельно от `data`, чтобы можно было соврать.
fn record(name: &[u8], size: &[u8], mtime: &[u8], prefix: &[u8], data: &[u8]) -> Vec<u8> {
    fn field(v: &[u8], w: usize) -> Vec<u8> {
        assert!(v.len() <= w);
        let mut out = v.to_vec();
        out.resize(w, 0);
        out
    }
    let mut out = field(name, NAME_LEN);
    out.extend_from_slice(&field(size, SIZE_LEN));
    out.extend_from_slice(&field(mtime, MTIME_LEN));
    out.extend_from_slice(&field(prefix, PREFIX_LEN));
    out.extend_from_slice(data);
    out
}

/// Хвостовой блок «конец архива» — заголовок из одних нулей.
fn eof_block() -> Vec<u8> {
    vec![0u8; HEADER_LEN]
}

fn write_tmp(dir: &Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let p = dir.join(name);
    let mut f = std::fs::File::create(&p).expect("create");
    f.write_all(bytes).expect("write");
    p
}

fn body_of(reader: &mut dyn ArchiveReader, name: &str) -> Vec<u8> {
    let idx = {
        let entries = reader.entries().expect("entries");
        entries
            .iter()
            .position(|e| e.path == Path::new(name))
            .unwrap_or_else(|| panic!("entry {name} not found"))
    };
    let mut body = Vec::new();
    reader.read_entry(idx, &mut body).expect("read_entry");
    body
}

// ── Счастливый путь ──────────────────────────────────────────────────────────

#[test]
fn wpress_lists_nested_paths() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_tmp(dir.path(), "site.wpress", SITE);
    let mut reader = open(&path, &OpenOptions::default()).expect("open wpress");
    assert_eq!(reader.format(), FormatId::Wpress);

    let entries = reader.entries().expect("entries").to_vec();
    let names: Vec<String> = entries
        .iter()
        .map(|e| e.path.to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        names,
        vec![
            "readme.txt".to_string(),
            "wp-content/index.php".to_string(),
            "wp-content/themes/kek/style.css".to_string(),
        ]
    );
    assert!(entries.iter().all(|e| e.kind == EntryKind::File));
    assert_eq!(entries[0].size, 13);
    assert_eq!(entries[1].size, 17);
    assert_eq!(entries[2].size, 16);
    // Время правки — поле заголовка, 1750000000 = 15 июня 2025.
    let modified = entries[0].modified.expect("mtime present");
    let secs = modified
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert_eq!(secs, 1_750_000_000);
}

#[test]
fn wpress_reads_bodies_byte_for_byte() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_tmp(dir.path(), "site.wpress", SITE);
    let mut reader = open(&path, &OpenOptions::default()).expect("open wpress");
    assert_eq!(body_of(reader.as_mut(), "readme.txt"), b"hello wpress\n");
    assert_eq!(
        body_of(reader.as_mut(), "wp-content/index.php"),
        b"<?php echo 'hi';\n"
    );
    assert_eq!(
        body_of(reader.as_mut(), "wp-content/themes/kek/style.css"),
        b"body{color:red}\n"
    );
    // Повторное чтение той же записи даёт то же самое (курсор не «съеден»).
    assert_eq!(body_of(reader.as_mut(), "readme.txt"), b"hello wpress\n");
}

#[test]
fn wpress_extracts_tree_to_disk() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_tmp(dir.path(), "site.wpress", SITE);
    let dest = tempfile::tempdir().unwrap();
    let mut reader = open(&path, &OpenOptions::default()).expect("open wpress");
    let report = extract_all(
        &mut *reader,
        &mut ExtractOptions {
            dest: dest.path().to_path_buf(),
            wrapper_name: None,
            strict: false,
            preserve: true,
            selection: None,
            progress: None,
            keep_macos_metadata: false,
        },
    )
    .expect("extract");
    assert_eq!(report.failed.len(), 0);
    assert_eq!(
        std::fs::read(dest.path().join("wp-content/themes/kek/style.css")).unwrap(),
        b"body{color:red}\n"
    );
}

// ── Опознание формата ────────────────────────────────────────────────────────

#[test]
fn wpress_extension_with_garbage_is_unknown_format() {
    let dir = tempfile::tempdir().unwrap();
    // Случайно выглядящие байты: поля заголовка не разбираются.
    let garbage: Vec<u8> = (0..9000u32)
        .map(|i| (i.wrapping_mul(37) % 251) as u8 + 1)
        .collect();
    let path = write_tmp(dir.path(), "junk.wpress", &garbage);
    let err = open(&path, &OpenOptions::default())
        .err()
        .expect("must err");
    assert!(matches!(err, Error::UnknownFormat), "got {err:?}");
}

#[test]
fn wpress_non_numeric_size_field_is_unknown_format() {
    let dir = tempfile::tempdir().unwrap();
    let mut blob = record(b"a.txt", b"NOTANUMBER", b"1750000000", b".", b"hi\n");
    blob.extend_from_slice(&eof_block());
    let path = write_tmp(dir.path(), "badsize.wpress", &blob);
    let err = open(&path, &OpenOptions::default())
        .err()
        .expect("must err");
    assert!(matches!(err, Error::UnknownFormat), "got {err:?}");
}

#[test]
fn wpress_empty_file_is_unknown_format() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_tmp(dir.path(), "empty.wpress", b"");
    let err = open(&path, &OpenOptions::default())
        .err()
        .expect("must err");
    assert!(matches!(err, Error::UnknownFormat), "got {err:?}");
}

// ── Битые и враждебные файлы ─────────────────────────────────────────────────

#[test]
fn truncated_wpress_is_error_not_panic() {
    let dir = tempfile::tempdir().unwrap();
    // Первая запись целая (4377 + 13 = 4390), вторая обрывается посреди тела:
    // её заголовок кончается на 8767, тело — на 8784, режем по 8770.
    let cut = HEADER_LEN + 13 + HEADER_LEN + 3;
    let path = write_tmp(dir.path(), "cut.wpress", &SITE[..cut]);
    let err = open(&path, &OpenOptions::default())
        .err()
        .expect("must err");
    assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
}

#[test]
fn truncated_header_is_error_not_panic() {
    let dir = tempfile::tempdir().unwrap();
    // Первая запись целая, вторая обрывается посреди заголовка.
    let path = write_tmp(dir.path(), "cuthdr.wpress", &SITE[..HEADER_LEN + 13 + 100]);
    let err = open(&path, &OpenOptions::default())
        .err()
        .expect("must err");
    assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
}

/// Поле длины — недоверенный вход: объявленный размер (сто триллионов байт,
/// предел четырнадцатизначного поля) больше всего файла. До проверки «влезает
/// ли тело в файл» такой заголовок либо уводил бы смещения в никуда, либо —
/// при преаллокации под объявленный размер — убивал процесс.
#[test]
fn crafted_huge_size_field_is_error_not_abort() {
    let dir = tempfile::tempdir().unwrap();
    let mut blob = record(b"a.txt", b"99999999999999", b"1750000000", b".", b"abc");
    blob.extend_from_slice(&eof_block());
    let path = write_tmp(dir.path(), "hugesize.wpress", &blob);
    let err = open(&path, &OpenOptions::default())
        .err()
        .expect("must error, not abort");
    // Не сошлась первая же запись, подтверждать формат нечем → «не наш формат».
    assert!(matches!(err, Error::UnknownFormat), "got {err:?}");
}

/// Граница на единицу: тело заявлено ровно на байт длиннее, чем осталось в
/// файле. Проверка «влезает ли» должна ловить и такой случай, иначе последняя
/// запись читалась бы короче объявленного молча.
#[test]
fn size_one_byte_past_end_of_file_is_error() {
    let dir = tempfile::tempdir().unwrap();
    // Файл кончается сразу за телом; заявляем 4 байта при трёх настоящих.
    let blob = record(b"a.txt", b"4", b"1750000000", b".", b"abc");
    let path = write_tmp(dir.path(), "offbyone.wpress", &blob);
    let err = open(&path, &OpenOptions::default())
        .err()
        .expect("must err");
    // Первая же запись не сходится → это не подтверждённый wpress.
    assert!(matches!(err, Error::UnknownFormat), "got {err:?}");
}

/// Вторая запись с крафт-длиной: формат уже подтверждён первой записью, значит
/// ответ — «архив битый», а не «неизвестный формат».
#[test]
fn crafted_size_in_second_record_is_corrupt() {
    let dir = tempfile::tempdir().unwrap();
    let mut blob = record(b"a.txt", b"3", b"1750000000", b".", b"abc");
    blob.extend_from_slice(&record(
        b"b.txt",
        b"99999999999999",
        b"1750000000",
        b".",
        b"xyz",
    ));
    blob.extend_from_slice(&eof_block());
    let path = write_tmp(dir.path(), "second.wpress", &blob);
    let err = open(&path, &OpenOptions::default())
        .err()
        .expect("must err");
    assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
}

/// Запись, чей путь выходит за корень, не должна писать файл за пределы
/// целевого каталога. Путь сохраняется дословно (`..` не «нормализуется»),
/// поэтому оркестратор его отбраковывает.
#[test]
fn parent_dir_escape_writes_nothing_outside_dest() {
    let dir = tempfile::tempdir().unwrap();
    let mut blob = record(b"evil.txt", b"3", b"1750000000", b"../..", b"pwn");
    blob.extend_from_slice(&eof_block());
    let path = write_tmp(dir.path(), "evil.wpress", &blob);

    let dest = tempfile::tempdir().unwrap();
    let mut reader = open(&path, &OpenOptions::default()).expect("open");
    let report = extract_all(
        &mut *reader,
        &mut ExtractOptions {
            dest: dest.path().to_path_buf(),
            wrapper_name: None,
            strict: false,
            preserve: true,
            selection: None,
            progress: None,
            keep_macos_metadata: false,
        },
    )
    .expect("extract must not fail as a whole");
    assert_eq!(report.extracted, 0);
    assert_eq!(report.failed.len(), 1);
    assert!(!dest.path().parent().unwrap().join("evil.txt").exists());
}

#[test]
fn parent_dir_escape_aborts_in_strict_mode() {
    let dir = tempfile::tempdir().unwrap();
    let mut blob = record(b"evil.txt", b"3", b"1750000000", b"../..", b"pwn");
    blob.extend_from_slice(&eof_block());
    let path = write_tmp(dir.path(), "evil2.wpress", &blob);

    let dest = tempfile::tempdir().unwrap();
    let mut reader = open(&path, &OpenOptions::default()).expect("open");
    let err = extract_all(
        &mut *reader,
        &mut ExtractOptions {
            dest: dest.path().to_path_buf(),
            wrapper_name: None,
            strict: true,
            preserve: true,
            selection: None,
            progress: None,
            keep_macos_metadata: false,
        },
    )
    .unwrap_err();
    assert!(matches!(err, Error::PathTraversal(_)), "got {err:?}");
}

// ── Мелочи разметки, зафиксированные эталоном ────────────────────────────────

/// Пустое поле каталога и `.` дают один и тот же корень; `./sub` теряет `./`.
/// Все три варианта проверены на `kwet`.
#[test]
fn prefix_variants_match_the_reference_unpacker() {
    let dir = tempfile::tempdir().unwrap();
    let mut blob = record(b"a.txt", b"1", b"1750000000", b"", b"a");
    blob.extend_from_slice(&record(b"b.txt", b"1", b"1750000000", b".", b"b"));
    blob.extend_from_slice(&record(b"c.txt", b"1", b"1750000000", b"./sub", b"c"));
    blob.extend_from_slice(&record(b"d.txt", b"1", b"1750000000", b"sub/", b"d"));
    blob.extend_from_slice(&eof_block());
    let path = write_tmp(dir.path(), "prefixes.wpress", &blob);
    let mut reader = open(&path, &OpenOptions::default()).expect("open");
    let names: Vec<String> = reader
        .entries()
        .unwrap()
        .iter()
        .map(|e| e.path.to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec!["a.txt", "b.txt", "sub/c.txt", "sub/d.txt"]);
}

/// Эталон принимает файл, кончающийся сразу после последнего тела, без
/// нулевого блока: физический конец файла — тоже конец архива.
#[test]
fn missing_eof_block_is_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let blob = record(b"a.txt", b"3", b"1750000000", b".", b"abc");
    let path = write_tmp(dir.path(), "noeof.wpress", &blob);
    let mut reader = open(&path, &OpenOptions::default()).expect("open");
    assert_eq!(reader.entries().unwrap().len(), 1);
    assert_eq!(body_of(reader.as_mut(), "a.txt"), b"abc");
}

/// Все поля заполнены до последнего байта — ни одного нулевого дополнения.
/// Этот же файл читается эталонным `kwet`, чем и закреплены ширины 255/14/12.
#[test]
fn fully_packed_fields_parse() {
    let dir = tempfile::tempdir().unwrap();
    let long_name = {
        let mut v = vec![b'a'; 251];
        v.extend_from_slice(b".txt");
        v
    };
    assert_eq!(long_name.len(), NAME_LEN);
    let body = b"fifteen bytes!\n";
    let mut blob = record(&long_name, b"00000000000015", b"001750000000", b".", body);
    blob.extend_from_slice(&eof_block());
    let path = write_tmp(dir.path(), "packed.wpress", &blob);
    let mut reader = open(&path, &OpenOptions::default()).expect("open");
    let name = String::from_utf8(long_name).unwrap();
    assert_eq!(body_of(reader.as_mut(), &name), body);
}
