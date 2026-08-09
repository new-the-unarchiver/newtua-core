use newtua_core::format::RarHandler;
use newtua_core::{ArchiveReader, EntrySink, FormatHandler, OpenOptions, SinkStep, Source};
use std::path::Path;

const FIXTURE: &[u8] = include_bytes!("../fixtures/hello.rar");

/// Открыть архив из встроенных байтов. Временный файл надо держать живым,
/// пока читатель открыт, поэтому он возвращается вместе с ним.
fn open_fixture(
    bytes: &[u8],
    opts: &OpenOptions,
) -> (tempfile::NamedTempFile, Box<dyn ArchiveReader>) {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), bytes).unwrap();
    let src = Source::path(tmp.path()).unwrap();
    let ar = RarHandler.open(src, opts).unwrap();
    (tmp, ar)
}

#[test]
fn lists_and_extracts_rar() {
    let (_tmp, mut ar) = open_fixture(FIXTURE, &OpenOptions::default());
    let entries = ar.entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path.to_str().unwrap(), "a.txt");
    let mut out = Vec::new();
    ar.read_entry(0, &mut out).unwrap();
    assert_eq!(out, b"hello rar");
}

// meta.rar: self-generated archive with known unix mode.
// Created with:
//   printf 'x' > f.txt && chmod 0755 f.txt
//   rar a meta.rar f.txt && rm f.txt
// (RAR 7.22, Host OS: Unix, Attributes: -rwxr-xr-x)
// file_attr = 0o100755 (full POSIX st_mode); file_attr & 0o7777 = 0o755.
const META_FIXTURE: &[u8] = include_bytes!("../fixtures/meta.rar");

#[test]
fn rar_populates_mode_when_available() {
    let (_tmp, mut ar) = open_fixture(META_FIXTURE, &OpenOptions::default());
    let entries = ar.entries().unwrap().to_vec();
    let f = entries
        .iter()
        .find(|e| e.path == Path::new("f.txt"))
        .expect("f.txt not found in meta.rar");
    // The unrar crate exposes file_attr: u32 on FileHeader.
    // For Unix-created RARs, file_attr is the full POSIX st_mode (e.g. 0o100755).
    // We detect Unix attributes by checking the file-type nibble (S_IFREG/S_IFDIR/S_IFLNK),
    // then mask with 0o7777 to get permission bits only.
    assert_eq!(f.mode, Some(0o755));
}

// secret.rar: self-generated data-encrypted archive, password "pw".
// Created with: printf 'hello rar' > a.txt && rar a -ppw secret.rar a.txt && rm a.txt
// (RAR 7.22 no longer supports -ma4; produces RAR5 data-encrypted archive.)
// The archive lists without a password; extraction with a wrong password errors.
const ENC_FIXTURE: &[u8] = include_bytes!("../fixtures/secret.rar");

#[test]
fn wrong_password_errors() {
    use newtua_core::Error;
    let opts = OpenOptions {
        password: Some("WRONG".into()),
        encoding_override: None,
    };
    let (_tmp, mut ar) = open_fixture(ENC_FIXTURE, &opts);
    ar.entries().unwrap();
    let mut out = Vec::new();
    let err = ar.read_entry(0, &mut out).unwrap_err();
    assert!(matches!(
        err,
        Error::WrongPassword | Error::Encrypted | Error::Corrupt(_)
    ));
}

#[test]
fn verify_password_without_password_is_encrypted() {
    use newtua_core::Error;
    let (_tmp, mut ar) = open_fixture(ENC_FIXTURE, &OpenOptions::default());
    // Listing works without a password; the guard comes from verify_password.
    ar.entries().unwrap();
    assert!(matches!(ar.verify_password(), Err(Error::Encrypted)));
}

#[test]
fn verify_password_with_wrong_password_errors() {
    use newtua_core::Error;
    let opts = OpenOptions {
        password: Some("WRONG".into()),
        encoding_override: None,
    };
    let (_tmp, mut ar) = open_fixture(ENC_FIXTURE, &opts);
    assert!(matches!(
        ar.verify_password(),
        Err(Error::WrongPassword) | Err(Error::Encrypted) | Err(Error::Corrupt(_))
    ));
}

#[test]
fn verify_password_with_correct_password_is_ok() {
    let opts = OpenOptions {
        password: Some("pw".into()),
        encoding_override: None,
    };
    let (_tmp, mut ar) = open_fixture(ENC_FIXTURE, &opts);
    assert!(ar.verify_password().is_ok());
}

// ── Timestamps ───────────────────────────────────────────────────────────────

/// RAR 5 хранит момент времени, и он доходит до записи точно.
///
/// Не «часы на стене», как MS-DOS в zip и в RAR 4, а мгновение: `rar` 7.22
/// кладёт его в расширенную запись заголовка `FHEXTRA_HTIME` восьмибайтовым
/// `FILETIME`. Поэтому и ожидание здесь — одно число, не зависящее от того, в
/// каком поясе гоняют тесты.
///
/// Судья не наш код: `unrar lt` (утилита самой libunrar, из Homebrew) на этой
/// же фикстуре говорит `2026-06-21 02:05:13,308719877` при `TZ=UTC`, то есть
/// 1782007513 секунд от эпохи. То же мгновение показывает и `unar`.
///
/// До тикета 26 здесь стояла обратная проверка — «секунда обязана быть
/// чётной». Читалось только слово MS-DOS с шагом в две секунды, потому что
/// биндинг libunrar не отдавал наружу ничего точнее, и файл, упакованный на
/// нечётной секунде, показывался на секунду раньше правды. Своему
/// распаковщику это поле доступно.
#[test]
fn rar5_reports_the_exact_stored_instant() {
    let (_tmp, mut ar) = open_fixture(META_FIXTURE, &OpenOptions::default());
    let e = &ar.entries().unwrap()[0];

    let secs = e
        .modified
        .expect("meta.rar carries a timestamp")
        .duration_since(std::time::UNIX_EPOCH)
        .expect("post-epoch")
        .as_secs();

    assert_eq!(
        secs, 1_782_007_513,
        "2026-06-21T02:05:13Z, как у `unrar lt`"
    );
}

// ── Пакетный проход ──────────────────────────────────────────────────────────

/// Всё, что сообщил `read_entries`: тела по номерам записей и отказы.
///
/// Тела нарочно не складываются в один буфер: половина этих проверок — про то,
/// **какой** записи приписано тело, а приёмник, копящий одни байты, прошёл бы
/// и с перепутанными записями.
#[derive(Default)]
struct Collector {
    current: Option<usize>,
    got: Vec<(usize, Vec<u8>)>,
    failed: Vec<usize>,
    skip: Vec<usize>,
    stop_before: Option<usize>,
}

impl Collector {
    fn body(&self, idx: usize) -> &[u8] {
        &self
            .got
            .iter()
            .find(|(i, _)| *i == idx)
            .unwrap_or_else(|| panic!("записи {idx} нет среди прочитанных"))
            .1
    }
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
        assert_eq!(self.current, Some(idx), "end() пришёл не за той записью");
        if outcome.is_err() {
            self.failed.push(idx);
            self.got.retain(|(i, _)| *i != idx);
        }
        Ok(true)
    }
}

// solid3.rar: три файла, сплошной архив (`rar a -s`).
//   printf 'one' > a.txt; printf 'two two' > b.txt
//   printf 'three three three' > c.txt; rar a -s -m3 solid3.rar a.txt b.txt c.txt
const SOLID3: &[u8] = include_bytes!("../fixtures/solid3.rar");

/// Пакетный проход отдаёт каждой записи её собственное тело.
#[test]
fn a_batch_pass_gives_each_entry_its_own_body() {
    let (_tmp, mut ar) = open_fixture(SOLID3, &OpenOptions::default());
    assert_eq!(ar.entries().unwrap().len(), 3);

    let mut sink = Collector::default();
    ar.read_entries(&[0, 1, 2], &mut sink).unwrap();

    assert!(sink.failed.is_empty(), "отказов быть не должно");
    assert_eq!(sink.body(0), b"one");
    assert_eq!(sink.body(1), b"two two");
    assert_eq!(sink.body(2), b"three three three");
}

/// Пропущенная запись не сдвигает те, что за ней.
///
/// Проход идёт по местам заголовков, а не по счётчику отданных тел: ответь
/// приёмник `Skip`, и следующая запись должна остаться собой.
#[test]
fn a_skipped_entry_does_not_shift_the_ones_after_it() {
    let (_tmp, mut ar) = open_fixture(SOLID3, &OpenOptions::default());
    let mut sink = Collector {
        skip: vec![1],
        ..Default::default()
    };
    ar.read_entries(&[0, 1, 2], &mut sink).unwrap();

    assert_eq!(
        sink.got.len(),
        2,
        "тело пропущенной записи не запрашивалось"
    );
    assert_eq!(sink.body(0), b"one");
    assert_eq!(sink.body(2), b"three three three");
}

/// Не весь список — а только то, что попросили.
#[test]
fn a_batch_pass_reads_only_the_asked_for_entries() {
    let (_tmp, mut ar) = open_fixture(SOLID3, &OpenOptions::default());
    let mut sink = Collector::default();
    ar.read_entries(&[2], &mut sink).unwrap();

    assert_eq!(sink.got.len(), 1);
    assert_eq!(sink.body(2), b"three three three");
}

/// `Stop` прекращает проход, а уже отданное остаётся.
#[test]
fn stop_ends_the_pass() {
    let (_tmp, mut ar) = open_fixture(SOLID3, &OpenOptions::default());
    let mut sink = Collector {
        stop_before: Some(2),
        ..Default::default()
    };
    ar.read_entries(&[0, 1, 2], &mut sink).unwrap();

    assert_eq!(sink.got.len(), 2);
    assert_eq!(sink.body(1), b"two two");
}

// dup.rar: два файла с **одинаковым** хранимым именем `same.txt` — так выходит
// при упаковке без путей:
//   printf 'from d1' > d1/same.txt; printf 'from d2 — other bytes' > d2/same.txt
//   rar a -ep -m0 dup.rar d1/same.txt d2/same.txt
const DUP: &[u8] = include_bytes!("../fixtures/dup.rar");

/// Два одноимённых файла — две разные записи.
///
/// Прежний обход искал запись **по имени** и на обеих отдавал первую: второй
/// файл молча подменялся первым. Теперь запись узнаётся по месту в заголовке,
/// и подмены нет.
#[test]
fn the_same_name_twice_stays_two_entries() {
    let (_tmp, mut ar) = open_fixture(DUP, &OpenOptions::default());
    let entries = ar.entries().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].path, entries[1].path, "имена и правда совпадают");

    let mut sink = Collector::default();
    ar.read_entries(&[0, 1], &mut sink).unwrap();
    assert_eq!(sink.body(0), "from d1".as_bytes());
    assert_eq!(sink.body(1), "from d2 — other bytes".as_bytes());

    // Та же беда была и у чтения по одной записи.
    let mut out = Vec::new();
    ar.read_entry(1, &mut out).unwrap();
    assert_eq!(out, "from d2 — other bytes".as_bytes());
}

// mixed.rar: зашифрована только средняя запись — так получается, когда файлы
// добавляют разными вызовами:
//   rar a mixed.rar p1.txt; rar a -ppw mixed.rar s.txt; rar a mixed.rar p2.txt
const MIXED: &[u8] = include_bytes!("../fixtures/mixed.rar");

/// Отказ одной записи не роняет проход по остальным.
///
/// Библиотека на C отдаёт ручку архива обратно не на всякой ошибке, поэтому
/// после отказа проход начинается заново с остатка списка. Проверяется именно
/// то, что запись **после** сломанной всё-таки доходит.
#[test]
fn a_refused_entry_does_not_end_the_pass() {
    let (_tmp, mut ar) = open_fixture(MIXED, &OpenOptions::default());
    let entries = ar.entries().unwrap();
    assert_eq!(entries.len(), 3);
    assert!(entries[1].is_encrypted, "средняя запись зашифрована");

    let mut sink = Collector::default();
    ar.read_entries(&[0, 1, 2], &mut sink).unwrap();

    assert_eq!(sink.failed, vec![1], "без пароля читается только средняя");
    assert_eq!(sink.body(0), b"first plain");
    assert_eq!(sink.body(2), b"second plain", "запись после отказа дошла");
}

// mvmulti.part1..3.rar: три файла по 12 000 несжимаемых байт, тома по 16 КБ —
// значит границы томов режут тела, и не по одному разу:
//   rar a -m0 -v16k mvmulti.rar mvA.bin mvB.bin mvC.bin
const MV_P1: &[u8] = include_bytes!("../fixtures/mvmulti.part1.rar");
const MV_P2: &[u8] = include_bytes!("../fixtures/mvmulti.part2.rar");
const MV_P3: &[u8] = include_bytes!("../fixtures/mvmulti.part3.rar");

/// Разложить три тома рядом друг с другом и открыть первый: libunrar ищет
/// продолжение по соседним именам, поэтому лежать они обязаны вместе.
fn open_multivolume() -> (tempfile::TempDir, Box<dyn ArchiveReader>) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("mvmulti.part1.rar"), MV_P1).unwrap();
    std::fs::write(dir.path().join("mvmulti.part2.rar"), MV_P2).unwrap();
    std::fs::write(dir.path().join("mvmulti.part3.rar"), MV_P3).unwrap();
    let src = Source::path(&dir.path().join("mvmulti.part1.rar")).unwrap();
    let ar = RarHandler.open(src, &OpenOptions::default()).unwrap();
    (dir, ar)
}

/// Тела фикстуры — тот же линейный конгруэнтный генератор, каким они созданы.
/// Хранить рядом ещё 36 КБ ожидаемых байт незачем.
fn blob(seed: u32, n: usize) -> Vec<u8> {
    let mut x = seed;
    (0..n)
        .map(|_| {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345) & 0x7FFF_FFFF;
            ((x >> 16) & 0xFF) as u8
        })
        .collect()
}

/// Многотомный набор из нескольких файлов проходится за один обход.
///
/// Один длинный проход пересекает границы томов чаще, чем прежние короткие,
/// а именно на них `newtua-unrar` и держит свои заплатки: без них здесь был
/// `SIGABRT`.
#[test]
fn a_multivolume_set_of_several_files_is_read_in_one_pass() {
    let (_dir, mut ar) = open_multivolume();
    assert_eq!(ar.entries().unwrap().len(), 3);

    let mut sink = Collector::default();
    ar.read_entries(&[0, 1, 2], &mut sink).unwrap();

    assert!(sink.failed.is_empty(), "отказов быть не должно");
    for (idx, seed) in [(0usize, 1u32), (1, 2), (2, 3)] {
        assert_eq!(sink.body(idx), blob(seed, 12_000), "запись {idx}");
    }
}

/// Та же многотомная фикстура, но выборочно: пропуск записи посреди набора
/// не должен сбить обход границ томов.
#[test]
fn a_multivolume_set_reads_a_subset() {
    let (_dir, mut ar) = open_multivolume();

    let mut sink = Collector::default();
    ar.read_entries(&[2], &mut sink).unwrap();
    assert_eq!(sink.body(2), blob(3, 12_000));
}

// ── RAR 1.5: настоящий архив эпохи, судья — `unar` ───────────────────────────

// rar15.rar — образец `RUN.RAR` из набора sembiance/file-format-samples,
// семь батников с BBS 1995 года. Метод 51 (`-m3`), версия распаковщика 15:
// это `Unpack15`, самый старый живой декодер в наборе, и создать такой архив
// сегодня нечем — `rar` 7.22 выкинул даже `-ma4`.
//
// Ожидаемое взято **не у нас**: суммы посчитаны с того, что распаковал `unar`
// из этого же файла. Пока RAR читался через libunrar, ту же ветку сторожил
// юнит-тест вендоренного кода, но он сам себе был судьёй — паковал нашим же
// кодировщиком и тут же распаковывал. Кодировщик ушёл в тикете 26, и хорошо:
// проверка от этого стала честнее.
const RAR15: &[u8] = include_bytes!("../fixtures/rar15.rar");

#[test]
fn rar15_matches_unar_byte_for_byte() {
    let (_tmp, mut ar) = open_fixture(RAR15, &OpenOptions::default());
    let names: Vec<String> = ar
        .entries()
        .unwrap()
        .iter()
        .map(|e| e.path.to_string_lossy().into_owned())
        .collect();

    let expected: [(&str, &str); 7] = [
        (
            "EXEBBS.BAT",
            "43a61403a7d1f8896cb2b6393c46f1517cf9acc3948a395b5b4baa8ba6bf0d56",
        ),
        (
            "1.BAT",
            "09c18ec9c9d0cbd4fe4b096b912bb33145899c468d0cf16e867beaaf2c4d8c79",
        ),
        (
            "RUN.BAT",
            "8302b778be24b58e9981f383e722d6d2e68113b005f551fba94e779bced57117",
        ),
        (
            "RUN0.BAT",
            "800dad3d7496f721d0f672fb94633a8390de4a08c96ea7aa2f072919e5cef44d",
        ),
        (
            "DOBBS0.BAT",
            "82cd99cbacfb310fd4f88189628dee0b72f7007d97d77f11b8e3acd11bbabfef",
        ),
        (
            "DOBBS.BAT",
            "5bb51f4f59667ed7492f07a0b37688de56b36ff0395c8cd67188db5b1948f3db",
        ),
        (
            "DOBBS1.BAT",
            "92b1e64e95f1be6a13c3c1f9d7d0789cf9d6a5e02e9c4bfc9a222fcf0150d37e",
        ),
    ];
    assert_eq!(names.len(), expected.len(), "записей в архиве: {names:?}");

    for (idx, (name, digest)) in expected.iter().enumerate() {
        assert_eq!(&names[idx], name, "запись {idx} — не та");
        let mut out = Vec::new();
        ar.read_entry(idx, &mut out).unwrap();
        assert_eq!(
            &crate::common::sha256_hex(&out),
            digest,
            "тело {name} разошлось с тем, что достаёт `unar`"
        );
    }
}
