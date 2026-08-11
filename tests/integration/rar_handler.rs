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
    let (tmp, opened) = try_open_fixture(bytes, opts);
    (tmp, opened.unwrap())
}

/// То же, но исход отдаётся как есть: тестам про отказ нужен `Err`, а
/// договорённость «временный файл живёт, пока жив читатель» — одна на всех.
fn try_open_fixture(
    bytes: &[u8],
    opts: &OpenOptions,
) -> (
    tempfile::NamedTempFile,
    newtua_core::Result<Box<dyn ArchiveReader>>,
) {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), bytes).unwrap();
    let src = Source::path(tmp.path()).unwrap();
    let opened = RarHandler.open(src, opts);
    (tmp, opened)
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
    // На архиве, собранном на Unix, поле атрибутов несёт полный `st_mode`
    // (здесь 0o100755). Отличаем это от флагов FAT/NTFS по тетраде типа файла
    // и оставляем только права — `unix_mode` в `format/rar.rs`.
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

// ── RAR 3 с зашифрованными заголовками ───────────────────────────────────────

/// Архив RAR 3 с зашифрованными заголовками (`rar a -hp`), собранный здесь же.
///
/// Фикстуры на этот случай у нас нет и взять её негде: `rar` 7.22 не умеет
/// делать RAR 4 (`-ma4` он уже не знает), а чужой образец повторил бы историю
/// тикета 31 — двоичный файл без объявленной лицензии в открытом репозитории.
/// Поэтому архив собран из байтов формата: `-hp` шифрует блоки **после**
/// главного заголовка, так что маркер и главный блок здесь настоящие, а
/// «зашифрованный» хвост — то, чем он и выглядит для неверного ключа.
///
/// 20 байт структуры: маркер `Rar!\x1a\x07\x00`, затем главный блок в 13 байт —
/// контрольная сумма `0x99ce`, тип `0x73`, флаги `0x0080` (`MHD_PASSWORD`),
/// размер 13 и два пустых зарезервированных поля. Дальше 32 байта хвоста:
/// восемь на соль и шестнадцать с лишним на тело заголовка.
#[rustfmt::skip]
const HEADER_ENC_FIXTURE: &[u8] = &[
    0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00,
    0xce, 0x99, 0x73, 0x80, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
    0xdd, 0xee, 0xff, 0x00, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
    0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
];

/// Неверный пароль к RAR 3 `-hp` — это «неверный пароль», а не порча архива.
///
/// Тикет 36. Неверный ключ даёт на выходе AES мусор, и мусор шёл в разбор как
/// настоящий заголовок: два байта случайного размера почти всегда больше
/// остатка файла, и человек получал `Corrupt("input is too short")` — то есть
/// «архив недокачан». Он шёл искать вторую копию из-за опечатки в пароле.
///
/// Отличить «пароль не тот» от «файл побит» в RAR 3 нельзя в принципе: поля для
/// проверки ключа формат не хранит, оно появилось только в RAR 5. Поэтому
/// вердикт называется по тому, что человеку делать: проверить пароль.
#[test]
fn rar3_header_encrypted_wrong_password_is_not_corruption() {
    use newtua_core::Error;
    let (_tmp, opened) = try_open_fixture(HEADER_ENC_FIXTURE, &with_password("WRONG"));
    let Err(err) = opened else {
        panic!("архив из мусора не должен открываться");
    };
    assert!(
        matches!(err, Error::WrongPassword),
        "неверный пароль к -hp обязан называться паролем, а не порчей: {err:?}"
    );
}

/// А отсутствие пароля остаётся отсутствием пароля.
///
/// Граница правки тикета 36: спросить пароль и объявить его неверным — разные
/// вещи, и первая была верна до правки. Пустая строка сюда не годится:
/// `std::env::var` отдаёт `Ok("")`, и заданный пустой пароль — это заданный
/// пароль (ловушка тикета 33).
#[test]
fn rar3_header_encrypted_without_password_still_asks_for_one() {
    use newtua_core::Error;
    let (_tmp, opened) = try_open_fixture(HEADER_ENC_FIXTURE, &OpenOptions::default());
    let Err(err) = opened else {
        panic!("архив с зашифрованными заголовками не открывается без пароля");
    };
    assert!(
        matches!(err, Error::Encrypted),
        "без пароля -hp обязан просить пароль: {err:?}"
    );
}

// ── RAR 5: зашифрованная запись, сохранённая без сжатия (тикет 37) ───────────

// encpad.rar: восемь файлов по 1500 байт случайных данных, собран здесь:
//   rar a -r -m0 -ep1 -pSecret123 encpad.rar pad
// 1500 не кратно 16, поэтому у каждой зашифрованной записи есть добивка, и
// `rar` 7.22 оставляет в ней остатки своего буфера — нулевая она только у
// первых записей архива. Судья целостности не наш код: CRC32 и BLAKE2sp
// каждой записи записал сам `rar`, и распаковщик их сверяет.
const ENC_PAD_FIXTURE: &[u8] = include_bytes!("../fixtures/encpad.rar");

// hpvol.partN.rar: шесть файлов по 1500 байт, шесть томов, собран здесь:
//   rar a -r -v2k -m0 -ep1 -hpSecret123 hpvol.rar src
// Тома по 2 КиБ гарантируют записи, разрезанные между томами, а `-hp` снимает
// у них флаг `uses_hash_mac` — сочетание, на котором терялся почти весь архив.
const HPVOL_PARTS: [&[u8]; 6] = [
    include_bytes!("../fixtures/hpvol.part1.rar"),
    include_bytes!("../fixtures/hpvol.part2.rar"),
    include_bytes!("../fixtures/hpvol.part3.rar"),
    include_bytes!("../fixtures/hpvol.part4.rar"),
    include_bytes!("../fixtures/hpvol.part5.rar"),
    include_bytes!("../fixtures/hpvol.part6.rar"),
];

/// Пароль всех собранных здесь зашифрованных фикстур.
const SECRET: &str = "Secret123";

/// Разложить тома набора рядом друг с другом и открыть первый: продолжение
/// ищется по соседним именам (`sibling_volumes`), поэтому лежать они обязаны
/// вместе.
///
/// `damage` — том (с нуля) и смещение байта, который надо испортить по дороге.
/// Портится копия в памяти, фикстура на диске остаётся целой и служит заодно
/// обычным многотомным образцом.
fn open_volumes(
    stem: &str,
    parts: &[&[u8]],
    opts: &OpenOptions,
    damage: Option<(usize, usize)>,
) -> (tempfile::TempDir, Box<dyn ArchiveReader>) {
    let dir = tempfile::tempdir().unwrap();
    for (i, part) in parts.iter().enumerate() {
        let mut bytes = part.to_vec();
        if let Some((volume, at)) = damage
            && volume == i
        {
            bytes[at] ^= 0xff;
        }
        std::fs::write(dir.path().join(format!("{stem}.part{}.rar", i + 1)), bytes).unwrap();
    }
    let first = dir.path().join(format!("{stem}.part1.rar"));
    let src = Source::path(&first).unwrap();
    let ar = RarHandler.open(src, opts).unwrap();
    (dir, ar)
}

fn with_password(password: &str) -> OpenOptions {
    OpenOptions {
        password: Some(password.into()),
        encoding_override: None,
    }
}

/// Распаковать весь архив одним проходом — тем самым, которым ходит движок.
///
/// Не циклом `read_entry`: у сплошного архива и у набора томов это разные пути,
/// и стеречь надо тот, по которому идёт распаковка на самом деле.
fn read_all(ar: &mut dyn ArchiveReader) -> Collector {
    let indices: Vec<usize> = (0..ar.entries().unwrap().len()).collect();
    let mut sink = Collector::default();
    ar.read_entries(&indices, &mut sink).unwrap();
    sink
}

/// Номера записей по именам: порядок в архиве — дело упаковщика, и привязка к
/// нему сделала бы тест хрупким.
fn index_of(ar: &mut dyn ArchiveReader, names: &[String]) -> Vec<usize> {
    let entries = ar.entries().unwrap();
    names
        .iter()
        .map(|name| {
            entries
                .iter()
                .position(|e| e.path.to_string_lossy() == *name)
                .unwrap_or_else(|| panic!("{name} нет в оглавлении"))
        })
        .collect()
}

fn numbered(dir: &str, stem: &str, count: usize) -> Vec<String> {
    (0..count).map(|i| format!("{dir}/{stem}{i}.bin")).collect()
}

/// Добивка зашифрованной записи, сохранённой без сжатия, отбрасывается — какая
/// бы в ней ни лежала труха.
///
/// Тикет 37. Требование «добивка обязана быть нулевой» формат нигде не даёт, а
/// `rar` 7.22 её ничем не заполняет: туда попадает то, что осталось в его
/// буфере. Отсюда и вид беды — первые записи архива выходили, а дальше человек
/// получал «архив побит» на файлах, которые `unrar` читает целиком.
#[test]
fn rar5_encrypted_stored_member_survives_non_zero_padding() {
    let (_tmp, mut ar) = open_fixture(ENC_PAD_FIXTURE, &with_password(SECRET));
    let at = index_of(ar.as_mut(), &numbered("pad", "p", 8));
    let sink = read_all(ar.as_mut());

    assert!(sink.failed.is_empty(), "отказов быть не должно");
    for (i, &idx) in at.iter().enumerate() {
        assert_eq!(sink.body(idx).len(), 1500, "запись pad/p{i}.bin");
    }
}

/// Запись, разрезанная между томами архива с зашифрованными заголовками,
/// проверяется тем же правилом, что и целая.
///
/// Тикет 37, второй дефект. Путь для разрезанной записи применял MAC к
/// контрольной сумме всегда, когда запись зашифрована, а путь для целой — лишь
/// когда взведён флаг `uses_hash_mac`. Архив, собранный `rar a -hp`, этого
/// флага не ставит, и каждая разрезанная запись объявлялась побитой: из 201
/// записи выходило пять.
#[test]
fn rar5_header_encrypted_split_member_is_not_reported_corrupt() {
    let (_dir, mut ar) = open_volumes("hpvol", &HPVOL_PARTS, &with_password(SECRET), None);
    let at = index_of(ar.as_mut(), &numbered("src", "e", 6));
    let sink = read_all(ar.as_mut());

    assert!(sink.failed.is_empty(), "отказов быть не должно");
    for (i, &idx) in at.iter().enumerate() {
        assert_eq!(sink.body(idx).len(), 1500, "запись src/e{i}.bin");
    }
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
    /// Текст отказа по записи: у отказа есть не только факт, но и причина, и
    /// неверная причина уводит человека чинить не то (тикет 37 §5).
    reasons: Vec<(usize, String)>,
    skip: Vec<usize>,
    stop_before: Option<usize>,
}

impl Collector {
    fn reason(&self, idx: usize) -> &str {
        &self
            .reasons
            .iter()
            .find(|(i, _)| *i == idx)
            .unwrap_or_else(|| panic!("записи {idx} нет среди отказавших"))
            .1
    }

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
        if let Err(e) = outcome {
            self.failed.push(idx);
            self.reasons.push((idx, e.to_string()));
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

fn open_multivolume() -> (tempfile::TempDir, Box<dyn ArchiveReader>) {
    open_volumes(
        "mvmulti",
        &[MV_P1, MV_P2, MV_P3],
        &OpenOptions::default(),
        None,
    )
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
/// Тела здесь режутся границами томов не по одному разу, и склеивает их обход
/// набора. Пока RAR читался через libunrar, на этих же границах её обратный
/// вызов ронял процесс по `SIGABRT`, и форк существовал ради трёх заплаток от
/// этого; своего кода та беда не касается, но проверка остаётся.
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

// ── Одна испорченная запись не уносит соседей (G14, тикет 37 §5) ────────────

// torn.part1..3.rar: шесть файлов по 700 несжимаемых байт, тома по 2 КиБ:
//   rar a -r -v2k -m0 -ep1 torn.rar t
// Тома режут часть тел, часть — нет; на этом и держится проверка. Фикстура на
// диске **целая**, портится копия в памяти: так один и тот же образец служит и
// обычным многотомным набором.
const TORN_PARTS: [&[u8]; 3] = [
    include_bytes!("../fixtures/torn.part1.rar"),
    include_bytes!("../fixtures/torn.part2.rar"),
    include_bytes!("../fixtures/torn.part3.rar"),
];

/// Тела фикстуры — тот же генератор, каким они созданы: один поток на все шесть
/// файлов подряд, потом порезанный по 700 байт.
fn torn_bodies() -> Vec<Vec<u8>> {
    blob(7, 6 * 700).chunks(700).map(<[u8]>::to_vec).collect()
}

/// Разложить набор, испортив один байт в теле внутри второго тома.
fn open_torn(damage: Option<usize>) -> (tempfile::TempDir, Box<dyn ArchiveReader>) {
    let damage = damage.map(|at| (1, at));
    open_volumes("torn", &TORN_PARTS, &OpenOptions::default(), damage)
}

/// Целый набор читается целиком — фикстура сама по себе исправна.
#[test]
fn a_torn_set_reads_whole_when_undamaged() {
    let (_dir, mut ar) = open_torn(None);
    let at = index_of(ar.as_mut(), &numbered("t", "f", 6));
    let sink = read_all(ar.as_mut());

    assert!(sink.failed.is_empty(), "отказов быть не должно");
    for (i, body) in torn_bodies().iter().enumerate() {
        assert_eq!(sink.body(at[i]), &body[..], "запись t/f{i}.bin");
    }
}

/// Одна испорченная запись не уносит с собой тех соседей, что от неё не зависят.
///
/// G14, названный внутри тикета 37 §5. Проход по архиву обрывается на первой
/// же неудаче и, начатый заново, спотыкается о ту же запись, — так весь остаток
/// набора объявлялся потерянным. Вне сплошного архива соседи от испорченной
/// записи не зависят, и те из них, что не разрезаны границей тома, читаются
/// поодиночке. На этом образце было три целых файла из шести, стало четыре;
/// `unrar` достаёт пять.
///
/// **И причина отказа теперь правдива.** Недошедшим записям сообщалось
/// «заголовки кончились», хотя заголовки на месте — прекратился обход.
#[test]
fn a_damaged_entry_does_not_take_its_neighbours_with_it() {
    let (_dir, mut ar) = open_torn(Some(500));
    let at = index_of(ar.as_mut(), &numbered("t", "f", 6));
    let sink = read_all(ar.as_mut());

    let bodies = torn_bodies();
    // Испорчено тело `t/f1.bin`; её отказ и есть настоящая причина.
    let damaged = at[1];
    assert!(
        sink.failed.contains(&damaged),
        "битая запись обязана отказать, отказали {:?}",
        sink.failed
    );
    assert!(
        sink.reason(damaged).contains("checksum mismatch"),
        "у настоящей порчи причина своя: {}",
        sink.reason(damaged)
    );
    // Записи после неё, не разрезанные границей тома, обязаны выйти целыми:
    // до правки весь остаток набора считался потерянным.
    for i in [3usize, 4, 5] {
        assert_eq!(sink.body(at[i]), &bodies[i][..], "сосед t/f{i}.bin потерян");
    }
    // А та, что разрезана и потому поодиночке не читается, честно говорит, почему.
    for &idx in &sink.failed {
        if idx == damaged {
            continue;
        }
        let why = sink.reason(idx);
        assert!(
            why.contains("обход архива прервался"),
            "недошедшей записи полагается правда, а не «заголовки кончились»: {why}"
        );
    }
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
//
// Оговорка о происхождении: у набора, откуда взят файл, лицензия не объявлена.
// Оставлен осознанно (решение человека 2026-08-10) — другого архива RAR 1.5 у
// нас нет, а собрать его сегодня нечем. В публикуемый пакет он не попадает.
// Подробности и путь к замене — `.claude/issues/31`, коротко — в README.
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

// links.rar: ссылки RAR 5 всех видов, какие умеет собрать сам `rar`.
// Собрано так:
//   printf 'real payload\n' > real.txt
//   mkdir sub && printf 'in sub\n' > sub/inner.txt
//   ln -s real.txt link.txt      # обычная ссылка
//   ln -s sub dirlink            # ссылка на каталог
//   ln -s /etc/hosts abs.txt     # ссылка наружу дерева распаковки
//   ln real.txt hard.txt         # жёсткая ссылка
//   cp real.txt copy.txt         # ссылка на одинаковый файл (`-oi`)
//   rar a -ma5 -ol -oh -oi1:1 -r links.rar \
//     real.txt sub link.txt dirlink abs.txt hard.txt copy.txt
// (RAR 7.22.) `unrar lt` называет их: Unix symbolic link, Hard link,
// File reference.
const LINKS: &[u8] = include_bytes!("../fixtures/links.rar");

/// Перенаправление RAR 5 любого вида доходит до `EntryKind::Symlink` с целью.
///
/// Эталон — `unar`: на этом самом архиве он кладёт символическую ссылку и на
/// месте жёсткой ссылки, и на месте ссылки на одинаковый файл. Своего вида
/// записи под них у нас нет, а пустой файл вместо жёсткой ссылки — молчаливая
/// потеря содержимого.
#[test]
fn rar5_redirections_of_every_kind_become_symlinks() {
    let (_tmp, mut ar) = open_fixture(LINKS, &OpenOptions::default());
    let entries = ar.entries().unwrap().to_vec();

    let kinds: Vec<(String, Option<String>)> = entries
        .iter()
        .map(|e| {
            let target = match &e.kind {
                newtua_core::EntryKind::Symlink { target } => {
                    Some(target.to_string_lossy().into_owned())
                }
                _ => None,
            };
            (e.path.to_string_lossy().into_owned(), target)
        })
        .collect();

    let expected: Vec<(String, Option<String>)> = [
        ("real.txt", None),
        ("sub/inner.txt", None),
        ("link.txt", Some("real.txt")),
        ("dirlink", Some("sub")),
        ("abs.txt", Some("/etc/hosts")),
        ("hard.txt", Some("real.txt")),
        ("copy.txt", Some("real.txt")),
        ("sub", None),
    ]
    .iter()
    .map(|(n, t)| ((*n).to_owned(), t.map(str::to_owned)))
    .collect();
    assert_eq!(kinds, expected);

    // Каталог остаётся каталогом, а ссылка на каталог — ссылкой: у неё стоят
    // оба признака, и порядок проверки решает, что вырастет на её месте.
    assert!(matches!(entries[7].kind, newtua_core::EntryKind::Dir));

    // Тела у ссылки нет: распаковщика на неё не зовут вовсе.
    let mut out = Vec::new();
    ar.read_entry(2, &mut out).unwrap();
    assert!(out.is_empty(), "у ссылки нет тела: {out:?}");
}

/// Распаковка ссылок: цели совпадают с тем, что даёт `unar`, а ссылка наружу
/// дерева отбивается.
///
/// `unar` абсолютную ссылку создаёт как есть — мы отказываем, как и сам
/// `unrar` («Absolute path link … skipped»): цель за пределами каталога
/// распаковки правил проекта не проходит.
#[cfg(unix)]
#[test]
fn rar5_symlinks_extract_like_unar_and_refuse_escaping_target() {
    let (_tmp, mut ar) = open_fixture(LINKS, &OpenOptions::default());
    let dest = tempfile::tempdir().unwrap();
    let report = newtua_core::extract_all(
        &mut *ar,
        &mut newtua_core::ExtractOptions {
            dest: dest.path().to_path_buf(),
            wrapper_name: Some("links".into()),
            strict: false,
            preserve: true,
            selection: None,
            progress: None,
            keep_macos_metadata: false,
        },
    )
    .unwrap();

    let root = dest.path().join("links");
    for (name, target) in [
        ("link.txt", "real.txt"),
        ("dirlink", "sub"),
        ("hard.txt", "real.txt"),
        ("copy.txt", "real.txt"),
    ] {
        let link = root.join(name);
        assert_eq!(
            std::fs::read_link(&link).unwrap(),
            Path::new(target),
            "цель ссылки {name} разошлась с тем, что кладёт `unar`"
        );
    }
    // Ссылка на каталог ведёт в каталог, а не в пустоту.
    assert_eq!(
        std::fs::read(root.join("dirlink/inner.txt")).unwrap(),
        b"in sub\n"
    );
    assert_eq!(
        std::fs::read(root.join("real.txt")).unwrap(),
        b"real payload\n"
    );

    assert!(
        root.join("abs.txt").symlink_metadata().is_err(),
        "ссылка на /etc/hosts не должна появиться на диске"
    );
    assert_eq!(
        report.failed.len(),
        1,
        "отказ ровно один — абсолютная цель: {:?}",
        report.failed
    );
    assert_eq!(report.failed[0].0, Path::new("abs.txt"));
}
