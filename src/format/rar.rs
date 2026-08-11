use std::cell::RefCell;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::archive::{
    ArchiveReader, Confidence, Entry, EntryKind, EntrySink, FormatHandler, FormatId, OneEntry,
    OpenOptions, SinkStep, SinkWriter, Source,
};
use crate::encoding::{decode_names, detect_encoding};
use crate::error::{Error, Result};
use crate::vendor::rars;

pub struct RarHandler;

// RAR4: "Rar!\x1a\x07\x00"; RAR5: "Rar!\x1a\x07\x01\x00"
const RAR_MAGIC: &[u8] = b"Rar!\x1a\x07";

impl FormatHandler for RarHandler {
    fn id(&self) -> FormatId {
        FormatId::Rar
    }

    fn probe(&self, header: &[u8], _name: Option<&str>) -> Confidence {
        if header.starts_with(RAR_MAGIC) {
            Confidence::MAGIC
        } else {
            Confidence::NONE
        }
    }

    fn open(&self, src: Source, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        let path = src
            .file_path()
            .ok_or_else(|| Error::Unsupported {
                format: "rar".into(),
                feature: "non-file source".into(),
            })?
            .to_path_buf();

        // Оглавление читается сперва **без** пароля, и только если так не
        // вышло — с ним. Зашифровано обычно одно тело записей, и тогда список
        // виден без пароля; заодно неверный пароль не мешает показать, что в
        // архиве лежит. Пароль нужен разбору лишь когда зашифрованы сами
        // заголовки (`rar a -hp`) — это и есть второй заход. На распаковку это
        // не влияет: туда пароль уходит своим путём.
        let password = opts.password.clone();
        let archives = match parse_set(path.as_path(), None) {
            Ok(archives) => archives,
            Err(without) => match password.as_deref() {
                Some(_) => parse_set(path.as_path(), password.as_deref())?,
                None => return Err(without),
            },
        };
        let toc = list(&archives, opts.encoding_override.as_deref());
        let volumes = Volumes::from_family(archives)?;
        // Обход по всему архиву нужен ради двух свойств, и оба уже известны:
        // сплошной архив спрашивается у набора, разрезанные записи посчитаны
        // оглавлением. Второй раз заголовки не перебираются.
        let solid = volumes.is_solid();
        let one_pass = solid || toc.any_split;

        Ok(Box::new(RarReader {
            volumes,
            password,
            entries: toc.entries,
            places: toc.places,
            one_pass,
            solid,
        }))
    }
}

// ── Разбор набора томов ──────────────────────────────────────────────────────

/// Разобрать архив, а если он часть многотомного набора — и все его тома.
///
/// В отличие от libunrar, которая искала соседние тома сама, вендоренный
/// распаковщик получает набор целиком: разрезанный файл он склеивает из кусков,
/// лежащих в разных томах, и потому обязан видеть их все.
fn parse_set(first: &Path, password: Option<&str>) -> Result<Vec<rars::Archive>> {
    // Пароль у набора один и соль тоже, а тома — отдельные `Archive`, каждый
    // со своей ячейкой под выведенный ключ. Ячейка заводится здесь, одна на
    // весь набор, и достаётся **разбору** каждого тома, первого в том числе.
    //
    // Отдавать её после разбора было мало: у архива с зашифрованными
    // заголовками (`rar a -hp`) ключ нужен, чтобы прочитать сами заголовки, то
    // есть внутри разбора, — и набор из 44 томов выводил ключ 44 раза, хотя
    // тот же набор без `-hp` обходился одним.
    let keys = rars::VolumeKeyCaches::default();
    let head = parse_one(first, password, &keys)?;
    if !is_volume(&head) {
        return Ok(vec![head]);
    }
    let mut archives = vec![head];
    for path in sibling_volumes(first) {
        archives.push(parse_one(&path, password, &keys)?);
    }
    Ok(archives)
}

fn parse_one(
    path: &Path,
    password: Option<&str>,
    keys: &rars::VolumeKeyCaches,
) -> Result<rars::Archive> {
    let opts = rars::ArchiveReadOptions {
        volume_keys: Some(keys),
        ..rars::ArchiveReadOptions::with_optional_password(password.map(str::as_bytes))
    };
    rars::ArchiveReader::read_path_with_options(path, opts).map_err(map_err)
}

fn is_volume(archive: &rars::Archive) -> bool {
    match archive {
        rars::Archive::Rar13(a) => a.main.is_volume(),
        rars::Archive::Rar15To40(a) => a.main.is_volume(),
        rars::Archive::Rar50Plus(a) => a.main.is_volume(),
    }
}

/// Тома набора после данного — по именам, до первого недостающего.
///
/// RAR знает две схемы имён, и обе начинаются с того файла, на который указали:
///
/// - **новая** (RAR 3 и дальше): `имя.part1.rar`, `имя.part2.rar`, … Ширина
///   числа берётся из имени, а числа шире её просто дописываются — так же
///   поступает и сам `rar`, когда томов оказывается больше, чем он заложил.
/// - **старая**: первый том `имя.rar`, дальше `имя.r00`, `имя.r01`, …
///
/// Дальше `.r99` старая схема продолжается буквой `.s00`; такие наборы (сто
/// томов и больше) здесь обрываются, и это осознанно: живьём они не
/// встречаются, а гадать без образца не на чем.
fn sibling_volumes(first: &Path) -> Vec<PathBuf> {
    let dir = first.parent().unwrap_or_else(|| Path::new("."));
    let Some(name) = first.file_name().and_then(|n| n.to_str()) else {
        return Vec::new();
    };
    let lower = name.to_ascii_lowercase();

    if let Some(stem) = lower.strip_suffix(".rar") {
        if let Some(cut) = stem.rfind(".part") {
            let digits = &stem[cut + ".part".len()..];
            if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
                let width = digits.len();
                let start: u64 = digits.parse().unwrap_or(0);
                // Регистр берётся из настоящего имени, а не из строчной копии:
                // на файловой системе, различающей регистр, `Имя.PART2.RAR`
                // иначе не найдётся.
                let head = &name[..cut + ".part".len()];
                let tail = &name[stem.len()..];
                return exists_while(dir, |n| {
                    format!("{head}{num:0width$}{tail}", num = start + n)
                });
            }
        }
        let base = &name[..stem.len()];
        return exists_while(dir, |n| format!("{base}.r{num:02}", num = n - 1));
    }

    // Указали не на первый том старой схемы, а на продолжение: `имя.r07`.
    if let Some(cut) = lower.rfind(".r") {
        let digits = &lower[cut + ".r".len()..];
        if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
            let width = digits.len();
            let start: u64 = digits.parse().unwrap_or(0);
            let head = &name[..cut + ".r".len()];
            return exists_while(dir, |n| format!("{head}{num:0width$}", num = start + n));
        }
    }
    Vec::new()
}

/// Имена, выданные `next` для n = 1, 2, 3, …, пока такой файл существует.
fn exists_while(dir: &Path, next: impl Fn(u64) -> String) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for n in 1.. {
        let candidate = dir.join(next(n));
        if !candidate.exists() {
            break;
        }
        out.push(candidate);
    }
    out
}

// ── Оглавление ───────────────────────────────────────────────────────────────

/// Место записи в наборе: том и её порядковый номер среди файловых заголовков
/// этого тома.
///
/// Опознание идёт **по месту, а не по имени**: `rar a -ep` кладёт в архив два
/// разных файла под одним именем, и поиск по имени отдавал бы на обоих первый.
#[derive(Clone, Copy)]
struct Place {
    volume: usize,
    ordinal: usize,
    /// Запись продолжается в следующем томе, то есть склеивается только обходом
    /// набора и поодиночке не читается (`alone_readable`).
    split: bool,
}

/// Оглавление набора: что в нём лежит, где лежит, и нужен ли обход целиком.
struct Toc {
    entries: Vec<Entry>,
    places: Vec<Place>,
    /// Хоть одна запись разрезана границей тома.
    ///
    /// Считается здесь, а не отдельным обходом заголовков: те же члены тех же
    /// томов уже перебираются ниже. И считается **до** пропуска продолжений —
    /// набор, открытый со среднего тома, начинается с продолжения, у которого
    /// головы нет вовсе, и по одному `is_split_after` оно бы не заметилось.
    any_split: bool,
}

/// Собрать оглавление набора и запомнить, где чья запись лежит.
fn list(archives: &[rars::Archive], encoding: Option<&str>) -> Toc {
    let mut raw_names: Vec<Vec<u8>> = Vec::new();
    let mut raw_links: Vec<Vec<u8>> = Vec::new();
    let mut places: Vec<Place> = Vec::new();
    let mut metas: Vec<rars::ArchiveMemberMeta> = Vec::new();
    let mut any_split = false;

    for (volume, archive) in archives.iter().enumerate() {
        let links = link_targets(archive);
        for (ordinal, member) in archive.members().enumerate() {
            any_split |= member.meta.is_split_before || member.meta.is_split_after;
            // Продолжение файла из прошлого тома — не отдельная запись
            // (тикет 19). Считать его записью значит сдвинуть все номера после
            // него: распаковка отдаёт разрезанный файл один раз, склеенным.
            if member.meta.is_split_before {
                continue;
            }
            raw_names.push(member.meta.name.clone());
            raw_links.push(links.get(ordinal).copied().unwrap_or(&[]).to_vec());
            places.push(Place {
                volume,
                ordinal,
                split: member.meta.is_split_after,
            });
            metas.push(member.meta);
        }
    }

    // Кодировку выбирают **имена всего архива**, и цель ссылки читается ею же:
    // цель — такой же путь, и правило «одна кодировка на архив» иначе
    // нарушится, а короткая цель вроде `..\файл` в одиночку опознаётся хуже
    // целого набора имён. Ярлык берётся один раз: определение идёт по всем
    // именам сразу и стоит прохода по ним.
    let label = detect_encoding(&raw_names, encoding);
    let names = decode_names(&raw_names, Some(&label));
    let link_names = if raw_links.iter().any(|t| !t.is_empty()) {
        decode_names(&raw_links, Some(&label))
    } else {
        Vec::new()
    };

    let entries = raw_names
        .into_iter()
        .zip(&metas)
        .enumerate()
        .map(|(i, (raw, meta))| Entry {
            path_raw: raw,
            path: PathBuf::from(&names[i]),
            // Ссылка проверяется первой: у ссылки на каталог стоит и признак
            // каталога, а создать надо ссылку, иначе на её месте вырастет
            // пустая папка.
            kind: match link_names.get(i).filter(|t| !t.is_empty()) {
                Some(target) => EntryKind::Symlink {
                    target: PathBuf::from(target),
                },
                None if meta.is_directory => EntryKind::Dir,
                None => EntryKind::File,
            },
            size: meta.unpacked_size,
            mode: unix_mode(meta.file_attr),
            is_encrypted: meta.is_encrypted,
            modified: modified(meta),
            is_resource_fork: false,
        })
        .collect();

    Toc {
        entries,
        places,
        any_split,
    }
}

/// Цели перенаправления RAR 5 по порядку файловых заголовков тома; пусто там,
/// где запись — обычный файл.
///
/// Порядок здесь тот же, которым живёт `Place::ordinal`, — номер среди
/// файловых заголовков тома, — поэтому цель и берётся по этому номеру.
///
/// До RAR 5 ссылка хранилась телом записи, а не полем заголовка, поэтому у
/// старших поколений список пуст и трогать их поведение нечем.
///
/// **Перенаправление любого вида становится ссылкой.** RAR 5 различает пять:
/// символическая ссылка Unix и Windows, точка соединения Windows, жёсткая
/// ссылка и ссылка на одинаковый файл (`rar -oi`). Эталон здесь `unar`, и на
/// собранных архивах он проверен: жёсткую ссылку и ссылку на одинаковый файл
/// он тоже кладёт символической (`unrar` вместо этого делает настоящую
/// жёсткую ссылку и настоящую копию). Своего вида записи под них у нас нет, а
/// пустой файл на месте жёсткой ссылки — молчаливая потеря содержимого.
fn link_targets(archive: &rars::Archive) -> Vec<&[u8]> {
    match archive {
        rars::Archive::Rar50Plus(a) => a
            .files()
            .map(|f| {
                f.redirection
                    .as_ref()
                    .map_or(&[][..], |r| r.target_name.as_slice())
            })
            .collect(),
        rars::Archive::Rar13(_) | rars::Archive::Rar15To40(_) => Vec::new(),
    }
}

/// Права POSIX, если архив собран на Unix.
///
/// На Unix RAR кладёт в поле атрибутов полное значение `st_mode` (скажем,
/// 0o100755 — обычный файл с правами rwxr-xr-x). На Windows там же лежат флаги
/// FAT/NTFS (READONLY = 0x1, DIRECTORY = 0x10 и подобные) — маленькие числа,
/// которым старшие биты типа файла взяться неоткуда. По ним одно от другого и
/// отличается.
fn unix_mode(attr: u64) -> Option<u32> {
    const S_IFMT: u32 = 0o170000;
    const S_IFREG: u32 = 0o100000;
    const S_IFDIR: u32 = 0o040000;
    const S_IFLNK: u32 = 0o120000;
    let attr = u32::try_from(attr).ok()?;
    match attr & S_IFMT {
        S_IFREG | S_IFDIR | S_IFLNK => Some(attr & 0o7777),
        _ => None,
    }
}

/// Время изменения записи — по правилам того семейства, что её записало.
///
/// RAR 1.3…4 хранят слово MS-DOS: часы на стене без часового пояса, ровно как
/// одноимённое поле zip, и читаются они как местное время. RAR 5 хранит
/// **момент времени** в секундах от эпохи Unix, и переводить его нечего.
///
/// Это же снимает расхождение с `unar`, которое годами было не по нашей воле:
/// libunrar отдавала наружу только слово MS-DOS с шагом в две секунды, и файл,
/// упакованный на нечётной секунде, показывался на секунду раньше правды.
fn modified(meta: &rars::ArchiveMemberMeta) -> Option<SystemTime> {
    let stamp = meta.file_time?;
    match meta.family {
        rars::ArchiveFamily::Rar50Plus => Some(UNIX_EPOCH + Duration::from_secs(u64::from(stamp))),
        rars::ArchiveFamily::Rar13 | rars::ArchiveFamily::Rar15To40 => {
            crate::datetime::dos_words_to_systime((stamp >> 16) as u16, stamp as u16)
        }
    }
}

// ── Тома, разложенные по семействам ──────────────────────────────────────────

/// Набор томов, приведённый к своему семейству формата.
///
/// Общий вид (`rars::Archive`) хорош для оглавления, но распаковка у каждого
/// семейства своя — и у RAR 5 она к тому же умеет отдавать ссылки отдельным
/// вызовом, чего общий фасад не показывает.
enum Volumes {
    Rar13(Vec<rars::rar13::Archive>),
    Rar15To40(Vec<rars::rar15_40::Archive>),
    Rar50Plus(Vec<rars::rar50::Archive>),
}

impl Volumes {
    fn from_family(archives: Vec<rars::Archive>) -> Result<Self> {
        let mixed = || Error::Corrupt("rar: тома набора разных поколений формата".into());
        let mut rar13 = Vec::new();
        let mut rar15_40 = Vec::new();
        let mut rar50 = Vec::new();
        for archive in archives {
            match archive {
                rars::Archive::Rar13(a) => rar13.push(a),
                rars::Archive::Rar15To40(a) => rar15_40.push(a),
                rars::Archive::Rar50Plus(a) => rar50.push(a),
            }
        }
        match (rar13.is_empty(), rar15_40.is_empty(), rar50.is_empty()) {
            (false, true, true) => Ok(Self::Rar13(rar13)),
            (true, false, true) => Ok(Self::Rar15To40(rar15_40)),
            (true, true, false) => Ok(Self::Rar50Plus(rar50)),
            _ => Err(mixed()),
        }
    }

    /// Сплошной ли архив: запись распаковывается только из окна, накопленного
    /// предыдущими, поэтому обход нужен весь — и поодиночке такую запись не
    /// прочитать даже после аварии (`alone_readable`).
    ///
    /// Второе основание для полного обхода — разрезанная между томами запись, —
    /// спрашивается не здесь, а у оглавления (`Toc::any_split`): оно и так
    /// перебирает всех членов всех томов, и второй такой перебор был бы вторым
    /// ответом на тот же вопрос.
    fn is_solid(&self) -> bool {
        match self {
            Self::Rar13(v) => v.iter().any(|a| a.main.is_solid()),
            Self::Rar15To40(v) => v
                .iter()
                .any(|a| a.main.is_solid() || a.files().any(|f| f.is_solid())),
            Self::Rar50Plus(v) => v
                .iter()
                .any(|a| a.main.is_solid() || a.files().any(rar50_solid)),
        }
    }

    /// Распаковать одну запись, ни к чему больше не прикасаясь.
    fn write_member(
        &self,
        place: Place,
        password: Option<&[u8]>,
        mut out: &mut dyn Write,
    ) -> Result<()> {
        let gone = || Error::Corrupt(format!("rar: записи {} нет в томе", place.ordinal));
        match self {
            Self::Rar13(v) => {
                let archive = v.get(place.volume).ok_or_else(gone)?;
                let entry = archive.entries.get(place.ordinal).ok_or_else(gone)?;
                entry.write_to(archive, password, &mut out)
            }
            Self::Rar15To40(v) => {
                let archive = v.get(place.volume).ok_or_else(gone)?;
                let file = archive.files().nth(place.ordinal).ok_or_else(gone)?;
                file.write_to(archive, password, &mut out)
            }
            Self::Rar50Plus(v) => {
                let archive = v.get(place.volume).ok_or_else(gone)?;
                let file = archive.files().nth(place.ordinal).ok_or_else(gone)?;
                file.write_to(archive, password, &mut out)
            }
        }
        .map_err(map_err)
    }

    /// Обойти набор целиком, отдавая каждую запись ходоку.
    fn walk(&self, password: Option<&[u8]>, walker: &mut Walker<'_>) -> rars::Result<()> {
        let opts = rars::ArchiveReadOptions::with_optional_password(password);
        // `RefCell` тут не от лени: у RAR 5 обходов два — на записи с телом и на
        // ссылки, — а замыкания взяли бы ходока в исключительное пользование
        // каждое.
        let walker = RefCell::new(walker);
        match self {
            Self::Rar13(v) => {
                rars::rar13::extract_volumes_to(v, password, |_| walker.borrow_mut().open_body())
            }
            Self::Rar15To40(v) => {
                rars::rar15_40::extract_volumes_to(v, opts, |_| walker.borrow_mut().open_body())
            }
            // Ссылка RAR 5 живёт отдельным полем заголовка, а не телом записи,
            // и обычный обход её молча пропускает. Пропуск сдвинул бы все
            // номера после неё, поэтому берётся обход, который о ссылках
            // сообщает. Цель отсюда не берётся: она уже прочитана в оглавление
            // (`link_targets`), а здесь у ссылки только пустое тело.
            Self::Rar50Plus(v) => rars::rar50::extract_volumes_to_with_redirections(
                v,
                opts,
                |_| walker.borrow_mut().open_body(),
                |_, _| walker.borrow_mut().open_link(),
            ),
        }
    }
}

/// Сплошная ли запись RAR 5. Нечитаемое поле сжатия считается сплошным: так
/// ошибка вылезет на распаковке этой записи, а не порчей чужих.
fn rar50_solid(file: &rars::rar50::FileHeader) -> bool {
    if file.is_directory() {
        return false;
    }
    match file.decoded_compression_info() {
        Ok(info) => info.solid,
        Err(_) => true,
    }
}

// ── Читатель ─────────────────────────────────────────────────────────────────

struct RarReader {
    volumes: Volumes,
    password: Option<String>,
    entries: Vec<Entry>,
    places: Vec<Place>,
    one_pass: bool,
    /// Архив сплошной: запись живёт только в общем окне предыдущих.
    solid: bool,
}

impl ArchiveReader for RarReader {
    fn format(&self) -> FormatId {
        FormatId::Rar
    }

    fn entries(&mut self) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn verify_password(&mut self) -> Result<()> {
        let Some(idx) = self.entries.iter().position(|e| e.is_encrypted) else {
            return Ok(());
        };
        // Расшифровываем первую зашифрованную запись «в раковину». Прочие
        // ошибки относим к паролю по тому, был ли он задан.
        match self.read_entry(idx, &mut std::io::sink()) {
            Ok(()) => Ok(()),
            Err(e @ (Error::Encrypted | Error::WrongPassword)) => Err(e),
            Err(_) if self.password.is_none() => Err(Error::Encrypted),
            Err(_) => Err(Error::WrongPassword),
        }
    }

    fn read_entry(&mut self, idx: usize, out: &mut dyn Write) -> Result<()> {
        // Зовётся собственный проход, а не `read_entries` из трейта: умолчание
        // трейта ведёт обратно сюда, и снятое когда-нибудь переопределение
        // обернулось бы не ошибкой сборки, а бесконечной рекурсией.
        self.walk(&[idx], &mut OneEntry { out })
    }

    /// Один проход по архиву на весь список вместо одного на каждую запись.
    ///
    /// У сплошного архива дойти до записи значит распаковать всё, что лежит до
    /// неё: на тысяче файлов чтение по одной выходило в тридцать девять раз
    /// дольше `unar` (тикет 19).
    fn read_entries(&mut self, indices: &[usize], sink: &mut dyn EntrySink) -> Result<()> {
        self.walk(indices, sink)
    }
}

impl RarReader {
    fn password_bytes(&self) -> Option<&[u8]> {
        self.password.as_deref().map(str::as_bytes)
    }

    fn walk(&self, indices: &[usize], sink: &mut dyn EntrySink) -> Result<()> {
        // Номер вне списка — ошибка вызывающего, и она не должна всплыть на
        // середине уже начатой распаковки.
        if let Some(&bad) = indices.iter().find(|&&i| i >= self.entries.len()) {
            return Err(Error::InvalidIndex(bad));
        }
        if self.one_pass {
            self.one_pass_walk(indices, sink)
        } else {
            self.read_each(indices, sink)
        }
    }

    /// Записи независимы: каждая распаковывается сама по себе, а до чужих дело
    /// не доходит вовсе.
    fn read_each(&self, indices: &[usize], sink: &mut dyn EntrySink) -> Result<()> {
        for &idx in indices {
            if !self.deliver_one(idx, None, sink)? {
                return Ok(());
            }
        }
        Ok(())
    }

    /// Одна запись приёмнику, от `begin` до `end`. `false` — приёмник просит
    /// остановиться.
    ///
    /// `refusal` задан, когда исход известен заранее: запись, до которой обход
    /// не дошёл, читать нечем, но сказать о ней приёмнику всё равно надо. Иначе
    /// тело читается прямо здесь.
    ///
    /// Одно рукопожатие с приёмником на оба случая: у `read_each` и у добора
    /// после аварии (`recover_rest`) оно одно и то же, а две копии договора
    /// «что значит `Skip`, что значит `end → false`» разошлись бы.
    fn deliver_one(
        &self,
        idx: usize,
        refusal: Option<Error>,
        sink: &mut dyn EntrySink,
    ) -> Result<bool> {
        match sink.begin(idx)? {
            SinkStep::Stop => return Ok(false),
            SinkStep::Skip => return Ok(true),
            SinkStep::Body => {}
        }
        let outcome = match refusal {
            Some(why) => Err(why),
            // У каталога и у ссылки тела нет: распаковщику такую запись не
            // отдают вовсе. Цель ссылки лежит в заголовке и уже прочитана в
            // оглавление.
            None if matches!(
                self.entries[idx].kind,
                EntryKind::Dir | EntryKind::Symlink { .. }
            ) =>
            {
                Ok(())
            }
            None => {
                let mut writer = SinkWriter::new(sink);
                let wrote =
                    self.volumes
                        .write_member(self.places[idx], self.password_bytes(), &mut writer);
                writer.outcome(wrote)
            }
        };
        sink.end(idx, outcome)
    }

    /// Сплошной архив или разрезанный файл: распаковщик идёт по архиву сам, от
    /// начала и подряд, а мы разбираем то, что он отдаёт.
    ///
    /// Отказ одной записи обрывает проход целиком, поэтому проход после него
    /// начинается заново с остатка списка — как это делал и прежний код поверх
    /// libunrar. На сплошном архиве это дорого (пропуск там означает
    /// распаковку), но дороже прежнего не будет: тот начинал сначала на
    /// **каждой** записи, а не на отказавшей.
    ///
    /// **Перезапуск спасает не всё, и это его предел.** Он идёт от начала
    /// архива и потому снова упирается в ту же испорченную запись — только
    /// теперь она уже отмечена, приписать отказ некому, и проход кончается
    /// молча. Остаток списка добирается поштучно (`recover_rest`).
    fn one_pass_walk(&self, indices: &[usize], sink: &mut dyn EntrySink) -> Result<()> {
        let mut broke_on = None;
        let reached = {
            let mut walker = Walker::new(indices, sink);
            loop {
                let outcome = self.volumes.walk(self.password_bytes(), &mut walker);
                if let Some(err) = walker.fatal.take() {
                    // Отказал приёмник — распаковку отменили или писать некуда.
                    // Это не беда архива, и остаток списка не отмечается.
                    return Err(err);
                }
                match outcome {
                    Ok(()) | Err(rars::Error::Cancelled) => break,
                    Err(e) => {
                        // Причина запоминается видом, а не текстом: неверный
                        // пароль, оборвавший обход, обязан остаться неверным
                        // паролем и для записей, до которых обход не дошёл, —
                        // иначе спросить пароль по ним будет уже нечем.
                        broke_on = Some(e.clone());
                        if !walker.blame_open(map_err(e))? {
                            break;
                        }
                        if walker.stop || walker.exhausted() {
                            break;
                        }
                        walker.pos = 0;
                    }
                }
            }
            walker.finish()?
        };
        self.recover_rest(&indices[reached..], broke_on.as_ref(), sink)
    }

    /// Записи, до которых проход не дошёл: прочитать поодиночке, если можно, а
    /// иначе сказать правду о том, почему их нет.
    ///
    /// Одна испорченная запись сбивала **весь** остаток архива, хотя вне
    /// сплошного архива соседи от неё не зависят: на многотомном наборе из
    /// шести файлов с одним битым `unrar` спасал пять, а мы отдавали три.
    /// Поштучное чтение — тот же путь, которым идёт несплошной архив всегда
    /// (`read_each`), и цена ему возникает только после аварии.
    ///
    /// **Чего добрать нельзя, о том говорится прямо.** В сплошном архиве запись
    /// распаковывается из окна, накопленного предыдущими, а разрезанная между
    /// томами склеивается только обходом набора — по одной их не прочитать.
    /// Прежде все они получали «rar: заголовки кончились на записи N», и это
    /// была неправда: заголовки на месте, обход прекратился.
    fn recover_rest(
        &self,
        rest: &[usize],
        broke_on: Option<&rars::Error>,
        sink: &mut dyn EntrySink,
    ) -> Result<()> {
        for &idx in rest {
            let refusal = if self.alone_readable(idx) {
                None
            } else {
                Some(not_reached(broke_on, idx))
            };
            if !self.deliver_one(idx, refusal, sink)? {
                return Ok(());
            }
        }
        Ok(())
    }

    /// Можно ли прочитать эту запись, не проходя по архиву целиком.
    fn alone_readable(&self, idx: usize) -> bool {
        !self.solid && !self.places[idx].split
    }
}

// ── Ходок по проходу ─────────────────────────────────────────────────────────

/// Состояние одного прохода: чей номер сейчас нужен, чьё тело копится и почему
/// проход прервали.
///
/// Распаковщик зовёт нас один раз на запись — **до** того, как отдаст её тело,
/// и о том, что тело кончилось, не сообщает вовсе. Поэтому `end` для записи
/// уходит приёмнику при следующем таком вызове или по завершении прохода.
struct Walker<'a> {
    /// Запрошенные номера, по возрастанию и без повторов.
    want: &'a [usize],
    /// Сколько из них уже отдано приёмнику или отмечено отказом.
    next: usize,
    /// Номер очередной записи в этом проходе.
    pos: usize,
    /// Приёмник, разделённый с писарем: обход держит писаря, пока льёт тело, а
    /// ходоку приёмник нужен на границах записей. Одновременно в него никто не
    /// пишет — писарь предыдущей записи умирает раньше, чем обход спросит
    /// следующую.
    ///
    /// Это тот же `SinkWriter`, что и на быстром пути (`read_each`): он и есть
    /// мост к приёмнику, и он же хранит его отказ отдельно от ошибки перелива.
    shared: Rc<RefCell<SinkWriter<'a>>>,
    /// Запись, чьё тело льётся прямо сейчас.
    open: Option<usize>,
    /// Отказ приёмника: наружу он уходит как есть, а проход обрывается.
    fatal: Option<Error>,
    stop: bool,
}

impl<'a> Walker<'a> {
    fn new(want: &'a [usize], sink: &'a mut dyn EntrySink) -> Self {
        Self {
            want,
            next: 0,
            pos: 0,
            shared: Rc::new(RefCell::new(SinkWriter::new(sink))),
            open: None,
            fatal: None,
            stop: false,
        }
    }

    /// Приёмнику сказать, что начинается запись `idx`.
    ///
    /// Отдельным методом, а не строчкой на месте: заём ячейки надо отпустить
    /// **до** разбора ответа, иначе ветки разбора не смогут тронуть самого
    /// ходока.
    fn sink_begin(&self, idx: usize) -> Result<SinkStep> {
        self.shared.borrow_mut().sink().begin(idx)
    }

    /// Приёмнику сказать, чем кончилась запись `idx`.
    fn sink_end(&self, idx: usize, outcome: Result<()>) -> Result<bool> {
        self.shared.borrow_mut().sink().end(idx, outcome)
    }

    fn exhausted(&self) -> bool {
        self.next >= self.want.len()
    }

    /// Очередная запись прохода: нужна ли она и куда писать её тело.
    fn open_body(&mut self) -> rars::Result<Box<dyn Write + 'a>> {
        if self.begin_next()? {
            Ok(Box::new(BodyWriter {
                shared: Rc::clone(&self.shared),
            }))
        } else {
            Ok(Box::new(std::io::sink()))
        }
    }

    /// То же для ссылки RAR 5: место в нумерации она занимает, тела у неё нет.
    fn open_link(&mut self) -> rars::Result<()> {
        self.begin_next()?;
        Ok(())
    }

    fn begin_next(&mut self) -> rars::Result<bool> {
        self.close_open(Ok(()))?;
        if self.stop || self.exhausted() {
            return Err(rars::Error::Cancelled);
        }
        let pos = self.pos;
        self.pos += 1;
        if pos != self.want[self.next] {
            return Ok(false);
        }
        match self.sink_begin(pos) {
            Ok(SinkStep::Body) => {
                self.open = Some(pos);
                Ok(true)
            }
            Ok(SinkStep::Skip) => {
                self.next += 1;
                Ok(false)
            }
            Ok(SinkStep::Stop) => {
                self.stop = true;
                Err(rars::Error::Cancelled)
            }
            Err(e) => {
                self.fatal = Some(e);
                Err(rars::Error::Cancelled)
            }
        }
    }

    /// Закрыть текущую запись: сообщить приёмнику исход её тела.
    ///
    /// Отказ самого приёмника перекрывает исход прохода: обход о нём узнал
    /// безликой ошибкой ввода-вывода и приписал бы её архиву.
    fn close_open(&mut self, outcome: Result<()>) -> rars::Result<()> {
        let Some(idx) = self.open.take() else {
            return Ok(());
        };
        let outcome = self.shared.borrow_mut().outcome(outcome);
        self.next += 1;
        match self.sink_end(idx, outcome) {
            Ok(true) => Ok(()),
            Ok(false) => {
                self.stop = true;
                Err(rars::Error::Cancelled)
            }
            Err(e) => {
                self.fatal = Some(e);
                Err(rars::Error::Cancelled)
            }
        }
    }

    /// Приписать ошибку прохода записи, чьё тело он не довёл.
    ///
    /// `false` — приписать некому: сломалось на записи, которой не просили, и
    /// повторный проход сломается ровно там же.
    fn blame_open(&mut self, err: Error) -> Result<bool> {
        if self.open.is_none() {
            return Ok(false);
        }
        let _ = self.close_open(Err(err));
        match self.fatal.take() {
            Some(e) => Err(e),
            None => Ok(true),
        }
    }

    /// Проход кончился: дописать последнюю запись и сказать, сколько записей
    /// списка он успел разобрать.
    ///
    /// Что делать с остальными — забота вызывающего: список у него свой, и там
    /// же известно, читаются ли они поодиночке. Приёмника этот метод после
    /// `close_open` больше не трогает, так что ходока можно уронить и взять
    /// приёмник обратно.
    fn finish(&mut self) -> Result<usize> {
        let _ = self.close_open(Ok(()));
        if let Some(e) = self.fatal.take() {
            return Err(e);
        }
        // Приёмник просил остановиться — недошедших для него нет.
        Ok(if self.stop {
            self.want.len()
        } else {
            self.next
        })
    }
}

/// Писарь, льющий тело записи прямо приёмнику: тот же `SinkWriter`, только
/// владеемый, а не одолженный.
///
/// Обход в вендоренном коде требует писаря, пережившего вызов замыкания, —
/// отсюда владение и ячейка. Время жизни у него от приёмника: подпись обхода
/// правлена под это (`Box<dyn Write + 'w>`, метка `NEWTUA`). До тикета 29
/// писаря требовали `'static`, и тело приходилось копить целиком в памяти.
struct BodyWriter<'a> {
    shared: Rc<RefCell<SinkWriter<'a>>>,
}

impl Write for BodyWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.shared.borrow_mut().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// ── Ошибки ───────────────────────────────────────────────────────────────────

/// Почему записи нет, если обход до неё не дошёл.
///
/// **Вид ошибки важнее её текста.** По виду вызывающий решает, спросить ли
/// пароль, — поэтому обход, оборвавшийся на неверном пароле, оставляет неверный
/// пароль и всем записям за ним. Заворачивать такое в `Corrupt` значило бы
/// повторить дефект тикета 36, только на соседях: человек услышал бы «архив
/// побит» там, где надо всего лишь исправить опечатку.
///
/// Пояснение приписывается только к поломке, где текст и есть весь смысл. А
/// `None` — это не авария: обход дошёл до конца, но заголовков под запрошенные
/// номера не хватило.
fn not_reached(broke_on: Option<&rars::Error>, idx: usize) -> Error {
    let Some(cause) = broke_on else {
        return Error::Corrupt(format!("rar: заголовки кончились на записи {idx}"));
    };
    match map_err(cause.clone()) {
        e @ (Error::WrongPassword | Error::Encrypted | Error::Unsupported { .. }) => e,
        other => Error::Corrupt(format!(
            "rar: обход архива прервался ({other}), до этой записи он не дошёл"
        )),
    }
}

/// Ошибка распаковщика — в нашу.
///
/// Обёртки «в записи такой-то» и «по смещению такому-то» разбираются до
/// причины: по ней решают, спросить пароль или доложить о поломке. Текст при
/// этом берётся внешний — в нём есть имя записи, и человеку он понятнее.
fn map_err(e: rars::Error) -> Error {
    use rars::Error as R;
    match &e {
        R::AtEntry { source, .. } | R::AtArchiveOffset { source, .. } => {
            match map_err((**source).clone()) {
                Error::Corrupt(_) => Error::Corrupt(e.to_string()),
                mapped => mapped,
            }
        }
        R::NeedPassword => Error::Encrypted,
        R::WrongPasswordOrCorruptData => Error::WrongPassword,
        R::Io(io) => Error::Io(std::io::Error::new(io.kind, io.message.clone())),
        R::UnsupportedSignature => Error::UnknownFormat,
        R::UnsupportedVersion(_)
        | R::UnsupportedFeature { .. }
        | R::UnsupportedFamilyFeature { .. }
        | R::UnsupportedCompression { .. }
        | R::UnsupportedEncryption { .. } => Error::Unsupported {
            format: "rar".into(),
            feature: e.to_string(),
        },
        _ => Error::Corrupt(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_detects_rar_magic() {
        assert_eq!(
            RarHandler.probe(b"Rar!\x1a\x07\x01\x00", None),
            Confidence::MAGIC
        );
    }

    #[test]
    fn probe_detects_rar4_magic() {
        assert_eq!(
            RarHandler.probe(b"Rar!\x1a\x07\x00", None),
            Confidence::MAGIC
        );
    }

    #[test]
    fn probe_rejects_other() {
        assert_eq!(RarHandler.probe(b"PK\x03\x04", None), Confidence::NONE);
    }

    #[test]
    fn rar_handler_id_is_rar() {
        assert_eq!(RarHandler.id(), FormatId::Rar);
    }

    /// Тома новой схемы находятся по имени, а поиск обрывается на первой дыре.
    #[test]
    fn part_volumes_are_found_until_the_first_gap() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["a.part1.rar", "a.part2.rar", "a.part3.rar", "a.part5.rar"] {
            std::fs::write(dir.path().join(name), b"x").unwrap();
        }
        let found = sibling_volumes(&dir.path().join("a.part1.rar"));
        assert_eq!(
            found,
            vec![
                dir.path().join("a.part2.rar"),
                dir.path().join("a.part3.rar")
            ],
            "пятый том без четвёртого — не продолжение набора"
        );
    }

    /// Ширина номера берётся из имени, но не мешает ему вырасти.
    #[test]
    fn part_volume_numbers_may_outgrow_their_width() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["a.part08.rar", "a.part09.rar", "a.part10.rar"] {
            std::fs::write(dir.path().join(name), b"x").unwrap();
        }
        let found = sibling_volumes(&dir.path().join("a.part08.rar"));
        assert_eq!(
            found,
            vec![
                dir.path().join("a.part09.rar"),
                dir.path().join("a.part10.rar")
            ]
        );
    }

    /// Старая схема: за `имя.rar` идут `имя.r00`, `имя.r01`, …
    #[test]
    fn old_scheme_volumes_follow_the_first_one() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["a.rar", "a.r00", "a.r01"] {
            std::fs::write(dir.path().join(name), b"x").unwrap();
        }
        let found = sibling_volumes(&dir.path().join("a.rar"));
        assert_eq!(
            found,
            vec![dir.path().join("a.r00"), dir.path().join("a.r01")]
        );
    }

    /// Однотомный архив соседей не набирает, даже если рядом лежит чужой файл.
    #[test]
    fn a_lone_archive_has_no_siblings() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.rar"), b"x").unwrap();
        std::fs::write(dir.path().join("b.r00"), b"x").unwrap();
        assert!(sibling_volumes(&dir.path().join("a.rar")).is_empty());
    }

    /// Приёмник, запоминающий каждый кусок тела отдельно.
    #[derive(Default)]
    struct Chunks {
        pieces: Vec<Vec<u8>>,
        ended: Vec<usize>,
    }

    impl EntrySink for Chunks {
        fn begin(&mut self, _idx: usize) -> Result<SinkStep> {
            Ok(SinkStep::Body)
        }

        fn write_body(&mut self, buf: &[u8]) -> Result<()> {
            self.pieces.push(buf.to_vec());
            Ok(())
        }

        fn end(&mut self, idx: usize, outcome: Result<()>) -> Result<bool> {
            outcome?;
            self.ended.push(idx);
            Ok(true)
        }
    }

    /// Тело уходит приёмнику по мере распаковки, а не одним куском в конце.
    ///
    /// Это и есть тикет 29 с нашей стороны: прежний ходок копил всю запись в
    /// `Vec` и отдавал её одним вызовом, то есть держал в памяти целый файл.
    #[test]
    fn body_reaches_the_sink_piece_by_piece() {
        let mut sink = Chunks::default();
        {
            let mut walker = Walker::new(&[0], &mut sink);
            let mut writer = walker.open_body().unwrap();
            writer.write_all(b"first").unwrap();
            writer.write_all(b"second").unwrap();
            drop(writer);
            walker.finish().unwrap();
        }
        assert_eq!(
            sink.pieces,
            vec![b"first".to_vec(), b"second".to_vec()],
            "куски должны дойти как есть, а не склеенными"
        );
        assert_eq!(sink.ended, vec![0]);
    }

    /// Отказ приёмника на куске тела доходит до `end` как наша ошибка, а не
    /// как безликая ошибка ввода-вывода от перелива.
    #[test]
    fn a_sink_refusal_survives_the_write() {
        struct Refuses;
        impl EntrySink for Refuses {
            fn begin(&mut self, _idx: usize) -> Result<SinkStep> {
                Ok(SinkStep::Body)
            }
            fn write_body(&mut self, _buf: &[u8]) -> Result<()> {
                Err(Error::Corrupt("некуда писать".into()))
            }
            fn end(&mut self, _idx: usize, outcome: Result<()>) -> Result<bool> {
                match outcome {
                    Err(Error::Corrupt(why)) => {
                        assert_eq!(why, "некуда писать");
                        Ok(true)
                    }
                    other => panic!("исход приёмника подменён: {other:?}"),
                }
            }
        }

        let mut sink = Refuses;
        let mut walker = Walker::new(&[0], &mut sink);
        let mut writer = walker.open_body().unwrap();
        assert!(writer.write_all(b"body").is_err());
        drop(writer);
        walker.finish().unwrap();
    }

    /// Права читаются только у архивов, собранных на Unix.
    #[test]
    fn unix_mode_ignores_windows_attributes() {
        assert_eq!(unix_mode(0o100755), Some(0o755));
        assert_eq!(unix_mode(0o040755), Some(0o755));
        assert_eq!(unix_mode(0x10), None, "FILE_ATTRIBUTE_DIRECTORY — не режим");
        assert_eq!(unix_mode(0x1), None, "FILE_ATTRIBUTE_READONLY — не режим");
    }
}
