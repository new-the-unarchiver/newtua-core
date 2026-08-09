use std::cell::RefCell;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::archive::{
    ArchiveReader, Confidence, Entry, EntryKind, EntrySink, FormatHandler, FormatId, OneEntry,
    OpenOptions, SinkStep, SinkWriter, Source,
};
use crate::encoding::decode_names;
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
        let (entries, places) = list(&archives, opts.encoding_override.as_deref());
        let volumes = Volumes::from_family(archives)?;
        let one_pass = volumes.needs_one_pass();

        Ok(Box::new(RarReader {
            volumes,
            password,
            entries,
            places,
            one_pass,
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
    let head = parse_one(first, password)?;
    if !is_volume(&head) {
        return Ok(vec![head]);
    }
    let mut archives = vec![head];
    for path in sibling_volumes(first) {
        archives.push(parse_one(&path, password)?);
    }
    Ok(archives)
}

fn parse_one(path: &Path, password: Option<&str>) -> Result<rars::Archive> {
    let opts = rars::ArchiveReadOptions::with_optional_password(password.map(str::as_bytes));
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
}

/// Собрать оглавление набора и запомнить, где чья запись лежит.
fn list(archives: &[rars::Archive], encoding: Option<&str>) -> (Vec<Entry>, Vec<Place>) {
    let mut raw_names: Vec<Vec<u8>> = Vec::new();
    let mut places: Vec<Place> = Vec::new();
    let mut metas: Vec<rars::ArchiveMemberMeta> = Vec::new();

    for (volume, archive) in archives.iter().enumerate() {
        for (ordinal, member) in archive.members().enumerate() {
            // Продолжение файла из прошлого тома — не отдельная запись
            // (тикет 19). Считать его записью значит сдвинуть все номера после
            // него: распаковка отдаёт разрезанный файл один раз, склеенным.
            if member.meta.is_split_before {
                continue;
            }
            raw_names.push(member.meta.name.clone());
            places.push(Place { volume, ordinal });
            metas.push(member.meta);
        }
    }

    let names = decode_names(&raw_names, encoding);
    let entries = raw_names
        .into_iter()
        .zip(&metas)
        .enumerate()
        .map(|(i, (raw, meta))| Entry {
            path_raw: raw,
            path: PathBuf::from(&names[i]),
            kind: if meta.is_directory {
                EntryKind::Dir
            } else {
                EntryKind::File
            },
            size: meta.unpacked_size,
            mode: unix_mode(meta.file_attr),
            is_encrypted: meta.is_encrypted,
            modified: modified(meta),
            is_resource_fork: false,
        })
        .collect();

    (entries, places)
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

    /// Нужен ли проход по всему архиву ради одной записи.
    ///
    /// Нужен в двух случаях: **сплошной** архив (запись распаковывается только
    /// из общего окна, накопленного предыдущими) и **разрезанный** файл
    /// (склеивается из кусков в разных томах, и делает это обход набора).
    /// Во всех прочих архивах записи независимы, и пропуск не стоит ничего.
    fn needs_one_pass(&self) -> bool {
        match self {
            Self::Rar13(v) => v.iter().any(|a| {
                a.main.is_solid()
                    || a.entries
                        .iter()
                        .any(|e| e.is_split_before() || e.is_split_after())
            }),
            Self::Rar15To40(v) => v.iter().any(|a| {
                a.main.is_solid()
                    || a.files()
                        .any(|f| f.is_solid() || f.is_split_before() || f.is_split_after())
            }),
            Self::Rar50Plus(v) => v.iter().any(|a| {
                a.main.is_solid()
                    || a.files()
                        .any(|f| f.is_split_before() || f.is_split_after() || rar50_solid(f))
            }),
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
            // сообщает. Тело у такой записи пустое — ровно то, что отдавала и
            // libunrar; разбирать поле ссылки будет тикет 15.
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
            match sink.begin(idx)? {
                SinkStep::Stop => return Ok(()),
                SinkStep::Skip => continue,
                SinkStep::Body => {}
            }
            let outcome = if matches!(self.entries[idx].kind, EntryKind::Dir) {
                Ok(())
            } else {
                let mut writer = SinkWriter::new(sink);
                let wrote =
                    self.volumes
                        .write_member(self.places[idx], self.password_bytes(), &mut writer);
                writer.outcome(wrote)
            };
            if !sink.end(idx, outcome)? {
                return Ok(());
            }
        }
        Ok(())
    }

    /// Сплошной архив или разрезанный файл: распаковщик идёт по архиву сам, от
    /// начала и подряд, а мы разбираем то, что он отдаёт.
    ///
    /// Отказ одной записи обрывает проход целиком, поэтому проход после него
    /// начинается заново с остатка списка — как это делал и прежний код поверх
    /// libunrar. На сплошном архиве это дорого (пропуск там означает
    /// распаковку), но дороже прежнего не будет: тот начинал сначала на
    /// **каждой** записи, а не на отказавшей.
    fn one_pass_walk(&self, indices: &[usize], sink: &mut dyn EntrySink) -> Result<()> {
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
        walker.finish()
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
    sink: &'a mut dyn EntrySink,
    /// Тело текущей записи.
    ///
    /// Копится целиком, а не льётся приёмнику по кускам: подпись обхода отдаёт
    /// наружу `Box<dyn Write>` без времени жизни, то есть писать в занятый
    /// приёмник такой писарь не может. Пик памяти от этого не растёт против
    /// прежнего кода — libunrar тоже собирала запись в памяти целиком, — но и
    /// не падает; этим занят тикет 29.
    body: Rc<RefCell<Vec<u8>>>,
    /// Запись, чьё тело копится прямо сейчас.
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
            sink,
            body: Rc::new(RefCell::new(Vec::new())),
            open: None,
            fatal: None,
            stop: false,
        }
    }

    fn exhausted(&self) -> bool {
        self.next >= self.want.len()
    }

    /// Очередная запись прохода: нужна ли она и куда писать её тело.
    fn open_body(&mut self) -> rars::Result<Box<dyn Write>> {
        if self.begin_next()? {
            Ok(Box::new(BodyWriter {
                buf: Rc::clone(&self.body),
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
        match self.sink.begin(pos) {
            Ok(SinkStep::Body) => {
                self.open = Some(pos);
                self.body.borrow_mut().clear();
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

    /// Закрыть накопленное тело: отдать его приёмнику и сообщить исход.
    fn close_open(&mut self, outcome: Result<()>) -> rars::Result<()> {
        let Some(idx) = self.open.take() else {
            return Ok(());
        };
        let body = std::mem::take(&mut *self.body.borrow_mut());
        let outcome = outcome.and_then(|()| self.sink.write_body(&body));
        self.next += 1;
        match self.sink.end(idx, outcome) {
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

    /// Проход кончился: дописать последнюю запись и отметить те, до которых он
    /// так и не дошёл.
    ///
    /// Виноват тут архив, а не вызывающий: номера пришли из `entries()`, а
    /// заголовков под них не хватило. Поэтому `Corrupt`, а не `InvalidIndex`.
    fn finish(&mut self) -> Result<()> {
        let _ = self.close_open(Ok(()));
        if let Some(e) = self.fatal.take() {
            return Err(e);
        }
        if self.stop {
            return Ok(());
        }
        while !self.exhausted() {
            let idx = self.want[self.next];
            self.next += 1;
            match self.sink.begin(idx)? {
                SinkStep::Stop => break,
                SinkStep::Skip => continue,
                SinkStep::Body => {}
            }
            let why = Error::Corrupt(format!("rar: заголовки кончились на записи {idx}"));
            if !self.sink.end(idx, Err(why))? {
                break;
            }
        }
        Ok(())
    }
}

/// Писарь, копящий тело записи.
///
/// Времени жизни у него нет намеренно: подпись обхода требует
/// `Box<dyn Write>` — то есть `'static`, — а приёмник живёт заимствованным.
struct BodyWriter {
    buf: Rc<RefCell<Vec<u8>>>,
}

impl Write for BodyWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buf.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// ── Ошибки ───────────────────────────────────────────────────────────────────

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
        | R::UnsupportedEncryption { .. }
        | R::Rar50BufferedDecodeLimitExceeded { .. } => Error::Unsupported {
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

    /// Права читаются только у архивов, собранных на Unix.
    #[test]
    fn unix_mode_ignores_windows_attributes() {
        assert_eq!(unix_mode(0o100755), Some(0o755));
        assert_eq!(unix_mode(0o040755), Some(0o755));
        assert_eq!(unix_mode(0x10), None, "FILE_ATTRIBUTE_DIRECTORY — не режим");
        assert_eq!(unix_mode(0x1), None, "FILE_ATTRIBUTE_READONLY — не режим");
    }
}
