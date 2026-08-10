use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result, io_err_to_corrupt};

/// Finds and orders a multi-volume archive's volumes from its first volume.
pub fn volume_members(first: &Path) -> Result<Vec<PathBuf>> {
    let name = first.file_name().and_then(|s| s.to_str()).unwrap_or("");
    // Схема .001/.002...
    if let Some(stem) = name.strip_suffix(".001") {
        let dir = first.parent().unwrap_or_else(|| Path::new("."));
        let mut members = Vec::new();
        let mut idx = 1u32;
        loop {
            let candidate = dir.join(format!("{stem}.{idx:03}"));
            if candidate.exists() {
                members.push(candidate);
                idx += 1;
            } else {
                break;
            }
        }
        if members.is_empty() {
            return Err(Error::MissingVolume(name.to_string()));
        }
        return Ok(members);
    }
    // Прочие схемы собирает не этот код. `.7z.001` — тот же случай выше;
    // `.partN.rar` и `.r00` набирает сам обработчик RAR (`sibling_volumes` в
    // `format/rar.rs`), и иначе нельзя: том RAR — не кусок сплошного потока, а
    // отдельный файл со своими заголовками, склеивать их байт к байту нечего.
    // Прежде это делала libunrar внутри себя, отчего здесь и было написано
    // «обрабатываются крейтами 7z/rar»; с тикета 26 своего кода это уже не так.
    Ok(vec![first.to_path_buf()])
}

/// Sequential reading of multiple files as a single stream.
pub struct ConcatReader {
    files: Vec<PathBuf>,
    idx: usize,
    current: Option<std::fs::File>,
}

impl ConcatReader {
    pub fn open(members: &[PathBuf]) -> Result<ConcatReader> {
        if members.is_empty() {
            return Err(Error::MissingVolume("<empty>".into()));
        }
        Ok(ConcatReader {
            files: members.to_vec(),
            idx: 0,
            current: None,
        })
    }
}

impl Read for ConcatReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.current.is_none() {
                if self.idx >= self.files.len() {
                    return Ok(0);
                }
                self.current = Some(std::fs::File::open(&self.files[self.idx])?);
                self.idx += 1;
            }
            let f = self.current.as_mut().unwrap();
            let n = f.read(buf)?;
            if n == 0 {
                self.current = None;
                continue;
            }
            return Ok(n);
        }
    }
}

// ── Тома `zip -s`: `имя.z01`, `имя.z02`, …, и последним `имя.zip` ────────────
//
// Точка входа тут — ПОСЛЕДНИЙ файл набора, а не первый: центральный каталог
// zip пишется в самом конце, то есть в `.zip`, а `.z01…` несут только тела
// записей. Это ровно наоборот к схеме `.001` выше.
//
// Крейт `zip` многотомность не умеет ни в одной версии (в 2.4.2 это `read.rs`:
// при `disk_number != disk_with_central_directory` возвращается «Support for
// multi-disk files is not implemented»), поэтому склейка и правка смещений
// делаются ЗДЕСЬ, до того как байты попадут в крейт: тома сцепляются по
// порядку, в каждой записи каталога номер тома обнуляется, а относительное
// смещение локального заголовка становится абсолютным.
//
// Все числа ниже приходят из архива, то есть от потенциального злоумышленника:
// каждое смещение проверяется на попадание в склеенный файл, вся арифметика —
// checked.

const EOCD_SIG: [u8; 4] = [b'P', b'K', 0x05, 0x06];
const EOCD64_SIG: [u8; 4] = [b'P', b'K', 0x06, 0x06];
const LOCATOR_SIG: [u8; 4] = [b'P', b'K', 0x06, 0x07];
const CD_SIG: [u8; 4] = [b'P', b'K', 0x01, 0x02];
/// Идентификатор zip64-поля в области extra записи каталога.
const ZIP64_EXTRA_ID: u16 = 0x0001;
/// 46 байт фиксированной части записи каталога плюс три поля переменной
/// длины, каждое не длиннее 64 КиБ. Верхняя граница на размер каталога при
/// известном числе записей — ею отсекается заведомо завышенный `cd_size`
/// раньше, чем под него что-то выделяется.
const MAX_CD_RECORD: u64 = 46 + 3 * 0xFFFF;

fn corrupt(msg: impl Into<String>) -> Error {
    Error::Corrupt(msg.into())
}

fn unsupported(feature: &str) -> Error {
    Error::Unsupported {
        format: "zip".into(),
        feature: feature.into(),
    }
}

fn le_u16(buf: &[u8], off: usize) -> Result<u16> {
    let b = buf
        .get(off..off + 2)
        .ok_or_else(|| corrupt("unexpected end of zip structure"))?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn le_u32(buf: &[u8], off: usize) -> Result<u32> {
    let b = buf
        .get(off..off + 4)
        .ok_or_else(|| corrupt("unexpected end of zip structure"))?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn le_u64(buf: &[u8], off: usize) -> Result<u64> {
    let b = buf
        .get(off..off + 8)
        .ok_or_else(|| corrupt("unexpected end of zip structure"))?;
    Ok(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

/// Тома схемы `zip -s` для точки входа `last`.
///
/// Возвращает `None`, если `last` — не `.zip` или рядом нет `.z01`: обычный
/// однотомный архив так и открывается напрямую, ничего не заметив. Перечисление
/// останавливается на первой дыре; сходится ли число томов с тем, что говорит
/// сам архив, проверяет уже [`join_split_zip`].
pub fn split_zip_members(last: &Path) -> Option<Vec<PathBuf>> {
    let name = last.file_name()?.to_str()?;
    if !name.to_ascii_lowercase().ends_with(".zip") {
        return None;
    }
    let stem = &name[..name.len() - 4];
    let dir = last.parent().unwrap_or_else(|| Path::new("."));

    let mut members = Vec::new();
    let mut idx = 1u32;
    loop {
        // `zip` нумерует тома как `z01`…`z99`, `z100`, … — то же, что `{idx:02}`.
        // Регистр расширения берём тот, который реально лежит на диске.
        let lower = dir.join(format!("{stem}.z{idx:02}"));
        let upper = dir.join(format!("{stem}.Z{idx:02}"));
        let candidate = if lower.is_file() {
            lower
        } else if upper.is_file() {
            upper
        } else {
            break;
        };
        members.push(candidate);
        idx += 1;
    }
    if members.is_empty() {
        return None;
    }
    members.push(last.to_path_buf());
    Some(members)
}

/// Склеивает тома `zip -s` во временный файл и переписывает в нём смещения,
/// превращая набор в обычный однотомный zip.
///
/// `Ok(None)` — набор оказался не разбитым архивом (в EOCD нулевые номера
/// томов, то есть найденный рядом `.z01` — посторонний файл); вызывающий
/// открывает исходный путь как обычно.
pub(crate) fn join_split_zip(members: &[PathBuf]) -> Result<Option<tempfile::TempPath>> {
    let Some(last) = members.last() else {
        return Ok(None);
    };
    let (eocd_in_last, mut eocd) = find_eocd(last)?;
    let eocd_disk = le_u16(&eocd, 4)?;
    let eocd_cd_disk = le_u16(&eocd, 6)?;
    if eocd_disk == 0 && eocd_cd_disk == 0 {
        return Ok(None);
    }
    // 0xFFFF — заглушка zip64: настоящий номер тома лежит в zip64-записи,
    // сверять число томов будем по ней (ниже, после склейки).
    if eocd_disk != u16::MAX && eocd_disk as usize + 1 != members.len() {
        return Err(Error::MissingVolume(format!(
            "split zip claims {} volumes, found {}",
            eocd_disk as u64 + 1,
            members.len()
        )));
    }

    // Шаг 1: сцепить тома по порядку, запомнив, с какого байта начинается
    // каждый из них — это и есть база для пересчёта смещений.
    let mut tmp = tempfile::NamedTempFile::new()?;
    let mut bases = Vec::with_capacity(members.len());
    let mut joined_len = 0u64;
    for member in members {
        bases.push(joined_len);
        let mut f = std::fs::File::open(member)?;
        joined_len += std::io::copy(&mut f, &mut tmp)?;
    }
    let eocd_abs = bases[members.len() - 1] + eocd_in_last;
    let file = tmp.as_file_mut();

    // Шаг 2: zip64-хвост, если он есть.
    let zip64 = read_zip64_end(file, &bases, eocd_abs)?;
    let has_zip64 = zip64.is_some();
    let (entries, cd_size, cd_off, cd_disk) = match &zip64 {
        Some(rec) => (
            le_u64(rec, 32)?,
            le_u64(rec, 40)?,
            le_u64(rec, 48)?,
            le_u32(rec, 20)? as u64,
        ),
        None => (
            le_u16(&eocd, 10)? as u64,
            le_u32(&eocd, 12)? as u64,
            le_u32(&eocd, 16)? as u64,
            eocd_cd_disk as u64,
        ),
    };
    if let Some(rec) = &zip64 {
        // Настоящий номер последнего тома (в EOCD на его месте стояла заглушка).
        let disks = le_u32(rec, 16)? as u64 + 1;
        if disks != members.len() as u64 {
            return Err(Error::MissingVolume(format!(
                "split zip claims {disks} volumes, found {}",
                members.len()
            )));
        }
    }

    // Шаг 3: прочитать центральный каталог по абсолютному смещению.
    let cd_base = *bases
        .get(usize::try_from(cd_disk).unwrap_or(usize::MAX))
        .ok_or_else(|| {
            Error::MissingVolume(format!("volume {} holding the directory", cd_disk + 1))
        })?;
    let cd_start = cd_base
        .checked_add(cd_off)
        .ok_or_else(|| corrupt("central directory offset overflows"))?;
    let cd_end = cd_start
        .checked_add(cd_size)
        .ok_or_else(|| corrupt("central directory size overflows"))?;
    if cd_end > joined_len {
        return Err(corrupt(
            "central directory runs past the end of the joined archive",
        ));
    }
    if cd_size > entries.saturating_mul(MAX_CD_RECORD) {
        return Err(corrupt(format!(
            "central directory of {cd_size} bytes cannot hold exactly {entries} records"
        )));
    }
    let mut cd = vec![
        0u8;
        usize::try_from(cd_size)
            .map_err(|_| unsupported("oversized central directory"))?
    ];
    file.seek(SeekFrom::Start(cd_start))?;
    file.read_exact(&mut cd).map_err(io_err_to_corrupt)?;

    // Шаг 4: переписать каталог и хвост. Каталог лежит после всех тел записей,
    // так что всё от `cd_start` и дальше можно смело выбросить.
    let new_cd = rebuild_central_directory(&cd, entries, &bases, cd_start)?;
    let new_cd_size = new_cd.len() as u64;
    file.set_len(cd_start)?;
    file.seek(SeekFrom::Start(cd_start))?;
    file.write_all(&new_cd)?;

    if let Some(mut rec) = zip64 {
        let eocd64_abs = cd_start + new_cd_size;
        rec[16..20].copy_from_slice(&0u32.to_le_bytes()); // номер тома
        rec[20..24].copy_from_slice(&0u32.to_le_bytes()); // том с каталогом
        rec[24..32].copy_from_slice(&entries.to_le_bytes()); // записей «здесь»
        rec[32..40].copy_from_slice(&entries.to_le_bytes()); // записей всего
        rec[40..48].copy_from_slice(&new_cd_size.to_le_bytes());
        rec[48..56].copy_from_slice(&cd_start.to_le_bytes());
        file.write_all(&rec)?;

        let mut loc = [0u8; 20];
        loc[..4].copy_from_slice(&LOCATOR_SIG);
        loc[8..16].copy_from_slice(&eocd64_abs.to_le_bytes());
        loc[16..20].copy_from_slice(&1u32.to_le_bytes()); // томов теперь один
        file.write_all(&loc)?;
    }

    let here = eocd16(le_u16(&eocd, 8)?, entries, has_zip64)?;
    let total = eocd16(le_u16(&eocd, 10)?, entries, has_zip64)?;
    let size32 = eocd32(le_u32(&eocd, 12)?, new_cd_size, has_zip64)?;
    let off32 = eocd32(le_u32(&eocd, 16)?, cd_start, has_zip64)?;
    eocd[4..6].copy_from_slice(&0u16.to_le_bytes());
    eocd[6..8].copy_from_slice(&0u16.to_le_bytes());
    eocd[8..10].copy_from_slice(&here.to_le_bytes());
    eocd[10..12].copy_from_slice(&total.to_le_bytes());
    eocd[12..16].copy_from_slice(&size32.to_le_bytes());
    eocd[16..20].copy_from_slice(&off32.to_le_bytes());
    file.write_all(&eocd)?;
    file.flush()?;

    Ok(Some(tmp.into_temp_path()))
}

/// Значение для классического поля EOCD после склейки.
///
/// Если в оригинале стояла zip64-заглушка, она и остаётся — настоящее значение
/// лежит в zip64-записи. Если новое значение в поле не влезает, ставим
/// заглушку, но только когда zip64-запись есть; иначе честно отказываемся,
/// вместо того чтобы записать заведомо неверное число.
fn eocd32(orig: u32, value: u64, has_zip64: bool) -> Result<u32> {
    if orig == u32::MAX || value >= u32::MAX as u64 {
        if orig != u32::MAX && !has_zip64 {
            return Err(unsupported(
                "joined split archive exceeds 4 GiB but carries no zip64 record",
            ));
        }
        return Ok(u32::MAX);
    }
    Ok(value as u32)
}

fn eocd16(orig: u16, value: u64, has_zip64: bool) -> Result<u16> {
    if orig == u16::MAX || value >= u16::MAX as u64 {
        if orig != u16::MAX && !has_zip64 {
            return Err(unsupported(
                "joined split archive has 65535 or more entries but carries no zip64 record",
            ));
        }
        return Ok(u16::MAX);
    }
    Ok(value as u16)
}

/// Находит EOCD в конце файла: последнюю сигнатуру `PK\x05\x06`, у которой
/// длина комментария ровно достаёт до конца файла. Возвращает её смещение в
/// файле и саму запись вместе с комментарием.
fn find_eocd(path: &Path) -> Result<(u64, Vec<u8>)> {
    let mut f = std::fs::File::open(path)?;
    let len = f.seek(SeekFrom::End(0))?;
    // 22 байта самого EOCD плюс комментарий, длина которого не больше 0xFFFF.
    let window = len.min(22 + 0xFFFF) as usize;
    if window >= 22 {
        f.seek(SeekFrom::Start(len - window as u64))?;
        let mut buf = vec![0u8; window];
        f.read_exact(&mut buf).map_err(io_err_to_corrupt)?;
        for p in (0..=window - 22).rev() {
            if buf[p..p + 4] != EOCD_SIG {
                continue;
            }
            let comment = le_u16(&buf, p + 20)? as usize;
            if p + 22 + comment == window {
                return Ok((len - window as u64 + p as u64, buf[p..].to_vec()));
            }
        }
    }
    Err(corrupt(
        "no end-of-central-directory record in the last zip volume",
    ))
}

/// Читает zip64-запись конца каталога через локатор, стоящий перед EOCD.
///
/// `Ok(None)` — локатора нет, архив не zip64.
fn read_zip64_end(
    file: &mut std::fs::File,
    bases: &[u64],
    eocd_abs: u64,
) -> Result<Option<Vec<u8>>> {
    if eocd_abs < 20 {
        return Ok(None);
    }
    let mut loc = [0u8; 20];
    file.seek(SeekFrom::Start(eocd_abs - 20))?;
    file.read_exact(&mut loc).map_err(io_err_to_corrupt)?;
    if loc[..4] != LOCATOR_SIG {
        return Ok(None);
    }
    let disk = le_u32(&loc, 4)? as u64;
    let base = *bases
        .get(usize::try_from(disk).unwrap_or(usize::MAX))
        .ok_or_else(|| {
            Error::MissingVolume(format!("volume {} named by the zip64 locator", disk + 1))
        })?;
    let abs = base
        .checked_add(le_u64(&loc, 8)?)
        .ok_or_else(|| corrupt("zip64 end-of-central-directory offset overflows"))?;

    let mut head = [0u8; 56];
    file.seek(SeekFrom::Start(abs))?;
    file.read_exact(&mut head).map_err(io_err_to_corrupt)?;
    if head[..4] != EOCD64_SIG {
        return Err(corrupt(
            "zip64 locator does not point at a zip64 end-of-central-directory record",
        ));
    }
    // Поле хранит размер записи без первых 12 байт. Разумный потолок — 1 МиБ:
    // за 56 байтами может идти «extensible data sector», но не такой.
    let total = le_u64(&head, 4)?
        .checked_add(12)
        .ok_or_else(|| corrupt("zip64 record size overflows"))?;
    if !(56..=1 << 20).contains(&total) {
        return Err(corrupt(format!(
            "implausible zip64 end-of-central-directory record size: {total}"
        )));
    }
    let mut rec = vec![0u8; total as usize];
    file.seek(SeekFrom::Start(abs))?;
    file.read_exact(&mut rec).map_err(io_err_to_corrupt)?;
    Ok(Some(rec))
}

/// Пересобирает центральный каталог: номер тома у каждой записи становится
/// нулём, а смещение локального заголовка — абсолютным в склеенном файле.
///
/// `data_end` — начало каталога: тела записей лежат до него, так что любое
/// смещение локального заголовка обязано быть меньше.
fn rebuild_central_directory(
    cd: &[u8],
    entries: u64,
    bases: &[u64],
    data_end: u64,
) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(cd.len());
    let mut pos = 0usize;
    for _ in 0..entries {
        let fixed = cd
            .get(pos..pos + 46)
            .ok_or_else(|| corrupt("central directory record is truncated"))?;
        if fixed[..4] != CD_SIG {
            return Err(corrupt("bad central directory record signature"));
        }
        let csize = le_u32(fixed, 20)?;
        let usize_ = le_u32(fixed, 24)?;
        let nlen = le_u16(fixed, 28)? as usize;
        let elen = le_u16(fixed, 30)? as usize;
        let clen = le_u16(fixed, 32)? as usize;
        let disk_raw = le_u16(fixed, 34)?;
        let lho_raw = le_u32(fixed, 42)?;

        let name = pos + 46;
        let extra = name + nlen;
        let comment = extra + elen;
        let end = comment + clen;
        if end > cd.len() {
            return Err(corrupt("central directory record runs past the directory"));
        }

        // Настоящие номер тома и смещение: при заглушке они лежат в zip64-поле.
        let (z64, other_extra) = split_extra(&cd[extra..comment]);
        let z64 = parse_zip64_extra(
            z64.unwrap_or(&[]),
            usize_ == u32::MAX,
            csize == u32::MAX,
            lho_raw == u32::MAX,
            disk_raw == u16::MAX,
        )?;
        let disk = z64.disk.unwrap_or(disk_raw as u32) as u64;
        let lho = z64.lho.unwrap_or(lho_raw as u64);
        let base = *bases
            .get(usize::try_from(disk).unwrap_or(usize::MAX))
            .ok_or_else(|| {
                Error::MissingVolume(format!("volume {} referenced by the directory", disk + 1))
            })?;
        let abs = base
            .checked_add(lho)
            .ok_or_else(|| corrupt("local header offset overflows"))?;
        // Локальный заголовок — 30 байт минимум, и он обязан лежать до каталога.
        if abs.checked_add(30).is_none_or(|e| e > data_end) {
            return Err(corrupt(format!(
                "local header offset {abs} lies outside the joined archive"
            )));
        }

        // Новое zip64-поле: только те значения, для которых в классических
        // полях осталась заглушка. Номер тома теперь всегда 0, поэтому его
        // zip64-двойник не нужен вовсе и просто исчезает.
        let mut z64_data = Vec::new();
        if let Some(v) = z64.usize_ {
            z64_data.extend_from_slice(&v.to_le_bytes());
        }
        if let Some(v) = z64.csize {
            z64_data.extend_from_slice(&v.to_le_bytes());
        }
        let new_lho = if abs >= u32::MAX as u64 {
            z64_data.extend_from_slice(&abs.to_le_bytes());
            u32::MAX
        } else {
            abs as u32
        };

        let mut new_extra = Vec::with_capacity(elen + 12);
        if !z64_data.is_empty() {
            new_extra.extend_from_slice(&ZIP64_EXTRA_ID.to_le_bytes());
            new_extra.extend_from_slice(&(z64_data.len() as u16).to_le_bytes());
            new_extra.extend_from_slice(&z64_data);
        }
        new_extra.extend_from_slice(&other_extra);
        let new_elen = u16::try_from(new_extra.len()).map_err(|_| {
            unsupported("central directory record grew past its 64 KiB extra limit")
        })?;

        let rec = out.len();
        out.extend_from_slice(fixed);
        out[rec + 30..rec + 32].copy_from_slice(&new_elen.to_le_bytes());
        out[rec + 34..rec + 36].copy_from_slice(&0u16.to_le_bytes());
        out[rec + 42..rec + 46].copy_from_slice(&new_lho.to_le_bytes());
        out.extend_from_slice(&cd[name..extra]);
        out.extend_from_slice(&new_extra);
        out.extend_from_slice(&cd[comment..end]);
        pos = end;
    }
    if pos != cd.len() {
        return Err(corrupt(format!(
            "central directory has {} trailing bytes after {entries} records",
            cd.len() - pos
        )));
    }
    Ok(out)
}

/// Разбирает область extra на поля `id/длина/данные`: отдельно данные
/// zip64-поля, отдельно все прочие поля как есть — их мы переносим в новую
/// запись нетронутыми.
///
/// Разбор нарочно снисходительный: остаток, который не разбирается на поля,
/// переносится побайтно. Ошибиться он нам не даёт — если в нём прятался
/// нужный zip64, [`parse_zip64_extra`] всё равно откажется работать без него.
fn split_extra(extra: &[u8]) -> (Option<&[u8]>, Vec<u8>) {
    let mut zip64 = None;
    let mut rest = Vec::with_capacity(extra.len());
    let mut p = 0usize;
    while p + 4 <= extra.len() {
        let id = u16::from_le_bytes([extra[p], extra[p + 1]]);
        let len = u16::from_le_bytes([extra[p + 2], extra[p + 3]]) as usize;
        let Some(end) = p.checked_add(4 + len).filter(|e| *e <= extra.len()) else {
            break;
        };
        if id == ZIP64_EXTRA_ID {
            zip64 = Some(&extra[p + 4..end]);
        } else {
            rest.extend_from_slice(&extra[p..end]);
        }
        p = end;
    }
    rest.extend_from_slice(&extra[p..]);
    (zip64, rest)
}

/// Значения из zip64-поля записи каталога.
struct Zip64Extra {
    usize_: Option<u64>,
    csize: Option<u64>,
    lho: Option<u64>,
    disk: Option<u32>,
}

/// Поля zip64-поля идут строго в этом порядке и присутствуют только для тех
/// классических полей, где стоит заглушка. Не хватило байт — запись битая.
fn parse_zip64_extra(
    data: &[u8],
    want_usize: bool,
    want_csize: bool,
    want_lho: bool,
    want_disk: bool,
) -> Result<Zip64Extra> {
    let mut p = 0usize;
    let usize_ = if want_usize {
        p += 8;
        Some(le_u64(data, p - 8)?)
    } else {
        None
    };
    let csize = if want_csize {
        p += 8;
        Some(le_u64(data, p - 8)?)
    } else {
        None
    };
    let lho = if want_lho {
        p += 8;
        Some(le_u64(data, p - 8)?)
    } else {
        None
    };
    let disk = if want_disk {
        Some(le_u32(data, p)?)
    } else {
        None
    };
    Ok(Zip64Extra {
        usize_,
        csize,
        lho,
        disk,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn single_file_is_its_own_member() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let members = volume_members(tmp.path()).unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0], tmp.path());
    }

    #[test]
    fn numbered_split_members_are_ordered() {
        let dir = tempfile::tempdir().unwrap();
        for (i, content) in [("001", b"AAA"), ("002", b"BBB"), ("003", b"CCC")] {
            let mut f = std::fs::File::create(dir.path().join(format!("a.bin.{i}"))).unwrap();
            f.write_all(content).unwrap();
        }
        let first = dir.path().join("a.bin.001");
        let members = volume_members(&first).unwrap();
        assert_eq!(members.len(), 3);

        let mut cat = ConcatReader::open(&members).unwrap();
        let mut out = Vec::new();
        cat.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"AAABBBCCC");
    }
}

#[cfg(test)]
mod split_zip {
    use super::*;
    use std::io::Write;

    /// Собирает запись центрального каталога: заполнены только те поля, что
    /// разбирает и правит `rebuild_central_directory`, остальное — нули.
    fn record(name: &str, disk: u16, lho: u32, extra: &[u8]) -> Vec<u8> {
        let mut r = vec![0u8; 46];
        r[..4].copy_from_slice(&CD_SIG);
        r[24..28].copy_from_slice(&1u32.to_le_bytes()); // uncompressed size
        r[28..30].copy_from_slice(&(name.len() as u16).to_le_bytes());
        r[30..32].copy_from_slice(&(extra.len() as u16).to_le_bytes());
        r[34..36].copy_from_slice(&disk.to_le_bytes());
        r[42..46].copy_from_slice(&lho.to_le_bytes());
        r.extend_from_slice(name.as_bytes());
        r.extend_from_slice(extra);
        r
    }

    fn disk_of(rec: &[u8]) -> u16 {
        le_u16(rec, 34).unwrap()
    }

    fn lho_of(rec: &[u8]) -> u32 {
        le_u32(rec, 42).unwrap()
    }

    #[test]
    fn offsets_become_absolute_and_volumes_collapse_to_one() {
        let mut cd = record("a", 0, 4, &[]);
        cd.extend_from_slice(&record("b", 1, 64, &[]));
        let out = rebuild_central_directory(&cd, 2, &[0, 1000], 5000).unwrap();

        assert_eq!(out.len(), cd.len(), "no extra field was added or dropped");
        assert_eq!((disk_of(&out), lho_of(&out)), (0, 4));
        let second = &out[47..];
        assert_eq!((disk_of(second), lho_of(second)), (0, 1064));
    }

    #[test]
    fn a_volume_number_with_no_volume_behind_it_is_rejected() {
        let cd = record("a", 5, 4, &[]);
        let err = rebuild_central_directory(&cd, 1, &[0, 1000], 5000).unwrap_err();
        assert!(matches!(err, Error::MissingVolume(_)), "got {err}");
    }

    #[test]
    fn an_offset_past_the_data_is_rejected() {
        let cd = record("a", 1, 4000, &[]);
        let err = rebuild_central_directory(&cd, 1, &[0, 1000], 5000).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "got {err}");
    }

    #[test]
    fn a_record_count_that_misses_the_directory_length_is_rejected() {
        let mut cd = record("a", 0, 4, &[]);
        cd.extend_from_slice(&record("b", 0, 64, &[]));
        // Заявлена одна запись, а байт хватает на две.
        let err = rebuild_central_directory(&cd, 1, &[0], 5000).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "got {err}");
        // И наоборот: заявлены три, а есть две.
        let err = rebuild_central_directory(&cd, 3, &[0], 5000).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "got {err}");
    }

    #[test]
    fn an_offset_above_four_gib_moves_into_a_zip64_field() {
        let base = 5_000_000_000u64;
        let cd = record("a", 1, 10, &[]);
        let out = rebuild_central_directory(&cd, 1, &[0, base], base + 4096).unwrap();

        assert_eq!(lho_of(&out), u32::MAX, "классическое поле — заглушка");
        assert_eq!(le_u16(&out, 30).unwrap(), 12, "выросла область extra");
        let extra = &out[47..];
        assert_eq!(le_u16(extra, 0).unwrap(), ZIP64_EXTRA_ID);
        assert_eq!(le_u16(extra, 2).unwrap(), 8);
        assert_eq!(le_u64(extra, 4).unwrap(), base + 10);
    }

    #[test]
    fn an_offset_that_was_in_a_zip64_field_comes_back_into_the_classic_one() {
        // usize и смещение — оба заглушки, значения лежат в поле 0x0001.
        let mut data = Vec::new();
        data.extend_from_slice(&7u64.to_le_bytes()); // uncompressed size
        data.extend_from_slice(&64u64.to_le_bytes()); // local header offset
        let mut extra = vec![0x01, 0x00, 0x10, 0x00];
        extra.extend_from_slice(&data);
        let mut rec = record("a", 1, u32::MAX, &extra);
        rec[24..28].copy_from_slice(&u32::MAX.to_le_bytes()); // usize — заглушка

        let out = rebuild_central_directory(&rec, 1, &[0, 1000], 5000).unwrap();
        assert_eq!(lho_of(&out), 1064, "смещение влезло в классическое поле");
        assert_eq!(
            le_u16(&out, 30).unwrap(),
            12,
            "в zip64 остался только размер"
        );
        let extra = &out[47..];
        assert_eq!(le_u16(extra, 0).unwrap(), ZIP64_EXTRA_ID);
        assert_eq!(le_u64(extra, 4).unwrap(), 7);
    }

    #[test]
    fn a_volume_number_that_was_in_a_zip64_field_disappears_with_it() {
        // Номер тома — заглушка 0xFFFF, настоящий (1) лежит в поле 0x0001
        // последним, после смещения.
        let mut data = Vec::new();
        data.extend_from_slice(&64u64.to_le_bytes()); // local header offset
        data.extend_from_slice(&1u32.to_le_bytes()); // disk
        let mut extra = vec![0x01, 0x00, 0x0C, 0x00];
        extra.extend_from_slice(&data);
        let rec = record("a", u16::MAX, u32::MAX, &extra);

        let out = rebuild_central_directory(&rec, 1, &[0, 1000], 5000).unwrap();
        assert_eq!(disk_of(&out), 0, "том теперь один");
        assert_eq!(lho_of(&out), 1064);
        assert_eq!(le_u16(&out, 30).unwrap(), 0, "zip64-поле стало не нужно");
    }

    #[test]
    fn a_zip64_field_too_short_for_its_placeholders_is_rejected() {
        let rec = record("a", 0, u32::MAX, &[0x01, 0x00, 0x04, 0x00, 0, 0, 0, 0]);
        let err = rebuild_central_directory(&rec, 1, &[0], 5000).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "got {err}");
    }

    #[test]
    fn other_extra_fields_survive_untouched() {
        // Поле 0x5455 (extended timestamp) — не наше дело, переносим как есть.
        let extra = [0x55, 0x54, 0x02, 0x00, 0xAA, 0xBB];
        let rec = record("a", 0, 4, &extra);
        let out = rebuild_central_directory(&rec, 1, &[0], 5000).unwrap();
        assert_eq!(&out[47..], &extra);
    }

    #[test]
    fn scheme_is_recognised_only_with_a_z01_sibling() {
        let dir = tempfile::tempdir().unwrap();
        let zip = dir.path().join("a.zip");
        std::fs::File::create(&zip)
            .unwrap()
            .write_all(b"x")
            .unwrap();
        assert!(
            split_zip_members(&zip).is_none(),
            "одинокий .zip — не набор"
        );

        std::fs::File::create(dir.path().join("a.z01"))
            .unwrap()
            .write_all(b"y")
            .unwrap();
        let members = split_zip_members(&zip).unwrap();
        assert_eq!(members, vec![dir.path().join("a.z01"), zip.clone()]);

        // Дыра в нумерации обрывает перечисление — .z03 без .z02 не берётся.
        std::fs::File::create(dir.path().join("a.z03"))
            .unwrap()
            .write_all(b"z")
            .unwrap();
        assert_eq!(split_zip_members(&zip).unwrap().len(), 2);
    }
}

#[cfg(test)]
mod edge {
    use super::*;
    use std::io::Write;

    #[test]
    fn gap_stops_enumeration() {
        let dir = tempfile::tempdir().unwrap();
        // только .001 и .003 — .002 отсутствует
        for i in ["001", "003"] {
            let mut f = std::fs::File::create(dir.path().join(format!("a.bin.{i}"))).unwrap();
            f.write_all(b"X").unwrap();
        }
        let members = volume_members(&dir.path().join("a.bin.001")).unwrap();
        assert_eq!(members.len(), 1); // перечисление останавливается на дыре
    }

    #[test]
    fn empty_members_rejected() {
        assert!(ConcatReader::open(&[]).is_err());
    }
}
