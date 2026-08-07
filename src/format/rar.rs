use std::io::Write;
use std::path::{Path, PathBuf};

use crate::archive::{
    ArchiveReader, Confidence, Entry, EntryKind, EntrySink, FormatHandler, FormatId, OneEntry,
    OpenOptions, SinkStep, Source,
};
use crate::encoding::decode_names;
use crate::error::{Error, Result};

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

        // For data-encrypted RAR archives (common case), listing does not require
        // a password — only extraction does. For header-encrypted archives, we
        // need the password even for listing; try without first, then with.
        let encoding = opts.encoding_override.as_deref();
        let entries = match list_entries(path.as_path(), None, encoding) {
            Ok(r) => r,
            Err(_) => list_entries(path.as_path(), opts.password.as_deref(), encoding)?,
        };

        Ok(Box::new(RarReader {
            path,
            password: opts.password.clone(),
            entries,
        }))
    }
}

/// What the header walk collects per entry, before names are charset-decoded:
/// size, is-a-directory, is-encrypted, POSIX mode, modification time.
type RawMeta = (u64, bool, bool, Option<u32>, Option<std::time::SystemTime>);

/// List all entries in the archive, collecting metadata.
///
/// Multi-volume sets need nothing special here: libunrar finds the sibling
/// volumes by path on its own, and the listing reports a file split across
/// them once.
fn list_entries(path: &Path, password: Option<&str>, encoding: Option<&str>) -> Result<Vec<Entry>> {
    let mut raw_names: Vec<Vec<u8>> = Vec::new();
    let mut metas: Vec<RawMeta> = Vec::new();

    // The Iterator impl on OpenArchive<List, CursorBeforeHeader> yields Result<FileHeader>.
    // We use it for listing (payloads are skipped automatically).
    let iter: Box<
        dyn Iterator<Item = std::result::Result<unrar::FileHeader, unrar::error::UnrarError>>,
    > = if let Some(pw) = password {
        Box::new(
            unrar::Archive::with_password(path, pw)
                .open_for_listing()
                .map_err(map_rar_err)?,
        )
    } else {
        Box::new(
            unrar::Archive::new(path)
                .open_for_listing()
                .map_err(map_rar_err)?,
        )
    };

    for item in iter {
        let header = item.map_err(map_rar_err)?;
        let raw = header.filename.to_string_lossy().as_bytes().to_vec();
        raw_names.push(raw);
        // Best-effort unix mode: for Unix-created RARs the unrar crate exposes
        // file_attr: u32 on FileHeader.  The host OS field exists in the native
        // HeaderDataEx struct but is NOT forwarded by the vendored FileHeader.
        //
        // On Unix hosts (macOS, Linux) RAR stores the full POSIX st_mode value
        // directly in file_attr (e.g. 0o100755 = 0x81ED for a regular file
        // with rwxr-xr-x permissions).  The file-type nibble occupies the top
        // bits of the low 16 bits (S_IFREG = 0o100000 = 0x8000, etc.).
        //
        // On Windows hosts file_attr carries FAT/NTFS attribute flags
        // (FILE_ATTRIBUTE_READONLY = 0x1, DIRECTORY = 0x10, etc.) which are
        // always small positive integers that cannot set the high bits used by
        // Unix file-type nibbles.  We detect Unix attributes by checking for a
        // known POSIX file-type nibble (S_IFREG, S_IFDIR, S_IFLNK).
        const S_IFMT: u32 = 0o170000;
        const S_IFREG: u32 = 0o100000;
        const S_IFDIR: u32 = 0o040000;
        const S_IFLNK: u32 = 0o120000;
        let attr = header.file_attr;
        let file_type = attr & S_IFMT;
        let mode = if file_type == S_IFREG || file_type == S_IFDIR || file_type == S_IFLNK {
            Some(attr & 0o7777)
        } else {
            None
        };
        // `file_time` is the packed MS-DOS word pair — date in the high half,
        // time in the low one. Wall-clock with no timezone, so it is read as
        // local time, exactly as zip's identical field is.
        //
        // RAR 5 also stores the exact instant as a Windows FILETIME, and
        // `libunrar` fills `RARHeaderDataEx::MtimeLow/High` with it — but that
        // is unreachable from here, and everything else past `FileAttr` with it.
        //
        // The vendored `dll.hpp` opens with `#pragma pack(push, 1)`: the C
        // struct is packed solid. `unrar_sys` 0.5.8 declares it plain
        // `#[repr(C)]`, so Rust inserts alignment padding before the first
        // pointer and every later field sits exactly 4 bytes too far. Measured
        // with `offsetof` against `offset_of!`: `FileAttr` 10280 = 10280, then
        // `CmtBuf` 10284 vs 10288, `MtimeLow` 10364 vs 10368, whole struct
        // 14340 vs 14344.
        //
        // Nothing here reads a field past `file_attr`, so no wrong value
        // reaches a caller today — but `redir_name` is a *pointer* read at the
        // shifted offset, so the first code that dereferences it walks off into
        // nowhere. See `.claude/issues/15-*` for the way out (a maintained
        // `unrar-ng-sys` already fixes this with `packed(1)`); until then the
        // two-second resolution of the DOS field is what we have, so an entry
        // written at an odd second reads back one second earlier than `unar`
        // reports it.
        let modified = crate::datetime::dos_words_to_systime(
            (header.file_time >> 16) as u16,
            header.file_time as u16,
        );
        metas.push((
            header.unpacked_size,
            header.is_directory(),
            header.is_encrypted(),
            mode,
            modified,
        ));
    }

    let names = decode_names(&raw_names, encoding);
    let entries = raw_names
        .into_iter()
        .zip(metas)
        .enumerate()
        .map(
            |(i, (raw, (size, is_dir, is_encrypted, mode, modified)))| Entry {
                path_raw: raw,
                path: PathBuf::from(&names[i]),
                kind: if is_dir {
                    EntryKind::Dir
                } else {
                    EntryKind::File
                },
                size,
                mode,
                is_encrypted,
                modified,
                is_resource_fork: false,
            },
        )
        .collect();

    Ok(entries)
}

fn map_rar_err(e: unrar::error::UnrarError) -> Error {
    use unrar::error::Code;
    match e.code {
        Code::BadPassword => Error::WrongPassword,
        Code::MissingPassword => Error::Encrypted,
        _ => Error::Corrupt(e.to_string()),
    }
}

struct RarReader {
    path: PathBuf,
    password: Option<String>,
    entries: Vec<Entry>,
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
        // read_entry уже маппит libunrar BadPassword→WrongPassword,
        // MissingPassword→Encrypted. Расшифровываем первую зашифрованную
        // запись «в раковину»; прочие ошибки относим к паролю по тому,
        // был ли он задан.
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
    /// Под RAR лежит библиотека на C, и её договор сам последовательный:
    /// `RARReadHeader` идёт вперёд по архиву, назад не отматывается — «начать
    /// сначала» для неё значит закрыть и открыть. Прежний `read_entry` именно
    /// это и делал на каждую запись, а у сплошного архива дойти до записи
    /// значит распаковать всё, что лежит до неё: на тысяче файлов выходило
    /// в тридцать девять раз дольше `unar`.
    fn read_entries(&mut self, indices: &[usize], sink: &mut dyn EntrySink) -> Result<()> {
        self.walk(indices, sink)
    }
}

/// Итог одной записи: что с ней вышло и жива ли ручка архива.
///
/// `None` вместо архива значит, что продолжать этот проход нечем. Методы
/// крейта съедают `self` и собирают возврат через `?`, поэтому на ошибке
/// `OpenArchive` роняется, а его `Drop` закрывает архив. Ручку отнимает
/// подпись обёртки на Rust, не сама libunrar, — почини это форк, и
/// перезапуск в `walk` стал бы не нужен.
type BodyOutcome = (
    Result<()>,
    Option<unrar::OpenArchive<unrar::Process, unrar::CursorBeforeHeader>>,
);

impl RarReader {
    fn open_for_processing(
        &self,
    ) -> Result<unrar::OpenArchive<unrar::Process, unrar::CursorBeforeHeader>> {
        match self.password.as_deref() {
            Some(pw) => unrar::Archive::with_password(self.path.as_path(), pw)
                .open_for_processing()
                .map_err(map_rar_err),
            None => unrar::Archive::new(self.path.as_path())
                .open_for_processing()
                .map_err(map_rar_err),
        }
    }

    /// Пройти архив, отдавая приёмнику записи из `indices`.
    ///
    /// Запись узнаётся **по месту**, а не по имени: список собран тем же
    /// обходом заголовков (`list_entries`), поэтому N-й заголовок — это и есть
    /// запись N. Прежнее сравнение имён путало два одноимённых файла, а имя
    /// каждой записи приходилось ещё и заново собирать в строку.
    ///
    /// Из заголовка читается ровно один флаг — «это продолжение из прошлого
    /// тома». Он лежит в `Flags`, то есть до `FileAttr`, и мина тикета 15
    /// остаётся спящей: раскладка биндинга съезжает позже, с `CmtBuf`.
    fn walk(&self, indices: &[usize], sink: &mut dyn EntrySink) -> Result<()> {
        // Номер вне списка — ошибка вызывающего, и она не должна всплыть на
        // середине уже начатой распаковки.
        if let Some(&bad) = indices.iter().find(|&&i| i >= self.entries.len()) {
            return Err(Error::InvalidIndex(bad));
        }
        let mut archive = self.open_for_processing()?;
        // `i` — место в списке запрошенного, `pos` — номер заголовка в архиве.
        let mut i = 0usize;
        let mut pos = 0usize;

        while i < indices.len() {
            let want = indices[i];
            let Some(with_file) = archive.read_header().map_err(map_rar_err)? else {
                // Заголовки кончились раньше списка — архив короче своего же
                // оглавления. Каждая недостающая запись отмечается отказом,
                // как это делал прежний обход по одной, чтобы уже записанное
                // осталось и было видно, чего не хватает.
                return fail_rest(&indices[i..], sink);
            };

            // Продолжение файла в следующем томе — не отдельная запись.
            //
            // Режимы открытия расходятся ровно здесь: листинг (`RAR_OM_LIST`,
            // `open_for_listing`), которым собран список, показывает
            // разрезанный файл **один раз** — куски он склеивает, о чём прямо
            // говорит соседний `open_for_listing_split`. Распаковка
            // (`RAR_OM_EXTRACT`) склеивать не обязана и отдаёт по заголовку на
            // кусок. Измерено на трёхтомном наборе: `mvB.bin` и `mvC.bin`
            // приходят дважды, вторым разом с поднятым `is_split_before`.
            // Считать такой заголовок за запись значит сдвинуть все номера
            // после него.
            //
            // Видно это только когда кусок **пропустили**: на распаковке
            // libunrar проводит файл через тома сама и лишних заголовков не
            // отдаёт.
            if with_file.entry().is_split_before() {
                archive = with_file.skip().map_err(map_rar_err)?;
                continue;
            }
            if pos < want {
                archive = with_file.skip().map_err(map_rar_err)?;
                pos += 1;
                continue;
            }

            match sink.begin(want)? {
                SinkStep::Stop => return Ok(()),
                SinkStep::Skip => {
                    archive = with_file.skip().map_err(map_rar_err)?;
                }
                SinkStep::Body => {
                    let (outcome, next) = body_in_memory(with_file, sink);
                    if !sink.end(want, outcome)? {
                        return Ok(());
                    }
                    match next {
                        Some(a) => archive = a,
                        // Ручка не пережила отказа (см. `BodyOutcome`). Отказ
                        // одной записи не должен ронять остальные, поэтому
                        // проход начинается заново, а список продолжается со
                        // следующего номера. На сплошном архиве это дорого:
                        // пропуск там означает распаковку, так что рестарт
                        // стоит всего, что лежит до точки возобновления.
                        // Дороже прежнего кода это не будет — тот начинал
                        // сначала на **каждой** записи, а не на отказавшей.
                        None => {
                            archive = self.open_for_processing()?;
                            pos = 0;
                            i += 1;
                            continue;
                        }
                    }
                }
            }
            pos += 1;
            i += 1;
        }
        Ok(())
    }
}

/// Тело записи читается средствами крейта.
///
/// Через границу тома libunrar проводит файл сама, и отдельного пути для
/// многотомного набора больше нет. Он был: чтение в память роняло процесс по
/// `SIGABRT`, когда тело пересекало границу, и приходилось извлекать запись во
/// временный файл. Причина — разыменование нулевого указателя в обратном
/// вызове `UCM_PROCESSDATA` — закрыта заплаткой в `newtua-unrar`; проверено
/// 2026-08-08 на трёхтомной фикстуре и четырёхтомном образце корпуса,
/// побайтно против `unar`, в том числе на выборочной распаковке с пропусками.
///
/// Осталась цена, которую этим не снять: тело кладётся в память целиком, то
/// есть пик равен самой большой распаковываемой записи. Дешевле будет только
/// потоковый режим в форке — крейт наружу отдаёт лишь «целиком в память» или
/// «целиком в файл», хотя libunrar внутри уже отдаёт тело кусками.
fn body_in_memory(
    with_file: unrar::OpenArchive<unrar::Process, unrar::CursorBeforeFile>,
    sink: &mut dyn EntrySink,
) -> BodyOutcome {
    match with_file.read() {
        Ok((data, next)) => (sink.write_body(&data), Some(next)),
        Err(e) => (Err(map_rar_err(e)), None),
    }
}

/// Отметить остаток списка как непрочитанный.
///
/// Виноват тут архив, а не вызывающий: номера пришли из `entries()`, а
/// заголовков под них не хватило. Поэтому `Corrupt`, а не `InvalidIndex`.
fn fail_rest(rest: &[usize], sink: &mut dyn EntrySink) -> Result<()> {
    for &idx in rest {
        match sink.begin(idx)? {
            SinkStep::Stop => break,
            SinkStep::Skip => continue,
            SinkStep::Body => {}
        }
        let why = Error::Corrupt(format!("rar: заголовки кончились на записи {idx}"));
        if !sink.end(idx, Err(why))? {
            break;
        }
    }
    Ok(())
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
}
