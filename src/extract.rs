use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use filetime::FileTime;

use crate::archive::{ArchiveReader, Entry, EntryKind, EntrySink, SinkStep};
use crate::error::{Error, Result};
use crate::path_safety::safe_join;

/// Streamed progress notifications during extraction.
pub enum ProgressEvent<'a> {
    EntryStart {
        index: usize,
        path: &'a str,
        size: u64,
    },
    Bytes {
        index: usize,
        written: u64,
    },
    EntryDone {
        index: usize,
    },
}

/// Returned by a progress callback to continue or cooperatively abort.
pub enum Flow {
    Continue,
    Abort,
}

/// Progress callback: invoked during extraction; returns `Flow` to control it.
pub type ProgressFn = Box<dyn FnMut(ProgressEvent) -> Flow + Send>;

fn apply_mtime(path: &Path, modified: Option<SystemTime>) {
    if let Some(t) = modified {
        let ft = FileTime::from_system_time(t);
        // best-effort: data is already written, ignore errors
        let _ = filetime::set_file_mtime(path, ft);
    }
}

#[cfg(unix)]
fn apply_mode(path: &Path, mode: Option<u32>) {
    use std::os::unix::fs::PermissionsExt;
    let Some(m) = mode else { return };
    let want = m & 0o7777;
    // Сперва посмотреть, а надо ли. Чаще всего не надо: только что созданный
    // файл уже имеет ровно те права, что записаны в архиве (`rw-r--r--` и там,
    // и там), и `chmod` тогда — работа вхолостую. На этой машине он стоит
    // 10 мкс на файл против 1,4 мкс у чтения прав, то есть на архиве из
    // семнадцати тысяч значков разница почти в секунду
    // (замеры: `.claude/issues/22-lishniy-chmod-i-odin-potok.md`).
    if let Ok(meta) = std::fs::metadata(path)
        && meta.permissions().mode() & 0o7777 == want
    {
        return;
    }
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(want));
}

#[cfg(not(unix))]
fn apply_mode(_path: &Path, _mode: Option<u32>) {}

#[cfg(unix)]
fn create_symlink(target: &Path, link: &Path) -> Result<()> {
    std::os::unix::fs::symlink(target, link)?;
    Ok(())
}

#[cfg(windows)]
fn create_symlink(target: &Path, link: &Path) -> Result<()> {
    // Best-effort; requires privilege. Treat as file symlink.
    std::os::windows::fs::symlink_file(target, link)?;
    Ok(())
}

fn apply_symlink_mtime(path: &Path, modified: Option<SystemTime>) {
    if let Some(t) = modified {
        let ft = FileTime::from_system_time(t);
        let _ = filetime::set_symlink_file_times(path, ft, ft);
    }
}

pub struct ExtractOptions {
    pub dest: PathBuf,
    /// Wrapper-folder name (usually the archive name without its extension).
    /// Used only when the entries have no single shared root directory.
    pub wrapper_name: Option<String>,
    pub strict: bool,
    /// Restore mtime (and in future: mode) from archive metadata. Default: true.
    pub preserve: bool,
    /// Restrict extraction to these original entry indices. `None` = all.
    ///
    /// On a solid format the entries before a selected one still have to be
    /// decompressed to reach it — but nothing outside the selection is written
    /// to disk.
    pub selection: Option<Vec<usize>>,
    /// Optional progress/cancellation callback.
    pub progress: Option<ProgressFn>,
    /// Skip macOS sidecar entries (`._*`, `.DS_Store`, `__MACOSX/`).
    /// Default behavior is to skip (set `false` only via `--keep-macos-metadata`).
    pub keep_macos_metadata: bool,
}

#[derive(Debug, Default)]
pub struct ExtractReport {
    pub extracted: usize,
    pub failed: Vec<(PathBuf, String)>,
    pub wrapped: bool,
    pub aborted: bool,
}

/// The single shared top-level directory of all entries, or None.
///
/// Returns None when entries do not all live under one common top-level
/// directory — including a single loose file at the archive root (which should
/// be wrapped). Bare directory entries (e.g. "root/") are recognized as
/// directory roots, so a normal single-folder archive that includes explicit
/// directory entries is still detected as having a common root and is NOT
/// wrapped.
pub fn common_root(entries: &[Entry]) -> Option<String> {
    if entries.is_empty() {
        return None;
    }
    let mut root: Option<String> = None;
    let mut is_dir_root = false;
    for e in entries {
        let mut comps = e.path.components();
        let first = comps.next()?; // empty path → no common root
        let comp = first.as_os_str().to_string_lossy().to_string();
        match &root {
            None => root = Some(comp),
            Some(r) if *r != comp => return None, // more than one top-level item
            _ => {}
        }
        // The top component is a directory if some entry nests under it,
        // or an entry is exactly that component and is itself a directory.
        if comps.next().is_some() || e.is_dir() {
            is_dir_root = true;
        }
    }
    if is_dir_root { root } else { None }
}

/// The wrapper-folder name for an archive: its file stem when `use_wrapper` is
/// set, else `None`. Used as `ExtractOptions::wrapper_name` so contents without
/// a single common root get wrapped in a folder named after the archive.
pub fn wrapper_name(archive: &Path, use_wrapper: bool) -> Option<String> {
    if use_wrapper {
        archive
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
    } else {
        None
    }
}

pub fn extract_all(ar: &mut dyn ArchiveReader, opts: &mut ExtractOptions) -> Result<ExtractReport> {
    let entries: Vec<Entry> = ar.entries()?.to_vec();

    // Пароль-пре-флайт. До создания каких-либо файлов убеждаемся, что архив
    // расшифровывается заданным паролем. Так ошибка пароля поднимается наверх
    // единообразно для всех форматов (а не тонет в report.failed) и не остаётся
    // частичных файлов. Листинг (open/entries) пароля по-прежнему не требует.
    ar.verify_password()?;

    let mut report = ExtractReport::default();

    // Selected subset for wrapper/common-root computation.
    // Built from immutable reads BEFORE we mutably borrow `opts.progress` below.
    let selected: Option<std::collections::HashSet<usize>> =
        opts.selection.as_ref().map(|v| v.iter().copied().collect());
    let keep_macos = opts.keep_macos_metadata;
    let is_skipped = |e: &Entry| !keep_macos && crate::is_macos_metadata(&e.path);
    let subset: Vec<Entry> = match &selected {
        Some(set) => entries
            .iter()
            .enumerate()
            .filter(|(i, e)| set.contains(i) && !is_skipped(e))
            .map(|(_, e)| e.clone())
            .collect(),
        None => entries.iter().filter(|e| !is_skipped(e)).cloned().collect(),
    };

    // Wrapper folder (The Unarchiver behavior). Computed over the selected subset.
    let dest = match (common_root(&subset), &opts.wrapper_name) {
        (None, Some(name)) => {
            report.wrapped = true;
            opts.dest.join(name)
        }
        _ => opts.dest.clone(),
    };
    if report.wrapped {
        std::fs::create_dir_all(&dest)?;
    }
    let preserve = opts.preserve;
    let strict = opts.strict;

    // Отобранные записи, по возрастанию — именно такой список ждёт
    // `read_entries`, и это же порядок заголовка архива.
    let indices: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter(|(i, e)| selected.as_ref().is_none_or(|set| set.contains(i)) && !is_skipped(e))
        .map(|(i, _)| i)
        .collect();

    // Один проход по архиву вместо `read_entry` на каждую запись. Формату,
    // под которым лежит последовательный поток (7z, RAR, папка CAB), это
    // разница между секундами и часом; остальные получают ровно прежнее
    // поведение через реализацию по умолчанию.
    let mut sink = ExtractSink {
        entries: &entries,
        dest: &dest,
        preserve,
        strict,
        progress: opts.progress.as_mut(),
        report: &mut report,
        dir_mtimes: Vec::new(),
        cur: None,
        aborted: false,
    };
    let outcome = ar.read_entries(&indices, &mut sink);
    let dir_mtimes = std::mem::take(&mut sink.dir_mtimes);
    outcome?;

    if preserve {
        for (path, modified) in &dir_mtimes {
            apply_mtime(path, *modified);
        }
    }

    Ok(report)
}

/// Приёмник, в который обработчик формата отдаёт тела записей на своём проходе
/// по архиву.
///
/// Раньше здесь был цикл `extract_one`, дёргавший `read_entry` на каждую
/// запись. Теперь порядок обратный: ходит по архиву обработчик, а эта
/// сторона отвечает на три вопроса — куда писать, что делать с тем, что
/// записалось, и не пора ли остановиться. Причина в том, что под 7z, RAR и
/// папкой CAB лежит последовательный поток, и «дай мне запись N» там означает
/// «распакуй всё, что до неё» (см. `.claude/PERF-2026-08-06-findings.md`).
struct ExtractSink<'a> {
    entries: &'a [Entry],
    dest: &'a Path,
    preserve: bool,
    strict: bool,
    progress: Option<&'a mut ProgressFn>,
    report: &'a mut ExtractReport,
    dir_mtimes: Vec<(PathBuf, Option<SystemTime>)>,
    /// Запись, тело которой пишется прямо сейчас.
    cur: Option<Current>,
    /// Человек отменил распаковку. Отдельно от ошибки: обрыв по отмене — не
    /// поломка, и разбираются с ним иначе.
    aborted: bool,
}

/// Запись, тело которой пишется прямо сейчас. Одна зараз: последовательный
/// носитель по-другому и не умеет.
struct Current {
    idx: usize,
    /// Путь самой записи: на нём права и дата, от него считается имя бокового
    /// файла AppleDouble.
    entry_path: PathBuf,
    /// Куда льются байты. Для обычного файла совпадает с `entry_path`; для
    /// ресурсной вилки на macOS это `entry_path/..namedfork/rsrc`.
    write_path: PathBuf,
    /// Это ресурсная вилка, а не сам файл.
    is_fork: bool,
    body: Body,
}

enum Body {
    File(std::fs::File),
    /// Ресурсная вилка там, где вилок нет: её надо обернуть в AppleDouble
    /// целиком, а в заголовке стоит длина — значит, сперва копим.
    #[cfg(not(target_os = "macos"))]
    Buffer(Vec<u8>),
}

impl ExtractSink<'_> {
    /// Запись не удалась: в строгом режиме это конец распаковки, иначе —
    /// строка в отчёте, и идём дальше.
    fn failed(&mut self, entry: &Entry, e: Error) -> Result<bool> {
        if self.strict {
            return Err(e);
        }
        self.report.failed.push((entry.path.clone(), e.to_string()));
        Ok(true)
    }

    /// Запись состоялась: посчитать и сообщить.
    fn done(&mut self, idx: usize) {
        self.report.extracted += 1;
        if let Some(p) = self.progress.as_mut() {
            let _ = p(ProgressEvent::EntryDone { index: idx });
        }
    }

    /// Создать то, у чего нет тела (каталог, ссылка), или открыть файл под
    /// тело. Ошибки отсюда ловит `begin`.
    fn prepare(&mut self, idx: usize, entry: &Entry) -> Result<SinkStep> {
        let target = safe_join(self.dest, &entry.path)?;
        if entry.is_resource_fork {
            return self.prepare_fork(idx, target);
        }
        match &entry.kind {
            EntryKind::Dir => {
                std::fs::create_dir_all(&target)?;
                if self.preserve {
                    apply_mode(&target, entry.mode);
                }
                self.dir_mtimes.push((target, entry.modified));
                self.done(idx);
                Ok(SinkStep::Skip)
            }
            EntryKind::Symlink {
                target: link_target,
            } => {
                crate::path_safety::safe_symlink_target(self.dest, &entry.path, link_target)?;
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                create_symlink(link_target, &target)?;
                if self.preserve {
                    apply_symlink_mtime(&target, entry.modified);
                }
                self.done(idx);
                Ok(SinkStep::Skip)
            }
            EntryKind::File => {
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let out = std::fs::File::create(&target)?;
                // Файл существует с этой строки — раньше, чем известен хоть
                // один байт содержимого. Как бы дальше ни вышло, недописанный
                // остаться не должен: пустой файл с правильным именем читается
                // как успех, а это хуже, чем честное отсутствие записи. Убирает
                // его `end`, на обоих выходах.
                self.cur = Some(Current {
                    idx,
                    entry_path: target.clone(),
                    write_path: target,
                    is_fork: false,
                    body: Body::File(out),
                });
                Ok(SinkStep::Body)
            }
        }
    }
}

/// AppleDouble v2 header, as Apple writes it when a Mac file lands on a
/// filesystem that has no forks: magic, version, sixteen filler bytes, then one
/// descriptor per stored part. We store exactly one part — the resource fork,
/// entry id 2 — so the header is a fixed 38 bytes and the fork's bytes follow.
#[cfg(not(target_os = "macos"))]
const APPLEDOUBLE_MAGIC: u32 = 0x0005_1607;
#[cfg(not(target_os = "macos"))]
const APPLEDOUBLE_VERSION: u32 = 0x0002_0000;
#[cfg(not(target_os = "macos"))]
const APPLEDOUBLE_RESOURCE_FORK_ID: u32 = 2;
#[cfg(not(target_os = "macos"))]
const APPLEDOUBLE_HEADER_LEN: u32 = 38;

/// Write the resource fork of `target`.
///
/// Two destinations, and both of them are Apple's own answer to the same
/// question — where does the second stream of a file go?
///
/// * **macOS** (and anything else with real forks): into the file itself, at
///   `target/..namedfork/rsrc`. The extracted file is then indistinguishable
///   from the original: one file, both streams, nothing extra in the folder.
/// * **Everywhere else**: beside it as `._name`, in the AppleDouble container
///   macOS itself writes when it copies a Mac file onto a foreign filesystem.
///   Those `._something` files people see on USB sticks from Mac users *are*
///   resource forks. Dumping raw fork bytes under that name would be a
///   different thing wearing its name — a Mac reading the disk back would not
///   recognise it.
///
/// The alternative — dropping the fork — is silent data loss, and for a picture
/// or an application it loses most of the file.
///
/// The data-fork entry may not have been written yet (nothing orders the two),
/// so on macOS the base file is created empty if it is missing.
impl ExtractSink<'_> {
    fn prepare_fork(&mut self, idx: usize, target: PathBuf) -> Result<SinkStep> {
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }

        #[cfg(target_os = "macos")]
        {
            if !target.exists() {
                std::fs::File::create(&target)?;
            }
            let write_path = target.join("..namedfork").join("rsrc");
            let out = std::fs::File::create(&write_path)?;
            self.cur = Some(Current {
                idx,
                entry_path: target,
                write_path,
                is_fork: true,
                body: Body::File(out),
            });
            Ok(SinkStep::Body)
        }

        #[cfg(not(target_os = "macos"))]
        {
            self.cur = Some(Current {
                idx,
                entry_path: target.clone(),
                write_path: target,
                is_fork: true,
                body: Body::Buffer(Vec::new()),
            });
            Ok(SinkStep::Body)
        }
    }

    /// Тело записи дошло целиком: доложить его до конца и проставить время и
    /// права.
    fn finish(&mut self, cur: Current, entry: &Entry) -> Result<()> {
        match cur.body {
            Body::File(out) => {
                drop(out);
                if cur.is_fork {
                    // Время ставится на файл, а не на вилку: вилка — не
                    // отдельный файл, и своих дат у неё нет.
                    if self.preserve {
                        apply_mtime(&cur.entry_path, entry.modified);
                    }
                } else if self.preserve {
                    apply_mode(&cur.entry_path, entry.mode);
                    apply_mtime(&cur.entry_path, entry.modified);
                }
            }
            #[cfg(not(target_os = "macos"))]
            Body::Buffer(fork) => {
                let len = u32::try_from(fork.len()).map_err(|_| Error::Unsupported {
                    format: "resource fork".into(),
                    feature: "fork larger than 4 GiB in an AppleDouble sidecar".into(),
                })?;

                let name = cur
                    .entry_path
                    .file_name()
                    .ok_or_else(|| Error::Corrupt("resource fork entry has no file name".into()))?;
                let mut sidecar_name = std::ffi::OsString::from("._");
                sidecar_name.push(name);
                let sidecar = cur.entry_path.with_file_name(sidecar_name);

                let mut buf = Vec::with_capacity(APPLEDOUBLE_HEADER_LEN as usize + fork.len());
                buf.extend_from_slice(&APPLEDOUBLE_MAGIC.to_be_bytes());
                buf.extend_from_slice(&APPLEDOUBLE_VERSION.to_be_bytes());
                buf.extend_from_slice(&[0u8; 16]);
                buf.extend_from_slice(&1u16.to_be_bytes());
                buf.extend_from_slice(&APPLEDOUBLE_RESOURCE_FORK_ID.to_be_bytes());
                buf.extend_from_slice(&APPLEDOUBLE_HEADER_LEN.to_be_bytes());
                buf.extend_from_slice(&len.to_be_bytes());
                buf.extend_from_slice(&fork);
                std::fs::write(&sidecar, &buf)?;

                if self.preserve {
                    apply_mtime(&sidecar, entry.modified);
                }
            }
        }
        Ok(())
    }
}

impl EntrySink for ExtractSink<'_> {
    fn begin(&mut self, idx: usize) -> Result<SinkStep> {
        // `entries` — общая ссылка, взятая насквозь: она не мешает менять сам
        // приёмник дальше по методу.
        let entries = self.entries;
        let entry = entries.get(idx).ok_or(Error::InvalidIndex(idx))?;

        // EntryStart, он же точка отмены для каталогов и ссылок.
        if let Some(p) = self.progress.as_mut() {
            let path = entry.path.to_string_lossy();
            if let Flow::Abort = p(ProgressEvent::EntryStart {
                index: idx,
                path: &path,
                size: entry.size,
            }) {
                self.report.aborted = true;
                return Ok(SinkStep::Stop);
            }
        }

        match self.prepare(idx, entry) {
            Ok(step) => Ok(step),
            Err(e) => {
                if self.strict {
                    return Err(e);
                }
                self.report.failed.push((entry.path.clone(), e.to_string()));
                // `Skip` — учёт по этой записи уже закрыт, `end` для неё не
                // придёт.
                Ok(SinkStep::Skip)
            }
        }
    }

    fn write_body(&mut self, buf: &[u8]) -> Result<()> {
        let Some(cur) = self.cur.as_mut() else {
            return Err(Error::Corrupt(
                "extract: entry body arrived without begin".into(),
            ));
        };
        let idx = cur.idx;
        match &mut cur.body {
            Body::File(f) => f.write_all(buf)?,
            #[cfg(not(target_os = "macos"))]
            Body::Buffer(v) => v.extend_from_slice(buf),
        }
        if let Some(p) = self.progress.as_mut()
            && let Flow::Abort = p(ProgressEvent::Bytes {
                index: idx,
                written: buf.len() as u64,
            })
        {
            self.aborted = true;
            return Err(Error::Io(std::io::Error::other("extraction aborted")));
        }
        Ok(())
    }

    fn end(&mut self, idx: usize, outcome: Result<()>) -> Result<bool> {
        let Some(cur) = self.cur.take() else {
            return Err(Error::Corrupt("extract: entry end without begin".into()));
        };
        let entries = self.entries;
        let entry = entries.get(idx).ok_or(Error::InvalidIndex(idx))?;

        match outcome {
            Ok(()) => match self.finish(cur, entry) {
                Ok(()) => {
                    self.done(idx);
                    Ok(true)
                }
                Err(e) => self.failed(entry, e),
            },
            Err(e) => {
                // Дескриптор надо закрыть до удаления, иначе на Windows файл не
                // убрать. Ресурсную вилку не трогаем: на macOS это второй поток
                // уже существующего файла, а не отдельная запись на диске.
                let is_fork = cur.is_fork;
                let write_path = cur.write_path.clone();
                drop(cur);
                if !is_fork {
                    let _ = std::fs::remove_file(&write_path);
                }
                // Отмена — не поломка. Раз человек отменил, эта запись ему не
                // нужна, а обрезанный файл выглядит ровно как целый. Записи,
                // дописанные до этого, остаются: это законченная работа.
                if self.aborted {
                    self.report.aborted = true;
                    return Ok(false);
                }
                self.failed(entry, e)
            }
        }
    }
}
