use std::path::{Path, PathBuf};
use std::time::SystemTime;

use filetime::FileTime;

use crate::archive::{ArchiveReader, Entry, EntryKind};
use crate::error::Result;
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
    if let Some(m) = mode {
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(m & 0o7777));
    }
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
    /// Имя обёртки-папки (обычно — имя архива без расширения). Используется,
    /// только если у записей нет единого общего корневого каталога.
    pub wrapper_name: Option<String>,
    pub strict: bool,
    /// Restore mtime (and in future: mode) from archive metadata. Default: true.
    pub preserve: bool,
    /// Restrict extraction to these original entry indices. `None` = all.
    /// (Honored starting in Task 2; accepted here for a stable struct shape.)
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

    let mut dir_mtimes: Vec<(PathBuf, Option<SystemTime>)> = Vec::new();

    for (idx, entry) in entries.iter().enumerate() {
        if let Some(set) = &selected {
            if !set.contains(&idx) {
                continue;
            }
        }
        if !opts.keep_macos_metadata && crate::is_macos_metadata(&entry.path) {
            continue;
        }
        // EntryStart (also a cancellation checkpoint for dirs/symlinks).
        if let Some(p) = opts.progress.as_mut() {
            let path = entry.path.to_string_lossy();
            if let Flow::Abort = p(ProgressEvent::EntryStart {
                index: idx,
                path: &path,
                size: entry.size,
            }) {
                report.aborted = true;
                break;
            }
        }

        let mut aborted = false;
        let ctx = ProgressCtx {
            progress: opts.progress.as_mut(),
            aborted: &mut aborted,
        };
        let result = extract_one(ar, idx, entry, &dest, preserve, &mut dir_mtimes, ctx);
        if aborted {
            report.aborted = true;
            break;
        }
        match result {
            Ok(()) => {
                report.extracted += 1;
                if let Some(p) = opts.progress.as_mut() {
                    let _ = p(ProgressEvent::EntryDone { index: idx });
                }
            }
            Err(e) => {
                if strict {
                    return Err(e);
                }
                report.failed.push((entry.path.clone(), e.to_string()));
            }
        }
    }

    if preserve {
        for (path, modified) in &dir_mtimes {
            apply_mtime(path, *modified);
        }
    }

    Ok(report)
}

/// Bundles the optional progress callback with the cooperative-abort flag so
/// `extract_one` stays within clippy's argument-count limit.
struct ProgressCtx<'a> {
    progress: Option<&'a mut ProgressFn>,
    aborted: &'a mut bool,
}

fn extract_one(
    ar: &mut dyn ArchiveReader,
    idx: usize,
    entry: &Entry,
    dest: &Path,
    preserve: bool,
    dir_mtimes: &mut Vec<(PathBuf, Option<SystemTime>)>,
    mut ctx: ProgressCtx<'_>,
) -> Result<()> {
    let target = safe_join(dest, &entry.path)?;
    match &entry.kind {
        EntryKind::Dir => {
            std::fs::create_dir_all(&target)?;
            if preserve {
                apply_mode(&target, entry.mode);
            }
            dir_mtimes.push((target.clone(), entry.modified));
        }
        EntryKind::Symlink {
            target: link_target,
        } => {
            crate::path_safety::safe_symlink_target(dest, &entry.path, link_target)?;
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            create_symlink(link_target, &target)?;
            if preserve {
                apply_symlink_mtime(&target, entry.modified);
            }
        }
        EntryKind::File => {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let out = std::fs::File::create(&target)?;
            match ctx.progress.as_mut() {
                Some(p) => {
                    let mut w = ProgressWriter {
                        idx,
                        inner: out,
                        progress: p,
                        aborted: ctx.aborted,
                    };
                    // On cooperative abort, ProgressWriter returns an io error and
                    // sets *aborted; swallow that specific stop here.
                    if let Err(e) = ar.read_entry(idx, &mut w) {
                        if *ctx.aborted {
                            return Ok(());
                        }
                        return Err(e);
                    }
                }
                None => {
                    let mut out = out;
                    ar.read_entry(idx, &mut out)?;
                }
            }
            if preserve {
                apply_mode(&target, entry.mode);
                apply_mtime(&target, entry.modified);
            }
        }
    }
    Ok(())
}

struct ProgressWriter<'a> {
    idx: usize,
    inner: std::fs::File,
    progress: &'a mut ProgressFn,
    aborted: &'a mut bool,
}

impl std::io::Write for ProgressWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        if let Flow::Abort = (self.progress)(ProgressEvent::Bytes {
            index: self.idx,
            written: n as u64,
        }) {
            *self.aborted = true;
            return Err(std::io::Error::other("extraction aborted"));
        }
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
