use std::path::{Path, PathBuf};
use std::time::SystemTime;

use filetime::FileTime;

use crate::archive::{ArchiveReader, Entry};
use crate::error::Result;
use crate::path_safety::safe_join;

fn apply_mtime(path: &Path, modified: Option<SystemTime>) {
    if let Some(t) = modified {
        let ft = FileTime::from_system_time(t);
        // best-effort: data is already written, ignore errors
        let _ = filetime::set_file_mtime(path, ft);
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
}

#[derive(Debug, Default)]
pub struct ExtractReport {
    pub extracted: usize,
    pub failed: Vec<(PathBuf, String)>,
    pub wrapped: bool,
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

pub fn extract_all(ar: &mut dyn ArchiveReader, opts: &ExtractOptions) -> Result<ExtractReport> {
    let entries: Vec<Entry> = ar.entries()?.to_vec();
    let mut report = ExtractReport::default();

    // Обёртка-папка как в The Unarchiver: если у записей нет единого общего
    // корневого каталога и задан wrapper_name — оборачиваем содержимое в
    // папку по имени архива.
    let dest = match (common_root(&entries), &opts.wrapper_name) {
        (None, Some(name)) => {
            report.wrapped = true;
            opts.dest.join(name)
        }
        _ => opts.dest.clone(),
    };
    if report.wrapped {
        std::fs::create_dir_all(&dest)?;
    }

    // Collect directory paths + their mtimes for a second pass (writing children
    // bumps the parent dir mtime, so we apply dir mtimes after all entries).
    let mut dir_mtimes: Vec<(PathBuf, Option<SystemTime>)> = Vec::new();

    for (idx, entry) in entries.iter().enumerate() {
        let result = extract_one(ar, idx, entry, &dest, opts.preserve, &mut dir_mtimes);
        match result {
            Ok(()) => report.extracted += 1,
            Err(e) => {
                if opts.strict {
                    return Err(e);
                }
                report.failed.push((entry.path.clone(), e.to_string()));
            }
        }
    }

    // Second pass: restore directory mtimes after all children are written.
    if opts.preserve {
        for (path, modified) in &dir_mtimes {
            apply_mtime(path, *modified);
        }
    }

    Ok(report)
}

fn extract_one(
    ar: &mut dyn ArchiveReader,
    idx: usize,
    entry: &Entry,
    dest: &Path,
    preserve: bool,
    dir_mtimes: &mut Vec<(PathBuf, Option<SystemTime>)>,
) -> Result<()> {
    let target = safe_join(dest, &entry.path)?;
    if entry.is_dir() {
        std::fs::create_dir_all(&target)?;
        dir_mtimes.push((target, entry.modified));
        return Ok(());
    }
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut out = std::fs::File::create(&target)?;
    ar.read_entry(idx, &mut out)?;
    if preserve {
        apply_mtime(&target, entry.modified);
    }
    Ok(())
}
