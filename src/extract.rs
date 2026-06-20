use std::path::{Path, PathBuf};

use crate::archive::{ArchiveReader, Entry};
use crate::error::{Error, Result};
use crate::path_safety::safe_join;

pub struct ExtractOptions {
    pub dest: PathBuf,
    /// Имя обёртки-папки (обычно — имя архива без расширения). Используется,
    /// только если у записей нет единого общего корневого каталога.
    pub wrapper_name: Option<String>,
    pub strict: bool,
}

#[derive(Debug, Default)]
pub struct ExtractReport {
    pub extracted: usize,
    pub failed: Vec<(PathBuf, String)>,
    pub wrapped: bool,
}

/// Общий верхний каталог всех записей, если он единственный.
pub fn common_root(entries: &[Entry]) -> Option<String> {
    let mut root: Option<String> = None;
    for e in entries {
        let first = e.path.components().next()?;
        let comp = first.as_os_str().to_string_lossy().to_string();
        match &root {
            None => root = Some(comp),
            Some(r) if *r != comp => return None,
            _ => {}
        }
    }
    root
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

    for (idx, entry) in entries.iter().enumerate() {
        let result = extract_one(ar, idx, entry, &dest);
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
    Ok(report)
}

fn extract_one(ar: &mut dyn ArchiveReader, idx: usize, entry: &Entry, dest: &Path) -> Result<()> {
    let target = safe_join(dest, &entry.path)?;
    if entry.is_dir {
        std::fs::create_dir_all(&target)?;
        return Ok(());
    }
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut out = std::fs::File::create(&target)?;
    ar.read_entry(idx, &mut out)?;
    Ok(())
}
