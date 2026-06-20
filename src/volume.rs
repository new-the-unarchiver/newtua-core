use std::io::Read;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Находит и упорядочивает тома многотомного архива по первому тому.
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
    // Прочие схемы (.partN, .r00) обрабатываются крейтами 7z/rar по первому тому.
    Ok(vec![first.to_path_buf()])
}

/// Последовательное чтение нескольких файлов как единого потока.
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
        Ok(ConcatReader { files: members.to_vec(), idx: 0, current: None })
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
