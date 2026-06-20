use std::io::Read;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Находит и упорядочивает тома многотомного архива по первому тому.
pub fn volume_members(_first: &Path) -> Result<Vec<PathBuf>> {
    todo!()
}

/// Последовательное чтение нескольких файлов как единого потока.
pub struct ConcatReader {
    _files: Vec<PathBuf>,
}

impl ConcatReader {
    pub fn open(_members: &[PathBuf]) -> Result<ConcatReader> {
        todo!()
    }
}

impl Read for ConcatReader {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        todo!()
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
