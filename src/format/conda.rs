use std::io::Write;

use crate::archive::{
    ArchiveReader, Confidence, Entry, FormatHandler, FormatId, OpenOptions, Source,
};
use crate::decompress::{Compressor, decompressor};
use crate::error::{Error, Result};
use crate::format::TarHandler;
use crate::format::zip::open_zip;

/// True, если имя `name` (в любом регистре) оканчивается на `.tar.zst` —
/// признак payload-члена conda. Сравнение по байтам — безопасно на мультибайте
/// (срез `&str` мог бы паниковать на не-границе символа).
fn is_tar_zst(name: &str) -> bool {
    let (nb, eb) = (name.as_bytes(), b".tar.zst".as_slice());
    nb.len() >= eb.len() && nb[nb.len() - eb.len()..].eq_ignore_ascii_case(eb)
}

/// Распознаёт пакеты conda (`.conda`) и разворачивает их внутренние
/// `*.tar.zst`-члены в единый список записей.
pub struct CondaHandler;

impl FormatHandler for CondaHandler {
    fn id(&self) -> FormatId {
        FormatId::Conda
    }

    fn probe(&self, header: &[u8], name: Option<&str>) -> Confidence {
        // Имя оканчивается на `.conda` (без аллокации, регистронезависимо; срез
        // по байтам безопасен на мультибайте) И zip-магия PK.
        let ext_ok = name.is_some_and(|n| {
            let (nb, eb) = (n.as_bytes(), b".conda".as_slice());
            nb.len() >= eb.len() && nb[nb.len() - eb.len()..].eq_ignore_ascii_case(eb)
        });
        if ext_ok && header.starts_with(b"PK\x03\x04") {
            Confidence::MAGIC
        } else {
            Confidence::NONE
        }
    }

    fn open(&self, src: Source, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        open_conda(src, opts)
    }
}

/// Открыть `.conda`: внешний zip → развернуть каждый `*.tar.zst`-член в tar и
/// слить их записи в один список.
fn open_conda(src: Source, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
    // conda — это файловый zip; стрим не поддержан (как zip/crx).
    if !matches!(src, Source::Seekable { .. }) {
        return Err(Error::Unsupported {
            format: "conda".into(),
            feature: "streaming (conda requires seek)".into(),
        });
    }

    // Открыть внешний zip и найти все `*.tar.zst`-члены (по индексам).
    let mut outer = open_zip(src, opts, FormatId::Conda)?;
    let members: Vec<usize> = outer
        .entries()?
        .iter()
        .enumerate()
        .filter(|(_, e)| is_tar_zst(&e.path.to_string_lossy()))
        .map(|(i, _)| i)
        .collect();
    if members.is_empty() {
        return Err(Error::Corrupt("conda: no .tar.zst members".into()));
    }

    let mut inners: Vec<Box<dyn ArchiveReader>> = Vec::with_capacity(members.len());
    let mut temps: Vec<tempfile::TempPath> = Vec::with_capacity(members.len());
    let mut entries: Vec<Entry> = Vec::new();
    let mut map: Vec<(usize, usize)> = Vec::new();

    for member_idx in members {
        // 1) Выгрузить байты члена (zstd-поток) во временный файл A.
        let mut zst = tempfile::NamedTempFile::new()?;
        outer.read_entry(member_idx, &mut zst)?;
        zst.as_file_mut().flush()?;

        // 2) Снять zstd: A → временный файл B (tar). Поток, без RAM-пика.
        //    reopen() даёт свежий хэндл с позиции 0 (read_entry оставил курсор
        //    в конце). Временный файл A удалится на выходе из итерации.
        let reopened = zst.reopen()?;
        let mut decoded = decompressor(Compressor::Zstd, Box::new(reopened))?;
        let mut tar_tmp = tempfile::NamedTempFile::new()?;
        std::io::copy(&mut decoded, &mut tar_tmp)?;
        let tar_path = tar_tmp.into_temp_path();

        // 3) Открыть B как tar и влить его записи в общий список.
        let mut reader = TarHandler.open(Source::path(&tar_path)?, opts)?;
        let reader_idx = inners.len();
        let cloned: Vec<Entry> = reader.entries()?.to_vec();
        for (j, e) in cloned.into_iter().enumerate() {
            entries.push(e);
            map.push((reader_idx, j));
        }
        inners.push(reader);
        temps.push(tar_path);
    }

    Ok(Box::new(CondaReader {
        inners,
        _temps: temps,
        entries,
        map,
    }))
}

/// Композитный ридер: держит по одному tar-ридеру на `*.tar.zst`-член и
/// диспетчеризует `read_entry` по карте `глобальный idx → (ридер, idx)`.
struct CondaReader {
    inners: Vec<Box<dyn ArchiveReader>>,
    /// Держат temp-tar живыми (Drop удаляет файлы).
    _temps: Vec<tempfile::TempPath>,
    entries: Vec<Entry>,
    map: Vec<(usize, usize)>,
}

impl ArchiveReader for CondaReader {
    fn format(&self) -> FormatId {
        FormatId::Conda
    }

    fn entries(&mut self) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn read_entry(&mut self, idx: usize, out: &mut dyn Write) -> Result<()> {
        let &(r, i) = self.map.get(idx).ok_or(Error::InvalidIndex(idx))?;
        self.inners[r].read_entry(i, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_tar_zst_matches_suffix() {
        assert!(is_tar_zst("pkg-foo-1.0.tar.zst"));
        assert!(is_tar_zst("info-foo-1.0.tar.zst"));
        assert!(is_tar_zst("X.TAR.ZST"));
        assert!(!is_tar_zst("metadata.json"));
        assert!(!is_tar_zst("foo.tar"));
        assert!(!is_tar_zst("foo.zst"));
        assert!(!is_tar_zst("zst"));
    }

    #[test]
    fn probe_pk_plus_conda_is_magic() {
        assert_eq!(
            CondaHandler.probe(b"PK\x03\x04xx", Some("pkg.conda")),
            Confidence::MAGIC
        );
    }

    #[test]
    fn probe_is_case_insensitive() {
        assert_eq!(
            CondaHandler.probe(b"PK\x03\x04xx", Some("PKG.CONDA")),
            Confidence::MAGIC
        );
    }

    #[test]
    fn probe_pk_plain_zip_is_none() {
        assert_eq!(
            CondaHandler.probe(b"PK\x03\x04xx", Some("plain.zip")),
            Confidence::NONE
        );
    }

    #[test]
    fn probe_conda_without_pk_is_none() {
        assert_eq!(
            CondaHandler.probe(b"not-a-zip", Some("pkg.conda")),
            Confidence::NONE
        );
    }

    #[test]
    fn probe_no_name_is_none() {
        assert_eq!(CondaHandler.probe(b"PK\x03\x04xx", None), Confidence::NONE);
    }
}
