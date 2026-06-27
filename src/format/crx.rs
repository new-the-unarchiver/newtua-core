use std::io::Read;

use crate::archive::{
    ArchiveReader, Confidence, FormatHandler, FormatId, OpenOptions, ReadSeek, Source,
};
use crate::detect::TempBackedReader;
use crate::error::{Error, Result};

/// Распознаёт Chrome-расширения (`Cr24`) и извлекает вложенный zip.
pub struct CrxHandler;

/// Вычислить смещение начала вложенного zip по фиксированному префиксу
/// заголовка CRX. Нужны только длины из префикса (≤16 байт):
///
/// - CRX3: `Cr24 | u32 version=3 | u32 header_len` → zip с `12 + header_len`.
/// - CRX2: `Cr24 | u32 version=2 | u32 pubkey_len | u32 sig_len`
///   → zip с `16 + pubkey_len + sig_len`.
///
/// Арифметика в u64 — переполнение u32-длин невозможно.
fn crx_zip_offset(head: &[u8]) -> Result<u64> {
    if head.len() < 12 || &head[0..4] != b"Cr24" {
        return Err(Error::Corrupt("crx: short header or bad magic".into()));
    }
    let version = u32::from_le_bytes([head[4], head[5], head[6], head[7]]);
    match version {
        3 => {
            let header_len = u32::from_le_bytes([head[8], head[9], head[10], head[11]]) as u64;
            Ok(12 + header_len)
        }
        2 => {
            if head.len() < 16 {
                return Err(Error::Corrupt("crx2: short header".into()));
            }
            let pubkey_len = u32::from_le_bytes([head[8], head[9], head[10], head[11]]) as u64;
            let sig_len = u32::from_le_bytes([head[12], head[13], head[14], head[15]]) as u64;
            Ok(16 + pubkey_len + sig_len)
        }
        v => Err(Error::Unsupported {
            format: "crx".into(),
            feature: format!("CRX version {v}"),
        }),
    }
}

impl FormatHandler for CrxHandler {
    fn id(&self) -> FormatId {
        FormatId::Crx
    }

    fn probe(&self, header: &[u8], _name: Option<&str>) -> Confidence {
        if header.starts_with(b"Cr24") {
            Confidence::MAGIC
        } else {
            Confidence::NONE
        }
    }

    fn open(&self, src: Source, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        // CRX читается последовательно вперёд; требуем seekable (как zip/sfx),
        // потому что detect отдаёт Seekable для файловых путей.
        let mut inner: Box<dyn ReadSeek> = match src {
            Source::Seekable { inner, .. } => inner,
            Source::Stream { .. } => {
                return Err(Error::Unsupported {
                    format: "crx".into(),
                    feature: "streaming (crx requires seek)".into(),
                });
            }
        };

        // Фиксированный префикс: 12 байт (CRX3) или 16 (CRX2). Читаем CRX3-часть
        // первой и добираем 4 байта только для CRX2 — так на CRX3 с маленьким
        // header_len мы не зачитываем байты вложенного zip.
        let mut head = [0u8; 16];
        inner
            .read_exact(&mut head[..12])
            .map_err(|e| Error::Corrupt(format!("crx header: {e}")))?;
        let version = u32::from_le_bytes([head[4], head[5], head[6], head[7]]);
        let consumed: u64 = if version == 2 {
            inner
                .read_exact(&mut head[12..16])
                .map_err(|e| Error::Corrupt(format!("crx2 header: {e}")))?;
            16
        } else {
            12
        };
        let zip_offset = crx_zip_offset(&head[..consumed as usize])?;
        let skip = zip_offset
            .checked_sub(consumed)
            .ok_or_else(|| Error::Corrupt("crx: header overlaps zip".into()))?;

        // Пропустить переменную часть заголовка (header/pubkey/sig).
        let skipped = std::io::copy(&mut inner.by_ref().take(skip), &mut std::io::sink())?;
        if skipped < skip {
            return Err(Error::Corrupt("crx: truncated before zip".into()));
        }

        // Вырезать вложенный zip во временный файл (потоково, без RAM-пика), затем
        // открыть его по пути общим zip-движком — тот же приём, что у deb/sfx.
        let mut tmp = tempfile::NamedTempFile::new()?;
        std::io::copy(&mut inner, &mut tmp)?;
        let temp_path = tmp.into_temp_path();
        let reader = crate::format::zip::open_zip(Source::path(&temp_path)?, opts, FormatId::Crx)?;
        Ok(Box::new(TempBackedReader::new(reader, temp_path)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_cr24_is_magic() {
        assert_eq!(
            CrxHandler.probe(b"Cr24\x03\x00\x00\x00", None),
            Confidence::MAGIC
        );
    }

    #[test]
    fn probe_zip_is_none() {
        assert_eq!(CrxHandler.probe(b"PK\x03\x04", None), Confidence::NONE);
    }

    #[test]
    fn offset_crx3() {
        // Cr24 | version=3 | header_len=7
        let mut h = b"Cr24".to_vec();
        h.extend_from_slice(&3u32.to_le_bytes());
        h.extend_from_slice(&7u32.to_le_bytes());
        assert_eq!(crx_zip_offset(&h).unwrap(), 12 + 7);
    }

    #[test]
    fn offset_crx2() {
        // Cr24 | version=2 | pubkey_len=12 | sig_len=9
        let mut h = b"Cr24".to_vec();
        h.extend_from_slice(&2u32.to_le_bytes());
        h.extend_from_slice(&12u32.to_le_bytes());
        h.extend_from_slice(&9u32.to_le_bytes());
        assert_eq!(crx_zip_offset(&h).unwrap(), 16 + 12 + 9);
    }

    #[test]
    fn unknown_version_is_unsupported() {
        let mut h = b"Cr24".to_vec();
        h.extend_from_slice(&4u32.to_le_bytes());
        h.extend_from_slice(&0u32.to_le_bytes());
        assert!(matches!(crx_zip_offset(&h), Err(Error::Unsupported { .. })));
    }

    #[test]
    fn short_header_is_corrupt() {
        assert!(matches!(
            crx_zip_offset(b"Cr24\x03\x00"),
            Err(Error::Corrupt(_))
        ));
    }

    #[test]
    fn crx2_short_header_is_corrupt() {
        // version=2, 12 байт: есть pubkey_len, но нет sig_len (CRX2 требует ≥16).
        // Так покрываем именно CRX2-ветку `head.len() < 16`, а не общий guard <12.
        let mut h = b"Cr24".to_vec();
        h.extend_from_slice(&2u32.to_le_bytes());
        h.extend_from_slice(&12u32.to_le_bytes());
        assert_eq!(h.len(), 12);
        assert!(matches!(crx_zip_offset(&h), Err(Error::Corrupt(_))));
    }
}
