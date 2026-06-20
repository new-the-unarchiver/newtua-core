use std::io::Write;

use crate::archive::{
    ArchiveReader, Confidence, Entry, FormatHandler, FormatId, OpenOptions, Source,
};
use crate::encoding::decode_names;
use crate::error::{Error, Result};

pub struct ZipHandler;

type ZipArc = zip::ZipArchive<Box<dyn crate::archive::ReadSeek>>;

impl FormatHandler for ZipHandler {
    fn id(&self) -> FormatId {
        FormatId::Zip
    }

    fn probe(&self, header: &[u8], _name: Option<&str>) -> Confidence {
        if header.starts_with(b"PK\x03\x04") || header.starts_with(b"PK\x05\x06") {
            Confidence::MAGIC
        } else {
            Confidence::NONE
        }
    }

    fn open(&self, src: Source, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        let inner: Box<dyn crate::archive::ReadSeek> = match src {
            Source::Seekable { inner, .. } => inner,
            Source::Stream { .. } => {
                return Err(Error::Unsupported {
                    format: "zip".into(),
                    feature: "streaming (zip requires seek)".into(),
                });
            }
        };
        let mut zip = zip::ZipArchive::new(inner).map_err(map_zip_err)?;
        let mut raw_names: Vec<Vec<u8>> = Vec::new();
        let mut metas: Vec<(u64, bool, bool, Option<std::time::SystemTime>)> = Vec::new();
        for i in 0..zip.len() {
            let f = zip.by_index_raw(i).map_err(map_zip_err)?;
            raw_names.push(f.name_raw().to_vec());
            metas.push((
                f.size(),
                f.is_dir(),
                f.encrypted(),
                f.last_modified().and_then(zip_dt_to_systime),
            ));
        }
        let names = decode_names(&raw_names, opts.encoding_override.as_deref());
        let mut entries = Vec::with_capacity(zip.len());
        for (i, (size, is_dir, is_encrypted, modified)) in metas.into_iter().enumerate() {
            entries.push(Entry {
                path_raw: raw_names[i].clone(),
                path: std::path::PathBuf::from(&names[i]),
                size,
                is_dir,
                is_encrypted,
                modified,
            });
        }
        Ok(Box::new(ZipReader {
            zip,
            entries,
            password: opts.password.clone(),
        }))
    }
}

/// Convert a zip::DateTime to SystemTime without the `time` crate.
/// Uses the MS-DOS date fields directly. Returns None on out-of-range values.
fn zip_dt_to_systime(dt: zip::DateTime) -> Option<std::time::SystemTime> {
    let year = dt.year() as i32;
    let month = dt.month() as u32;
    let day = dt.day() as u32;
    let hour = dt.hour() as u64;
    let min = dt.minute() as u64;
    let sec = dt.second() as u64;
    // Validate ranges
    if month == 0 || month > 12 || day == 0 || day > 31 || year < 1970 {
        return None;
    }
    // Days since Unix epoch (1970-01-01) — approximate via days_from_civil
    let days = days_from_civil(year, month, day)?;
    let secs = days * 86400 + hour * 3600 + min * 60 + sec;
    Some(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs))
}

/// Compute days since 1970-01-01 for a given date.
/// Algorithm from http://howardhinnant.github.io/date_algorithms.html
fn days_from_civil(y: i32, m: u32, d: u32) -> Option<u64> {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = (y - era * 400) as u32; // [0, 399]
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    let days_since_epoch = era as i64 * 146097 + doe as i64 - 719468;
    if days_since_epoch < 0 {
        None
    } else {
        Some(days_since_epoch as u64)
    }
}

fn map_zip_err(e: zip::result::ZipError) -> Error {
    use zip::result::ZipError;
    match e {
        ZipError::Io(io) => Error::Io(io),
        // In zip 2.x, wrong password yields InvalidPassword
        ZipError::InvalidPassword => Error::WrongPassword,
        ZipError::UnsupportedArchive(s) if s == ZipError::PASSWORD_REQUIRED => Error::Encrypted,
        ZipError::UnsupportedArchive(s) => Error::Unsupported {
            format: "zip".into(),
            feature: s.into(),
        },
        other => Error::Corrupt(other.to_string()),
    }
}

struct ZipReader {
    zip: ZipArc,
    entries: Vec<Entry>,
    password: Option<String>,
}

impl ArchiveReader for ZipReader {
    fn format(&self) -> FormatId {
        FormatId::Zip
    }

    fn entries(&mut self) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn read_entry(&mut self, idx: usize, out: &mut dyn Write) -> Result<()> {
        let is_encrypted = self
            .entries
            .get(idx)
            .ok_or(Error::InvalidIndex(idx))?
            .is_encrypted;
        if is_encrypted {
            let pw = self.password.clone().ok_or(Error::Encrypted)?;
            let mut f = self
                .zip
                .by_index_decrypt(idx, pw.as_bytes())
                .map_err(map_zip_err)?;
            std::io::copy(&mut f, out)?;
        } else {
            let mut f = self.zip.by_index(idx).map_err(map_zip_err)?;
            std::io::copy(&mut f, out)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Confidence;

    #[test]
    fn probe_detects_pk_magic() {
        assert_eq!(ZipHandler.probe(b"PK\x03\x04....", None), Confidence::MAGIC);
    }

    #[test]
    fn probe_detects_empty_archive_magic() {
        assert_eq!(ZipHandler.probe(b"PK\x05\x06....", None), Confidence::MAGIC);
    }

    #[test]
    fn probe_rejects_other() {
        assert_eq!(ZipHandler.probe(b"7z\xbc\xaf", None), Confidence::NONE);
    }

    #[test]
    fn probe_rejects_empty_header() {
        assert_eq!(ZipHandler.probe(b"", None), Confidence::NONE);
    }

    #[test]
    fn zip_handler_id_is_zip() {
        assert_eq!(ZipHandler.id(), FormatId::Zip);
    }

    #[test]
    fn days_from_civil_epoch() {
        assert_eq!(days_from_civil(1970, 1, 1), Some(0));
    }

    #[test]
    fn days_from_civil_known_date() {
        // 2000-01-01 is 10957 days after 1970-01-01
        assert_eq!(days_from_civil(2000, 1, 1), Some(10957));
    }

    #[test]
    fn days_from_civil_before_epoch_returns_none() {
        assert_eq!(days_from_civil(1969, 12, 31), None);
    }
}
