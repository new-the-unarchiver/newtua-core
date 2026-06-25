use crate::archive::{ArchiveReader, Confidence, FormatHandler, FormatId, OpenOptions, Source};
use crate::decompress::{Compressor, decompressor};
use crate::detect::TempBackedReader;
use crate::error::{Error, Result};
use crate::format::CpioHandler;

// ── Handler ──────────────────────────────────────────────────────────────────

pub struct RpmHandler;

impl FormatHandler for RpmHandler {
    fn id(&self) -> FormatId {
        FormatId::Rpm
    }

    fn probe(&self, header: &[u8], _name: Option<&str>) -> Confidence {
        // RPM lead magic: ED AB EE DB
        if header.starts_with(&[0xED, 0xAB, 0xEE, 0xDB]) {
            Confidence::MAGIC
        } else {
            Confidence::NONE
        }
    }

    fn open(&self, src: Source, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        // RPM requires a seekable source with a real file path (the rpm crate
        // opens the file by path).
        let path = match &src {
            Source::Seekable { path: Some(p), .. } => p.clone(),
            Source::Stream { .. } => {
                return Err(Error::Unsupported {
                    format: "rpm".into(),
                    feature: "streaming (rpm requires seek)".into(),
                });
            }
            Source::Seekable { path: None, .. } => {
                return Err(Error::Unsupported {
                    format: "rpm".into(),
                    feature: "seekable source without a path".into(),
                });
            }
        };

        // 1. Parse the package header (metadata only — no payload reads yet).
        let pkg = rpm::Package::open(&path).map_err(|e| Error::Corrupt(e.to_string()))?;

        // 2. Check payload format (expect "cpio").
        let payload_format = pkg
            .metadata
            .header
            .get_entry_data_as_string(rpm::IndexTag::RPMTAG_PAYLOADFORMAT)
            .unwrap_or("cpio");
        if payload_format != "cpio" {
            return Err(Error::Unsupported {
                format: "rpm".into(),
                feature: format!("payload format {payload_format}"),
            });
        }

        // 3. Read the payload-compressor tag as a raw string so we can handle
        //    "lzma" (not in rpm::CompressionType) ourselves.
        let compressor_str = pkg
            .metadata
            .header
            .get_entry_data_as_string(rpm::IndexTag::RPMTAG_PAYLOADCOMPRESSOR)
            .unwrap_or("");
        let comp = map_payload_compressor(compressor_str)?;

        // 4. The rpm crate already holds the payload in memory; stream it
        //    (decompressing if needed) into a cpio temp file. CpioHandler.open
        //    needs a real path, so the cpio temp is required; the still-compressed
        //    bytes never touch disk.
        let payload = std::io::Cursor::new(pkg.payload);
        let mut cpio_bytes: Box<dyn std::io::Read> = match comp {
            Some(c) => decompressor(c, Box::new(payload))?,
            None => Box::new(payload), // payload is already an uncompressed cpio
        };
        let mut temp_cpio = tempfile::NamedTempFile::new()?;
        std::io::copy(&mut cpio_bytes, &mut temp_cpio)?;
        let cpio_temp = temp_cpio.into_temp_path();

        // 5. Open the cpio payload with CpioHandler; keep the temp file alive and
        //    report `Rpm` (not the inner cpio) as the format.
        let inner = CpioHandler.open(Source::path(&cpio_temp)?, opts)?;
        Ok(Box::new(TempBackedReader::with_format(
            inner,
            cpio_temp,
            FormatId::Rpm,
        )))
    }
}

/// Map an RPM payload-compressor string to our `Compressor` enum.
///
/// Returns:
/// - `Ok(Some(c))` for a recognised compressor
/// - `Ok(None)` for "none" or "" (uncompressed)
/// - `Err(Unsupported)` for anything else
pub(crate) fn map_payload_compressor(s: &str) -> Result<Option<Compressor>> {
    match s {
        "gzip" => Ok(Some(Compressor::Gzip)),
        "xz" => Ok(Some(Compressor::Xz)),
        "zstd" => Ok(Some(Compressor::Zstd)),
        "lzma" => Ok(Some(Compressor::Lzma)),
        "bzip2" => Ok(Some(Compressor::Bzip2)),
        "" | "none" => Ok(None),
        other => Err(Error::Unsupported {
            format: "rpm".into(),
            feature: format!("payload compressor {other}"),
        }),
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Confidence;
    use crate::decompress::Compressor;

    #[test]
    fn id_is_rpm() {
        assert_eq!(RpmHandler.id(), FormatId::Rpm);
    }

    #[test]
    fn probe_positive_rpm_magic() {
        let header = &[0xED, 0xAB, 0xEE, 0xDB, 0x03, 0x00, 0x00, 0x01];
        assert_eq!(RpmHandler.probe(header, None), Confidence::MAGIC);
    }

    #[test]
    fn probe_negative_zip() {
        assert_eq!(RpmHandler.probe(b"PK\x03\x04....", None), Confidence::NONE);
    }

    #[test]
    fn probe_negative_short() {
        assert_eq!(RpmHandler.probe(b"\xED\xAB", None), Confidence::NONE);
    }

    #[test]
    fn map_compressor_gzip() {
        assert_eq!(
            map_payload_compressor("gzip").unwrap(),
            Some(Compressor::Gzip)
        );
    }

    #[test]
    fn map_compressor_xz() {
        assert_eq!(map_payload_compressor("xz").unwrap(), Some(Compressor::Xz));
    }

    #[test]
    fn map_compressor_zstd() {
        assert_eq!(
            map_payload_compressor("zstd").unwrap(),
            Some(Compressor::Zstd)
        );
    }

    #[test]
    fn map_compressor_lzma() {
        assert_eq!(
            map_payload_compressor("lzma").unwrap(),
            Some(Compressor::Lzma)
        );
    }

    #[test]
    fn map_compressor_bzip2() {
        assert_eq!(
            map_payload_compressor("bzip2").unwrap(),
            Some(Compressor::Bzip2)
        );
    }

    #[test]
    fn map_compressor_none_empty() {
        assert_eq!(map_payload_compressor("").unwrap(), None);
        assert_eq!(map_payload_compressor("none").unwrap(), None);
    }

    #[test]
    fn map_compressor_unknown_is_unsupported() {
        let result = map_payload_compressor("snappy");
        assert!(
            matches!(
                result,
                Err(crate::error::Error::Unsupported { ref format, ref feature })
                if format == "rpm" && feature.contains("snappy")
            ),
            "expected Unsupported for 'snappy', got {:?}",
            result
        );
    }
}
