use std::io::{Read, Seek};

use crate::archive::{
    ArchiveReader, Confidence, FormatHandler, FormatId, OpenOptions, ReadSeek, Source,
};
use crate::decompress::{Compressor, decompressor};
use crate::detect::{TempBackedReader, detect_compressor, is_tar};
use crate::error::{Error, Result, io_err_to_corrupt};
use crate::format::TarHandler;

pub struct DebHandler;

impl FormatHandler for DebHandler {
    fn id(&self) -> FormatId {
        FormatId::Deb
    }

    fn probe(&self, header: &[u8], _name: Option<&str>) -> Confidence {
        // Same 8-byte magic as `ar`; distinguish a .deb by its first member
        // `debian-binary` (ar member name lives in header bytes 8..24).
        if header.len() >= 24
            && header.starts_with(b"!<arch>\n")
            && header[8..24].starts_with(b"debian-binary")
        {
            Confidence::MAGIC
        } else {
            Confidence::NONE
        }
    }

    fn open(&self, src: Source, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        let inner: Box<dyn ReadSeek> = match src {
            Source::Seekable { inner, .. } => inner,
            Source::Stream { .. } => {
                return Err(Error::Unsupported {
                    format: "deb".into(),
                    feature: "streaming (deb requires seek)".into(),
                });
            }
        };

        // 1. Locate the first `data.tar*` member (its index and lowercased name).
        let mut archive = ar::Archive::new(inner);
        let mut found: Option<(usize, String)> = None;
        let mut idx = 0usize;
        while let Some(entry) = archive.next_entry() {
            let entry = entry.map_err(io_err_to_corrupt)?;
            let name = entry.header().identifier();
            if name.starts_with(b"data.tar") {
                found = Some((idx, String::from_utf8_lossy(name).to_lowercase()));
                break;
            }
            idx += 1;
        }
        let (data_idx, data_name) =
            found.ok_or_else(|| Error::Corrupt("deb: missing data.tar member".into()))?;

        // 2. Copy that member (still compressed) to a temp file.
        let mut temp_raw = tempfile::NamedTempFile::new()?;
        {
            let mut member = archive.jump_to_entry(data_idx).map_err(io_err_to_corrupt)?;
            std::io::copy(&mut member, &mut temp_raw)?;
        }
        drop(archive);

        // 3. Detect the compressor from the member's first bytes, reusing one
        //    open handle. Content magic first; the alone-format `.lzma` has no
        //    reliable magic, so it is selected only by the member-name extension.
        let mut file = std::fs::File::open(temp_raw.path())?;
        let mut head = [0u8; 6];
        let n = file.read(&mut head)?;
        file.rewind()?;
        let comp = detect_compressor(&head[..n])
            .or_else(|| data_name.ends_with(".lzma").then_some(Compressor::Lzma));

        // 4. Produce the tar temp file (decompress, or pass through if uncompressed).
        let tar_temp: tempfile::TempPath = match comp {
            Some(c) => {
                let mut decoded = decompressor(c, Box::new(file))?;
                let mut temp_tar = tempfile::NamedTempFile::new()?;
                std::io::copy(&mut decoded, &mut temp_tar)?;
                temp_tar.into_temp_path()
            }
            None => {
                if !is_tar(&mut file)? {
                    return Err(Error::Unsupported {
                        format: "deb".into(),
                        feature: "data.tar compression".into(),
                    });
                }
                temp_raw.into_temp_path()
            }
        };

        // 5. Open the payload as tar; keep the temp file alive past the reader
        //    and report `Deb` (not the inner tar) as the format.
        let inner = TarHandler.open(Source::path(&tar_temp)?, opts)?;
        Ok(Box::new(TempBackedReader::with_format(
            inner,
            tar_temp,
            FormatId::Deb,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Confidence;

    fn ar_with_first_member(name: &[u8]) -> Vec<u8> {
        // 8-byte ar magic, then a 60-byte member header whose first 16 bytes
        // are the (space-padded) member name. Content/size are irrelevant to probe.
        let mut v = Vec::from(&b"!<arch>\n"[..]);
        let mut field = [b' '; 16];
        field[..name.len()].copy_from_slice(name);
        v.extend_from_slice(&field);
        v.extend_from_slice(&[b' '; 60 - 16]); // rest of the header (don't care)
        v
    }

    #[test]
    fn probe_detects_deb() {
        let h = ar_with_first_member(b"debian-binary");
        assert_eq!(DebHandler.probe(&h, None), Confidence::MAGIC);
    }

    #[test]
    fn probe_rejects_plain_ar() {
        let h = ar_with_first_member(b"hello.txt/");
        assert_eq!(DebHandler.probe(&h, None), Confidence::NONE);
    }

    #[test]
    fn probe_rejects_non_ar() {
        assert_eq!(DebHandler.probe(b"PK\x03\x04....", None), Confidence::NONE);
    }

    #[test]
    fn probe_rejects_short_header() {
        // Magic present but fewer than 24 bytes: cannot read the member name.
        assert_eq!(DebHandler.probe(b"!<arch>\n", None), Confidence::NONE);
    }

    #[test]
    fn deb_handler_id_is_deb() {
        assert_eq!(DebHandler.id(), FormatId::Deb);
    }
}
