use crate::archive::{ArchiveReader, Confidence, FormatHandler, FormatId, OpenOptions, Source};
use crate::error::{Error, Result};

/// Reads AppImage files: an ELF runtime with an appended filesystem.
pub struct AppImageHandler;

impl FormatHandler for AppImageHandler {
    fn id(&self) -> FormatId {
        FormatId::AppImage
    }

    /// Detect by ELF magic + the `AI` type marker at offset 8, OR the
    /// `.appimage` extension (case-insensitive). All bytes inspected are within
    /// the 512-byte header the registry peeks.
    fn probe(&self, header: &[u8], name: Option<&str>) -> Confidence {
        let magic_ok = header.starts_with(b"\x7fELF")
            && matches!(header.get(8..11), Some([b'A', b'I', 1 | 2]));
        let ext_ok = name.is_some_and(|n| n.to_ascii_lowercase().ends_with(".appimage"));
        if magic_ok || ext_ok {
            Confidence::MAGIC
        } else {
            Confidence::NONE
        }
    }

    fn open(&self, _src: Source, _opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        // Implemented in Task 4.
        Err(Error::Corrupt("appimage: open not yet implemented".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_is_appimage() {
        assert_eq!(AppImageHandler.id(), FormatId::AppImage);
    }

    #[test]
    fn probe_type2_magic_is_magic() {
        assert_eq!(
            AppImageHandler.probe(b"\x7fELF\x02\x01\x01\x00AI\x02", None),
            Confidence::MAGIC
        );
    }

    #[test]
    fn probe_type1_magic_is_magic() {
        assert_eq!(
            AppImageHandler.probe(b"\x7fELF\x02\x01\x01\x00AI\x01", None),
            Confidence::MAGIC
        );
    }

    #[test]
    fn probe_appimage_extension_is_magic() {
        // No AI magic, but the `.appimage` extension (any case) is enough.
        assert_eq!(
            AppImageHandler.probe(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00", Some("Foo.AppImage")),
            Confidence::MAGIC
        );
    }

    #[test]
    fn probe_plain_elf_without_ai_is_none() {
        assert_eq!(
            AppImageHandler.probe(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00", Some("a.out")),
            Confidence::NONE
        );
    }

    #[test]
    fn probe_foreign_magic_is_none() {
        assert_eq!(
            AppImageHandler.probe(b"PK\x03\x04", Some("a.zip")),
            Confidence::NONE
        );
    }

    #[test]
    fn probe_no_name_no_magic_is_none() {
        assert_eq!(
            AppImageHandler.probe(b"\x00\x00\x00\x00", None),
            Confidence::NONE
        );
    }
}
