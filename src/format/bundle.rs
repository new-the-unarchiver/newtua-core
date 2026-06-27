use crate::archive::{ArchiveReader, Confidence, FormatHandler, FormatId, OpenOptions, Source};
use crate::error::Result;

/// Внутренняя таблица детект-расширений: одно каноническое расширение на
/// подтип. Синонимы (war/ear/aab/docm/...) сюда НЕ добавляем — это
/// презентационный слой UI, не вход детекта.
pub(crate) const ZIP_BUNDLES: &[(&str, FormatId)] = &[
    (".jar", FormatId::Jar),
    (".apk", FormatId::Apk),
    (".ipa", FormatId::Ipa),
    (".epub", FormatId::Epub),
    (".docx", FormatId::Docx),
    (".xlsx", FormatId::Xlsx),
    (".pptx", FormatId::Pptx),
    (".odt", FormatId::Odt),
    (".ods", FormatId::Ods),
    (".odp", FormatId::Odp),
];

/// Тонкий хендлер: zip-подтип, опознаваемый по `PK`-магии плюс канони­ческое
/// расширение имени. Открытие делегируется общему zip-движку с нужным
/// `FormatId`.
pub struct ZipBundleHandler {
    ext: &'static str,
    format: FormatId,
}

impl ZipBundleHandler {
    pub fn new(ext: &'static str, format: FormatId) -> Self {
        Self { ext, format }
    }
}

impl FormatHandler for ZipBundleHandler {
    fn id(&self) -> FormatId {
        self.format
    }

    fn probe(&self, header: &[u8], name: Option<&str>) -> Confidence {
        // Сравниваем суффикс без аллокации и без учёта регистра; срез по байтам
        // безопасен на любых именах (срез &str мог бы паниковать на мультибайте).
        let ext_ok = name.is_some_and(|n| {
            let (nb, eb) = (n.as_bytes(), self.ext.as_bytes());
            nb.len() >= eb.len() && nb[nb.len() - eb.len()..].eq_ignore_ascii_case(eb)
        });
        if ext_ok && header.starts_with(b"PK\x03\x04") {
            Confidence::MAGIC
        } else {
            Confidence::NONE
        }
    }

    fn open(&self, src: Source, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        crate::format::zip::open_zip(src, opts, self.format)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h() -> ZipBundleHandler {
        ZipBundleHandler::new(".apk", FormatId::Apk)
    }

    #[test]
    fn probe_pk_plus_matching_ext_is_magic() {
        assert_eq!(
            h().probe(b"PK\x03\x04xx", Some("game.apk")),
            Confidence::MAGIC
        );
    }

    #[test]
    fn probe_is_case_insensitive() {
        assert_eq!(
            h().probe(b"PK\x03\x04xx", Some("GAME.APK")),
            Confidence::MAGIC
        );
    }

    #[test]
    fn probe_pk_wrong_ext_is_none() {
        assert_eq!(
            h().probe(b"PK\x03\x04xx", Some("plain.zip")),
            Confidence::NONE
        );
    }

    #[test]
    fn probe_matching_ext_without_pk_is_none() {
        assert_eq!(h().probe(b"not-a-zip", Some("game.apk")), Confidence::NONE);
    }

    #[test]
    fn probe_no_name_is_none() {
        assert_eq!(h().probe(b"PK\x03\x04xx", None), Confidence::NONE);
    }

    #[test]
    fn table_covers_ten_bundle_formats() {
        assert_eq!(ZIP_BUNDLES.len(), 10);
        for want in [
            FormatId::Jar,
            FormatId::Apk,
            FormatId::Ipa,
            FormatId::Epub,
            FormatId::Docx,
            FormatId::Xlsx,
            FormatId::Pptx,
            FormatId::Odt,
            FormatId::Ods,
            FormatId::Odp,
        ] {
            assert!(
                ZIP_BUNDLES.iter().any(|&(_, f)| f == want),
                "table missing {want:?}"
            );
        }
    }
}
