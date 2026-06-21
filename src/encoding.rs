use chardetng::EncodingDetector;
use encoding_rs::{Encoding, UTF_8};

/// Декодирует набор сырых имён, определяя единую кодировку по всему набору.
/// `override_label` (если задан и валиден) принудительно выбирает кодировку.
pub fn decode_names(raw: &[Vec<u8>], override_label: Option<&str>) -> Vec<String> {
    let encoding = resolve_encoding(raw, override_label);
    raw.iter()
        .map(|bytes| {
            let (cow, _, _) = encoding.decode(bytes);
            cow.into_owned()
        })
        .collect()
}

fn resolve_encoding(raw: &[Vec<u8>], override_label: Option<&str>) -> &'static Encoding {
    if let Some(label) = override_label {
        if let Some(enc) = Encoding::for_label(label.as_bytes()) {
            return enc;
        }
    }
    // Если всё валидный UTF-8 — берём UTF-8.
    if raw.iter().all(|b| std::str::from_utf8(b).is_ok()) {
        return UTF_8;
    }
    // Иначе агрегируем сигнал по всем именам.
    let mut det = EncodingDetector::new();
    for b in raw {
        det.feed(b, false);
    }
    det.feed(&[], true);
    det.guess(None, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_names_pass_through() {
        let raw = vec!["café.txt".as_bytes().to_vec(), "naïve".as_bytes().to_vec()];
        let out = decode_names(&raw, None);
        assert_eq!(out, vec!["café.txt".to_string(), "naïve".to_string()]);
    }

    #[test]
    fn override_label_forces_encoding() {
        // 0xE9 = 'é' в windows-1252 / latin1
        let raw = vec![vec![b'c', b'a', b'f', 0xE9]];
        let out = decode_names(&raw, Some("windows-1252"));
        assert_eq!(out, vec!["café".to_string()]);
    }

    #[test]
    fn aggregate_detection_decodes_legacy_bytes() {
        // Кириллица в windows-1251: "файл" = F4 E0 E9 EB
        let raw = vec![vec![0xF4, 0xE0, 0xE9, 0xEB]];
        let out = decode_names(&raw, None);
        // детект должен дать осмысленную кириллицу, а не U+FFFD
        assert!(out[0].chars().all(|c| c != '\u{FFFD}'));
    }
}

#[cfg(test)]
mod edge {
    use super::*;

    #[test]
    fn empty_input_yields_empty() {
        assert!(decode_names(&[], None).is_empty());
    }

    #[test]
    fn invalid_override_label_falls_back() {
        let raw = vec!["ok.txt".as_bytes().to_vec()];
        let out = decode_names(&raw, Some("not-a-real-encoding"));
        assert_eq!(out, vec!["ok.txt".to_string()]);
    }

    #[test]
    fn empty_name_decodes_to_empty_string() {
        let raw = vec![Vec::new()];
        assert_eq!(decode_names(&raw, None), vec![String::new()]);
    }
}
