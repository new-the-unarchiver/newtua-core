//! Две горячие мелочи разбора: длина совпадения и поиск байта команды x86.
//!
//! Апстрим держит здесь две реализации каждой — векторную под флагом `fast` и
//! обычную. Векторная требует ночной сборки Rust (`portable_simd`), а нас
//! собирают на стабильной, поэтому здесь остались только обычные, а вместе с
//! ними ушли `cfg` и `*_impl`-прослойки, которые между ними выбирали. Терять
//! было нечего: на стабильном компиляторе векторная ветка не собралась бы.
//!
//! Тесты апстрима вместе с ней потеряли смысл: они сверяли векторную ветку со
//! скалярной, а без первой сверяли бы вторую сама с собой. Здесь вместо них
//! проверяется то, что решают сами эти функции, — границы.

/// NEWTUA: поиск векторный, а не побайтный, и спрашивают его признаком, а не
/// маской (тикет 30, Е5).
///
/// Апстрим брал `cmp_mask` и сравнивал `byte & mask == 0xe8`. Значений у маски
/// было ровно два, и оба выражаются готовым вызовом: `0xff` — «найти `0xe8`»,
/// `0xfe` — «найти `0xe8` или `0xe9`». Признак `include_e9` называет то же
/// самое, но третьего значения у него не бывает.
///
/// Векторную ветку апстрима мы потеряли не по своей воле: она под
/// `portable_simd` и требует ночной сборки. `memchr` даёт её на стабильной, а
/// `unsafe` остаётся внутри чужого крейта — наш `#[forbid(unsafe_code)]` цел.
pub(crate) fn next_x86_opcode(
    data: &[u8],
    start: usize,
    end_exclusive: usize,
    include_e9: bool,
) -> Option<usize> {
    let end = end_exclusive.min(data.len());
    if start >= end {
        return None;
    }

    let haystack = &data[start..end];
    let offset = if include_e9 {
        memchr::memchr2(0xe8, 0xe9, haystack)
    } else {
        memchr::memchr(0xe8, haystack)
    };
    offset.map(|offset| start + offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86_opcode_scan_resumes_and_respects_the_end() {
        // Только 0xe8, затем 0xe8 вместе с 0xe9. Ожидания
        // записаны числами, а не тем же условием, что и в самой функции.
        let mut data = vec![0x41u8; 96];
        for pos in [0, 31, 32, 33, 63, 64, 91] {
            data[pos] = 0xe8;
        }
        data[47] = 0xe9;

        let scan = |include_e9: bool, limit: usize| {
            let mut found = Vec::new();
            let mut pos = 0usize;
            while let Some(next) = next_x86_opcode(&data, pos, limit, include_e9) {
                found.push(next);
                pos = next + 1;
            }
            found
        };

        assert_eq!(scan(false, 92), vec![0, 31, 32, 33, 63, 64, 91]);
        assert_eq!(scan(true, 92), vec![0, 31, 32, 33, 47, 63, 64, 91]);
        // Граница исключающая: с limit = 91 последний байт уже не виден.
        assert_eq!(scan(false, 91), vec![0, 31, 32, 33, 63, 64]);
    }

    #[test]
    fn x86_opcode_scan_finds_nothing_in_an_empty_range() {
        let data = vec![0xe8u8; 8];

        assert_eq!(next_x86_opcode(&data, 4, 4, false), None);
        assert_eq!(next_x86_opcode(&data, 9, 16, false), None);
    }
}
