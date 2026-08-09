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

pub(crate) fn next_x86_opcode(
    data: &[u8],
    start: usize,
    end_exclusive: usize,
    cmp_mask: u8,
) -> Option<usize> {
    let end = end_exclusive.min(data.len());
    if start >= end {
        return None;
    }

    data[start..end]
        .iter()
        .position(|&byte| byte & cmp_mask == 0xe8)
        .map(|offset| start + offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86_opcode_scan_resumes_and_respects_the_end() {
        // Только 0xe8 (маска 0xff) и 0xe8 вместе с 0xe9 (маска 0xfe). Ожидания
        // записаны числами, а не тем же условием, что и в самой функции.
        let mut data = vec![0x41u8; 96];
        for pos in [0, 31, 32, 33, 63, 64, 91] {
            data[pos] = 0xe8;
        }
        data[47] = 0xe9;

        let scan = |cmp_mask: u8, limit: usize| {
            let mut found = Vec::new();
            let mut pos = 0usize;
            while let Some(next) = next_x86_opcode(&data, pos, limit, cmp_mask) {
                found.push(next);
                pos = next + 1;
            }
            found
        };

        assert_eq!(scan(0xff, 92), vec![0, 31, 32, 33, 63, 64, 91]);
        assert_eq!(scan(0xfe, 92), vec![0, 31, 32, 33, 47, 63, 64, 91]);
        // Граница исключающая: с limit = 91 последний байт уже не виден.
        assert_eq!(scan(0xff, 91), vec![0, 31, 32, 33, 63, 64]);
    }

    #[test]
    fn x86_opcode_scan_finds_nothing_in_an_empty_range() {
        let data = vec![0xe8u8; 8];

        assert_eq!(next_x86_opcode(&data, 4, 4, 0xff), None);
        assert_eq!(next_x86_opcode(&data, 9, 16, 0xff), None);
    }
}
