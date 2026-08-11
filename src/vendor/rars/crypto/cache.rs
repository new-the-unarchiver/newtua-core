//! NEWTUA, целиком наш файл (тикеты 33 и 35): один выведенный ключ, запомненный
//! на весь архив.
//!
//! Превращение пароля в ключ у RAR стоит дорого нарочно: у RAR 5 это
//! `2^kdf_count` раундов HMAC-SHA256 (при обычном `kdf_count = 15` — 32 768
//! раундов, около 6 мс), у RAR 3 — 262 144 раунда SHA-1. Соль лежит в заголовке
//! **каждой** записи, но в одном архиве это одно и то же значение, повторённое
//! N раз, поэтому вывод на каждую запись — это одна и та же работа, сделанная
//! заново. До тикета 33 сплошной архив из 4000 мелких файлов под паролем шёл
//! 17 с против 0,16 с у libunrar.
//!
//! Здесь один тип на оба поколения формата, чтобы правило промаха было записано
//! один раз: **промах по любой части ключа кэша выводит секрет заново**. Архив
//! с разными солями законен — libarchive такие и пишет, — и отдать ему секрет,
//! выведенный из чужой соли, значит расшифровать мусор. Пароль входит в ключ
//! кэша потому, что вызывающий вправе перебирать пароли на одном архиве.
//!
//! `Mutex` внутри `Arc`, а не `RefCell`: `Archive` доезжает до вызывающего
//! внутри `Box<dyn ArchiveReader>`, и `Send`/`Sync` у него отнимать нельзя.
//! Незанятый `Mutex` бесплатен.

use std::sync::{Arc, Mutex, PoisonError};
use zeroize::Zeroizing;

/// Одна ячейка: секрет `V`, выведенный из пароля и параметров `K`.
///
/// `K` — то, что вместе с паролем определяет секрет: у RAR 5 это соль и число
/// итераций, у RAR 3 — соль (её может и не быть). Одна ячейка, а не таблица:
/// архивы с разными солями существуют, но перемежающихся солей ни один упаковщик
/// не пишет, а промах стоит ровно того же, что стоил вывод до кэша.
pub struct DerivedSecretCache<K, V> {
    entry: Arc<Mutex<Option<Cached<K, V>>>>,
}

struct Cached<K, V> {
    password: Zeroizing<Vec<u8>>,
    params: K,
    secret: V,
}

impl<K, V> Clone for DerivedSecretCache<K, V> {
    /// Копия делит ячейку с исходником, а не заводит свою. На этом держится
    /// «один вывод ключа на набор томов»: тома — отдельные `Archive`, и ячейку
    /// им раздаёт `format/rar.rs`, `parse_set`.
    ///
    /// Написано руками, а не выведено: `#[derive(Clone)]` потребовал бы
    /// `K: Clone, V: Clone`, которых копированию `Arc` не нужно.
    fn clone(&self) -> Self {
        Self {
            entry: Arc::clone(&self.entry),
        }
    }
}

impl<K, V> Default for DerivedSecretCache<K, V> {
    fn default() -> Self {
        Self {
            entry: Arc::new(Mutex::new(None)),
        }
    }
}

impl<K, V> std::fmt::Debug for DerivedSecretCache<K, V> {
    /// Ни секрета, ни пароля в отладочной печати: `Rar50Keys` поступает так же.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DerivedSecretCache").finish_non_exhaustive()
    }
}

impl<K: PartialEq, V: Clone> DerivedSecretCache<K, V> {
    /// Отдаёт запомненный секрет или выводит новый через `derive`.
    ///
    /// Проверка пароля (`check_value` у RAR 5) остаётся заботой вызывающего и
    /// обязана идти **и на попадании тоже**: она стоит одного хеша, а пропустить
    /// её значит изменить путь «неверный пароль».
    pub fn get_or_derive<E>(
        &self,
        password: &[u8],
        params: K,
        derive: impl FnOnce() -> Result<V, E>,
    ) -> Result<V, E> {
        let mut slot = self.entry.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(cached) = slot.as_ref()
            && cached.params == params
            && cached.password.as_slice() == password
        {
            return Ok(cached.secret.clone());
        }
        let secret = derive()?;
        *slot = Some(Cached {
            password: Zeroizing::new(password.to_vec()),
            params,
            secret: secret.clone(),
        });
        Ok(secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// Счётчик выводов — то же прямое доказательство, каким дефект и был найден:
    /// не «стало быстрее», а «работа сделана один раз».
    fn derive(calls: &Cell<usize>, password: &[u8], params: (u8, u8)) -> String {
        calls.set(calls.get() + 1);
        format!(
            "{}-{}-{}",
            String::from_utf8_lossy(password),
            params.0,
            params.1
        )
    }

    #[test]
    fn any_difference_in_the_key_derives_again() {
        let cache = DerivedSecretCache::<(u8, u8), String>::default();
        let calls = Cell::new(0);
        cache
            .get_or_derive::<()>(b"pw", (1, 2), || Ok(derive(&calls, b"pw", (1, 2))))
            .unwrap();

        let other_params = cache
            .get_or_derive::<()>(b"pw", (9, 2), || Ok(derive(&calls, b"pw", (9, 2))))
            .unwrap();
        assert_eq!(other_params, "pw-9-2");

        let other_password = cache
            .get_or_derive::<()>(b"other", (9, 2), || Ok(derive(&calls, b"other", (9, 2))))
            .unwrap();
        assert_eq!(other_password, "other-9-2");

        // И прежняя пара после вытеснения выводится заново, а не берётся из
        // занятой ячейки.
        let back = cache
            .get_or_derive::<()>(b"pw", (1, 2), || Ok(derive(&calls, b"pw", (1, 2))))
            .unwrap();
        assert_eq!(back, "pw-1-2");
        assert_eq!(calls.get(), 4);
    }

    #[test]
    fn a_hit_does_not_derive_and_a_failed_derivation_leaves_the_cell_alone() {
        let cache = DerivedSecretCache::<(u8, u8), String>::default();
        let calls = Cell::new(0);
        let first = cache
            .get_or_derive::<()>(b"pw", (1, 2), || Ok(derive(&calls, b"pw", (1, 2))))
            .unwrap();
        assert!(
            cache
                .get_or_derive::<&str>(b"pw", (3, 4), || Err("плохой пароль"))
                .is_err()
        );

        // Ошибка не должна ни затереть годную ячейку, ни запомниться сама, а
        // попадание в неё — не считать заново.
        let hit = cache
            .get_or_derive::<()>(b"pw", (1, 2), || Ok(derive(&calls, b"pw", (1, 2))))
            .unwrap();
        assert_eq!(hit, first);
        assert_eq!(calls.get(), 1, "второй раз выводить было незачем");
    }

    #[test]
    fn a_clone_shares_the_cell_with_its_source() {
        // На этом стоит «один вывод на набор томов»: том получает копию ячейки
        // первого тома, а не пустую свою.
        let cache = DerivedSecretCache::<(u8, u8), String>::default();
        let calls = Cell::new(0);
        let volume = cache.clone();

        cache
            .get_or_derive::<()>(b"pw", (1, 2), || Ok(derive(&calls, b"pw", (1, 2))))
            .unwrap();
        let from_clone = volume
            .get_or_derive::<()>(b"pw", (1, 2), || Ok(derive(&calls, b"pw", (1, 2))))
            .unwrap();

        assert_eq!(from_clone, "pw-1-2");
        assert_eq!(calls.get(), 1, "копия ячейки обязана делить содержимое");
    }
}
