//! Vendored third-party readers.
//!
//! A crate lands here instead of in `Cargo.toml` when the code the engine needs
//! exists upstream but not in any published release, and a git dependency is
//! not an option — crates.io refuses one, and `newtua-core` is published there.
//! Vendoring keeps the fix in hand without adding a forced fork to maintain and
//! publish (see `CLAUDE.md`, "Forced forks").
//!
//! Each module carries its upstream licence beside it and a `VENDORED.md` that
//! records the release it came from, what was cut, and every deliberate change.

pub(crate) mod cab;
// Пока `RarHandler` не переключён на этот код (тикет 26), модуль ничем не
// вызывается. Оба разрешения снимаются тем же тикетом, а не отдельной уборкой:
// у нечитаемого модуля весь публичный слой выглядит мёртвым.
// Пока `RarHandler` не переключён на этот код (тикет 26), в модуль не ведёт ни
// один вызов, и мёртвым для компилятора выглядит всё — включая чтение. Оба
// разрешения снимает тикет 26: там появляется живое дерево вызовов, и по нему
// дорезается чужой кодировщик, оставшийся внутри `codec/` (см. VENDORED.md,
// «Что осталось на этап Б»).
#[allow(dead_code, unused_imports)]
#[forbid(unsafe_code)]
pub(crate) mod rars;
