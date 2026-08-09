//! Vendored third-party readers.
//!
//! A crate lands here instead of in `Cargo.toml` for one of two reasons, and
//! both are on the shelf today:
//!
//! - **The code exists upstream but in no release**, and a git dependency is
//!   not an option — crates.io refuses one, and `newtua-core` is published
//!   there. That is `cab`.
//! - **We carry changes of our own and do not intend to follow upstream**,
//!   whose releases come weekly. That is `rars`.
//!
//! Either way vendoring keeps the code in hand without adding a forced fork to
//! maintain and publish (see `CLAUDE.md`, "Vendor and forks").
//!
//! Each module carries its upstream licence beside it and a `VENDORED.md` that
//! records the release it came from, what was cut, and every deliberate change.

pub(crate) mod cab;
// Пока `RarHandler` не переключён на этот код (тикет 26), в модуль не ведёт ни
// один вызов, и мёртвым для компилятора выглядит всё — включая чтение. Оба
// разрешения снимает тикет 26: там появляется живое дерево вызовов, и по нему
// дорезается чужой кодировщик, оставшийся внутри `codec/` (см. VENDORED.md,
// «Что осталось на этап Б»).
#[allow(dead_code, unused_imports)]
pub(crate) mod rars;
