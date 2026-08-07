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
