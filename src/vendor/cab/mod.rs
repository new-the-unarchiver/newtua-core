//! Reading [Windows cabinet](https://en.wikipedia.org/wiki/Cabinet_(file_format))
//! (CAB) files.
//!
//! **Vendored, and why.** This is the read half of the `cab` crate
//! (<https://github.com/mdsteele/rust-cab>, © Matthew D. Steele, MIT — see
//! `LICENSE-MIT` beside this file), taken from release 0.6.0 and reworked.
//! `VENDORED.md` records what was cut, what was changed, and how to compare
//! against upstream.
//!
//! The rework exists for one reason: a CAB *folder* is a solid stream, and the
//! released crate resolves a file by name, building a fresh folder decoder and
//! seeking from the start of the folder every time. Asking for the five
//! hundredth file therefore decompresses the first four hundred and ninety
//! nine again, and the cost of an extraction grows with the square of the file
//! count — the same shape [`crate::archive::ArchiveReader::read_entries`]
//! exists to break. Reaching the one-pass walk needed `FolderReader`, which is
//! private upstream and stays crate-private here.
//!
//! **This half never writes.** `builder.rs` and the compressor side of MSZIP
//! are gone: the engine extracts and lists, and nothing in it creates an
//! archive. Upstream `cab` is still a dev-dependency, and that is deliberate —
//! the CAB fixtures in `tests/` are built by *its* writer, so the thing that
//! produces the test data is not the thing under test.
//!
//! | Compression                | Read              |
//! |----------------------------|-------------------|
//! | Uncompressed               | Yes               |
//! | MSZIP ([Deflate][deflate]) | Yes               |
//! | [Quantum][quantum]         | No                |
//! | [LZX][lzx]                 | Yes               |
//!
//! [deflate]: https://en.wikipedia.org/wiki/DEFLATE
//! [quantum]: https://en.wikipedia.org/wiki/Quantum_compression
//! [lzx]: https://en.wikipedia.org/wiki/LZX_(algorithm)

pub use cabinet::Cabinet;
pub use ctype::CompressionType;
pub use folder::FolderReader;

#[macro_use]
mod macros;

mod cabinet;
mod checksum;
mod consts;
mod ctype;
mod file;
mod folder;
mod mszip;
mod string;
