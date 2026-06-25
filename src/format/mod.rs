pub mod ar;
pub use ar::ArHandler;

pub mod rpm;
pub use rpm::RpmHandler;

pub mod cpio;
pub use cpio::CpioHandler;

pub mod deb;
pub use deb::DebHandler;

pub mod cab;
pub use cab::CabHandler;

pub mod tar;
pub use tar::TarHandler;

pub mod zip;
pub use zip::ZipHandler;

pub mod sevenz;
pub use sevenz::SevenZHandler;

pub mod rar;
pub use rar::RarHandler;

// XAR (.xar/.pkg): in-house decode-only reader, always built.
pub mod xar;
pub use xar::XarHandler;

// MSI is gated off by default (see crates/newtua-core/Cargo.toml [features]):
// the model-B handler emits raw CAB-member keys, not resolved install paths.
// Excluded from the shipped build pending its follow-up phase (Д2).
#[cfg(feature = "msi")]
pub mod msi;
#[cfg(feature = "msi")]
pub use msi::MsiHandler;

pub mod iso;
pub use iso::IsoHandler;

pub mod sfx;
pub use sfx::SfxHandler;

pub mod warc;
pub use warc::WarcHandler;
