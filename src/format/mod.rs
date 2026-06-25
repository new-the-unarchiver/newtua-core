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

// XAR and MSI are gated off by default (see crates/newtua-core/Cargo.toml
// [features]); each is excluded from the shipped build pending its own
// follow-up phase. The source is kept compiling under the feature flag.
#[cfg(feature = "xar")]
pub mod xar;
#[cfg(feature = "xar")]
pub use xar::XarHandler;

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
