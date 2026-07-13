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

pub mod bundle;
pub use bundle::ZipBundleHandler;

pub mod crx;
pub use crx::CrxHandler;

pub mod conda;
pub use conda::CondaHandler;

pub mod sevenz;
pub use sevenz::SevenZHandler;

pub mod rar;
pub use rar::RarHandler;

// XAR (.xar/.pkg): in-house decode-only reader, always built.
pub mod xar;
pub use xar::XarHandler;

// MSI (.msi): CFB + embedded CAB, with File/Component/Directory path resolution.
pub mod msi;
pub use msi::MsiHandler;

pub mod iso;
pub use iso::IsoHandler;

pub mod sfx;
pub use sfx::SfxHandler;

pub mod warc;
pub use warc::WarcHandler;

pub mod squashfs;
pub use squashfs::SquashfsHandler;

pub mod appimage;
pub use appimage::AppImageHandler;

pub mod wim;
pub use wim::WimHandler;

pub mod hfsplus;
pub use hfsplus::HfsPlusHandler;

pub mod dmg;
pub use dmg::DmgHandler;
