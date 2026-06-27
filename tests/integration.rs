//! Single integration-test binary for `newtua-core`.
//!
//! Each former `tests/<name>.rs` file now lives in `tests/integration/` and is
//! pulled in as a module below. Cargo compiles one binary instead of ~23, so a
//! change to the crate relinks once rather than per file. Module scoping also
//! isolates each file's helpers (`fixture()`, etc.), so no name clashes.
//!
//! `#[path]` is required: this file is the test crate's root, whose submodules
//! would otherwise resolve in `tests/` (where Cargo would auto-compile each as
//! its own binary — exactly what we are avoiding). The subdirectory is not
//! auto-discovered, so the files there compile only via these declarations.
//!
//! Fixtures are referenced via `env!("CARGO_MANIFEST_DIR")` or `include_bytes!`
//! with `../fixtures/` (relative to the `integration/` subdir).

#[path = "integration/ar_handler.rs"]
mod ar_handler;
#[path = "integration/brotli.rs"]
mod brotli;
#[path = "integration/bundles.rs"]
mod bundles;
#[path = "integration/cab_handler.rs"]
mod cab_handler;
#[path = "integration/cpio_handler.rs"]
mod cpio_handler;
#[path = "integration/deb_handler.rs"]
mod deb_handler;
#[path = "integration/detect.rs"]
mod detect;
#[path = "integration/extract.rs"]
mod extract;
#[path = "integration/iso_handler.rs"]
mod iso_handler;
#[path = "integration/lz4.rs"]
mod lz4;
#[path = "integration/lzc.rs"]
mod lzc;
#[path = "integration/macos_skip.rs"]
mod macos_skip;
#[path = "integration/msi_handler.rs"]
mod msi_handler;
#[path = "integration/progress.rs"]
mod progress;
#[path = "integration/rar_handler.rs"]
mod rar_handler;
#[path = "integration/rpm_handler.rs"]
mod rpm_handler;
#[path = "integration/selection.rs"]
mod selection;
#[path = "integration/sevenz_handler.rs"]
mod sevenz_handler;
#[path = "integration/sfx_handler.rs"]
mod sfx_handler;
#[path = "integration/source.rs"]
mod source;
#[path = "integration/tar_handler.rs"]
mod tar_handler;
#[path = "integration/volume_open.rs"]
mod volume_open;
#[path = "integration/warc_handler.rs"]
mod warc_handler;
#[path = "integration/xar_handler.rs"]
mod xar_handler;
#[path = "integration/zip_handler.rs"]
mod zip_handler;
#[path = "integration/zipx_handler.rs"]
mod zipx_handler;
