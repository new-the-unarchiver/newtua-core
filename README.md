# newtua-core

`newtua-core` is the extraction engine behind **New The Unarchiver**
(`newtua`) — it lists and extracts archives across more than 50 formats
entirely in-process, with no subprocess fallbacks, and it never creates
archives.

## Install

```bash
cargo add newtua-core
```

## Example

```rust
use newtua_core::{OpenOptions, open};
use std::fs::File;
use std::path::Path;

fn main() -> newtua_core::Result<()> {
    let mut reader = open(Path::new("archive.zip"), &OpenOptions::default())?;
    for entry in reader.entries()? {
        println!("{}", entry.path.display());
    }
    let mut out = File::create("first_entry.bin")?;
    reader.read_entry(0, &mut out)?;
    Ok(())
}
```

## Supported formats

Every variant below is a `FormatId` from [`src/archive.rs`](src/archive.rs).

### Modern

| Format | Notes |
| --- | --- |
| `Zip` | `.zip`, incl. ZipCrypto/AES encryption, LZMA/Deflate64 members |
| `Tar` | `.tar` |
| `Gzip` | `.gz` (single compressed file, no container) |
| `Bzip2` | `.bz2` (single compressed file, no container) |
| `Xz` | `.xz` (single compressed file, no container) |
| `Raw` | any other single decompressed stream (e.g. `.zst`, `.lz4`, `.Z`, `.br`) |
| `SevenZ` | `.7z`, incl. AES-256 encryption |
| `Rar` | `.rar`, single- and multi-volume |
| `Cab` | `.cab` |
| `Ar` | `.ar`/`.a` |
| `Deb` | `.deb` (Debian package, ar + tar members) |
| `Cpio` | `.cpio` |
| `Rpm` | `.rpm` |
| `Xar` | `.xar`/`.pkg` |
| `Msi` | `.msi` (Windows Installer, CFB + embedded CAB) |
| `Iso` | `.iso` (ISO 9660) |
| `Sfx` | self-extracting `.exe` wrapper (reports the inner format) |
| `Warc` | `.warc`/`.warc.gz` |
| `Squashfs` | `.squashfs`/`.sfs` |
| `AppImage` | AppImage (ELF runtime + appended SquashFS or ISO 9660) |
| `Wim` | `.wim`/`.esd`/`.swm` (Windows imaging format) |
| `HfsPlus` | `.hfs`/`.hfsplus`/`.hfsx` (HFS+/HFSX volumes, incl. `decmpfs`) |
| `Dmg` | `.dmg` (Apple Disk Image / UDIF container) |
| `Apfs` | Apple File System, bare container or embedded in a DMG |

### Zip-based containers

All open through the shared zip engine; only the reported `FormatId` differs.

| Format | Notes |
| --- | --- |
| `Jar` | Java archive (`.jar`) |
| `Apk` | Android package (`.apk`) |
| `Ipa` | iOS app archive (`.ipa`) |
| `Epub` | e-book (`.epub`) |
| `Docx` | Word document (`.docx`) |
| `Xlsx` | Excel workbook (`.xlsx`) |
| `Pptx` | PowerPoint deck (`.pptx`) |
| `Odt` | OpenDocument text (`.odt`) |
| `Ods` | OpenDocument spreadsheet (`.ods`) |
| `Odp` | OpenDocument presentation (`.odp`) |
| `Crx` | Chrome extension (`.crx`, `Cr24` header + embedded zip) |
| `Conda` | Conda package (`.conda`, zip of `*.tar.zst` members) |

### Legacy

Ports from XADMaster, backed by the `newtua-formats` crate family.

| Format | Notes |
| --- | --- |
| `Arj` | ARJ (`.arj`), Robert Jung's DOS archiver |
| `Zoo` | Zoo (`.zoo`), Rahul Dhesi's cross-platform archiver |
| `Lbr` | LBR (`.lbr`), CP/M library container |
| `Crunch` | Crunch, DOS/CP-M LZW cruncher container |
| `Arc` | ARC (`.arc`/`.ark`/`.pak`/`.spark`), SEA's PC archiver |
| `Squeeze` | Squeeze (`.sq`/`.qqq`), Huffman-coded CP/M & DOS file |
| `BinHex` | BinHex 4.0 (`.hqx`), 7-bit Mac transport encoding |
| `MacBinary` | MacBinary I/II/III (`.bin`), resource-fork container |
| `AppleSingle` | AppleSingle/AppleDouble, fork-preserving encoding |
| `CompactPro` | Compact Pro (`.cpt`), early-90s Mac archiver |
| `PackIt` | PackIt (`.pit`), early Mac archiver |
| `StuffIt` | StuffIt classic (`.sit`) |
| `StuffIt5` | StuffIt 5 (`.sit`), incl. RC4/MD5 |
| `StuffItX` | StuffItX (`.sitx`), range-coded successor |
| `Alz` | ALZip (`.alz`), ESTsoft's Korean archiver |
| `Nsis` | NSIS (`.exe`), contents of a Nullsoft installer |
| `Lzx` | Amiga LZX (`.lzx`) |
| `PowerPacker` | PowerPacker (`.pp`), Amiga single-file cruncher |
| `Dms` | DMS (`.dms`), Disk Masher System floppy image |

## Dependencies

The engine depends on three **forced forks** — `newtua-unrar`,
`newtua-apfs`, `newtua-hfsplus`. We do not develop them and will drop them
as soon as the upstream crates meet our requirements. Each fork's README
explains why it exists.

## Tests

The package published to crates.io carries the library only — no `tests/`
directory. The suite is driven by real archives: 11 MB of binary fixtures that
the test files embed at compile time with `include_bytes!`. Shipping them would
blow past the 10 MiB package limit, and shipping the tests without them would
hand you a suite that cannot compile at all.

Nothing is hidden. All 572 tests and every fixture live in the
[repository on GitHub](https://github.com/new-the-unarchiver/newtua-core) and
run in CI on Linux, macOS and Windows. To run them yourself:

```bash
git clone https://github.com/new-the-unarchiver/newtua-core
cd newtua-core
cargo test
```

## License

**LGPL-3.0-or-later.** The engine links the `newtua-formats` crate family,
whose decoders are ported from XADMaster (The Unarchiver) under the LGPL, so
the engine inherits that license. In practice this means you may link
`newtua-core` from a program under any license, including a proprietary one,
provided you keep the engine itself replaceable and pass on its source. See
[`LICENSE`](LICENSE), [`GPL-3.0.txt`](GPL-3.0.txt) and [`NOTICE`](NOTICE).

## Part of New The Unarchiver

`newtua-core` is one of the crates behind
**[New The Unarchiver](https://github.com/new-the-unarchiver)** (`newtua`) — a
cross-platform archive extractor written in Rust, a modern rewrite of the
macOS tool The Unarchiver. It extracts and lists archives; it never creates
them.

`newtua-core` is the engine itself: a standalone library with no CLI or UI
attached, usable on its own by anyone who wants archive extraction in a
Rust program.

See the [project map](https://github.com/new-the-unarchiver) for what to take
for what you need.
