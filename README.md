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

## Entry names and their encoding

An archive is not obliged to store names in UTF-8, and older ones rarely do.
Every `Entry` therefore carries both forms: `path_raw` holds the bytes exactly
as the archive stores them, and `path` holds the decoded, normalized path.
Base your path-safety checks on `path_raw` — decoding can distort a name.

The engine decides on one encoding for the whole archive rather than guessing
per name: it feeds every raw name to the detector at once, so a short name that
would be ambiguous on its own is resolved by the rest of the set. Names that are
all valid UTF-8 take that path directly.

`detect_encoding` reports the label that decoding would settle on, which is
what a front-end needs to show the user which encoding was assumed:

```rust
use newtua_core::{OpenOptions, detect_encoding, open};
use std::path::Path;

let mut reader = open(Path::new("old.zip"), &OpenOptions::default())?;
let raw: Vec<Vec<u8>> = reader.entries()?.iter().map(|e| e.path_raw.clone()).collect();

println!("{}", detect_encoding(&raw, None));   // e.g. "windows-1251"
```

To override the guess, set `OpenOptions::encoding_override` — the same label
then also comes back from `detect_encoding(&raw, Some(label))`. An unknown
label is ignored and detection proceeds as usual.

`decode_names` is the decoding itself: it takes the same set of raw names and
returns the decoded strings, using exactly the encoding `detect_encoding`
reports.

## Supported formats

Every variant below is a `FormatId` from [`src/archive.rs`](src/archive.rs).

### What "supported" means here

The word carries three different strengths in the three tables, and it is worth
saying which is which rather than letting one table borrow the other's
credibility.

**Modern formats are proven.** Each has at least one reference archive that we
extract and compare byte-for-byte against a source that is not this crate:
either the payload the archive was built from by a real packer, or a foreign
reader — `unar`, `7zz`, `unsquashfs`, `msiinfo`, `zipfile`. The reference set is
118 archives and it runs before a release, not once.

**Zip-based containers inherit that**, since they are the same engine with a
different `FormatId`.

**Legacy formats are held to XADMaster and to nothing more.** They open and
list, and where a sample exists we extract it — but their content is not
independently proven, because for most of these formats no second implementation
exists to prove it against. Treat them as "what The Unarchiver does", not as a
byte guarantee.

Four gaps we know of, all of them shared with XADMaster, so closing them would
be new work rather than a repair: a `.xar` whose members are LZMA-coded, a
StuffItX archive, a Mach-O self-extracting `.exe`, and a `.dmg` using the old
ADC compression. `unar` fails every one of them too.

One gap that is ours alone: the three compression methods PKZIP used before
Deflate — Shrink, Reduce and Implode. We open and list such an archive and then
refuse its members with a clean `Unsupported`; we never mis-read them. Other
readers do decompress them, so this is a missing capability rather than a
defect, and it is deliberately deferred: these archives are from 1989–1990.

**XADMaster is the floor, not the ceiling.** Two places where we already read
what it cannot: a zip member compressed with zstd — `unar` exits non-zero and
leaves a zero-length file, while our output is confirmed by `7zz` — and
AppImage, which it does not recognise at all.

### Modern

| Format | Notes |
| --- | --- |
| `Zip` | `.zip`, incl. ZipCrypto/AES encryption, LZMA/Deflate64/zstd/PPMd members, and `zip -s` split archives (`.z01`…) |
| `Tar` | `.tar`, bare or inside any supported compressor (`.tar.gz`, `.tar.xz`, `.tar.sz`, `.tar.lz`, `.tar.lzma`, …) |
| `Gzip` | `.gz` (single compressed file, no container) |
| `Bzip2` | `.bz2` (single compressed file, no container) |
| `Xz` | `.xz` (single compressed file, no container) |
| `Raw` | any other single decompressed stream (e.g. `.zst`, `.lz4`, `.Z`, `.br`, `.sz`, `.lzma`, `.lz`) |
| `SevenZ` | `.7z`, incl. AES-256 encryption |
| `Rar` | `.rar`, single- and multi-volume |
| `Cab` | `.cab` |
| `Ar` | `.ar`/`.a` |
| `Deb` | `.deb` (Debian package, ar + tar members) |
| `Cpio` | `.cpio` and `.cpgz` (cpio inside a compressor); the newc, crc and odc variants |
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
| `Apfs` | Apple File System, bare container or embedded in a DMG, incl. `decmpfs` |
| `Wpress` | `.wpress` (WordPress site dump: All-in-One WP Migration) |

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
| `War` | Java web application archive (`.war`) |
| `Appx` | Windows app package (`.appx`) |
| `Xpi` | Mozilla browser extension (`.xpi`) |
| `Crx` | Chrome extension (`.crx`, `Cr24` header + embedded zip) |
| `Conda` | Conda package (`.conda`, zip of `*.tar.zst` members) |

### Legacy

Ports from XADMaster, backed by the `newtua-formats` crate family. These are the
rows the paragraph above applies to: they match XADMaster, without a byte-level
promise of their own.

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

The engine depends on four **forced forks** — `newtua-unrar`,
`newtua-apfs`, `newtua-hfsplus` and `newtua-cdfs`. We do not develop them and
will drop them as soon as the upstream crates meet our requirements. Each
fork's README explains why it exists.

None of them requires a system library. That is largely the point of
`newtua-cdfs`: upstream `cdfs` would otherwise make every Linux build depend on
`libfuse3`, for a mounting feature this engine never uses.

## Tests

The package published to crates.io carries the library only — no `tests/`
directory. The suite is driven by real archives: 11 MB of binary fixtures that
the test files embed at compile time with `include_bytes!`. Shipping them would
blow past the 10 MiB package limit, and shipping the tests without them would
hand you a suite that cannot compile at all.

Nothing is hidden. All 750 tests and every fixture live in the
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
