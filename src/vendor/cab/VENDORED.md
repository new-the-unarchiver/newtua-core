# Vendored: the read half of `cab`

**Upstream:** <https://github.com/mdsteele/rust-cab> — © Matthew D. Steele,
MIT (`LICENSE-MIT`, beside this file).
**Taken from:** release **0.6.0** (the crate as published on crates.io).
**Vendored:** 2026-08-07.

## Why it is here and not in `Cargo.toml`

A CAB *folder* is one solid compressed stream holding many files. The released
crate exposes only `Cabinet::read_file(name)`, and that call builds a fresh
folder decoder and seeks from the folder's start every time — so extracting a
folder of N files decoded it N times over. Measured before the change: **×8.9
the time `7zz` takes on a thousand files, and ×3.4 for every doubling** of the
file count, where a healthy curve is ×2. A real Windows installer holds tens of
thousands of entries, and that curve turns minutes into an afternoon.

The fix needed `FolderReader`, which upstream keeps private. Upstream *has*
written a one-pass walk — `Cabinet::all_files()`, committed 2025-07-14 — but it
is on `master` and in no release. A git dependency was not an option:
`newtua-core` is published to crates.io, and crates.io refuses a crate that has
one. That left three ways out — ask upstream for a release and wait, publish a
fifth forced fork, or carry the code here. Carrying it publishes nothing, adds
no fork to maintain, and does not block the release. See `.claude/issues/18`.

**Not a licence workaround.** MIT permits this; the notice travels with the code
and is repeated in the repository's `NOTICE`.

## What was cut

Everything that writes, and everything nothing here reads:

- **`builder.rs` (686 lines)** — `CabinetBuilder`/`CabinetWriter` and friends.
  The engine extracts and lists; it never creates an archive.
- **`MsZipCompressor`** and `CompressionType::to_bitfield`, for the same reason.
- **`FileReader`** and `Cabinet::read_file`/`get_file_entry` — the name-based
  path they served is gone (see below).
- **`datetime.rs`** — timestamps now leave as the raw MS-DOS words. That took
  the `time` crate out of this module; the conversion lives in
  `format/cab.rs`, which reads them by the same rule as zip. Upstream returned
  a `time::PrimitiveDateTime` — a civil date with no zone attached — and left
  the caller to decide what it meant; the caller decided "UTC", which put every
  date in every cabinet a whole timezone away from what the packer saw.
  Measured against `unar` in `.claude/issues/18`.
- `FileEntry`'s DOS attribute accessors, `FolderEntry::num_data_blocks` and the
  reserve-data accessors, `Cabinet::cabinet_set_id`/`_index`/`reserve_data`,
  and the flat copy of the file list `Cabinet` kept alongside the per-folder
  one. All unread. Reserve areas are still **`read_exact`**-ed past, never
  skipped: a header that ends early has to stay an error.
- Upstream's MSZIP round-trip tests, which compressed with its own encoder and
  decoded the result — they could only ever prove the code agrees with itself.
  The one test kept, `read_compressed_data`, is a fixed block of real MSZIP
  bytes. The `cabinet.rs` tests are hand-built binaries from the CAB spec and
  are all kept, rewritten against the new API.

## What was changed

- **`Cabinet::open_folder(index)`** replaces the private `read_folder`, and
  takes `&self` rather than `&mut self` — the file handle already lives behind
  a `RefCell`, and `&mut` would have stopped a caller holding a folder reader
  while reading its own entry list. `FolderReader` is public within this crate.
- **Files are addressed by position, never by name.** Two files in different
  folders may legally share a name; `read_file(name)` resolved both to whichever
  came first, so one was extracted twice and the other never appeared. The
  regression test is `the_same_name_in_two_folders_stays_two_entries` in
  `tests/integration/cab_handler.rs` — it fails against the pre-vendoring code.
- **A decoder's refusal is `InvalidData`, not `Other`** (`ctype.rs`). A deflate
  or LZX stream that will not decode means the cabinet is damaged, and that kind
  is the only thing `format/cab.rs` reads to tell `Error::Corrupt` from
  `Error::Io`. Reported as `Other`, a shredded archive reached the person as an
  I/O failure — as if their disk were at fault.
- **One copy per data block removed**: upstream wrote
  `decompress_block(..)?.to_vec()`, and `decompress_block` already returns a
  `Vec<u8>`, so `.to_vec()` copied every decoded block a second time.
- **Names leave as bytes, not as a `String`.** `FileEntry::name()` returns
  `&[u8]` and `name_is_utf8()` reports the bit upstream parsed and then ignored
  (its own TODO). Upstream ran every name through `String::from_utf8_lossy`,
  which turns each byte it does not recognise into U+FFFD and cannot be undone:
  a cabinet packed under a Windows code page came out as a row of replacement
  characters. `format/cab.rs` now feeds the raw bytes to
  `encoding::decode_names`, which picks one encoding for the whole archive, as
  every other handler does.
- Formatting is this repository's `rustfmt`, and the module paths are `super::`
  instead of `crate::`. Both are noise in a diff against upstream; see below.

## Comparing against upstream

```bash
# The release this came from.
cargo download cab==0.6.0        # or: unpack ~/.cargo/registry/src/*/cab-0.6.0
diff -r <that>/src src/vendor/cab

# What upstream has done since.
curl -sL -o cab-master.tar.gz \
  https://github.com/mdsteele/rust-cab/archive/refs/heads/master.tar.gz
```

Expect the diff to be large in shape and small in substance: the cuts above,
plus reformatting.

**Going back to the registry is not the plan, and saying so is kinder than
pretending.** Upstream has no Quantum decoder at all, so returning would cost a
compression method outright; and its unreleased `next_file()` hands out *all*
files of a folder with no way to select a subset, and swallows a folder that
fails to open (`FolderReader::new(..).ok()?`) as "no more files" — an extraction
truncated and reported as success. `newtua-hfsplus` went the same way and its
README says so rather than keeping up appearances.

**So what is the resemblance still for?** One thing: picking up an upstream
*fix*. If a header-parsing bug is fixed there, we want to find the same place
here. That needs the **layout** preserved — same files, same function names,
same boundaries between them — and nothing more. It is not a reason to keep an
implementation we would otherwise improve: a rewritten function body costs
nothing to a future patch, while moving or renaming things costs everything.

Judged that way, `mszip.rs`'s per-block allocations stay as they are on the
evidence, not on principle: an 88 MB single-file cabinet (2691 blocks) extracts
at **447 MB/s here against 333 MB/s for `cabextract`**, which is libmspack —
the implementation whose own `TODO` complains about those very allocations.
There is nothing to win there.

## Quantum

**Decoded, unlike upstream** — `quantum.rs`, ported from XADMaster rather than
from this crate's lineage, since upstream `cab` has no Quantum decoder at all
and no Rust implementation exists anywhere. It plugs into `Decompressor` beside
MSZIP and LZX; see the module's own documentation for the format and for what
is bounded. Its bit reader and sliding window are `newtua-common`'s, not its
own: that crate's `LzssWindow` is a port of the same XADMaster `LZSS.c` the
donor calls, so borrowing it moves the port closer to its source rather than
further from it.

The reader now covers every compression a cabinet can declare.
