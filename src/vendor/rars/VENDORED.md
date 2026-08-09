# Vendored: the read half of `rars`

**Upstream:** <https://github.com/bitplane/rars> — © Gareth Davidson
(`bitplane`). Licence: see "Licence" below — the crate declares one thing and
ships another, and that is worth reading before reusing this code.
**Taken from:** release **0.4.8** (2026-08-03), plus five performance commits of
ours listed below.
**Vendored:** 2026-08-09.

## Why it is here and not in `Cargo.toml`

RAR used to be read through `libunrar` — a megabyte and a half of someone
else's C++, compiled on every build, behind twelve `unsafe` FFI call sites and
a licence that fits nothing else we ship. It also cost us a published forced
fork, `newtua-unrar`, and it kept three fields locked away that the format
stores and we could not reach (exact RAR 5 time, symlink target, BLAKE2sp).

`rars` closes all of that at once: pure Rust, `unsafe_code = "forbid"` upstream
and `#[forbid(unsafe_code)]` on our module declaration, MIT/Apache-2.0, and
coverage wider than ours — from `RE~^` (RAR 1.3) to RAR 7.

Vendoring rather than depending, for two reasons. We carry our own changes, and
we do not intend to follow upstream releases — there is one about every week.
This is the second module here after `src/vendor/cab/`; the rule it follows is
in `CLAUDE.md` and in the `minimal-fork` skill.

**There is no return path, and saying so is kinder than pretending.** More than
ten thousand lines of the package are gone (below), so this is no longer the
same crate; a pull request from here would not apply. We opened one PR upstream
(`bitplane/rars` #30, the `copy_match` change) and told the author the rest is
his to take from our tree if he wants it. We track nothing.

## What was cut

The engine reads and lists; it never writes an archive and never promises to
repair one. Roughly ten thousand lines went before anything else was touched:

- **`rar50/write/` (5019 lines)** and **`rar15_40/write.rs` (2412)** — the
  writers, plus their filter policy and volume splitter.
- **`recovery/` (1889)** — repair from recovery records. Not something we offer,
  and it is the only user of the RAR 3 / RAR 5 recovery error variants, which
  went with it.
- **`write_progress.rs` (187)** — progress reporting for writing.
- **`x86_filter_scan.rs` (314)** — speeds up *compression*, not decoding.
- **`parallel.rs` and every `#[cfg(feature = "parallel")]` block** — `rayon`
  parallelism *across members*. The engine has its own orchestration and its own
  entry order (see `read_entries` in `CLAUDE.md`); a second scheduler underneath
  it would fight it.
- **`src/fast.rs`** — a duplicate of the x86 scan used only by the writer path.
- **The writing halves inside shared files** — `rar13.rs` lost its writer block
  (705 lines) and the facade lost `repair_recovery*` and the parallel wrappers.
- **`rars-cli` and `rars-python`** — we need a library, not someone's program.
  With the CLI goes the test upstream cannot keep green either
  (`rejects_output_path_that_is_existing_symlink`, `cli.rs:514`), which fails on
  a clean checkout and leaves state behind between runs.
- **The nightly SIMD paths.** `codec/fast.rs` had a vectorised branch under
  `feature = "fast"` requiring `portable_simd`; we build on stable, so only the
  scalar branch is left and the `cfg` scaffolding around it went with it.

## What was changed

- **Five performance commits of ours, all measured**, from the `speed-work`
  branch. They took RAR 5 decoding from ×2.82 of `libunrar` to **×2.07** by
  wall clock; by CPU time the gap is **×1.10**, the rest being libunrar's
  multi-threaded decode. Against `unar` — the threshold that binds us — this
  code is about a quarter *faster*. In upstream order:
  1. `copy_match` copies runs, not one byte at a time (this one is PR #30);
  2. CRC-32 through `crc32fast` — the hand-rolled slice-by-8 ran at ~1.8 GB/s
     and ate a fifth of decode time; hardware CRC does ~4.5 GB/s here. A
     dependency is the only route: the intrinsic needs `unsafe`, which this code
     forbids;
  3. Huffman symbols decoded with one wide peek and a 10-bit quick table,
     replacing a bit-at-a-time reader (up to 15 calls per symbol);
  4. decode into a position-tracked buffer, matches copied in chunks;
  5. availability checks skipped while four whole bytes remain ahead.

  Numbers, method and the four A/B failures that were rolled back and must not
  be retried: `.claude/perf/RARS-REPORT-2026-08-08.md`.

  **Where they are, so "what here is ours" has an answer inside the package.**
  All five sit in `codec/rar50.rs` except the CRC one: (1) and (4) are
  `Unpack50Decoder::copy_match` and the position-tracked output buffer around
  it; (3) is `HuffmanTable::decode` plus the wide `read_bits`; (5) is the fast
  path in the bit reader that skips availability checks. (2) is `crc32/mod.rs`,
  now a thin call into `crc32fast`. The `#[allow(clippy::…)]` on `copy_match`
  and the scalar-only `codec/fast.rs` are ours too.
- **Module paths are `crate::vendor::rars::` instead of `crate::`**, and the
  crate root became `mod.rs`. Noise in a diff against upstream; unavoidable.
- **Edition 2024, not 2021.** One pattern needed adjusting for the stricter
  match ergonomics (`codec/huffman.rs`, `assign_flat_complete_code`).
- **`dead_code`/`unused_imports` are allowed on the module declaration** until
  ticket 26 switches `RarHandler` over. Both come off with that ticket.

## Tests

**Every unit test inside `src/` came along** — codecs, crypto, headers, CRC,
BLAKE2sp, detection — and they run in our suite. What was dropped:

- **Tests that needed the writer to build their fixture.** 206 functions, cut
  mechanically: a test whose archive is produced by the code under test can only
  ever prove that code agrees with itself (`oracle-independence`). Ours are
  judged by `unar` and by the reference corpus instead.
- **One test that read an archive from disk** (`tests/fixtures/rar15_40/` in the
  upstream checkout) — it was the only unit test needing a file, and it asserted
  on the recovery-record flag we no longer act on.
- **The crate's own integration tests** — 337 of them, over 5.3 MB of archive
  fixtures. Not portable here: half of them exercise writing and repair, and the
  other half address the crate through a public API this module deliberately
  does not have (it is `pub(crate)`). Reading is guarded instead by the layer
  that judges us against something other than ourselves: our own RAR tests, the
  141-row reference corpus, and byte-for-byte comparison with `unar` — see
  ticket 27.

## What is still here and should not be — the encoder inside `codec/`

The writers went as whole files. **The compression side inside `codec/` did
not**: `rar13.rs`, `rar20.rs`, `rar29.rs`, `rar50.rs` and `ppmd.rs` each hold a
decoder and an encoder in one file, sharing tables and state. Roughly ten
thousand lines of that are unreachable from reading and are carried dead, under
`#[allow(dead_code)]` on the module declaration in `src/vendor/mod.rs`.

**Why it was not cut now, and this is a decision rather than an oversight.**
The reliable judge is the compiler: whatever the handler cannot reach is dead.
But the handler is not switched over until ticket 26, so at this point nothing
reaches into this module at all and *everything* reads as dead — the compiler
cannot tell the encoder from our own reading. The alternative, cutting by
function names and brace counting, was tried and failed three times: brace
counting does not know a `{` inside a string literal, and it took out the
codecs' whole `Error` type and a live `impl Read` before it was noticed. On
someone else's decoder that is how a defect gets planted that no test names.

**So it moves to ticket 26**, where a real call graph exists, and where the
guards that would catch a bad cut — the 141-row corpus and byte-for-byte
comparison against `unar` — are running anyway.

The cost of waiting is small and measured: the published package is 456 KiB
compressed (1.9 MiB unpacked) against a 10 MiB limit, and dead code is
unreachable from any input, so it widens no attack surface.

## Licence

**The crate says one thing and ships another, and the discrepancy is upstream's,
not ours.** `Cargo.toml` of 0.4.8 declares `MIT OR Apache-2.0`; the only licence
file in the repository is `COPYING`, which is WTFPL plus "don't blame me". No
MIT or Apache text is shipped at all.

Both readings permit what we do here, so nothing is blocked — but the text that
actually travelled with the code has to travel with it, and it is beside this
file as `COPYING`. Our `NOTICE` names the crate, the author, and this same
discrepancy, so a reader downstream is not left to discover it themselves.

## Comparing against upstream

```bash
# The release this came from, plus our five commits.
git clone https://github.com/bitplane/rars /tmp/rars && cd /tmp/rars
git checkout v0.4.8            # or the 0.4.8 tarball from crates.io
diff -r /tmp/rars/crates/rars/src src/vendor/rars
```

Expect the diff to be large in shape and small in substance: the cuts above,
the `crate::` → `crate::vendor::rars::` rewrite, and our five commits.

**What the resemblance is still for.** One thing only: finding where an upstream
*fix* would land. That needs the **layout** — same files, same function names,
same boundaries — and nothing more. It is not a reason to keep an implementation
we would otherwise improve, and improving a body costs a future patch nothing
while moving or renaming things costs everything.
