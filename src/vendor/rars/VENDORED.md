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

**Wired to `RarHandler` on 2026-08-10** (ticket 26). Before that the module
compiled but nothing called it; now it is the only way this engine reads RAR,
and `newtua-unrar` is out of `Cargo.toml`.

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

### Three fixes of ours, made when the handler was wired (ticket 26)

Each is marked `NEWTUA:` in the source, so `grep -rn NEWTUA src/vendor/rars`
answers "what here is not upstream's" without reading this file.

1. **`rar50.rs` — the `FHEXTRA_HTIME` record is parsed.** Upstream reads the
   modification time only from the `FHFL_MTIME` field of the file header.
   Modern `rar` (checked on 7.22) does not set that flag at all and stores the
   time only in the extra record, as a Windows `FILETIME`. Without this,
   **every RAR 5 archive made in recent years lists with no timestamps at
   all** — which is how the gap was found: an existing test went from a date
   to `None`. We read the modification time out of it (whole seconds, Unix
   epoch); creation and access times sit in the same record and wait for
   ticket 15.
2. **`rar15_40.rs` — `FileHeader::write_to` handles a stored member.** It went
   straight to picking a codec by `unp_ver`, which for an uncompressed member
   is the same value as for a compressed one, so a `-m0` entry was "unpacked"
   as if it were packed. Upstream never noticed because its own whole-archive
   walk makes that branch itself and never calls `write_to`; our fast path for
   non-solid archives does call it.
3. **Two decryption tests rewritten to decrypt** (`crypto/rar13.rs`,
   `crypto/rar20.rs`). They used to encrypt a phrase, compare against a pinned
   byte string and decrypt it back. The encryptor left with the writer; the
   pinned bytes stayed, and the test now only decrypts them — which is a
   better test than it was, since the input is no longer produced by the code
   under test.

### Four fixes of ours about memory (ticket 29, stage Г of the roadmap)

Extracting a member used to cost as much memory as the member is large: a 4 GB
film inside an archive needed 4 GB of RAM. These four are what changed that, and
each is marked `NEWTUA:` in the source.

1. **The walk hands out a writer with a lifetime** (`rar13.rs`,
   `rar15_40/extract.rs`, `rar50/extract.rs` — six signatures). Upstream's
   `Box<dyn Write>` means `'static`, so a caller whose sink is borrowed could
   not hand one over and had to collect the whole member in a `Vec` first. This
   is what unblocked our own side (`format/rar.rs`, `Walker`/`BodyWriter`).
   Measured on a solid archive holding one 700 MB file: **peak memory 863 → 114
   MB**, the body arriving in 11 201 pieces of 64 KiB instead of one piece of
   734 003 200 bytes. The 114 MB is the archive's dictionary, so it stays the
   same for a file of any size.
2. **`rar50/extract.rs` — the packed body is no longer read into memory whole.**
   Upstream called `read_to_end` and so kept the *packed* member alongside the
   unpacked one. The decoder reads a stream perfectly well; the buffered path
   now feeds it one (`decode_packed_reader_with_decoder_mode`), and the
   slice-taking twin delegates to it through a `Cursor` — which is exactly what
   upstream's own decoder does one level down, so there is one decode tail here,
   not two. A stored member still takes the old route: its length and padding
   checks need the whole payload, and it has its own streaming path anyway
   (`write_stored_to`).
3. **`codec/rar50.rs` — the dictionary window only takes its own tail, and
   takes it as a tail.** Upstream first cloned the *whole* unfiltered output,
   then appended all of it to the history, and only then trimmed the history to
   the dictionary size — two spare copies of the member at the peak, so a 300 MB
   file with a 32 MiB dictionary grew twice to 300 MB for nothing. Measured on a
   196 MB executable inside a solid archive — the case where filters actually
   fire: **peak 502 → 272 MB**. What ends up in the window is unchanged: a
   filtered member still contributes its unfiltered bytes, and `apply_filters`
   cannot change the length, so the tail before filters is the tail after.
   `Unpack50Decoder::decode_member_with_dictionary` lost its last caller as part
   of fix 2 and carries an `allow(dead_code)` with the reason on it; the method
   itself is untouched.
4. **`source.rs` — the file reader is buffered.** Upstream handed out a bare
   descriptor, which was tolerable while the packed body arrived in one
   `read_to_end`. Fix 2 made it a stream, and RAR 5 block parsing reads two and
   three bytes at a time — without a buffer that is a system call per header
   field.

Fixes 2 and 3 together: **peak 751 → 414 MB** on a 300 MB member.

**Closed by ticket 34** (below): the streaming path applies filters now, the
threshold is 1 MiB instead of 512 MiB, and a member's peak no longer depends on
its size — 300 MB member, **347 → 79 MB**.

### Six fixes of ours about speed (ticket 30, stage Е of the roadmap)

A solid archive of many small files — the commonest shape there is — used to
grow **quadratically in the number of members**: ×1.45 of libunrar at 250
entries, ×3.60 at 2000, **×14.55 at 8000**, where libunrar is linear. It is now
linear and **twice as fast as libunrar** across the whole range: ×0.43…×0.49 at
250…8000 entries, doubling ratio ≈×2. On 8000 entries that is **1.73 s →
0.062 s**, measured in memory, interleaved, medians of paired runs.

The per-step ratios below come from lighter runs taken while the work was going
on (`ROUNDS=3 INNER=5`) and are there to say which step bought what; the figures
in the paragraph above are the careful run at the end (`ROUNDS=5 INNER=9`).
Each fix is marked `NEWTUA:` in the source.

1. **`codec/rar50.rs`, `rar50/extract.rs` — a checkpoint instead of a copy of
   the decoder.** Upstream took `self.decoder.clone()` before every member, as
   the point to roll back to if integrity does not check out with filters
   applied. The decoder carries the dictionary window inside it, so on 8000
   entries with a 16 MiB window that clone is on the order of 50 GB of memory
   traffic — and in the profile 84 % of the time was `memmove`. The rollback is
   needed almost never and was paid for always.
   `Unpack50Checkpoint` stores what actually changes: the window's *length* plus
   `reps`, `last_length` and the tables. The window between checkpoint and
   rollback is **append-only**, so the old state is its first `history_len`
   bytes. The one exception is trimming from the front, and that path saves what
   it drops (`drop_history_front`), so the whole window is always
   `discarded ++ history`. **Counted, not assumed:** on solid archives of 250…
   8000 small files the trim never fires once — the whole output is smaller than
   the dictionary — and on a 400 MB solid archive it fired twice, for 5 bytes.
   Alone this took ×14.55 down to **×1.42** and left the doubling ratio at ×2
   across the range.
2. **`source.rs` — the open file survives the member.** Upstream called
   `File::open` per member; with the window copy gone, `__open`/`__lseek`/
   `close` were about two thirds of the profile. `FileSource` keeps one
   descriptor and hands it out through `PooledFile`, which returns it on `Drop`.
   Not "always one file": a member split across volumes assembles several
   readers at once (`fragment_reader`), so it is a rack with one slot — taken
   means open another, freed means put it back. **×1.42 → ×0.50.**
3. **`source.rs` — the read buffer is no larger than the range.** A member of a
   solid archive of small files is a couple of hundred bytes, and a 64 KiB
   buffer was allocated for each. **×0.50 → ×0.46.**
4. **`codec/rar50.rs` — the streaming window is trimmed in one piece.**
   `StreamingOutput::flush` dropped bytes one at a time (`pop_front`), and
   `flush` runs once per 64 KiB: after the window fills, that is 65 536 calls
   each time. The streaming path was **×1.49** of the buffered one by CPU time;
   this alone brought it to **×1.12**.
5. **`codec/rar50.rs` — the streaming path copies matches in blocks.** It called
   `byte_at_distance` and `push` per byte — 44 % of its profile — while the
   buffered path copies runs. A `VecDeque` is a ring already, so `as_slices`
   gives the history in at most two contiguous pieces, and the part that lies in
   `pending` is copied with `extend_from_within`, overlap and all. To keep the
   offsets still under our feet, a match is never flushed through: `pending` is
   sized for the longest match beyond the flush threshold and the flush happens
   after it. **×1.12 → ×1.04**, and the gap with the buffered path is now within
   the noise of a paired run.
6. **`codec/fast.rs` — the x86 opcode scan is vectorised, and asks by a flag.**
   The E8/E9 filter runs over every decoded block of a packed executable, the
   commonest shape of a large RAR; it was 14 % of the profile there. Upstream's
   `cmp_mask` had exactly two values and both are a ready call — `memchr` for
   `0xe8`, `memchr2` for `0xe8`/`0xe9` — so the parameter became `include_e9`,
   which has no third value. Upstream's own vectorised branch is behind
   `portable_simd` and needs a nightly build; this is how it comes back on
   stable, with the `unsafe` staying inside someone else's crate.
   **×0.92** on an archive of x86 code.

Two more, measured and small: the RAR 5 decrypting reader now decrypts 16 KiB
at a time instead of one AES block (it sits *outside* the source buffer, so that
buffer never helped it) — **×0.97** on a large encrypted member; and the "take
`Unpack50Decoder::new()` instead of the clone when the archive is not solid"
idea from the 2026-08-09 review is moot, since no clone is taken any more.

**Six new unit tests came with them**, all in `codec/rar50.rs`, guarding the two
branches nothing else reaches: the rollback — rare by construction, since it
needs a member whose integrity fails *after* filters, so neither the corpus nor
the `unar` comparison ever takes it — and a match that reads the history across
the seam of the ring. They reach into private fields on purpose: they sit in the
same module, and the alternative, synthesising a RAR 5 block stream, would need
the encoder that was cut.

**Not regressed, checked on purpose:** on a single large member we were already
ahead of libunrar by CPU time, and still are — ×0.84 (`big_m3`), ×0.81
(`big_m5`), ×0.88 (a 400 MB solid archive). The wall-clock gap there (×1.9…2.3)
is libunrar's multithreading and cannot be answered on one core.

### Filters in the streaming path, and a hole it closed (ticket 34)

Upstream has two decode paths and only the buffered one applies RAR 5 filters;
the streaming one refused with a typed sentinel, which the caller turned into
"filtered member requires buffered decoding above the configured limit". Since
the choice between the paths was made **by member size**, that refusal was a
real hole: **a filtered member larger than 512 MiB did not extract at all.** It
is exactly what RAR applies filters to — a large `.exe`/`.dll`/installer (E8/E9)
or uncompressed audio and bitmaps (Delta) — and from outside it looked like a
broken archive.

Four changes, each marked `NEWTUA:`:

1. **One filter implementation for both paths.** `apply_one_filter` transforms a
   block; `apply_filters` (buffered, whole output at the end) and the streaming
   emission stage both call it. The rules that constrain them — a block no
   longer than 4 MiB, blocks that run forward without overlapping, a block that
   fits inside the member — live in one function, `filter_block_end`, and are
   checked by both. They have to be identical: the streaming path cannot go back
   to bytes it has already handed out, so what one path refuses the other must
   refuse too, or the two disagree and disagreement here is corruption, not a
   refusal.
   The 4 MiB ceiling is `unrar`'s own (`MAX_FILTER_BLOCK_SIZE` in `unpack.hpp`),
   and so is the response to a longer block: drop the filter rather than fail.
   It is also what makes deferred emission bounded at all — the length field is
   32 bits wide.
2. **The streaming emission stage.** Bytes before a filter's block go straight
   to the sink; the block itself is held until complete, transformed, then sent.
   A filter is always declared *ahead* of its block, so nothing already emitted
   ever has to be revisited. The window keeps the **unfiltered** bytes — the same
   rule `unrar` states in `UnpWriteBuf`: "we cannot process them just in place in
   Window buffer, because these data can be used for future string matches".
3. **The decoder copy in `stream_file_to` is gone.** It insured against failing
   mid-member and cost a copy of the dictionary window per member — the same
   disease ticket 30 cured on the buffered side, hiding in the streaming branch.
   With the threshold lowered it made a solid archive of 8000 small files **×48**
   slower. The window now returns to the decoder whichever way the decode ends,
   so there is nothing left to insure.
4. **"The window is all zeros" is carried, not recomputed.** The streaming path
   used to scan the whole incoming window on entry to seed its zero-run
   shortcut — O(window) per member, and on the same archive that alone was worth
   several-fold. The decoder carries the flag; the buffered path keeps it up to
   date over the member's own tail, which is O(member).

**What it bought, measured:** peak memory on a 300 MB member **347 → 79 MB**, on
a 196 MB filtered executable **272 → 72 MB**, and the 79 MB is the archive's
dictionary, so it no longer depends on the member's size.

**What it cost, measured the same way** — one code, two thresholds, paired runs:
on a large member streaming costs **+2…3 % of CPU time** and up to +10 % of wall
clock. Four times less memory for three per cent. On thousands of small members
streaming is the *faster* of the two (×0.86…×0.92), but those stay below the
threshold anyway. That is the trade `BUFFERED_DECODE_LIMIT` = 1 MiB makes; the
earlier claim of "no price at all" came from a single unpaired run on a loaded
machine and did not survive a paired one.

### What `/simplify` found afterwards, and it was not cosmetic

The cleanup pass over this work turned up **a second quadratic of the same
family, still live**, and it is worth recording how it hid.

Stage Е's evidence said the window is trimmed from the front almost never —
"counted, not assumed". That count was honest and useless: every sample in the
reference set is smaller than the archive's dictionary, so the trim never fires
in them. **A solid archive larger than its dictionary trims on every member**,
and the trim was `Vec::drain` from the front — a shift of the whole window, per
member. Measured on a solid archive of 4000 files totalling 74 MB with a 32 MiB
dictionary: **×8.9 of libunrar**, where the same shape below the dictionary runs
at ×0.47.

The window is a `VecDeque` in the decoder now, so dropping its front costs
nothing, and the streaming path no longer rebuilds it either: it used to take
the window as a `Vec`, convert to a ring and convert back, and the way back is
O(window) once the ring's start has moved. **×8.9 → ×1.0**, with no change to
the archives that were already fast.

Three more from the same pass, each measured:

- `Unpack50Checkpoint` cloned `DecodeTables` — four Huffman tables with a
  1024-entry quick index each, ~23 KB and eight allocations **per member**. The
  tables are never edited in place, only replaced wholesale, so `Arc` makes the
  snapshot free and the method's promise of O(1) true.
- `reset()` copied the whole window into the rollback store; for a **non-solid**
  archive that is every member. Taking the window instead of copying it costs
  nothing.
- The decrypting reader allocated and zeroed a full 16 KiB per member even for a
  200-byte one; it is sized by the member now, as the source buffer already was.

And one trap for whoever cleans up next: the first version of the shared
ring-copy helper took a destination slice, which forced the streaming caller to
zero the space first. That extra pass over every matched byte cost **8 % on a
large member** and did not show up in tests — only in a paired measurement. The
helper hands out the two slices instead.

**What the threshold means now.** Not "filters do not work above this" — they
work on both paths. Only "below this we still decode into a `Vec`", and only for
one thing: the retry that re-decodes a member without filters from the
checkpoint when integrity fails. The streaming path cannot offer that, because
its bytes are already gone. Worth knowing: **`unrar` has no such retry either**
— it applies filters and checks the CRC — so the shrinking coverage is a
divergence from upstream `rars`, not from the oracle.

### The encryption key was derived once per member (ticket 33)

RAR 5 derives its key with PBKDF2-HMAC-SHA256, and `rar`'s default `kdf_count`
of 15 means `2^15` = 32 768 HMAC rounds — about 6 ms — per derivation. Salt and
count live in **every member's** header, but within one archive they are the
same value repeated, so the work is the same key computed again and again.
Upstream derived it per member on extraction, and per header on parsing when the
archive has encrypted headers (`rar a -hp`).

`Archive` now carries `Rar50KeyCache`: one derived key, keyed on the triple
`(password, salt, kdf_count)`, `Mutex` inside `Arc` so `ArchiveSource` keeps
`Send`/`Sync`. A miss on any part of that triple derives again — an archive with
different salts per member is legal, and handing it a key derived from another
salt would decrypt garbage. Modelled on `EncryptedHeaderCipherCache`, the same
cache RAR 3 already had for its headers.

Measured on a solid archive of 4000 small files, paired against libunrar:

| archive | before | after | libunrar |
|---|---|---|---|
| `rar a -s -p` (encrypted bodies) | 17.0 s, **×108** | 0.031 s, **×0.20** | 0.16 s |
| `rar a -s -hp` (encrypted headers too) | 20.2 s, **×40** | 0.037 s, **×0.09** | 0.41 s |

A probe inside the derivation counted **4000 derivations with one distinct salt**
before, and **one per archive** after. The password check (`check_value`) still
runs on every member, cache hit or not — it is one SHA-256, and skipping it would
change the wrong-password path. That path was compared before and after on four
cases (wrong password and no password, on both archives): identical message,
identical exit code.

### RAR 3 had the same defect, and its KDF is dearer (ticket 35)

RAR 3 turns a password into a key with **262 144 rounds of SHA-1**
(`HASH_ROUNDS`, `crypto/rar30.rs`) — more than RAR 5 pays. Upstream cached that
only for **headers** (`EncryptedHeaderCipherCache`); every member's **body**
derived its own. A probe on three RAR 4 samples showed what packers actually
write: WinRAR 4.20 and SharpCompress use **one salt for the whole archive**
(so every derivation after the first was the same work again), while libarchive
writes a different salt per member (so a cache there must miss, and does).

Both caches are now one `Rar30CipherCache` on `Archive`, and both caches in the
tree — RAR 3's and RAR 5's — are the same type, `DerivedSecretCache` in
`crypto/cache.rs`, which is **entirely ours**. One home for the rule that
matters: a miss on any part of `(password, params)` derives again. The cell holds
a *pristine* cipher and hands out clones, because `Rar30Cipher` chains blocks and
mutates its IV as it decrypts — a shared one would be corruption, and a clone is
~200 bytes of AES key schedule.

Measured, paired, same window (small archives, so the ratio is the number that
means anything):

| sample | members | derivations per open | ours, before → after | vs libunrar |
|---|---|---|---|---|
| SharpCompress, one salt | 3 encrypted | 3 → **1** | 0.0164 → **0.0044 s** | ×1.07 → **×0.44** |
| WinRAR 4.20, one salt | 2 encrypted | 2 → **1** | 0.0131 → **0.0047 s** | ×0.73 → **×0.36** |
| libarchive, two salts | 2 | 2 → 2 (correct miss) | — | — |

Checked against `unar` byte for byte on **eight** encrypted RAR 3/4 archives,
including the `-hp` ones and a compact-Unicode name; refusals on a wrong and on a
missing password were captured before and after the change and matched line for
line. No archive of thousands of encrypted RAR 4 members exists to measure — `rar`
7.22 cannot write RAR 4 at all — so the proof here is the derivation count, not
seconds.

### What `/simplify` found after tickets 33 and 35

**The cache was per volume, not per volume set.** Volumes are parsed one at a
time, each `Archive` starting with its own empty cell, while the password and the
salt belong to the whole set — so a 43-volume encrypted set derived the key 43
times. Measured, paired, our own two builds: **0.1885 s → 0.0074 s**. Single
volume archives are untouched (×1.00, ×1.00, ×0.98 on the three controls), and
the extracted tree still matches `unar` byte for byte on the 43-volume set.

The cell is shared by `Archive::share_key_cache_with` (`mod.rs`), handed out in
`format/rar.rs`'s `parse_set` — the cache is `Arc` inside, so "share" is a
pointer copy. That also removed the need for `fragment_reader` to *choose* a
volume to take the cache from: any volume's cell is the same cell now.

Two more from the same pass:

- **The rule for accepting an encrypted RAR 5 member was written twice** — once
  in parsing (`attach_file_crypto`) and once in extraction
  (`crypto_with_password`), about twenty lines each, and the key cache had just
  been threaded through both. `keys_from_encryption` is now the one place, for
  the same reason the filter rules are: two copies of an acceptance rule mean
  parsing and extraction can come to accept different archives.
- `K: Clone` was required by the cache and used by nothing.

### A wrong password on a header-encrypted RAR 3 archive read as a broken file (ticket 36)

`rar a -hp` encrypts every block after the main header. A wrong key turns them
into noise, and upstream fed that noise to the header parser: the two bytes it
reads as `head_size` are uniform over 0…65 535, so almost always they exceed
what is left of the file and the answer was `TooShort` — which reaches a person
as **"input is too short"**, i.e. *your download is truncated*. They would go
looking for a second copy of a file that is intact, over a typo in the password.
RAR 5 has said `WrongPassword` here all along, and the difference between the two
generations is not explicable to anyone.

`read_encrypted_header_at` (`rar15_40.rs`) now says what it means: a header
decrypted with an unknown key that does not parse is
`WrongPasswordOrCorruptData`. **I/O errors are passed through untouched** — a
disk failure has nothing to do with the password, and relabelling it would be the
very mistake being fixed here.

RAR 3 cannot do better than "password or corruption", and does not need to: the
format has no key-check field — that arrived with RAR 5 — so the two causes are
indistinguishable **in principle**, and the verdict is named after what the
person should do. Genuine corruption of an `-hp` archive now reports the same
thing; `unrar` blames the password in that case too.

Guarded by two tests in `tests/integration/rar_handler.rs` over a fixture built
from format bytes in the test itself: `rar` 7.22 cannot produce RAR 4 any more
(`-ma4` is gone), and a third-party sample would repeat ticket 31 — an
undeclared-licence binary in a public repository. Since `-hp` leaves the marker
and the main header in the clear, both are real there and the encrypted tail is
what it looks like to a wrong key. On the unpatched tree the first test fails
with exactly the string from the ticket, `Corrupt("input is too short")`.

### Two ways an encrypted member stored without compression was lost (ticket 37)

Data loss, both inherited from upstream, both reproduced on `e214774` — they
arrived with the move to the vendored reader, not with anything since. On the
sample they were found on, 5 of 201 entries came out; `unrar` reads all of them,
byte for byte with the files the archive was built from.

**1. The discarded padding had to be zero, and there is no such promise.** An
encrypted stored member is padded to 16 bytes, and upstream refused the member
unless the tail was all zeros (three sites: buffered, streaming and split).
`rar` 7.22 does not fill it — what lands there is whatever was left in its
buffer, so the first members of an archive came out (buffer still clean) and the
rest were reported as a broken archive. The padding is now dropped in silence,
as `unrar` drops it. The password is guarded by the encryption record's
`check_value`, and integrity by CRC32 and BLAKE2sp; the padding guarded nothing.

**The ticket's stated boundary was wrong, and the measurement is what corrected
it.** It said the defect needed encrypted headers *and* volumes *and* `-m0`. It
needs none of the first two: a **single-volume** `rar a -m0 -p` archive loses
36 of 40 members. The `-p` control that looked healthy held files of 2000 bytes —
a multiple of 16, so it had no padding at all to trip over. The condition is
"member size not a multiple of 16", full stop.

**2. The split path checked integrity by a different rule than the whole one.**
It applied the key's MAC to the checksum whenever the member was encrypted; the
whole-member path applies it only when `uses_hash_mac` is set (bit 1 of the
encryption record's flags). An archive built with `rar a -hp` does not set that
bit, so every member split across a volume boundary was declared corrupt — and
the bytes were right all along, which a probe showed before a line was changed.
`PendingSplitRefs::write_stored_to` now calls `verify_streaming_integrity`, the
same function the whole-member path uses. One rule in one place, for the same
reason the filter rules are.

Two fixtures guard them, both built here and both failing on the unpatched tree:
`encpad.rar` (single volume, `-m0 -p`, 1500-byte members — refused with
"non-zero padding") and `hpvol.part1…6.rar` (six 2 KiB volumes, `-m0 -hp` —
"checksum mismatch" on the first split member).

### The key cache never reached parsing, so `-hp` volume sets paid per volume

Ticket 33 moved key derivation behind a cache; the `/simplify` pass after it made
that cache shared across a volume set. Both stopped one step short: the cache was
handed to a volume **after** it was parsed (`share_key_cache_with`). For an
archive with encrypted headers the key is what makes the headers readable, so it
is needed *during* parsing — and a 44-volume `-hp` set derived it 44 times. The
same set without `-hp` derived it once, which is exactly why no measurement
caught it.

The cache is now an input to parsing: `ArchiveReadOptions::volume_keys` carries a
`VolumeKeyCaches` that `format/rar.rs` creates once per set and gives to every
volume, first one included. `share_key_cache_with` is gone from all three files —
one road to the cell, not two.

Counted, not inferred: derivations per open went **44 → 1** and **22 → 1** on the
two `-hp` sets, and stayed **1** on the `-p` controls. Paired, medians of eleven
rounds: 734 → 146 ms and 368 → 66 ms; the `-p` controls moved ×1.03 and ×0.99,
which is noise (their ranges overlap). Both `parse_path_with_signature_and_password`
entry points went with the change — nothing called them any more.

### The two stored-body loops became one (`/simplify` after tickets 36/37)

`FileHeader::write_stored_to` and `PendingSplitRefs::write_stored_to` were near
word-for-word twins: read 64 KiB, trim the tail to `unpacked_size`, update CRC32
and the hash, write, check the length, verify. **They had already drifted twice**
— once in the integrity rule, which is what lost most of a `-hp` archive, and
once in when to trim at all (the whole-member copy trimmed unconditionally, the
split one only for encrypted members). Ticket 37 had to be applied to both.

`stream_stored_body` is now the one body; each caller supplies only what
actually differs — where the stream comes from and where the keys come from. The
padding rule, which was written in three places, is written in one. Trimming is
unconditional: an unencrypted stored member has packed size equal to unpacked, so
a branch for it would only have grown a second rule.

One visible consequence: the split path now labels its own errors with the entry
name, the way the whole-member path always did, instead of being labelled from
outside by `write_to`. Three upstream unit tests matched on the bare error and
now unwrap the `AtEntry` context first — the same way `format/rar.rs` unwraps it
to decide whether to ask for a password.

### The walk survives a damaged member, if the caller allows it (остаток G14)

Upstream's three walks — `rar13::extract_volumes_to`,
`rar15_40::extract_volumes_to`,
`rar50::extract_volumes_to_with_redirections` — ended at the first member whose
body would not decode, and took the rest of the set with it. Everything after
the damage was lost, including members that do not depend on it at all.

Each of the three now takes one more argument: `resume: &mut dyn FnMut(Error) ->
Result<()>`, called **only** when the body of an already-opened member failed.
`Ok(())` means "count that member as failed and carry on"; `Err` means "stop",
which is upstream's behaviour to the letter. Header, key and set-structure
errors do not go through it — there is nothing to carry on with after those.

Why the caller decides and not the walk: in a solid archive the next member is
decoded out of the window its predecessors filled, so after a failure that
window is worthless. `format/rar.rs` passes a closure that refuses for solid
archives and allows otherwise. Measured, not assumed: on a solid sample with one
damaged member `unrar` declares **all four** members damaged.

**One reordering came with it.** In `rar13` and `rar50` the split-member path
(`PendingSplitRefs::write_to`) prepared its reader — and in RAR 5 derived the
key — before calling `open`. A failure there would have been blamed on the
previous member, because the caller is told a body has ended only when the next
`open` arrives. `open` now comes first in all three generations, so a failure
always belongs to the member it happened in.

What it buys, on the damaged six-file split set in `tests/fixtures/torn.part*`:
**four intact members out of six → five**, which is what `unrar` recovers there,
byte for byte, and the sixth is the one that is genuinely damaged. The member
that was unreachable before is the one split across a volume boundary: it is
assembled by the walk and by nothing else, so no amount of per-member retrying
would have found it.

## Tests

**Every unit test inside `src/` came along** — codecs, crypto, headers, CRC,
BLAKE2sp, detection — and they run in our suite. A second wave went with the
encoder in ticket 26; that ledger is in "The encoder inside `codec/`" below.
What was dropped in the first pass:

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

## The encoder inside `codec/` — cut on 2026-08-10

The writers went as whole files in the first pass, but **the compression side
inside `codec/` did not**: `rar13.rs`, `rar20.rs`, `rar29.rs`, `rar50.rs` and
`ppmd.rs` each hold a decoder and an encoder in one file, sharing tables and
state. It was carried dead under `#[allow(dead_code)]` until the handler was
wired, because the reliable judge is the compiler and there was no call graph
to judge with — cutting by function names and brace counting had been tried and
had broken the file three times.

With `RarHandler` on this code the call graph exists, and the cut was made by
it: **13 400 lines gone, 30 655 → 17 241**. How, in case it has to be repeated:

1. `cargo check --lib --message-format json` names every dead item and gives
   its byte offset. **The offsets, not the names** — a name like `match_hash`
   or `BitWriter` exists in four codec files at once, and matching by name
   across files cut live code in the first attempt.
2. A throwaway tool parses the file with `syn` and deletes the *item* that
   contains the offset. Real boundaries from a real parser; the ban on brace
   counting stands.
3. The cut is **one pass over all files at once**. Dead code refers to dead
   code across file boundaries, so cutting file by file leaves dangling
   references (the second attempt, rolled back).
4. What breaks afterwards is the test side, and the compiler names it: every
   error span points at a test that only existed to exercise the encoder, and
   the same tool deletes the item at that span. Repeat until it builds.
5. Warnings pointing *inside* a type — an enum variant, a struct field — are
   skipped by the tool and handled by hand. There are seven of them.

**No blanket allowance is left.** Four narrow ones remain, each with its reason
in the source: `ArchiveVersion` and the `Error` enum (taxonomies of the format,
meaningless with values picked out of them), `ArchiveSource::Memory` (the
engine always has a file), and `Archive::sfx_offset` in the three families
(filled by the parser, unread — SFX is `format/sfx.rs`'s business here).

**Cost, measured** — two runs each way, back to back, `touch src/lib.rs`
before every one: `cargo check --lib` **1.38 s → 1.17 s**, published package
456 KiB → 391 KiB compressed. Worth saying plainly: the ticket expected more.
Its figure ("0.98 s → 1.94 s") compared the tree *before* `rars` was vendored
at all against the tree with it; against the same tree with the encoder still
in, the saving is about a sixth of the type-check, not a half.

### What the cut cost in tests, and what replaced it

**204 unit tests went** — every one of them a test that could not compile
without the encoder, because it built its input by encoding. That is the same
class, and the same reason, as the 206 dropped in the first pass: a test whose
fixture is produced by the code under test can only prove the code agrees with
itself.

What each decoder is guarded by now, so this is not taken on trust:

| Decoder | Guard |
| --- | --- |
| RAR 5 (`rar50`) | 11 unit tests (tables, slots, window bounds) + the corpus rows and our own RAR 5 fixtures |
| RAR 2.9 (`rar29`) | 7 unit tests, including a pinned packed member decoded through the live streaming path |
| RAR 2.0 (`rar20`) | 2 unit tests, one of them the same pinned-member decode |
| PPMd | 18 unit tests — allocator and range decoder, all robustness |
| RARVM | 21 unit tests |
| RAR 1.5 (`rar13`, `Unpack15`) | **had nothing left**, so a real archive was added: `tests/fixtures/rar15.rar` (`RUN.RAR` from sembiance/file-format-samples, method 51, version 15), extracted and compared file by file against what `unar` gets from it |

The RAR 1.5 case is the honest ledger of this cut: the test that went was
self-judged, the one that replaced it is judged by `unar`. One caveat travels
with it — the sample collection it came from declares no licence, and this
repository is public. Kept deliberately (there is no other RAR 1.5 archive to
be had, and none can be created today), noted in `README.md`, and to be
replaced by an archive we build ourselves under DOSBox.

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
