# Changelog

What changed for someone extracting an archive. Entries say what was wrong and
what now happens instead — the commit log has the rest.

This file starts at 0.3.0. Earlier releases are summarised from their commits.

## 0.3.0 — unreleased

The largest release so far: a dozen new ways in, a run of silent data-loss bugs
closed, and permissions and timestamps that now survive extraction across most
of the supported formats.

### New formats and new ways in

- **Framed Snappy (`.sz`)**, **lzip (`.lz`)** and **bare LZMA1 (`.lzma`)** open
  like any other compressor. Raw Snappy stays deliberately undetected: it has no
  magic to detect it by.
- **`.cpgz`** — a cpio archive inside a compressor, which is what macOS Archive
  Utility produces when it fails to expand something. Both tar-in-compressor and
  cpio-in-compressor are recognised.
- **cpio odc (`070707`) and crc (`070702`)**, alongside newc. The crc checksum is
  verified while a file is read out, never while listing.
- **`.wpress`** — the site dump written by the All-in-One WP Migration plugin.
- **`.war`, `.appx`, `.xpi`** report as their own formats instead of plain zip.
- **zip members compressed with PPMd**, and **multi-volume `zip -s` archives**
  (`name.z01`, `name.z02`, …) including the zip64 forms. The `zip` crate refuses
  multi-disk archives in every version, so the volumes are joined — with every
  central-directory offset rewritten — before it ever sees the data.
- **The three PKZIP methods that predate Deflate** — Shrink, Reduce and Implode.
  Until now these archives opened, listed their members and then refused every
  one of them. Shrink and Implode are confirmed byte-for-byte against `unzip` on
  real 1989–1990 archives; Reduce has no second reader anywhere, so it is
  checked against the files the reference archives were built from.
- **BinHex and MacBinary envelopes open what they carry**, when the name inside
  ends in `.sit`, `.cpt` or `.sea` — the same narrow rule XADMaster applies.
- **macOS self-extracting archives** — a Mach-O executable with the archive
  appended, which is what `7zz a -sfx` builds on a Mac. Windows PE
  self-extractors were already supported; the macOS ones were not recognised at
  all. The universal (fat) form works too.

### Silent data loss, fixed

These are the ones that produced a file rather than an error, which is worse
than failing.

- **bzip2 and xz stopped after the first member.** Parallel compressors write
  one member per CPU — Keka's bzip2 is `pbzip2` — so a real Keka archive came
  out **78 % short, with no error at all**. Every multi-member container now
  spans members: gzip, bzip2, xz, zstd and lzip.
- **A cpio entry whose name is not UTF-8 failed the whole archive.** cpio is now
  parsed here directly, with no crate behind it; names are decoded by the same
  charset detector every other format uses.
- **A short read in tar and WARC was treated as a short file.** It is an error
  now, so a truncated archive says so instead of quietly handing over less.
- **Resource forks were dropped.** The classic-Mac formats (StuffIt, StuffIt 5,
  BinHex, MacBinary, AppleSingle, PackIt, Compact Pro) report both forks of a
  file as two entries sharing one name; the second was being thrown away. For a
  picture or an application the resource fork is most of the file. It is written
  to `path/..namedfork/rsrc` on macOS and as an AppleDouble `._name` sidecar
  everywhere else.
- **A refused or cancelled entry left a zero-length file wearing the right
  name**, which reads as success. The unfinished file is now removed on both
  ways out; entries already written in full stay.
- **An APFS file compressed with decmpfs reported the wrong size.**
- **HFS+ exposed the volume's own service directories** as if they were content.

### Permissions and timestamps

Before this release most formats extracted their contents correctly and then
handed the files to you with today's date and default permissions.

- **Dates of the DOS and classic-Mac era are read as local time**, because that
  is what those formats store — a wall clock with no timezone at all. Reading
  them as UTC shifted every date by the reader's own offset. The conversion goes
  through the C library, which is the only thing that knows the rules **at that
  historical date**: summer-time rules differ between a January and a July file
  in the same zone.
- **Dates now reach disk** for ARC, ARJ, Zoo, LZX, NSIS, LBR, ALZip, 7z and RAR.
- **Zoo records the packer's own timezone**, so its dates are real instants
  rather than a wall clock. The field counts quarter hours **west** of GMT — we
  read it that way, which is the opposite of what XADMaster does.
- **Permissions now reach disk** for ISO 9660 (Rock Ridge), HFS+, APFS and WIM.
  WIM keeps them in a tagged item at the tail of each directory entry
  (`UNIX Data`), which is why they looked absent.

### Passwords

- **StuffIt 5 and ALZip encryption is visible in the listing**, and the password
  is judged from the header **before the first byte hits disk**. Previously an
  encrypted entry in these formats was not flagged, so the "fail before writing
  anything" guarantee silently did not apply to them.

### RAR is read in pure Rust

- **libunrar is gone.** RAR used to be decoded by a megabyte and a half of C++
  compiled into every build, behind a fork of our own and a licence that fits
  nothing else here. RAR 1.3 through RAR 7 are now decoded by Rust carried in
  this crate. Nothing about what opens changes — the same archives, the same
  bytes, checked file by file against `unar` on single-volume, multi-volume,
  solid and password-protected samples — but the build no longer compiles C++,
  and the UnRAR licence no longer applies to anything shipped.
- **The date of a RAR 5 entry is now exact.** It used to be read from a field
  with two-second resolution, so a file packed on an odd second showed up a
  second early; the exact instant was in the archive all along and unreachable
  through the old binding.
- **A link inside a RAR 5 archive now comes out as a link.** A symbolic link, a
  hard link and a reference to an identical file (`rar -oi`) all used to land as
  an empty file bearing the right name: the target sat in a header field the old
  binding never handed out. All three are extracted as symbolic links now, which
  is what `unar` makes of them too. One difference from `unar`, and it is
  deliberate: a link whose target leads outside the extraction folder is refused
  instead of created, exactly as `unrar` itself refuses it.
- **Extracting a few files from a large RAR no longer reads the whole archive**
  unless it has to. A solid archive still does — there the entries share one
  compression window and there is no way around it — but an ordinary archive
  now decompresses only what was asked for.
- **A large file inside a RAR no longer needs as much memory as it is big.** A
  4 GB film used to mean 4 GB of RAM held until extraction finished, which on a
  smaller machine meant swapping or the system killing the process outright. The
  body now reaches disk as it is decompressed: on a 700 MB file inside a solid
  archive the peak went from 863 MB to 114 MB, and that 114 MB is the archive's
  dictionary, so a file of any size costs the same. A member under 512 MiB is
  still decoded in one piece, but it too got lighter — a 300 MB one went from
  751 MB to 414 MB, and a 196 MB executable, where RAR's filters actually run,
  from 502 MB to 272 MB.
- **A solid RAR of many small files no longer gets slower the more files it
  holds.** This is the commonest shape a RAR comes in — a folder of thousands of
  small files packed as one stream — and the wait used to grow faster than the
  archive: 8000 files took 1.7 s where 1000 took 0.03 s, so 20 000 would have
  meant tens of seconds. The engine was copying the whole compression window
  before every single file, and reopening the archive file for every single file
  on top of that. Both are gone. The same 8000 files now take **0.06 s**, the
  wait grows in step with the number of files, and the result is about **twice
  as fast as libunrar** across the whole range — where before it was fourteen
  times slower at 8000 files. Nothing about the output changed: every byte,
  permission and timestamp still matches `unar` on the reference archives.
- **A packed executable extracts about a tenth faster**, and the same for a
  large file read as a stream: the byte-at-a-time loops that scanned for x86
  instructions and copied repeated runs now work in blocks.
- **A large executable inside a RAR could fail to extract at all.** RAR
  transforms x86 code and uncompressed audio before packing them, and a member
  over 512 MiB carrying such a transform was refused outright — from the outside
  it looked like a broken archive. It extracts now. The engine had two ways of
  decoding, and only the slower one knew about those transforms; now both do.
- **The memory a RAR member costs no longer depends on how big it is.** A 300 MB
  file inside an archive needed 347 MB of RAM, a 196 MB executable needed 272 MB;
  both now need about 79 MB, which is the archive's dictionary — the same figure
  for a member of any size. Extraction did not get slower for it: measured
  against the old path it is between a tenth faster and exactly even.
- **A password-protected RAR of many files is no longer hundreds of times slower
  than the same archive without a password.** Turning a password into a key is
  deliberately expensive — 32 768 rounds of hashing, about 6 ms — and the engine
  was paying it for every single file, although one archive uses one key
  throughout. A folder of 4000 small files under a password took **17 seconds**
  where the same archive without one took 0.03 s; with the names encrypted too
  (`rar -hp`) it took **20 seconds**. The key is derived once per archive now:
  both take about **0.03 s**, which is five times faster than libunrar on the
  first and ten times on the second. An archive that really does use a different
  salt per file still gets a fresh key for each — the wrong key would produce
  garbage, so the check is by value, not by assumption. Wrong and missing
  passwords are refused exactly as before, and the extracted bytes, permissions
  and timestamps still match `unar` on 8001 files across three encrypted
  archives.

### Other

- MSRV is **1.93**, measured rather than declared — `sevenz-rust2` 0.21 sets the
  floor — and CI has a job that builds on exactly that toolchain.
- Four defects found by a reference-corpus run across 7z, ISO, XAR and AppImage.

## 0.2.1 — 2026-07-24

- ISO and HFS+ are detected by content, not by extension alone.
- DMG is detected by its `koly` trailer rather than by the `.dmg` name, so an
  image with any name opens.

## 0.2.0 — 2026-07-22

- Entry names: one encoding is chosen for the whole archive by feeding every raw
  name to the detector at once, so short ambiguous names are resolved by the
  rest of the set. `OpenOptions::encoding_override` forces a label.
- XAR rejects rooted names on Windows as well as Unix.

## 0.1.1 — 2026-07-19

- **Building on Linux no longer requires the system `libfuse3` package.** The
  ISO 9660 reader's upstream declared `fuser` as an ordinary dependency of the
  library, for a mounting feature this crate never uses.
- XAR reader hardened against crafted input (overflow, recursion, traversal);
  the 7z header guarded against out-of-memory.
- Tests and their binary fixtures are excluded from the published package: the
  fixtures alone are 11 MB against a 10 MiB limit.

## 0.1.0 — 2026-07-19

First release. Lists and extracts over 50 archive and filesystem formats
entirely in-process, with no subprocess fallbacks. Extract only — it never
creates archives.
