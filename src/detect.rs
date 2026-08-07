use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::archive::{
    ArchiveReader, Confidence, Entry, EntryKind, FormatHandler, FormatId, OpenOptions, Source,
};
use crate::decompress::{Compressor, decompressor};
use crate::error::{Error, Result};
use crate::format::{
    AlzHandler, ApfsHandler, AppImageHandler, AppleSingleHandler, ArHandler, ArcHandler,
    ArjHandler, BinHexHandler, CabHandler, CompactProHandler, CondaHandler, CpioHandler,
    CrunchHandler, CrxHandler, DebHandler, DmgHandler, DmsHandler, HfsPlusHandler, IsoHandler,
    LbrHandler, LzxHandler, MacBinaryHandler, MsiHandler, NsisHandler, PackItHandler,
    PowerPackerHandler, RarHandler, RpmHandler, SevenZHandler, SfxHandler, SquashfsHandler,
    SqueezeHandler, StuffIt5Handler, StuffItHandler, StuffItXHandler, TarHandler, WarcHandler,
    WimHandler, WpressHandler, XarHandler, ZipBundleHandler, ZipHandler, ZooHandler, bundle,
};
use crate::volume::{ConcatReader, join_split_zip, split_zip_members, volume_members};

/// Returns the full handler registry in priority order.
pub fn registry() -> Vec<Box<dyn FormatHandler>> {
    let mut handlers: Vec<Box<dyn FormatHandler>> =
        Vec::with_capacity(bundle::ZIP_BUNDLES.len() + 16);
    // Zip-бандлы ДОЛЖНЫ идти перед ZipHandler: они делят PK-магию, а селектор на
    // ничьей MAGIC берёт первого. Обычный .zip не совпадает ни с одним бандлом
    // (NONE) и проваливается в ZipHandler.
    for &(ext, format) in bundle::ZIP_BUNDLES {
        handlers.push(Box::new(ZipBundleHandler::new(ext, format)));
    }
    // CRX: уникальная магия `Cr24` (не PK), карвит вложенный zip из-за заголовка.
    handlers.push(Box::new(CrxHandler));
    // Conda: zip + расширение `.conda`; делит PK-магию с zip (как бандлы), но
    // разворачивает вложенные `*.tar.zst`. Должен идти перед ZipHandler.
    handlers.push(Box::new(CondaHandler));
    handlers.push(Box::new(ZipHandler));
    handlers.push(Box::new(CpioHandler));
    handlers.push(Box::new(SevenZHandler));
    handlers.push(Box::new(RarHandler));
    handlers.push(Box::new(TarHandler));
    handlers.push(Box::new(CabHandler));
    // DebHandler MUST precede ArHandler: a .deb shares the `!<arch>\n` magic
    // with a plain ar archive, so both probe MAGIC. The selector keeps the
    // first MAGIC on a tie, so order is the tie-break (a plain ar still falls
    // through to ArHandler, since DebHandler probes NONE without debian-binary).
    handlers.push(Box::new(DebHandler));
    handlers.push(Box::new(ArHandler));
    // RpmHandler: unique lead magic (ED AB EE DB), no tie-break with peers.
    handlers.push(Box::new(RpmHandler));
    // XarHandler: unique magic "xar!" (78 61 72 21), used for .xar and .pkg.
    handlers.push(Box::new(XarHandler));
    // MsiHandler: CFB magic + .msi extension. Reuses CabHandler for embedded
    // CAB streams; resolves File/Component/Directory tables to install paths.
    handlers.push(Box::new(MsiHandler));
    // IsoHandler: detected by .iso extension; CD001 signature verified in open.
    handlers.push(Box::new(IsoHandler));
    // SquashfsHandler: unique magic `hsqs` (no tie-break with peers); also
    // detected by .squashfs/.sfs extension.
    handlers.push(Box::new(SquashfsHandler));
    // AppImageHandler: unique ELF+`AI` magic (also detected by `.appimage`).
    // A plain ELF executable probes NONE (no AI marker, no `.appimage`), so no
    // false positives; no tie-break with peers.
    handlers.push(Box::new(AppImageHandler));
    // WimHandler: unique magic `MSWIM\0\0\0` (also detected by `.wim`/`.esd`/
    // `.swm`); no tie-break with peers.
    handlers.push(Box::new(WimHandler));
    // SfxHandler: MZ → Confidence(50), below MAGIC(100), so real archives always
    // win. Carves the appended archive past the PE overlay and reopens it.
    handlers.push(Box::new(SfxHandler));
    // WarcHandler: WARC/1.x magic; .warc.gz is handled by the early extension
    // branch in open_single and never reaches this registry probe.
    handlers.push(Box::new(WarcHandler));
    // HfsPlusHandler: detected by .hfs/.hfsplus/.hfsx extension (the H+/HX
    // signature at offset 1024 is past the registry's 512-byte peek, same
    // situation as ISO); no tie-break with peers.
    handlers.push(Box::new(HfsPlusHandler));
    // ApfsHandler: unlike HFS+, `NXSB` at offset 32 IS reachable within the
    // registry's 512-byte peek, so this probe actually fires (also detected
    // by .apfs extension); no tie-break with peers.
    handlers.push(Box::new(ApfsHandler));
    // DmgHandler: detected by .dmg extension (the koly trailer lives in the
    // last 512 bytes, unreachable from the registry's header peek, same
    // situation as HFS+/ISO). Registered for uniform enumeration, but this
    // probe never actually fires: `.dmg` is intercepted by the early extension
    // branch in open_single (before the registry loop), so dispatch is there.
    handlers.push(Box::new(DmgHandler));
    // WpressHandler: detected by the `.wpress` extension alone — the format has
    // no magic anywhere, so there is nothing for a header peek to match. The
    // guess is confirmed inside `open` by parsing the first header (same shape
    // as ISO/HFS+). At `EXTENSION` confidence it cannot shadow a content match,
    // and no peer claims `.wpress`, so there is no tie-break here.
    handlers.push(Box::new(WpressHandler));
    // Legacy formats (newtua-formats family). Content-first detection via the
    // upstream `recognize`; their magics/extensions don't tie with the modern
    // handlers above, so they're simply appended. ARC has no content sniff and
    // detects by extension only; Squeeze detects by both its `76 FF` magic and
    // its extension. As with the modern handlers, an extension fallback is
    // added where a format has a distinctive conventional extension.
    // --- newtua-dos ---
    handlers.push(Box::new(ArjHandler));
    handlers.push(Box::new(ZooHandler));
    handlers.push(Box::new(LbrHandler));
    handlers.push(Box::new(CrunchHandler));
    handlers.push(Box::new(ArcHandler));
    handlers.push(Box::new(SqueezeHandler));
    // --- newtua-mac ---
    handlers.push(Box::new(BinHexHandler));
    handlers.push(Box::new(MacBinaryHandler));
    handlers.push(Box::new(AppleSingleHandler));
    handlers.push(Box::new(CompactProHandler));
    handlers.push(Box::new(PackItHandler));
    // --- newtua-stuffit --- (distinct signatures; a `.sit` routes to classic
    // or SIT5 by content, so registration order is not a tie-break here).
    handlers.push(Box::new(StuffIt5Handler));
    handlers.push(Box::new(StuffItHandler));
    handlers.push(Box::new(StuffItXHandler));
    // --- newtua-alz / newtua-nsis --- (NsisHandler's probe is always NONE, so
    // it is registry-invisible — like DmgHandler, which the early branch in
    // open_single intercepts before its probe is ever consulted. NSIS is reached
    // only via the `MZ` early branch in open_single; registered here for uniform
    // enumeration.)
    handlers.push(Box::new(AlzHandler));
    handlers.push(Box::new(NsisHandler));
    // --- newtua-amiga ---
    handlers.push(Box::new(PowerPackerHandler));
    handlers.push(Box::new(LzxHandler));
    handlers.push(Box::new(DmsHandler));
    handlers
}

/// Probe magic bytes to detect a compression wrapper.
///
/// Supported signatures:
/// - Gzip:  `1f 8b`
/// - Bzip2: `BZh`
/// - Xz:    `fd 37 7a 58 5a 00`
/// - Zstd:  `28 b5 2f fd`
/// - Lzc:   `1f 9d`
/// - Lz4:   `04 22 4d 18`
/// - Snappy: `ff 06 00 00 73 4e 61 50 70 59`
/// - Lzip:  `4c 5a 49 50 01` (`LZIP` + format version)
pub fn detect_compressor(header: &[u8]) -> Option<Compressor> {
    if header.starts_with(&[0x1f, 0x8b]) {
        return Some(Compressor::Gzip);
    }
    if header.starts_with(b"BZh") {
        return Some(Compressor::Bzip2);
    }
    if header.starts_with(&[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]) {
        return Some(Compressor::Xz);
    }
    if header.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
        return Some(Compressor::Zstd);
    }
    if header.starts_with(&[0x1f, 0x9d]) {
        return Some(Compressor::Lzc);
    }
    if header.starts_with(&[0x04, 0x22, 0x4D, 0x18]) {
        // LZ4 frame format. Legacy frame (0x02 0x21 0x4C 0x18) is intentionally
        // unsupported — lz4_flex's FrameDecoder doesn't decode it. TODO if needed.
        return Some(Compressor::Lz4);
    }
    if header.starts_with(&[0xFF, 0x06, 0x00, 0x00, 0x73, 0x4E, 0x61, 0x50, 0x70, 0x59]) {
        // Framed Snappy (`.sz`, Keka's SNAPPY; snzip's default `framing2`).
        // The signature is the mandatory first chunk of the stream: type byte
        // 0xff, 3-byte little-endian length 6, payload `sNaPpY`. Raw (unframed)
        // Snappy has no header at all and is intentionally not detected.
        return Some(Compressor::Snappy);
    }
    if header.starts_with(b"LZIP\x01") {
        // lzip (`.lz`). The version byte is part of the signature on purpose:
        // only format version 1 is decodable (see `Compressor::Lzip`), so a
        // version-0 or future-version file must fall through and be reported
        // as an unknown format rather than opened and then failed mid-read.
        return Some(Compressor::Lzip);
    }
    None
}

/// Every compressor file-name suffix this crate knows, in scan order.
///
/// The single source of truth for two questions that used to keep two lists in
/// sync: which suffix names a compressor that has **no content magic**
/// (`Some(_)`, detected by extension alone), and which suffix must be stripped
/// off to derive the entry name of a plain compressed file (all of them).
///
/// A `None` here means "content magic detects this one — the suffix is only
/// good for naming". Adding a magic-less compressor is one row with `Some(_)`;
/// `detect_compressor` (the byte-magic detector) stays untouched either way.
///
/// **Order matters**: both readers take the first suffix that matches, so a
/// longer suffix must precede any shorter one it ends with.
const COMPRESSOR_EXTS: &[(&str, Option<Compressor>)] = &[
    (".gz", None),
    (".bz2", None),
    (".xz", None),
    (".zst", None),
    // Uppercase on purpose: `.Z` is compress(1), lowercase `.z` is not.
    (".Z", None),
    (".lz4", None),
    (".br", Some(Compressor::Brotli)),
    (".sz", None),
    // Bare LZMA1 ("alone" format), the same decoder deb/rpm already use for
    // their payloads. Its header is coder properties plus a dictionary size,
    // with no tag: any file could start that way, so detecting it by content
    // would claim arbitrary data. Extension only, on purpose.
    (".lzma", Some(Compressor::Lzma)),
    (".lz", None),
];

/// Detect a compressor from the file name's extension, for formats that have
/// **no content magic** and therefore cannot be recognised by `detect_compressor`.
///
/// This is intentionally separate from `detect_compressor` (which inspects bytes):
/// magic-less formats are detected only by an explicit extension, never by
/// content. `lower_name` must already be lowercased by the caller.
///
/// - `.br` / `.tar.br` → Brotli
/// - `.lzma` / `.tar.lzma` → bare LZMA1 (the "alone" container)
fn detect_compressor_by_ext(lower_name: &str) -> Option<Compressor> {
    COMPRESSOR_EXTS
        .iter()
        .find_map(|&(ext, comp)| comp.filter(|_| lower_name.ends_with(ext)))
}

// ── TempBackedReader ──────────────────────────────────────────────────────────

/// Generic wrapper that delegates all [`ArchiveReader`] calls to an inner reader
/// while keeping a temp file alive (and auto-deleted on drop).
///
/// Used for multi-volume reconstruction, the decompressed temp file backing a
/// tar- or cpio-inside-compressed-file (`.tar.gz`, `.cpgz`), SFX carving, and
/// the format-specific readers (deb/rpm) that decompress a payload to a temp
/// file. The cpio reader has no temp file of its own — it reads bodies straight
/// out of this one, which is exactly why the wrapper has to outlive it. By
/// default `format()`
/// delegates to the inner reader; pass a `format_override` to report a wrapper
/// format (e.g. `Deb`/`Rpm`) instead of the inner payload format.
pub(crate) struct TempBackedReader {
    inner: Box<dyn ArchiveReader>,
    /// Keeps the temp file alive (deleted on drop).
    _temp: tempfile::TempPath,
    /// When set, `format()` reports this instead of the inner reader's format.
    format_override: Option<FormatId>,
}

impl TempBackedReader {
    /// Wrap `inner`, keeping `temp` alive; `format()` delegates to `inner`.
    pub(crate) fn new(inner: Box<dyn ArchiveReader>, temp: tempfile::TempPath) -> Self {
        Self {
            inner,
            _temp: temp,
            format_override: None,
        }
    }

    /// Like [`new`](Self::new) but `format()` reports `format` (e.g. the
    /// container format whose payload was decompressed to `temp`).
    pub(crate) fn with_format(
        inner: Box<dyn ArchiveReader>,
        temp: tempfile::TempPath,
        format: FormatId,
    ) -> Self {
        Self {
            inner,
            _temp: temp,
            format_override: Some(format),
        }
    }
}

impl ArchiveReader for TempBackedReader {
    fn format(&self) -> FormatId {
        self.format_override.unwrap_or_else(|| self.inner.format())
    }

    fn entries(&mut self) -> Result<&[Entry]> {
        self.inner.entries()
    }

    fn read_entry(&mut self, idx: usize, out: &mut dyn Write) -> Result<()> {
        self.inner.read_entry(idx, out)
    }

    /// Проброс обязателен: без него обёртка подсунула бы реализацию по
    /// умолчанию (цикл по `read_entry`) и отняла бы у вложенного обработчика
    /// его собственный однопроходный путь. Через эту обёртку открываются SFX,
    /// deb/rpm и тома — то есть и 7z внутри самораспаковки.
    fn read_entries(
        &mut self,
        indices: &[usize],
        sink: &mut dyn crate::archive::EntrySink,
    ) -> Result<()> {
        self.inner.read_entries(indices, sink)
    }

    fn verify_password(&mut self) -> Result<()> {
        self.inner.verify_password()
    }
}

/// Copy exactly `size` bytes starting at `offset` from `src` into `out`.
///
/// Недобор — это потеря данных, а не безобидный EOF: `io::copy` отдал бы `Ok`
/// на укороченном теле, и наверх ушёл бы обрезанный файл под видом успеха.
/// Поэтому прочитанное сверяется с обещанным и расхождение становится
/// `Error::Corrupt` — та же форма, что у `WpressReader::read_entry`.
/// `what` называет источник (`"tar"`, `"warc"`, …), чтобы сообщение говорило,
/// что именно оборвалось.
///
/// Ничего не резервируется под `size`: копия ограничена `take`, а выход растёт
/// по мере поступления байтов.
pub(crate) fn copy_slice_exact<R: Read + Seek>(
    src: &mut R,
    offset: u64,
    size: u64,
    out: &mut dyn Write,
    what: &str,
) -> Result<()> {
    if size == 0 {
        return Ok(());
    }
    src.seek(SeekFrom::Start(offset))?;
    let copied = std::io::copy(&mut src.by_ref().take(size), out)?;
    if copied != size {
        return Err(Error::Corrupt(format!(
            "{what}: truncated body at offset {offset} ({copied} of {size} bytes)"
        )));
    }
    Ok(())
}

// ── SingleFileReader ──────────────────────────────────────────────────────────

/// Reader that presents a single decompressed file as a one-entry archive.
///
/// The decompressed content lives in a `NamedTempFile` on disk; streaming is
/// done via a regular file seek/read so that large files never reside in RAM.
struct SingleFileReader {
    entries: Vec<Entry>,
    /// Path to the temp file on disk; owns the file so it is deleted on drop.
    temp_path: tempfile::TempPath,
}

impl SingleFileReader {
    /// Create a reader from an already-decompressed temp file.
    ///
    /// * `original_path` — path of the compressed source file (e.g. `notes.txt.gz`).
    ///   The compressor extension (`.gz`, `.bz2`, `.xz`) is stripped to derive the
    ///   entry name.
    /// * `tmp` — the `NamedTempFile` holding the decompressed payload.
    /// * `size` — decompressed byte count.
    /// * `modified` — optional modification timestamp (only gzip headers carry one).
    fn new(
        original_path: &Path,
        tmp: tempfile::NamedTempFile,
        size: u64,
        modified: Option<SystemTime>,
    ) -> Self {
        let entry_name = stem_without_compressor_ext(original_path);
        let path_raw = entry_name.as_bytes().to_vec();
        let entry = Entry {
            path_raw,
            path: PathBuf::from(&entry_name),
            kind: EntryKind::File,
            size,
            mode: None,
            is_encrypted: false,
            modified,
            is_resource_fork: false,
        };
        SingleFileReader {
            entries: vec![entry],
            temp_path: tmp.into_temp_path(),
        }
    }
}

/// Read the gzip mtime from the original `.gz` file.
///
/// The gzip header stores the original modification time as a little-endian
/// `u32` at byte offset 4 (seconds since Unix epoch; 0 = "no timestamp").
/// Returns `Some(timestamp)` if the mtime is non-zero, `None` otherwise.
fn read_gz_mtime(path: &Path) -> Option<SystemTime> {
    let mut buf = [0u8; 8];
    let mut f = std::fs::File::open(path).ok()?;
    // We only need bytes 0..8; a short read means the file is too small.
    let n = f.read(&mut buf).ok()?;
    if n < 8 {
        return None;
    }
    let mtime = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if mtime == 0 {
        None
    } else {
        Some(UNIX_EPOCH + Duration::from_secs(mtime as u64))
    }
}

impl ArchiveReader for SingleFileReader {
    fn format(&self) -> FormatId {
        FormatId::Raw
    }

    fn entries(&mut self) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn read_entry(&mut self, idx: usize, out: &mut dyn Write) -> Result<()> {
        if idx != 0 {
            return Err(Error::InvalidIndex(idx));
        }
        let mut file = std::fs::File::open(&self.temp_path)?;
        std::io::copy(&mut file, out)?;
        Ok(())
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Strip the outermost compressor extension from a path's file name.
///
/// Examples:
/// - `notes.txt.gz`  → `"notes.txt"`
/// - `data.gz`       → `"data"`
/// - `archive.tar.bz2` → `"archive.tar"`
/// - `file.xz`       → `"file"`
///
/// The suffix list is [`COMPRESSOR_EXTS`] — every compressor, magic-less or not.
fn stem_without_compressor_ext(path: &Path) -> String {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("data");

    for (ext, _) in COMPRESSOR_EXTS {
        if let Some(stem) = name.strip_suffix(ext) {
            return stem.to_string();
        }
    }
    // No recognised compressor extension — use the full name.
    name.to_string()
}

/// Fill `buf` from the start of `reader`, then rewind the reader to position 0.
///
/// Returns how many bytes were actually read: a short read is not an error, it
/// just means the file is smaller than `buf` (callers decide what that means).
/// `Interrupted` is retried, as `read_exact` would do; any other error is
/// propagated and the reader is left where it is.
fn peek_from_start<R: Read + Seek>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0usize;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    reader.seek(SeekFrom::Start(0))?;
    Ok(filled)
}

/// Check whether the first 263 bytes of a reader contain the tar `ustar` magic
/// at offset 257. Rewinds the reader to position 0 after the check.
pub(crate) fn is_tar<R: Read + Seek>(reader: &mut R) -> std::io::Result<bool> {
    let mut buf = [0u8; 263];
    let filled = peek_from_start(reader, &mut buf)?;
    Ok(filled >= 263 && &buf[257..262] == b"ustar")
}

/// Check whether a reader starts with a cpio magic this crate can open — SVR4
/// "new ASCII" (`070701`), its checksummed twin crc (`070702`) or POSIX "old
/// portable"/odc (`070707`). Rewinds the reader to position 0 after the check.
///
/// This is the companion of [`is_tar`] for the one other archive format looked
/// for inside a decompressed stream (`.cpgz` — cpio inside gzip — is what macOS
/// Archive Utility produces; its engine, `ditto`, writes the odc variant).
/// The question is delegated to `cpio::is_supported_magic` rather than restated
/// here, so the set claimed here cannot drift from the set `CpioHandler::open`
/// can actually parse.
pub(crate) fn is_cpio<R: Read + Seek>(reader: &mut R) -> std::io::Result<bool> {
    let mut buf = [0u8; crate::format::cpio::MAGIC_LEN];
    let filled = peek_from_start(reader, &mut buf)?;
    Ok(filled == buf.len() && crate::format::cpio::is_supported_magic(&buf))
}

// ── open_single ───────────────────────────────────────────────────────────────

/// Internal helper: open a single concrete file path (no volume logic).
///
/// This is the original `open()` body, now callable from both the normal code
/// path and the volume-reconstruction path.
pub(crate) fn open_single(path: &Path, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
    let mut src = Source::path(path)?;
    let header = src.peek_header(512)?;

    // Early WARC extension branch — MUST come before detect_compressor.
    //
    // A `.warc.gz` file uses per-record gzip (each WARC record is a separate
    // gzip member, concatenated). Its file magic is the gzip signature `1f 8b`,
    // so the generic compressor layer would decompress it as a single byte
    // stream and lose the record boundaries.  By routing `.warc` and `.warc.gz`
    // straight to WarcHandler here, we bypass that layer entirely and let the
    // handler apply MultiGzDecoder itself (which handles concatenated members).
    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let lower_name = file_name.to_ascii_lowercase();
    if lower_name.ends_with(".warc") || lower_name.ends_with(".warc.gz") {
        // `src` is already rewound to 0 by peek_header — reuse it directly.
        return WarcHandler.open(src, opts);
    }

    // Early DMG extension branch — same rationale as WARC above.
    //
    // A DMG's data fork (sector-compressed chunks) starts at byte 0 of the
    // file whenever `koly.DataForkOffset` and the first blkx chunk's
    // `CompressedOffset` are both 0 (the common case). That chunk's own
    // compressed bytes can coincidentally start with another compressor's
    // magic — observed with real `hdiutil`-generated UDBZ/ULMO images, whose
    // first chunk happens to open with the bzip2/xz stream header — which
    // would otherwise make the generic compressor layer below swallow the
    // whole file as one compressed stream and fail once it runs past that
    // first chunk's boundary. Routing `.dmg` straight to DmgHandler bypasses
    // that layer entirely; `koly`'s own magic is validated inside `open`.
    // A DMG is recognized by its `koly` trailer, not its extension: the trailer
    // lives in the last 512 bytes, so a DMG mislabeled with another extension
    // (e.g. a `.dmg` renamed to `.iso`, as reported) is invisible to the
    // registry's header peek. Check the extension first (cheap), then fall back
    // to a content probe of the trailer.
    //
    // This probe reads the file tail on every non-`.dmg` open. It must stay here,
    // ahead of BOTH the compression layer (above rationale) and the registry:
    // IsoHandler now claims `.iso` at `EXTENSION` confidence, so a DMG named
    // `.iso` would be captured by the registry and never reach the late content
    // fallback. Do not gate or move it later without re-checking that path.
    if lower_name.ends_with(".dmg") || crate::format::dmg::has_koly_trailer(path) {
        return DmgHandler.open(src, opts);
    }

    // Compression layer. Magic-based detection first; then an extension-only
    // fallback for magic-less compressors (Brotli — no content signature).
    if let Some(comp) = detect_compressor(&header).or_else(|| detect_compressor_by_ext(&lower_name))
    {
        // Step 1: decompress to a temp file via streaming io::copy (no RAM spike).
        let file = std::fs::File::open(path)?;
        let mut decoded: Box<dyn Read> = decompressor(comp, Box::new(file))?;
        let mut tmp = tempfile::NamedTempFile::new()?;
        let size = std::io::copy(&mut decoded, &mut tmp)?;

        // Step 2: peek the decompressed content for an archive we unwrap here.
        // The io::copy above left the file cursor at the end; rewind first.
        //
        // Exactly two formats are looked for, in this order: tar, then cpio
        // (`.cpgz` — what macOS Archive Utility produces — is cpio inside gzip).
        // Deliberately NOT the whole registry: a `.zip.gz`, `.7z.gz` and every
        // other nesting must keep coming out as one entry holding the raw inner
        // file. Do not "while we're here" this into a general re-dispatch.
        // Both checks are by content, never by file name.
        tmp.as_file_mut().seek(SeekFrom::Start(0))?;
        let inner_handler: Option<&dyn FormatHandler> = if is_tar(tmp.as_file_mut())? {
            Some(&TarHandler)
        } else if is_cpio(tmp.as_file_mut())? {
            Some(&CpioHandler)
        } else {
            None
        };

        if let Some(handler) = inner_handler {
            // Open the temp file as a seekable archive; TempBackedReader keeps
            // the temp file alive for as long as the reader lives.
            let temp_path = tmp.into_temp_path();
            let inner_src = Source::path(&temp_path)?;
            let inner = handler.open(inner_src, opts)?;
            return Ok(Box::new(TempBackedReader::new(inner, temp_path)));
        } else {
            // Plain compressed file — present as one entry.
            // For gzip only: read the original-file mtime from the header (bytes 4..8).
            // bzip2, xz, and zstd carry no mtime in their standard headers.
            let modified = if comp == Compressor::Gzip {
                read_gz_mtime(path)
            } else {
                None
            };
            return Ok(Box::new(SingleFileReader::new(path, tmp, size, modified)));
        }
    }

    // NSIS installers are PE executables (`MZ`) with the archive appended past
    // the stub — the firstheader sits far beyond the 512-byte header peek, so
    // no registry probe can see it. Read the whole file once and let the
    // handler sniff it: a genuine NSIS installer opens here (before the generic
    // SFX carve); anything else returns `UnknownFormat` and falls through to
    // the registry, where `SfxHandler` still handles other self-extractors.
    if header.starts_with(b"MZ") {
        match NsisHandler::open_bytes(std::fs::read(path)?, opts) {
            Ok(reader) => return Ok(reader),
            Err(Error::UnknownFormat) => {}
            Err(e) => return Err(e),
        }
    }

    // Container formats: pick handler with highest probe confidence.
    let name = path.file_name().and_then(|s| s.to_str());
    let handlers = registry();
    let mut best: Option<(Confidence, usize)> = None;
    for (i, h) in handlers.iter().enumerate() {
        let c = h.probe(&header, name);
        if c > Confidence::NONE && best.is_none_or(|(bc, _)| c > bc) {
            best = Some((c, i));
        }
    }
    let Some((_, idx)) = best else {
        // No registry handler matched. Fall back to the deep-signature formats
        // whose magic lives past the 512-byte header peek and so can only be
        // confirmed by a targeted read: content-detect a mislabeled ISO/HFS+
        // (wrong or missing extension). Genuine content-magic formats already
        // won above, so this never shadows them.
        if crate::format::iso::has_iso_signature(path) {
            return IsoHandler.open(Source::path(path)?, opts);
        }
        if crate::format::hfsplus::has_hfsplus_signature(path) {
            return HfsPlusHandler.open(Source::path(path)?, opts);
        }
        return Err(Error::UnknownFormat);
    };
    // Re-open to get a fresh seekable source at position 0.
    let fresh_src = Source::path(path)?;
    handlers.into_iter().nth(idx).unwrap().open(fresh_src, opts)
}

/// Public entry point: open an archive at `path`.
///
/// Logic:
/// 1. If `path` ends with `.001`, check for sibling volumes (`.002`, etc.).
///    If more than one member exists, concatenate all members into a temp file
///    and open the reconstructed archive from the temp path. The temp file is
///    kept alive via [`TempBackedReader`] until the reader is dropped.
/// 2. If `path` ends with `.zip` and a `.z01` sibling exists, it is a `zip -s`
///    split archive whose entry point is the LAST volume (the central
///    directory lives there). The volumes are concatenated into a temp file and
///    the directory's per-volume offsets are rewritten to absolute ones — the
///    `zip` crate cannot read a multi-disk archive itself. Kept alive by
///    [`TempBackedReader`], same as above.
/// 3. Otherwise (or when `.001` has no siblings), open the file directly.
///    Within direct open:
///
///    - If a compression wrapper is detected (gzip/bzip2/xz), decompress to a
///      temp file, then peek its content for tar magic at offset 257 and then
///      for a cpio magic (newc, crc or odc) at offset 0 — those two formats
///      only:
///      - If tar or cpio → open with that handler (file-backed via temp),
///        wrapped so the temp file outlives the reader.
///      - Otherwise → return a [`SingleFileReader`] with one entry whose name
///        is the original file name with the compressor extension stripped.
///        A nested `.zip.gz`/`.7z.gz` lands here on purpose: the decompressed
///        content is not re-dispatched through the registry.
///    - Otherwise, select the handler with the highest `Confidence` from the
///      registry and delegate to it.
pub fn open(path: &Path, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
    // Check for generic raw byte-split volumes (.001/.002/... scheme).
    // The comparison is case-insensitive so that e.g. `ARCHIVE.ZIP.001` is
    // also handled correctly on case-sensitive file systems.
    let is_first_volume = path
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.to_ascii_lowercase().ends_with(".001"));

    if is_first_volume {
        let members = volume_members(path)?;
        if members.len() > 1 {
            // Reconstruct the original archive by concatenating all volumes.
            let mut tmp = tempfile::NamedTempFile::new()?;
            {
                let mut cat = ConcatReader::open(&members)?;
                std::io::copy(&mut cat, &mut tmp)?;
            }
            // Convert to TempPath so the file is deleted when it goes out of scope,
            // but first persist into a path we can open.
            let temp_path = tmp.into_temp_path();
            let inner = open_single(&temp_path, opts)?;
            return Ok(Box::new(TempBackedReader::new(inner, temp_path)));
        }
        // Exactly 1 member (the .001 file itself, no siblings) — open normally.
    }

    // Тома `zip -s`: `имя.z01`, `имя.z02`, …, и последним `имя.zip`. Точка
    // входа здесь — последний файл, а не первый: центральный каталог пишется в
    // конце, то есть в `.zip`. Отдельная ветка именно поэтому, а не
    // продолжение схемы `.001` выше.
    if let Some(members) = split_zip_members(path) {
        // `None` — рядом лежал посторонний `.z01`, а сам архив однотомный;
        // тогда просто открываем его как обычно.
        if let Some(temp_path) = join_split_zip(&members)? {
            // Мимо `open_single` намеренно: формат тут уже известен, а склеенный
            // файл начинается с четырёхбайтовой метки разбиения `PK\x07\x08`
            // (по APPNOTE она стоит в начале первого тома, и смещения записей
            // её уже учитывают), так что по магии его никто бы не опознал.
            let inner = ZipHandler.open(Source::path(&temp_path)?, opts)?;
            return Ok(Box::new(TempBackedReader::new(inner, temp_path)));
        }
    }

    open_single(path, opts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_each_compressor() {
        assert_eq!(
            detect_compressor(&[0x1f, 0x8b, 0x08]),
            Some(Compressor::Gzip)
        );
        assert_eq!(detect_compressor(b"BZh9"), Some(Compressor::Bzip2));
        assert_eq!(
            detect_compressor(&[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]),
            Some(Compressor::Xz)
        );
        assert_eq!(
            detect_compressor(&[0x28, 0xB5, 0x2F, 0xFD]),
            Some(Compressor::Zstd)
        );
        assert_eq!(detect_compressor(b"PK\x03\x04"), None);
    }

    #[test]
    fn empty_header_returns_none() {
        assert_eq!(detect_compressor(&[]), None);
    }

    #[test]
    fn is_cpio_matches_the_variants_cpio_handler_opens() {
        use std::io::Cursor;

        let mut newc = Cursor::new(b"070701000000".to_vec());
        assert!(is_cpio(&mut newc).unwrap());
        // Rewound for the caller.
        assert_eq!(newc.position(), 0);

        // odc (070707) is what `ditto` writes, so a real `.cpgz` lands here.
        let mut odc = Cursor::new(b"070707000000".to_vec());
        assert!(is_cpio(&mut odc).unwrap());
        assert_eq!(odc.position(), 0);

        // crc (070702) — three variants now, not two: `CpioHandler` gained it,
        // so it has to be claimed here too, or a `.cpio.gz` of that variant
        // would come out of the compression layer as one opaque entry while a
        // bare `.cpio` of the same bytes opened fine.
        let mut crc = Cursor::new(b"070702000000".to_vec());
        assert!(is_cpio(&mut crc).unwrap());
        assert_eq!(crc.position(), 0);

        let mut zip = Cursor::new(b"PK\x03\x04....".to_vec());
        assert!(!is_cpio(&mut zip).unwrap());

        // Shorter than the magic — no match, no panic.
        let mut tiny = Cursor::new(b"0707".to_vec());
        assert!(!is_cpio(&mut tiny).unwrap());
    }

    #[test]
    fn registry_has_expected_handlers() {
        // 21 базовый + 16 legacy (6 dos + 5 mac + 3 stuffit + alz + nsis + 3 amiga)
        // + zip-бандлы + CRX + Conda.
        //
        // Базовых стало 21: к двадцати добавился WpressHandler (`.wpress`),
        // зарегистрированный сразу за DmgHandler.
        assert_eq!(
            registry().len(),
            21 + 6 + 5 + 3 + 2 + 3 + bundle::ZIP_BUNDLES.len() + 2
        );
    }

    #[test]
    fn stem_strips_gz() {
        assert_eq!(
            stem_without_compressor_ext(Path::new("/tmp/notes.txt.gz")),
            "notes.txt"
        );
    }

    #[test]
    fn stem_strips_bz2() {
        assert_eq!(stem_without_compressor_ext(Path::new("data.bz2")), "data");
    }

    #[test]
    fn stem_strips_xz() {
        assert_eq!(
            stem_without_compressor_ext(Path::new("/path/to/archive.tar.xz")),
            "archive.tar"
        );
    }

    #[test]
    fn stem_strips_zst() {
        assert_eq!(
            stem_without_compressor_ext(Path::new("/tmp/data.tar.zst")),
            "data.tar"
        );
        assert_eq!(
            stem_without_compressor_ext(Path::new("notes.txt.zst")),
            "notes.txt"
        );
    }

    #[test]
    fn detect_compressor_recognizes_dot_z() {
        assert_eq!(
            detect_compressor(&[0x1f, 0x9d, 0x90]),
            Some(Compressor::Lzc)
        );
    }

    #[test]
    fn detect_compressor_recognizes_lz4() {
        assert_eq!(
            detect_compressor(&[0x04, 0x22, 0x4D, 0x18, 0x64]),
            Some(Compressor::Lz4)
        );
    }

    #[test]
    fn stem_strips_lz4() {
        assert_eq!(
            stem_without_compressor_ext(Path::new("/tmp/data.tar.lz4")),
            "data.tar"
        );
        assert_eq!(
            stem_without_compressor_ext(Path::new("notes.txt.lz4")),
            "notes.txt"
        );
    }

    #[test]
    fn stem_strips_dot_z() {
        assert_eq!(
            stem_without_compressor_ext(Path::new("/tmp/archive.Z")),
            "archive"
        );
        assert_eq!(
            stem_without_compressor_ext(Path::new("/tmp/data.tar.Z")),
            "data.tar"
        );
        // Lowercase ".z" is NOT a compress extension — must be left intact.
        assert_eq!(stem_without_compressor_ext(Path::new("file.z")), "file.z");
    }

    #[test]
    fn stem_no_compressor_ext_unchanged() {
        assert_eq!(
            stem_without_compressor_ext(Path::new("file.zip")),
            "file.zip"
        );
    }

    #[test]
    fn detect_compressor_by_ext_recognizes_br() {
        assert_eq!(
            detect_compressor_by_ext("data.br"),
            Some(Compressor::Brotli)
        );
        assert_eq!(
            detect_compressor_by_ext("archive.tar.br"),
            Some(Compressor::Brotli)
        );
        assert_eq!(detect_compressor_by_ext("data.txt"), None);
        assert_eq!(detect_compressor_by_ext("noext"), None);
    }

    #[test]
    fn detect_compressor_by_ext_recognizes_lzma() {
        assert_eq!(
            detect_compressor_by_ext("data.lzma"),
            Some(Compressor::Lzma)
        );
        assert_eq!(
            detect_compressor_by_ext("archive.tar.lzma"),
            Some(Compressor::Lzma)
        );
        // `.lz` is lzip, a different container. It is not claimed *here*
        // because it does not belong here: lzip has a real signature and is
        // detected by content, in `detect_compressor`, one arm below Snappy.
        // This assertion pins the split, not the absence of lzip support —
        // `detect_compressor_recognizes_lzip` is the other half of it.
        assert_eq!(detect_compressor_by_ext("data.lz"), None);
        assert_eq!(detect_compressor(b"LZIP\x01\x0c"), Some(Compressor::Lzip));
    }

    #[test]
    fn detect_compressor_recognizes_lzip() {
        // `LZIP` + format version 1 + coded dictionary size (0x0c = 4 KiB).
        assert_eq!(detect_compressor(b"LZIP\x01\x0c"), Some(Compressor::Lzip));
        // The version byte is part of the signature: version 0 is the 2008
        // format with a different trailer, and we decode only version 1, so it
        // must not be claimed here.
        assert_eq!(detect_compressor(b"LZIP\x00\x0c"), None);
        assert_eq!(detect_compressor(b"LZIP\x02\x0c"), None);
        // Magic alone, with nothing after it, is not enough.
        assert_eq!(detect_compressor(b"LZIP"), None);
    }

    #[test]
    fn lzma_has_no_content_magic() {
        // Asymmetry guard, same as Brotli's below: bare LZMA1 must never be
        // recognised by content. Its first byte is packed coder properties
        // (`5d` for the common lc/lp/pb preset), not a tag, and the next four
        // are a dictionary size — nothing there is reliably distinguishable
        // from arbitrary data, so a magic branch would produce false hits.
        assert_eq!(
            detect_compressor(&[0x5d, 0x00, 0x00, 0x80, 0x00, 0xff]),
            None
        );
    }

    #[test]
    fn brotli_has_no_content_magic() {
        // Asymmetry guard: Brotli must never be recognised by content magic —
        // it has no signature, so `detect_compressor` (the byte-magic detector)
        // must return None for it. The invariant under test is the *absence* of
        // a magic match; the particular bytes don't matter — these happen to be
        // the start of a valid Brotli stream (the first byte encodes the window
        // size, not a fixed tag), but any input that isn't another format's
        // magic would serve equally.
        assert_eq!(detect_compressor(&[0x0b, 0x00, 0x80]), None);
    }

    #[test]
    fn detect_compressor_recognizes_snappy() {
        // Framed Snappy (framing2): the stream-identifier chunk — type 0xff,
        // 3-byte length 0x000006, payload `sNaPpY`.
        assert_eq!(
            detect_compressor(&[
                0xFF, 0x06, 0x00, 0x00, 0x73, 0x4E, 0x61, 0x50, 0x70, 0x59, 0x01
            ]),
            Some(Compressor::Snappy)
        );
        // A prefix of the identifier is not enough — raw (unframed) Snappy has
        // no magic and must stay undetected.
        assert_eq!(detect_compressor(&[0xFF, 0x06, 0x00, 0x00]), None);
    }

    #[test]
    fn stem_strips_sz() {
        assert_eq!(
            stem_without_compressor_ext(Path::new("/tmp/data.tar.sz")),
            "data.tar"
        );
        assert_eq!(
            stem_without_compressor_ext(Path::new("notes.txt.sz")),
            "notes.txt"
        );
    }

    #[test]
    fn stem_strips_lz() {
        assert_eq!(
            stem_without_compressor_ext(Path::new("/tmp/payload.tar.lz")),
            "payload.tar"
        );
        assert_eq!(
            stem_without_compressor_ext(Path::new("hello.txt.lz")),
            "hello.txt"
        );
        // A `.lzma` name keeps its whole suffix: `.lz` is not a suffix of
        // `.lzma`, so only the `.lzma` row can match it.
        assert_eq!(
            stem_without_compressor_ext(Path::new("hello.txt.lzma")),
            "hello.txt"
        );
    }

    #[test]
    fn stem_strips_lzma() {
        assert_eq!(
            stem_without_compressor_ext(Path::new("/tmp/data.tar.lzma")),
            "data.tar"
        );
        assert_eq!(
            stem_without_compressor_ext(Path::new("notes.txt.lzma")),
            "notes.txt"
        );
    }

    #[test]
    fn stem_strips_br() {
        assert_eq!(
            stem_without_compressor_ext(Path::new("/tmp/data.tar.br")),
            "data.tar"
        );
        assert_eq!(
            stem_without_compressor_ext(Path::new("notes.txt.br")),
            "notes.txt"
        );
    }

    #[test]
    fn copy_slice_exact_copies_the_whole_range() {
        let mut src = std::io::Cursor::new(b"0123456789".to_vec());
        let mut out = Vec::new();
        copy_slice_exact(&mut src, 3, 4, &mut out, "test").unwrap();
        assert_eq!(out, b"3456");
    }

    #[test]
    fn copy_slice_exact_refuses_a_short_read() {
        // Обещано 8 байт с 6-го, а в источнике их всего 4: молчаливый Ok здесь
        // и есть та самая тихая потеря данных.
        let mut src = std::io::Cursor::new(b"0123456789".to_vec());
        let mut out = Vec::new();
        let err = copy_slice_exact(&mut src, 6, 8, &mut out, "warc").unwrap_err();
        let msg = err.to_string();
        assert!(matches!(err, Error::Corrupt(_)), "expected Corrupt: {msg}");
        assert!(msg.contains("warc"), "message must name the source: {msg}");
        assert!(
            msg.contains("4 of 8 bytes"),
            "message must say how much arrived: {msg}"
        );
    }
}
