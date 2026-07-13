//! DMG (`.dmg`) Apple Disk Image — UDIF container.
//!
//! A `.dmg` stores a disk image sector-range-compressed: a koly trailer (last
//! 512 bytes) points at an XML plist holding `blkx` records, each a base64
//! `mish` chunk table. Each chunk decodes to a byte range of the "raw" disk
//! image; assembling all chunks into a temp file yields a bare disk that
//! (today) holds an HFS+ volume, opened via [`open_hfsplus`](super::hfsplus::open_hfsplus).
//!
//! See `task_n_reports/task-21b-udif-container.md` for the full format
//! writeup and the offset formula this module implements.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use base64::Engine as _;

use crate::archive::{ArchiveReader, Confidence, FormatHandler, FormatId, OpenOptions, Source};
use crate::detect::TempBackedReader;
use crate::error::{Error, Result};
use crate::format::hfsplus::{
    HFS_PLUS_SIGNATURE, HFSX_SIGNATURE, VOLUME_HEADER_OFFSET, open_hfsplus,
};
use crate::format::xar::exceeds_nesting_depth;

/// Read a big-endian `u32` at byte offset `off` in `b`. Callers bounds-check
/// `b` first, so the fixed-width slice conversion never fails.
fn be_u32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(b[off..off + 4].try_into().unwrap())
}

/// Read a big-endian `u64` at byte offset `off` in `b` (see [`be_u32`]).
fn be_u64(b: &[u8], off: usize) -> u64 {
    u64::from_be_bytes(b[off..off + 8].try_into().unwrap())
}

/// Cap plist XML nesting, same rationale/guard as XAR's TOC (`xar.rs`):
/// `roxmltree` recurses per level and would overflow the stack (uncatchable
/// abort) on a deeply-nested crafted plist.
const MAX_PLIST_DEPTH: usize = 64;

/// `koly` signature, big-endian `b"koly"` read as a `u32`.
const KOLY_SIGNATURE: u32 = 0x6B6F6C79;
/// The koly trailer is always the last 512 bytes of the file.
const KOLY_SIZE: u64 = 512;

/// The koly trailer fields we need (§6.1). Everything else in the 512-byte
/// block is unused (checksums, segment metadata) and left unparsed.
#[derive(Debug)]
struct Koly {
    data_fork_offset: u64,
    xml_offset: u64,
    xml_length: u64,
}

/// Read and validate the koly trailer from the last 512 bytes of `path`.
/// A file shorter than 512 bytes or without the `koly` magic is a clean
/// detection failure (`UnknownFormat`), not a panic.
fn read_koly(path: &Path) -> Result<Koly> {
    let mut file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    if len < KOLY_SIZE {
        return Err(Error::UnknownFormat);
    }
    file.seek(SeekFrom::Start(len - KOLY_SIZE))?;
    let mut buf = [0u8; KOLY_SIZE as usize];
    file.read_exact(&mut buf)?;
    parse_koly(&buf)
}

/// Parse a 512-byte koly trailer block (already read into memory).
fn parse_koly(buf: &[u8; KOLY_SIZE as usize]) -> Result<Koly> {
    if be_u32(buf, 0x00) != KOLY_SIGNATURE {
        return Err(Error::UnknownFormat);
    }
    Ok(Koly {
        data_fork_offset: be_u64(buf, 0x18),
        xml_offset: be_u64(buf, 0xD8),
        xml_length: be_u64(buf, 0xE0),
    })
}

/// Sector size assumed throughout the mish/chunk tables (§6.3).
const SECTOR_SIZE: u64 = 512;

/// Read `[koly.xml_offset .. +xml_length]` from `path`: the DMG's XML plist.
fn read_plist_bytes(path: &Path, koly: &Koly) -> Result<Vec<u8>> {
    let mut file = std::fs::File::open(path)?;
    let file_len = file.metadata()?.len();
    // Bound the allocation by the real file size before trusting `xml_length`:
    // the koly trailer is attacker-controlled, and `xml_length` flows straight
    // into a `Vec` allocation — a crafted value would otherwise abort the
    // process (an uncatchable OOM), not fail cleanly.
    match koly.xml_offset.checked_add(koly.xml_length) {
        Some(end) if end <= file_len => {}
        _ => {
            return Err(Error::Corrupt(
                "dmg: plist offset/length out of range".into(),
            ));
        }
    }
    file.seek(SeekFrom::Start(koly.xml_offset))?;
    let mut buf = vec![0u8; koly.xml_length as usize];
    file.read_exact(&mut buf)
        .map_err(crate::error::io_err_to_corrupt)?;
    Ok(buf)
}

/// Disassemble the UDIF container at `path` (koly already validated) into a
/// raw disk image written to a fresh temp file, and return its path.
///
/// For each blkx's chunk table: chunks are decoded and written at
/// `(mish.sector_number + chunk.sector_number) · 512` in the output; the
/// file's total length is the highest sector any blkx covers. ZERO_FILL/
/// IGNORE chunks are skipped (the temp file is zero-initialized by
/// `set_len`), and COMMENT/TERMINATOR carry no payload.
fn build_raw_image(path: &Path, koly: &Koly) -> Result<tempfile::TempPath> {
    let plist_bytes = read_plist_bytes(path, koly)?;
    let blkx_entries = parse_plist_blkx(&plist_bytes)?;

    let mut mish_entries = Vec::with_capacity(blkx_entries.len());
    let mut total_sectors = 0u64;
    for mish_bytes in &blkx_entries {
        let mish = parse_mish(mish_bytes)?;
        // All sector arithmetic uses checked ops: the sector fields come from
        // the (attacker-controlled) mish table, and an overflow would panic in
        // debug or silently wrap in release.
        let end = mish
            .sector_number
            .checked_add(mish.sector_count)
            .ok_or_else(|| Error::Corrupt("dmg: mish sector range overflow".into()))?;
        total_sectors = total_sectors.max(end);
        mish_entries.push(mish);
    }
    let total_bytes = total_sectors
        .checked_mul(SECTOR_SIZE)
        .ok_or_else(|| Error::Corrupt("dmg: raw image size overflow".into()))?;

    let mut tmp = tempfile::NamedTempFile::new()?;
    tmp.as_file_mut().set_len(total_bytes)?;

    let mut src = std::fs::File::open(path)?;
    let src_len = src.metadata()?.len();
    for mish in &mish_entries {
        for chunk in &mish.chunks {
            // Payload-less chunks: the temp file is already zero-initialized by
            // `set_len`, and COMMENT/TERMINATOR carry no data.
            if matches!(
                chunk.entry_type,
                ENTRY_ZERO_FILL | ENTRY_IGNORE | ENTRY_COMMENT | ENTRY_TERMINATOR
            ) {
                continue;
            }
            let out_offset = mish
                .sector_number
                .checked_add(chunk.sector_number)
                .and_then(|s| s.checked_mul(SECTOR_SIZE))
                .ok_or_else(|| Error::Corrupt("dmg: chunk output offset overflow".into()))?;
            let out_len = chunk
                .sector_count
                .checked_mul(SECTOR_SIZE)
                .ok_or_else(|| Error::Corrupt("dmg: chunk output size overflow".into()))?
                as usize;

            let file_pos = koly
                .data_fork_offset
                .checked_add(mish.data_offset)
                .and_then(|v| v.checked_add(chunk.compressed_offset))
                .ok_or_else(|| Error::Corrupt("dmg: chunk offset overflow".into()))?;
            // Bound the compressed read by the real file size before allocating
            // `comp`: `compressed_length` is attacker-controlled and feeds a
            // `Vec` allocation directly (crafted value → process abort).
            match file_pos.checked_add(chunk.compressed_length) {
                Some(end) if end <= src_len => {}
                _ => return Err(Error::Corrupt("dmg: chunk data out of range".into())),
            }
            src.seek(SeekFrom::Start(file_pos))?;
            let mut comp = vec![0u8; chunk.compressed_length as usize];
            src.read_exact(&mut comp)
                .map_err(crate::error::io_err_to_corrupt)?;

            let decoded = decode_chunk(chunk.entry_type, &comp, out_len)?;
            tmp.as_file_mut().seek(SeekFrom::Start(out_offset))?;
            tmp.as_file_mut().write_all(&decoded)?;
        }
    }

    Ok(tmp.into_temp_path())
}

/// Locate the HFS+/HFSX volume inside the assembled raw image (§8): try offset
/// 0 first (bare volume), else sweep sector boundaries for the Volume Header
/// signature (`H+`/`HX`) at `s + VOLUME_HEADER_OFFSET`. Each signature hit is
/// fully validated by `open_hfsplus`, so a coincidental 2-byte match is
/// rejected and the sweep continues.
///
/// The sweep is a single buffered forward read: `BufReader::seek_relative`
/// keeps the small inter-sector skips inside the buffer, so a large
/// HFS+-free image (an APFS DMG, #21c) costs one read per buffer, not one
/// seek+read syscall per 512-byte sector.
fn locate_hfsplus(raw_path: &Path) -> Result<u64> {
    if open_hfsplus(raw_path, 0).is_ok() {
        return Ok(0);
    }

    let mut reader = std::io::BufReader::new(std::fs::File::open(raw_path)?);
    reader.seek_relative(VOLUME_HEADER_OFFSET as i64)?;
    let mut s = 0u64;
    let mut sig = [0u8; 2];
    while reader.read_exact(&mut sig).is_ok() {
        let signature = u16::from_be_bytes(sig);
        if (signature == HFS_PLUS_SIGNATURE || signature == HFSX_SIGNATURE)
            && open_hfsplus(raw_path, s).is_ok()
        {
            return Ok(s);
        }
        // Advance to the next sector's header: we already consumed 2 bytes.
        reader.seek_relative((SECTOR_SIZE - 2) as i64)?;
        s += SECTOR_SIZE;
    }
    Err(Error::UnknownFormat)
}

/// Decode an ADC (Apple Data Compression, UDCO) chunk: a byte-oriented LZSS
/// variant. `out_len` is the known decompressed size (`chunk.SectorCount ·
/// 512`). Reconstructed from the public format description (§7.4);
/// cross-checked against real `hdiutil -format UDCO` output in Step 0.
fn adc_decode(input: &[u8], out_len: usize) -> Result<Vec<u8>> {
    // Grow `out` as we decode rather than pre-allocating `out_len`: `out_len`
    // comes from an attacker-controlled sector count, so `vec![0u8; out_len]`
    // could abort on a crafted chunk. Growth is bounded by the input (the loop
    // stops at end-of-input), and `out_len` is only the ceiling we refuse to
    // exceed.
    let mut out: Vec<u8> = Vec::new();
    let mut i = 0usize;
    while i < input.len() && out.len() < out_len {
        let b = input[i];
        if b & 0x80 != 0 {
            // Literal run: 1xxxxxxx, length (b & 0x7F) + 1.
            let n = (b & 0x7F) as usize + 1;
            let src_end = i + 1 + n;
            if src_end > input.len() || out.len() + n > out_len {
                return Err(Error::Corrupt("dmg: ADC literal run out of bounds".into()));
            }
            out.extend_from_slice(&input[i + 1..src_end]);
            i = src_end;
        } else if b & 0x40 != 0 {
            // Long match: 01xxxxxx + 2 bytes offset, length (b & 0x3F) + 4.
            let n = (b & 0x3F) as usize + 4;
            if i + 2 >= input.len() {
                return Err(Error::Corrupt(
                    "dmg: ADC long match header truncated".into(),
                ));
            }
            let offset = ((input[i + 1] as usize) << 8) | (input[i + 2] as usize);
            adc_copy_overlap(&mut out, offset + 1, n, out_len)?;
            i += 3;
        } else {
            // Short match: 00xxxxxx, length ((b & 0x3F) >> 2) + 3, 10-bit offset.
            let n = (((b & 0x3F) >> 2) as usize) + 3;
            if i + 1 >= input.len() {
                return Err(Error::Corrupt(
                    "dmg: ADC short match header truncated".into(),
                ));
            }
            let offset = (((b & 0x03) as usize) << 8) | (input[i + 1] as usize);
            adc_copy_overlap(&mut out, offset + 1, n, out_len)?;
            i += 2;
        }
    }
    Ok(out)
}

/// Append `n` bytes to `out` copied from `back` bytes before its current end,
/// one byte at a time (LZ77-style back-references may overlap the copy
/// destination, so a bulk `copy_from_slice`/`copy_within` is not correct here).
/// `out_len` caps the output so a crafted match can't grow `out` unboundedly.
fn adc_copy_overlap(out: &mut Vec<u8>, back: usize, n: usize, out_len: usize) -> Result<()> {
    let pos = out.len();
    if back > pos || pos + n > out_len {
        return Err(Error::Corrupt(
            "dmg: ADC back-reference out of bounds".into(),
        ));
    }
    let src_start = pos - back;
    for k in 0..n {
        out.push(out[src_start + k]);
    }
    Ok(())
}

// ── mish (BLKXTable) + chunk table ──────────────────────────────────────────

/// `mish` signature, big-endian `b"mish"` read as a `u32`.
const MISH_SIGNATURE: u32 = 0x6D697368;
/// Byte offset of `NumberOfBlockChunks` within a mish block (§6.3).
const MISH_CHUNK_COUNT_OFFSET: usize = 0xC8;
/// Byte offset of the first `BLKXChunkEntry` within a mish block.
const MISH_CHUNKS_OFFSET: usize = 0xCC;
/// Size of one `BLKXChunkEntry`.
const CHUNK_ENTRY_SIZE: usize = 40;

#[derive(Debug)]
struct ChunkEntry {
    entry_type: u32,
    /// Output sector, relative to `Mish::sector_number`.
    sector_number: u64,
    sector_count: u64,
    compressed_offset: u64,
    compressed_length: u64,
}

#[derive(Debug)]
struct Mish {
    /// First output sector this blkx covers.
    sector_number: u64,
    sector_count: u64,
    /// Base offset added to each chunk's `compressed_offset` (§7.2).
    data_offset: u64,
    chunks: Vec<ChunkEntry>,
}

/// Parse a mish (BLKXTable) block: header + chunk table. `bytes` is the
/// base64-decoded `Data` field of one `blkx` plist entry.
fn parse_mish(bytes: &[u8]) -> Result<Mish> {
    if bytes.len() < MISH_CHUNKS_OFFSET {
        return Err(Error::Corrupt("dmg: mish block truncated (header)".into()));
    }
    let sig = be_u32(bytes, 0x00);
    if sig != MISH_SIGNATURE {
        return Err(Error::Corrupt(format!(
            "dmg: bad mish signature {sig:#010x}"
        )));
    }
    let sector_number = be_u64(bytes, 0x08);
    let sector_count = be_u64(bytes, 0x10);
    let data_offset = be_u64(bytes, 0x18);
    let num_chunks = be_u32(bytes, MISH_CHUNK_COUNT_OFFSET) as usize;

    let needed = MISH_CHUNKS_OFFSET + num_chunks * CHUNK_ENTRY_SIZE;
    if bytes.len() < needed {
        return Err(Error::Corrupt(
            "dmg: mish block truncated (chunk table)".into(),
        ));
    }

    let mut chunks = Vec::with_capacity(num_chunks);
    for i in 0..num_chunks {
        let off = MISH_CHUNKS_OFFSET + i * CHUNK_ENTRY_SIZE;
        chunks.push(ChunkEntry {
            entry_type: be_u32(bytes, off),
            sector_number: be_u64(bytes, off + 8),
            sector_count: be_u64(bytes, off + 16),
            compressed_offset: be_u64(bytes, off + 24),
            compressed_length: be_u64(bytes, off + 32),
        });
    }

    Ok(Mish {
        sector_number,
        sector_count,
        data_offset,
        chunks,
    })
}

// ── plist / blkx ─────────────────────────────────────────────────────────────

/// Decode a base64 blob, ignoring embedded whitespace (plist `<data>` text
/// nodes wrap their base64 across multiple lines).
fn decode_base64(s: &str) -> Result<Vec<u8>> {
    let filtered: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(filtered.as_bytes())
        .map_err(|e| Error::Corrupt(format!("dmg: base64 decode: {e}")))
}

/// Find the value element paired with `<key>{key}</key>` as a direct child of
/// `dict_node` — plist dicts store pairs as adjacent key/value sibling
/// elements in document order (no attributes to match on).
fn dict_value<'a, 'input>(
    dict_node: roxmltree::Node<'a, 'input>,
    key: &str,
) -> Option<roxmltree::Node<'a, 'input>> {
    let mut children = dict_node.children().filter(|c| c.is_element());
    while let Some(c) = children.next() {
        if c.has_tag_name("key") && c.text() == Some(key) {
            return children.next();
        }
    }
    None
}

/// Parse the DMG XML plist and return each `blkx` entry's base64-decoded `mish`
/// chunk table (still to be parsed by [`parse_mish`]), in document order.
fn parse_plist_blkx(xml_bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    let xml = std::str::from_utf8(xml_bytes)
        .map_err(|_| Error::Corrupt("dmg: plist is not valid UTF-8".into()))?;
    if exceeds_nesting_depth(xml, MAX_PLIST_DEPTH) {
        return Err(Error::Corrupt("dmg: plist nesting too deep".into()));
    }
    // Real DMG plists carry an Apple DOCTYPE (`<!DOCTYPE plist PUBLIC ...>`),
    // so DTD parsing must be allowed. Safe: no `entity_resolver` is set, so
    // the external DTD it references is never fetched (roxmltree does no
    // I/O), and roxmltree still guards against billion-laughs internally.
    let opts = roxmltree::ParsingOptions {
        allow_dtd: true,
        ..roxmltree::ParsingOptions::default()
    };
    let doc = roxmltree::Document::parse_with_options(xml, opts)
        .map_err(|e| Error::Corrupt(format!("dmg: plist XML: {e}")))?;
    let root = doc.root_element(); // <plist>
    let top_dict = root
        .children()
        .find(|c| c.is_element() && c.has_tag_name("dict"))
        .ok_or_else(|| Error::Corrupt("dmg: plist missing top-level dict".into()))?;
    let rsrc_fork = dict_value(top_dict, "resource-fork")
        .ok_or_else(|| Error::Corrupt("dmg: plist missing resource-fork".into()))?;
    let blkx_array = dict_value(rsrc_fork, "blkx")
        .ok_or_else(|| Error::Corrupt("dmg: plist missing blkx".into()))?;
    if !blkx_array.has_tag_name("array") {
        return Err(Error::Corrupt("dmg: blkx is not an array".into()));
    }

    let mut out = Vec::new();
    for entry in blkx_array
        .children()
        .filter(|c| c.is_element() && c.has_tag_name("dict"))
    {
        let data_node = dict_value(entry, "Data")
            .ok_or_else(|| Error::Corrupt("dmg: blkx entry missing Data".into()))?;
        out.push(decode_base64(data_node.text().unwrap_or(""))?);
    }
    Ok(out)
}

// ── chunk decode (§7) ────────────────────────────────────────────────────────

const ENTRY_ZERO_FILL: u32 = 0x0000_0000;
const ENTRY_RAW: u32 = 0x0000_0001;
const ENTRY_IGNORE: u32 = 0x0000_0002;
const ENTRY_ADC: u32 = 0x8000_0004;
const ENTRY_ZLIB: u32 = 0x8000_0005;
const ENTRY_BZIP2: u32 = 0x8000_0006;
const ENTRY_LZFSE: u32 = 0x8000_0007;
const ENTRY_LZMA: u32 = 0x8000_0008;
const ENTRY_COMMENT: u32 = 0x7FFF_FFFE;
const ENTRY_TERMINATOR: u32 = 0xFFFF_FFFF;

/// Read a decoder stream to end. Output grows as it goes (no
/// `with_capacity(out_len)`): `out_len` is derived from an attacker-controlled
/// sector count, so pre-sizing to it could abort on a crafted chunk. Real
/// output is bounded by the compressed stream, and `decode_chunk` verifies the
/// final length.
fn read_all(mut r: impl Read) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    r.read_to_end(&mut v)
        .map_err(crate::error::io_err_to_corrupt)?;
    Ok(v)
}

/// Decode one chunk's compressed bytes into exactly `out_len` decoded bytes.
/// Only called for entry types that carry payload (ZERO_FILL/IGNORE/COMMENT/
/// TERMINATOR are filtered out by the caller before reaching here — they have
/// no compressed data to decode).
fn decode_chunk(entry_type: u32, comp: &[u8], out_len: usize) -> Result<Vec<u8>> {
    let out = match entry_type {
        ENTRY_RAW => comp.to_vec(),
        ENTRY_ZLIB => read_all(flate2::read::ZlibDecoder::new(comp))?,
        ENTRY_BZIP2 => read_all(bzip2::read::BzDecoder::new(comp))?,
        ENTRY_LZMA => read_all(xz2::read::XzDecoder::new(comp))?,
        ENTRY_LZFSE => {
            let mut v = Vec::new();
            lzfse_rust::decode_bytes(comp, &mut v)
                .map_err(|e| Error::Corrupt(format!("dmg: lzfse decode: {e}")))?;
            v
        }
        ENTRY_ADC => adc_decode(comp, out_len)?,
        other => {
            return Err(Error::Corrupt(format!(
                "dmg: unknown chunk type {other:#010x}"
            )));
        }
    };
    if out.len() != out_len {
        return Err(Error::Corrupt(format!(
            "dmg: chunk decoded to {} bytes, expected {out_len}",
            out.len()
        )));
    }
    Ok(out)
}

/// Reads DMG (UDIF) disk images: decodes the koly/plist/blkx/mish chunk
/// tables into a raw disk image, locates the HFS+ volume inside, and
/// delegates to [`open_hfsplus`].
pub struct DmgHandler;

impl FormatHandler for DmgHandler {
    fn id(&self) -> FormatId {
        FormatId::Dmg
    }

    /// Detect by extension only: the `koly` trailer lives in the last 512
    /// bytes of the file, unreachable from the 512-byte header the registry
    /// peeks (same situation as ISO/HFS+). `koly` itself is validated in
    /// `open`.
    fn probe(&self, _header: &[u8], name: Option<&str>) -> Confidence {
        let is_dmg = name.is_some_and(|n| {
            Path::new(n)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("dmg"))
        });
        if is_dmg {
            Confidence::MAGIC
        } else {
            Confidence::NONE
        }
    }

    fn open(&self, src: Source, _opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        let path = src
            .file_path()
            .ok_or_else(|| Error::Unsupported {
                format: "dmg".into(),
                feature: "non-file source (dmg requires a file path)".into(),
            })?
            .to_path_buf();

        let koly = read_koly(&path)?;
        let temp_path = build_raw_image(&path, &koly)?;
        let offset = locate_hfsplus(&temp_path)?;
        let inner = open_hfsplus(&temp_path, offset)?;
        Ok(Box::new(TempBackedReader::with_format(
            inner,
            temp_path,
            FormatId::Dmg,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_is_dmg() {
        assert_eq!(DmgHandler.id(), FormatId::Dmg);
    }

    #[test]
    fn probe_dmg_extension_is_magic() {
        assert_eq!(DmgHandler.probe(&[], Some("image.dmg")), Confidence::MAGIC);
    }

    #[test]
    fn probe_dmg_extension_case_insensitive() {
        assert_eq!(DmgHandler.probe(&[], Some("Image.DMG")), Confidence::MAGIC);
    }

    #[test]
    fn probe_other_extension_is_none() {
        assert_eq!(DmgHandler.probe(&[], Some("image.hfs")), Confidence::NONE);
    }

    #[test]
    fn probe_no_name_is_none() {
        assert_eq!(DmgHandler.probe(&[], None), Confidence::NONE);
    }

    #[test]
    fn open_path_less_source_is_unsupported() {
        let src = Source::Stream {
            inner: Box::new(std::io::empty()),
            path: None,
        };
        let err = DmgHandler
            .open(src, &OpenOptions::default())
            .err()
            .expect("path-less source must be unsupported");
        assert!(matches!(err, Error::Unsupported { .. }), "got {err:?}");
    }

    // ── koly trailer ─────────────────────────────────────────────────────────

    fn synthetic_koly(data_fork_offset: u64, xml_offset: u64, xml_length: u64) -> [u8; 512] {
        let mut buf = [0u8; 512];
        buf[0x00..0x04].copy_from_slice(b"koly");
        buf[0x18..0x20].copy_from_slice(&data_fork_offset.to_be_bytes());
        buf[0xD8..0xE0].copy_from_slice(&xml_offset.to_be_bytes());
        buf[0xE0..0xE8].copy_from_slice(&xml_length.to_be_bytes());
        buf
    }

    #[test]
    fn parse_koly_extracts_offsets() {
        let buf = synthetic_koly(0, 11379, 8264);
        let koly = parse_koly(&buf).expect("valid koly");
        assert_eq!(koly.data_fork_offset, 0);
        assert_eq!(koly.xml_offset, 11379);
        assert_eq!(koly.xml_length, 8264);
    }

    #[test]
    fn parse_koly_nonzero_data_fork_offset() {
        let buf = synthetic_koly(4096, 20000, 500);
        let koly = parse_koly(&buf).expect("valid koly");
        assert_eq!(koly.data_fork_offset, 4096);
        assert_eq!(koly.xml_offset, 20000);
        assert_eq!(koly.xml_length, 500);
    }

    #[test]
    fn parse_koly_rejects_bad_magic() {
        let mut buf = synthetic_koly(0, 0, 0);
        buf[0..4].copy_from_slice(b"NOPE");
        let err = parse_koly(&buf).expect_err("must error");
        assert!(matches!(err, Error::UnknownFormat), "got {err:?}");
    }

    #[test]
    fn read_koly_rejects_short_file() {
        let mut f = tempfile::NamedTempFile::new().expect("tmp");
        f.write_all(&[0u8; 100]).expect("write");
        f.flush().expect("flush");
        let err = read_koly(f.path()).expect_err("must error");
        assert!(matches!(err, Error::UnknownFormat), "got {err:?}");
    }

    #[test]
    fn read_koly_reads_trailer_from_end_of_file() {
        let mut f = tempfile::NamedTempFile::new().expect("tmp");
        // Some leading padding, then the koly trailer at the very end.
        f.write_all(&[0xAAu8; 1000]).expect("write padding");
        let koly_bytes = synthetic_koly(0, 1000, 42);
        f.write_all(&koly_bytes).expect("write koly");
        f.flush().expect("flush");
        let koly = read_koly(f.path()).expect("valid koly");
        assert_eq!(koly.xml_offset, 1000);
        assert_eq!(koly.xml_length, 42);
    }

    // ── ADC decoder ──────────────────────────────────────────────────────────

    #[test]
    fn adc_decodes_literal_run() {
        // 0x84 = 1_0000100 -> literal run of 5 bytes.
        let input = [0x84u8, b'h', b'e', b'l', b'l', b'o'];
        let out = adc_decode(&input, 5).expect("decode");
        assert_eq!(out, b"hello");
    }

    #[test]
    fn adc_decodes_short_match() {
        // "AB" literal (n=2 -> byte 0x81), then a short match copying "AB"
        // again: 00xxxxxx with n = ((b&0x3F)>>2)+3 = 2 -> b's top nibble bits
        // (b&0x3F)>>2 == -1 impossible (min n=3), so copy 3 bytes "ABA":
        // offset = 1 (back-reference of 2, i.e. offset field 1 -> back=2).
        let mut input = vec![0x81u8, b'A', b'B']; // literal run "AB"
        // short match: b = 0b00_000000 | ((n-3)<<2) | (offset_hi), n=3, offset=1 (back=2)
        let n = 3u8;
        let offset: u16 = 1; // back = offset+1 = 2
        let b = ((n - 3) << 2) | ((offset >> 8) as u8 & 0x03);
        input.push(b);
        input.push((offset & 0xFF) as u8);
        let out = adc_decode(&input, 5).expect("decode");
        assert_eq!(out, b"ABABA");
    }

    #[test]
    fn adc_decodes_long_match() {
        // Literal "AB" (back=2 available), then a long match: 01xxxxxx + 2
        // bytes offset, n = (b&0x3F)+4 = 4, offset=1 (back=2) -> copies "ABAB".
        let mut input = vec![0x81u8, b'A', b'B'];
        let n: u8 = 4;
        let offset: u16 = 1; // back = offset+1 = 2
        let b = 0x40 | (n - 4);
        input.push(b);
        input.push((offset >> 8) as u8);
        input.push((offset & 0xFF) as u8);
        let out = adc_decode(&input, 6).expect("decode");
        assert_eq!(out, b"ABABAB");
    }

    #[test]
    fn adc_overlapping_match_expands_pattern() {
        // "A" literal, then a short match with back=1 (offset=0), n=3: each
        // copied byte must see the byte just written (overlap), producing
        // "AAAA" (1 literal + 3-byte overlapping copy).
        let mut input = vec![0x80u8, b'A']; // literal run of 1: "A"
        let n = 3u8;
        let offset: u16 = 0; // back = offset+1 = 1
        let b = ((n - 3) << 2) | ((offset >> 8) as u8 & 0x03);
        input.push(b);
        input.push((offset & 0xFF) as u8);
        let out = adc_decode(&input, 4).expect("decode");
        assert_eq!(out, b"AAAA");
    }

    #[test]
    fn adc_rejects_back_reference_before_start() {
        // A short match as the very first token: back-reference with nothing
        // written yet must error, not panic/underflow.
        let input = [0x00u8, 0x00u8]; // n=3, offset=0 -> back=1, but pos=0
        let err = adc_decode(&input, 3).expect_err("must error");
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }

    #[test]
    fn adc_rejects_literal_run_past_output_bounds() {
        // out_len=2 but literal run wants to write 5 bytes.
        let input = [0x84u8, b'h', b'e', b'l', b'l', b'o'];
        let err = adc_decode(&input, 2).expect_err("must error");
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }

    #[test]
    fn adc_real_udco_vector_matches_hdiutil_oracle() {
        // Real chunk 0 extracted from `hdiutil -format UDCO` output during
        // Step 0 (task §4): the Protective MBR block, entry_type 0x80000004.
        // Verified byte-for-byte against `hdiutil convert -format UDTO`.
        let comp: &[u8] = include_bytes!("../../tests/fixtures/dmg_adc_chunk0.bin");
        let expected: &[u8] = include_bytes!("../../tests/fixtures/dmg_adc_chunk0.expected");
        let out = adc_decode(comp, expected.len()).expect("decode");
        assert_eq!(out, expected);
    }

    // ── mish / chunk table ───────────────────────────────────────────────────

    /// Build a synthetic mish block: header fields + a chunk table, matching
    /// the byte layout in task §6.3 (all fields big-endian).
    fn synthetic_mish(
        sector_number: u64,
        sector_count: u64,
        data_offset: u64,
        chunks: &[(u32, u64, u64, u64, u64)],
    ) -> Vec<u8> {
        let mut buf = vec![0u8; MISH_CHUNKS_OFFSET + chunks.len() * CHUNK_ENTRY_SIZE];
        buf[0x00..0x04].copy_from_slice(b"mish");
        buf[0x04..0x08].copy_from_slice(&1u32.to_be_bytes()); // version
        buf[0x08..0x10].copy_from_slice(&sector_number.to_be_bytes());
        buf[0x10..0x18].copy_from_slice(&sector_count.to_be_bytes());
        buf[0x18..0x20].copy_from_slice(&data_offset.to_be_bytes());
        buf[MISH_CHUNK_COUNT_OFFSET..MISH_CHUNK_COUNT_OFFSET + 4]
            .copy_from_slice(&(chunks.len() as u32).to_be_bytes());
        for (i, &(entry_type, c_sector, c_count, c_off, c_len)) in chunks.iter().enumerate() {
            let off = MISH_CHUNKS_OFFSET + i * CHUNK_ENTRY_SIZE;
            buf[off..off + 4].copy_from_slice(&entry_type.to_be_bytes());
            // Comment field (off+4..off+8) left zeroed -- unused.
            buf[off + 8..off + 16].copy_from_slice(&c_sector.to_be_bytes());
            buf[off + 16..off + 24].copy_from_slice(&c_count.to_be_bytes());
            buf[off + 24..off + 32].copy_from_slice(&c_off.to_be_bytes());
            buf[off + 32..off + 40].copy_from_slice(&c_len.to_be_bytes());
        }
        buf
    }

    #[test]
    fn parse_mish_extracts_header_and_chunks() {
        let bytes = synthetic_mish(
            40,
            3720,
            0,
            &[
                (0x80000005, 0, 2010, 6060, 5319),
                (0x00000000, 2010, 38, 0, 0),
                (0xFFFFFFFF, 2048, 0, 0, 0),
            ],
        );
        let mish = parse_mish(&bytes).expect("valid mish");
        assert_eq!(mish.sector_number, 40);
        assert_eq!(mish.sector_count, 3720);
        assert_eq!(mish.data_offset, 0);
        assert_eq!(mish.chunks.len(), 3);
        assert_eq!(mish.chunks[0].entry_type, 0x80000005);
        assert_eq!(mish.chunks[0].sector_count, 2010);
        assert_eq!(mish.chunks[0].compressed_offset, 6060);
        assert_eq!(mish.chunks[0].compressed_length, 5319);
        assert_eq!(mish.chunks[2].entry_type, 0xFFFFFFFF);
    }

    #[test]
    fn parse_mish_rejects_bad_signature() {
        let mut bytes = synthetic_mish(0, 0, 0, &[]);
        bytes[0..4].copy_from_slice(b"NOPE");
        let err = parse_mish(&bytes).expect_err("must error");
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }

    #[test]
    fn parse_mish_rejects_truncated_header() {
        let bytes = vec![0u8; 10]; // shorter than MISH_CHUNKS_OFFSET
        let err = parse_mish(&bytes).expect_err("must error");
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }

    #[test]
    fn parse_mish_rejects_truncated_chunk_table() {
        let mut bytes = synthetic_mish(0, 0, 0, &[(0x1, 0, 1, 0, 512)]);
        bytes.truncate(bytes.len() - 5); // chop the last chunk entry short
        let err = parse_mish(&bytes).expect_err("must error");
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }

    // ── base64 / plist ───────────────────────────────────────────────────────

    #[test]
    fn decode_base64_known_vector() {
        assert_eq!(decode_base64("bWlzaA==").expect("decode"), b"mish");
    }

    #[test]
    fn decode_base64_ignores_embedded_newlines() {
        assert_eq!(decode_base64("bWlz\naA==\n").expect("decode"), b"mish");
    }

    #[test]
    fn decode_base64_rejects_invalid_input() {
        assert!(decode_base64("not valid base64!!!").is_err());
    }

    fn plist_with_one_blkx(cfname: &str, mish_b64: &str) -> Vec<u8> {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>resource-fork</key>
    <dict>
        <key>blkx</key>
        <array>
            <dict>
                <key>Attributes</key><string>0x0050</string>
                <key>CFName</key><string>{cfname}</string>
                <key>Data</key><data>{mish_b64}</data>
                <key>ID</key><string>-1</string>
            </dict>
        </array>
    </dict>
</dict>
</plist>"#
        )
        .into_bytes()
    }

    #[test]
    fn parse_plist_blkx_extracts_mish() {
        let mish = synthetic_mish(0, 1, 0, &[(0x1, 0, 1, 0, 512)]);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&mish);
        let xml = plist_with_one_blkx("disk image (Apple_HFS : 4)", &b64);

        let entries = parse_plist_blkx(&xml).expect("parse plist");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], mish);
    }

    #[test]
    fn parse_plist_blkx_rejects_missing_blkx() {
        let xml = br#"<?xml version="1.0"?><plist><dict><key>other</key><dict/></dict></plist>"#;
        let err = parse_plist_blkx(xml).expect_err("must error");
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }

    #[test]
    fn parse_plist_blkx_rejects_malformed_xml() {
        let xml = b"<plist><dict>not closed";
        let err = parse_plist_blkx(xml).expect_err("must error");
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }

    #[test]
    fn parse_plist_blkx_accepts_real_apple_doctype() {
        // Real `hdiutil`-generated plists carry this DOCTYPE line; roxmltree
        // rejects any DTD by default (`allow_dtd: false`), so this proves the
        // parser explicitly opts in rather than merely tolerating DTD-less input.
        let mish = synthetic_mish(0, 1, 0, &[(0x1, 0, 1, 0, 512)]);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&mish);
        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>resource-fork</key>
    <dict>
        <key>blkx</key>
        <array>
            <dict>
                <key>CFName</key><string>disk image (Apple_HFS : 4)</string>
                <key>Data</key><data>{b64}</data>
            </dict>
        </array>
    </dict>
</dict>
</plist>"#
        )
        .into_bytes();

        let entries = parse_plist_blkx(&xml).expect("parse plist with DOCTYPE");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], mish);
    }

    // ── decode_chunk ─────────────────────────────────────────────────────────

    #[test]
    fn decode_chunk_raw_copies_bytes() {
        let out = decode_chunk(ENTRY_RAW, b"hello dmg\n", 10).expect("decode");
        assert_eq!(out, b"hello dmg\n");
    }

    #[test]
    fn decode_chunk_zlib_known_vector() {
        use std::io::Write as _;
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(b"hello dmg zlib chunk").unwrap();
        let comp = enc.finish().unwrap();
        let out = decode_chunk(ENTRY_ZLIB, &comp, 20).expect("decode");
        assert_eq!(out, b"hello dmg zlib chunk");
    }

    #[test]
    fn decode_chunk_bzip2_known_vector() {
        use std::io::Write as _;
        let mut enc = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
        enc.write_all(b"hello dmg bzip2 chunk").unwrap();
        let comp = enc.finish().unwrap();
        let out = decode_chunk(ENTRY_BZIP2, &comp, 21).expect("decode");
        assert_eq!(out, b"hello dmg bzip2 chunk");
    }

    #[test]
    fn decode_chunk_xz_known_vector() {
        use std::io::Write as _;
        let mut enc = xz2::write::XzEncoder::new(Vec::new(), 6);
        enc.write_all(b"hello dmg xz chunk").unwrap();
        let comp = enc.finish().unwrap();
        let out = decode_chunk(ENTRY_LZMA, &comp, 18).expect("decode");
        assert_eq!(out, b"hello dmg xz chunk");
    }

    #[test]
    fn decode_chunk_lzfse_real_vector_matches_hdiutil_oracle() {
        // Real ULFO chunk 0 (Protective MBR block) from Step 0 (task §4),
        // verified against `hdiutil convert -format UDTO`.
        let comp: &[u8] = include_bytes!("../../tests/fixtures/dmg_lzfse_chunk0.bin");
        let expected: &[u8] = include_bytes!("../../tests/fixtures/dmg_lzfse_chunk0.expected");
        let out = decode_chunk(ENTRY_LZFSE, comp, expected.len()).expect("decode");
        assert_eq!(out, expected);
    }

    #[test]
    fn decode_chunk_adc_real_vector_matches_hdiutil_oracle() {
        let comp: &[u8] = include_bytes!("../../tests/fixtures/dmg_adc_chunk0.bin");
        let expected: &[u8] = include_bytes!("../../tests/fixtures/dmg_adc_chunk0.expected");
        let out = decode_chunk(ENTRY_ADC, comp, expected.len()).expect("decode");
        assert_eq!(out, expected);
    }

    #[test]
    fn decode_chunk_unknown_entry_type_is_corrupt() {
        let err = decode_chunk(0x1234_5678, b"", 0).expect_err("must error");
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }

    #[test]
    fn decode_chunk_length_mismatch_is_corrupt() {
        let err = decode_chunk(ENTRY_RAW, b"abc", 10).expect_err("must error");
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }
}
