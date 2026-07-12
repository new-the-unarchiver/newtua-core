use std::collections::HashMap;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::archive::{
    ArchiveReader, Confidence, Entry, EntryKind, FormatHandler, FormatId, OpenOptions, ReadSeek,
    Source,
};
use crate::error::{Error, Result, io_err_to_corrupt};

/// WIM magic `MSWIM\0\0\0` at offset 0.
const MAGIC: &[u8; 8] = b"MSWIM\0\0\0";
/// Fixed header size (`WIMHEADER_V1_PACKED`).
const HEADER_LEN: usize = 208;

const FLAG_SPANNED: u32 = 0x0000_0008;
const FLAG_HEADER_COMPRESSION: u32 = 0x0000_0002;
const FLAG_COMPRESS_XPRESS: u32 = 0x0002_0000;
const FLAG_COMPRESS_LZX: u32 = 0x0004_0000;
const FLAG_COMPRESS_LZMS: u32 = 0x0008_0000;

/// Image-wide resource compressor, as declared by the WIM header's
/// `dwFlags`. Every compressed resource in the file uses this codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Compressor {
    Xpress,
    /// Decoded via `newtua_mscompress::lzx` (task 20c) — a port of the
    /// `lzxd` crate's CAB-LZX core with the WIM-specific framing
    /// differences documented on that module. See
    /// `task_n_reports/report-20c-mscompress-lzx.md`.
    Lzx,
    /// Detected but not decodable at all (no decoder yet) — task 20d.
    Lzms,
}

/// Parsed `WIMHEADER_V1_PACKED` (208 bytes at offset 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WimHeader {
    /// Chunk size for compressed resources (0 when the header carries no
    /// compression at all).
    pub(crate) chunk_size: u32,
    /// `None` when `HEADER_COMPRESSION` is unset (all resources stored raw).
    pub(crate) compressor: Option<Compressor>,
    pub(crate) part_number: u16,
    pub(crate) total_parts: u16,
    pub(crate) image_count: u32,
    pub(crate) offset_table: ResourceHeader,
    pub(crate) boot_metadata: ResourceHeader,
}

impl WimHeader {
    pub(crate) fn spanned(&self) -> bool {
        self.total_parts > 1
    }

    fn parse(b: &[u8]) -> Result<Self> {
        if b.len() < HEADER_LEN {
            return Err(Error::Corrupt("wim: header shorter than 208 bytes".into()));
        }
        if &b[0..8] != MAGIC {
            return Err(Error::Corrupt("wim: bad magic".into()));
        }
        let dw_flags = u32::from_le_bytes(b[16..20].try_into().unwrap());
        let chunk_size = u32::from_le_bytes(b[20..24].try_into().unwrap());
        let part_number = u16::from_le_bytes(b[40..42].try_into().unwrap());
        let total_parts = u16::from_le_bytes(b[42..44].try_into().unwrap());
        let image_count = u32::from_le_bytes(b[44..48].try_into().unwrap());
        let offset_table = ResourceHeader::parse(&b[48..72])?;
        let boot_metadata = ResourceHeader::parse(&b[96..120])?;

        let compressor = if dw_flags & FLAG_HEADER_COMPRESSION != 0 {
            let xpress = dw_flags & FLAG_COMPRESS_XPRESS != 0;
            let lzx = dw_flags & FLAG_COMPRESS_LZX != 0;
            let lzms = dw_flags & FLAG_COMPRESS_LZMS != 0;
            match (xpress, lzx, lzms) {
                (true, false, false) => Some(Compressor::Xpress),
                (false, true, false) => Some(Compressor::Lzx),
                (false, false, true) => Some(Compressor::Lzms),
                _ => {
                    return Err(Error::Corrupt(
                        "wim: HEADER_COMPRESSION set but compressor flags are ambiguous".into(),
                    ));
                }
            }
        } else {
            None
        };

        let spanned_flag = dw_flags & FLAG_SPANNED != 0;
        if spanned_flag && total_parts <= 1 {
            // A file can claim SPANNED without usTotalParts agreeing; treat the
            // flag as authoritative so callers still see it as spanned.
        }

        Ok(WimHeader {
            chunk_size,
            compressor,
            part_number,
            total_parts: if spanned_flag && total_parts <= 1 {
                total_parts.max(2)
            } else {
                total_parts
            },
            image_count,
            offset_table,
            boot_metadata,
        })
    }
}

/// `RESHDR_DISK_SHORT` (24 bytes): how the WIM header and lookup table refer
/// to any resource (offset/size on disk, decompressed size, flags).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct ResourceHeader {
    pub(crate) size_on_disk: u64,
    pub(crate) flags: u8,
    pub(crate) offset: u64,
    pub(crate) original_size: u64,
}

impl ResourceHeader {
    const FLAG_METADATA: u8 = 0x02;
    const FLAG_COMPRESSED: u8 = 0x04;

    fn parse(b: &[u8]) -> Result<Self> {
        if b.len() < 24 {
            return Err(Error::Corrupt(
                "wim: resource header shorter than 24 bytes".into(),
            ));
        }
        let raw = u64::from_le_bytes(b[0..8].try_into().unwrap());
        let size_on_disk = raw & 0x00FF_FFFF_FFFF_FFFF;
        let flags = (raw >> 56) as u8;
        let offset = u64::from_le_bytes(b[8..16].try_into().unwrap());
        let original_size = u64::from_le_bytes(b[16..24].try_into().unwrap());
        Ok(ResourceHeader {
            size_on_disk,
            flags,
            offset,
            original_size,
        })
    }

    pub(crate) fn is_metadata(&self) -> bool {
        self.flags & Self::FLAG_METADATA != 0
    }

    pub(crate) fn is_compressed(&self) -> bool {
        self.flags & Self::FLAG_COMPRESSED != 0
    }
}

/// One `WIM_LOOKUP_TABLE_ENTRY` (50 bytes): resource location plus the SHA-1
/// of its decompressed content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LookupEntry {
    pub(crate) resource: ResourceHeader,
    pub(crate) hash: [u8; 20],
}

const LOOKUP_ENTRY_LEN: usize = 50;

/// Parse a lookup-table resource (already decompressed) into its entries.
pub(crate) fn parse_lookup_table(bytes: &[u8]) -> Result<Vec<LookupEntry>> {
    if bytes.len() % LOOKUP_ENTRY_LEN != 0 {
        return Err(Error::Corrupt(format!(
            "wim: lookup table size {} is not a multiple of {LOOKUP_ENTRY_LEN}",
            bytes.len()
        )));
    }
    let mut out = Vec::with_capacity(bytes.len() / LOOKUP_ENTRY_LEN);
    for entry in bytes.chunks(LOOKUP_ENTRY_LEN) {
        let resource = ResourceHeader::parse(&entry[0..24])?;
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&entry[30..50]);
        out.push(LookupEntry { resource, hash });
    }
    Ok(out)
}

/// Read one resource fully into memory, decoding it if the resource's own
/// `COMPRESSED` flag is set. `header_compressor` is the WIM's image-wide
/// codec (`None` when the file carries no compression at all); it is only
/// consulted for resources that are actually marked compressed — the
/// lookup table itself is typically stored raw even in a compressed WIM.
pub(crate) fn read_resource(
    src: &mut dyn ReadSeek,
    chunk_size: u32,
    header_compressor: Option<Compressor>,
    rh: &ResourceHeader,
) -> Result<Vec<u8>> {
    src.seek(SeekFrom::Start(rh.offset))?;
    let mut raw = vec![0u8; rh.size_on_disk as usize];
    src.read_exact(&mut raw).map_err(io_err_to_corrupt)?;

    if !rh.is_compressed() {
        return Ok(raw);
    }
    let compressor = header_compressor.ok_or_else(|| {
        Error::Corrupt("wim: resource is COMPRESSED but the header has no compressor".into())
    })?;
    decode_chunked_resource(
        &raw,
        chunk_size as usize,
        rh.original_size as usize,
        compressor,
    )
}

/// Decode a compressed resource's raw on-disk bytes (an optional chunk
/// offset table followed by chunk data) into its full decompressed content.
fn decode_chunked_resource(
    raw: &[u8],
    chunk_size: usize,
    original_size: usize,
    compressor: Compressor,
) -> Result<Vec<u8>> {
    if original_size == 0 {
        return Ok(Vec::new());
    }
    let num_chunks = original_size.div_ceil(chunk_size);
    if num_chunks <= 1 {
        // Single-chunk resource: no offset table, the whole buffer is one chunk.
        return decode_one_chunk(raw, original_size, compressor);
    }

    // Chunk offset table: (num_chunks - 1) little-endian entries, u32 unless
    // the resource is >= 4 GiB uncompressed. Entry i is the byte offset (from
    // the start of the chunk *data*, i.e. right after this table) where
    // chunk i+1 begins; chunk 0 implicitly starts at offset 0.
    let entry_width = if (original_size as u64) < 0xFFFF_FFFF {
        4
    } else {
        8
    };
    let table_len = (num_chunks - 1) * entry_width;
    if raw.len() < table_len {
        return Err(Error::Corrupt(
            "wim: resource shorter than its chunk offset table".into(),
        ));
    }
    let mut chunk_ends = Vec::with_capacity(num_chunks);
    for i in 0..num_chunks - 1 {
        let v = if entry_width == 4 {
            u32::from_le_bytes(raw[i * 4..i * 4 + 4].try_into().unwrap()) as u64
        } else {
            u64::from_le_bytes(raw[i * 8..i * 8 + 8].try_into().unwrap())
        };
        chunk_ends.push(v);
    }
    let data = &raw[table_len..];
    chunk_ends.push(data.len() as u64);

    let mut out = Vec::with_capacity(original_size);
    let mut start = 0u64;
    for (i, &end) in chunk_ends.iter().enumerate() {
        if end < start || end as usize > data.len() {
            return Err(Error::Corrupt("wim: bad chunk offset table entry".into()));
        }
        let compressed_chunk = &data[start as usize..end as usize];
        let uncompressed_len = if i + 1 == num_chunks {
            let rem = original_size % chunk_size;
            if rem == 0 { chunk_size } else { rem }
        } else {
            chunk_size
        };
        out.extend_from_slice(&decode_one_chunk(
            compressed_chunk,
            uncompressed_len,
            compressor,
        )?);
        start = end;
    }
    Ok(out)
}

/// Decode one chunk: a verbatim copy when the "compressed" size already
/// equals the uncompressed size (WIM's stored-chunk convention — the codec
/// would have expanded this particular chunk, so the encoder skipped it),
/// else run the image codec.
fn decode_one_chunk(
    compressed: &[u8],
    uncompressed_len: usize,
    compressor: Compressor,
) -> Result<Vec<u8>> {
    if compressed.len() == uncompressed_len {
        return Ok(compressed.to_vec());
    }
    match compressor {
        Compressor::Xpress => decode_xpress_chunk(compressed, uncompressed_len),
        Compressor::Lzx => decode_lzx_chunk(compressed, uncompressed_len),
        Compressor::Lzms => Err(Error::Unsupported {
            format: "wim".into(),
            feature: "LZMS compression (.esd)".into(),
        }),
    }
}

/// Decode one XPRESS-Huffman chunk via `newtua_mscompress`. WIM supplies the
/// chunk's uncompressed length externally (the offset table / resource
/// header) — the MS-XCA bitstream itself carries no length prefix.
fn decode_xpress_chunk(compressed: &[u8], uncompressed_len: usize) -> Result<Vec<u8>> {
    newtua_mscompress::xpress::decompress_chunk(compressed, uncompressed_len)
        .map_err(|e| Error::Corrupt(format!("wim: xpress chunk decode: {e}")))
}

/// Decode one WIM-LZX chunk via `newtua_mscompress` (task 20c). Same
/// externally-supplied-length convention as [`decode_xpress_chunk`].
fn decode_lzx_chunk(compressed: &[u8], uncompressed_len: usize) -> Result<Vec<u8>> {
    newtua_mscompress::lzx::decompress_chunk(compressed, uncompressed_len)
        .map_err(|e| Error::Corrupt(format!("wim: lzx chunk decode: {e}")))
}

// ── Metadata resource: directory tree ───────────────────────────────────

/// Windows `FILETIME` (100 ns intervals since 1601-01-01) → `SystemTime`.
/// `0` conventionally means "no timestamp".
fn filetime_to_systime(ticks: u64) -> Option<SystemTime> {
    // 100 ns intervals between the FILETIME epoch (1601-01-01) and the Unix
    // epoch (1970-01-01).
    const EPOCH_DIFF_100NS: u64 = 116_444_736_000_000_000;
    if ticks == 0 {
        return None;
    }
    let unix_100ns = ticks.checked_sub(EPOCH_DIFF_100NS)?;
    let secs = unix_100ns / 10_000_000;
    let nanos = (unix_100ns % 10_000_000) * 100;
    Some(UNIX_EPOCH + Duration::new(secs, nanos as u32))
}

/// Decode a raw UTF-16LE byte slice (no terminator included) to a `String`.
fn decode_utf16le(b: &[u8]) -> Result<String> {
    if b.len() % 2 != 0 {
        return Err(Error::Corrupt("wim: odd-length UTF-16LE name".into()));
    }
    let units: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    char::decode_utf16(units)
        .collect::<std::result::Result<String, _>>()
        .map_err(|e| Error::Corrupt(format!("wim: invalid UTF-16 name: {e}")))
}

const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
/// Fixed dentry prefix up to and including `FileNameLength`, per wimlib's
/// `struct wim_dentry_on_disk` (verified against `src/dentry.c`): Length(8) +
/// Attributes(4) + SecurityId(4) + SubdirOffset(8) + 2×reserved(8+8) +
/// 3×FILETIME(8+8+8) + Hash(20) + unknown_0x54(4) + reparse/hardlink
/// union(8) + StreamCount(2) + ShortNameLength(2) + FileNameLength(2) = 0x66.
const DIRENTRY_FIXED_LEN: usize = 0x66;

/// One parsed `DIRENTRY`, before resolving its hash against the lookup table.
#[derive(Debug)]
struct RawDentry {
    is_dir: bool,
    subdir_offset: u64,
    modified: Option<SystemTime>,
    /// SHA-1 of the unnamed data stream. All-zero means "no data" (empty
    /// file, or a directory, which never carries a stream).
    hash: [u8; 20],
    name: String,
}

/// Security block length in bytes (rounded up to 8), to skip at the start of
/// a metadata resource. Per spec: `u32 TotalLength, u32 NumEntries, ...`; we
/// don't need the descriptors themselves, only where they end.
fn security_block_len(meta: &[u8]) -> Result<usize> {
    if meta.len() < 8 {
        return Err(Error::Corrupt(
            "wim: metadata resource too small for a security block".into(),
        ));
    }
    let total_length = u32::from_le_bytes(meta[0..4].try_into().unwrap()) as usize;
    // Some encoders write TotalLength=0 for "no security descriptors" even
    // though the two header fields themselves take 8 bytes; treat 0 (and any
    // value smaller than the header) as the minimum 8-byte block.
    let effective = total_length.max(8);
    let len = effective.div_ceil(8) * 8;
    if len > meta.len() {
        return Err(Error::Corrupt(
            "wim: security block longer than the metadata resource".into(),
        ));
    }
    Ok(len)
}

/// Parse one `DIRENTRY` at `meta[offset..]`. Returns `None` for the
/// end-of-children-list sentinel (`Length <= 8`, per wimlib), else the
/// parsed dentry plus the offset of the next sibling (`offset + Length`,
/// already 8-byte aligned in valid input; we align defensively).
fn parse_dirent(meta: &[u8], offset: usize) -> Result<Option<(RawDentry, usize)>> {
    if offset.checked_add(8).is_none_or(|end| end > meta.len()) {
        return Err(Error::Corrupt(
            "wim: dirent Length field runs past the metadata resource".into(),
        ));
    }
    let length = u64::from_le_bytes(meta[offset..offset + 8].try_into().unwrap());
    if length <= 8 {
        return Ok(None);
    }
    let aligned_length = length.div_ceil(8) * 8;
    let next = offset
        .checked_add(aligned_length as usize)
        .filter(|&e| e <= meta.len())
        .ok_or_else(|| {
            Error::Corrupt("wim: dirent Length runs past the metadata resource".into())
        })?;
    if offset + DIRENTRY_FIXED_LEN > meta.len() {
        return Err(Error::Corrupt(
            "wim: dirent shorter than its fixed-size prefix".into(),
        ));
    }
    let b = &meta[offset..];
    let attributes = u32::from_le_bytes(b[8..12].try_into().unwrap());
    let subdir_offset = u64::from_le_bytes(b[16..24].try_into().unwrap());
    let last_write_time = u64::from_le_bytes(b[0x38..0x40].try_into().unwrap());
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&b[0x40..0x54]);
    let short_name_nbytes = u16::from_le_bytes(b[0x62..0x64].try_into().unwrap()) as usize;
    let name_nbytes = u16::from_le_bytes(b[0x64..0x66].try_into().unwrap()) as usize;

    let mut cursor = DIRENTRY_FIXED_LEN;
    let name = if name_nbytes > 0 {
        let start = offset + cursor;
        let end_name = start
            .checked_add(name_nbytes)
            .filter(|&e| e <= meta.len())
            .ok_or_else(|| {
                Error::Corrupt("wim: dirent file name runs past the metadata resource".into())
            })?;
        let s = decode_utf16le(&meta[start..end_name])?;
        cursor += name_nbytes + 2; // + NUL terminator, per wimlib's read_dentry
        s
    } else {
        String::new()
    };
    // Short (8.3) name: skipped, only its length matters to locate what
    // follows (nothing does, in 20a's scope — streams beyond the unnamed one
    // are ignored).
    if short_name_nbytes > 0 {
        cursor = cursor
            .checked_add(short_name_nbytes + 2)
            .ok_or_else(|| Error::Corrupt("wim: dirent short name length overflow".into()))?;
    }
    let _ = cursor; // remaining bytes up to `next` are padding / stream records we skip.

    Ok(Some((
        RawDentry {
            is_dir: attributes & FILE_ATTRIBUTE_DIRECTORY != 0,
            subdir_offset,
            modified: filetime_to_systime(last_write_time),
            hash,
            name,
        },
        next,
    )))
}

/// Walk one directory's children (starting at `offset`, the parent's
/// `SubdirOffset`), appending each to `entries`/`bodies` and recursing into
/// subdirectories. `bodies[i]` is `Some(resource)` for a file with data,
/// `None` for a directory or an empty (all-zero-hash) file.
fn walk_children(
    meta: &[u8],
    offset: usize,
    parent: &Path,
    lookup: &HashMap<[u8; 20], ResourceHeader>,
    entries: &mut Vec<Entry>,
    bodies: &mut Vec<Option<ResourceHeader>>,
) -> Result<()> {
    let mut offset = offset;
    while let Some((d, next)) = parse_dirent(meta, offset)? {
        let path = parent.join(&d.name);
        let is_zero_hash = d.hash == [0u8; 20];

        let (kind, body, size) = if d.is_dir {
            (EntryKind::Dir, None, 0u64)
        } else if is_zero_hash {
            (EntryKind::File, None, 0u64)
        } else {
            let rh = lookup.get(&d.hash).copied().ok_or_else(|| {
                Error::Corrupt(format!(
                    "wim: dirent {} references a hash absent from the lookup table",
                    path.display()
                ))
            })?;
            (EntryKind::File, Some(rh), rh.original_size)
        };

        entries.push(Entry {
            path_raw: path.to_string_lossy().into_owned().into_bytes(),
            path: path.clone(),
            kind,
            size,
            mode: None,
            is_encrypted: false,
            modified: d.modified,
        });
        bodies.push(body);

        // SubdirOffset == 0 means "no children" regardless of the directory
        // attribute bit (an empty directory), so it alone gates recursion.
        if d.subdir_offset != 0 {
            walk_children(
                meta,
                d.subdir_offset as usize,
                &path,
                lookup,
                entries,
                bodies,
            )?;
        }
        offset = next;
    }
    Ok(())
}

/// Parse a decompressed metadata resource into a flat entry list plus a
/// parallel `bodies` table. The root dentry (always unnamed) is consumed but
/// never itself added to `entries` — only its descendants are.
fn build_dir_tree(
    meta: &[u8],
    lookup: &HashMap<[u8; 20], ResourceHeader>,
) -> Result<(Vec<Entry>, Vec<Option<ResourceHeader>>)> {
    let sec_len = security_block_len(meta)?;
    let mut entries = Vec::new();
    let mut bodies = Vec::new();
    let Some((root, _)) = parse_dirent(meta, sec_len)? else {
        return Ok((entries, bodies)); // no root dentry — an empty image
    };
    if root.subdir_offset != 0 {
        walk_children(
            meta,
            root.subdir_offset as usize,
            Path::new(""),
            lookup,
            &mut entries,
            &mut bodies,
        )?;
    }
    Ok((entries, bodies))
}

/// Reads WIM (`.wim`/`.esd`/`.swm`) install images.
pub struct WimHandler;

impl FormatHandler for WimHandler {
    fn id(&self) -> FormatId {
        FormatId::Wim
    }

    /// Detect by the `MSWIM\0\0\0` magic at offset 0, OR the `.wim`/`.esd`/
    /// `.swm` extension (case-insensitive). The magic lives well within the
    /// 512-byte header the registry peeks.
    fn probe(&self, header: &[u8], name: Option<&str>) -> Confidence {
        let magic_ok = header.starts_with(MAGIC);
        let ext_ok = name.is_some_and(|n| {
            let lower = n.to_ascii_lowercase();
            lower.ends_with(".wim") || lower.ends_with(".esd") || lower.ends_with(".swm")
        });
        if magic_ok || ext_ok {
            Confidence::MAGIC
        } else {
            Confidence::NONE
        }
    }

    fn open(&self, src: Source, _opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        let mut inner = match src {
            Source::Seekable { inner, .. } => inner,
            Source::Stream { .. } => {
                return Err(Error::Unsupported {
                    format: "wim".into(),
                    feature: "non-seekable source (wim requires seek)".into(),
                });
            }
        };

        inner.seek(SeekFrom::Start(0))?;
        let mut header_bytes = vec![0u8; HEADER_LEN];
        inner
            .read_exact(&mut header_bytes)
            .map_err(io_err_to_corrupt)?;
        let header = WimHeader::parse(&header_bytes)?;

        if header.spanned() {
            return Err(Error::Unsupported {
                format: "wim".into(),
                feature: format!(
                    "multi-volume WIM / .swm (part {} of {})",
                    header.part_number, header.total_parts
                ),
            });
        }
        if header.compressor == Some(Compressor::Lzms) {
            return Err(Error::Unsupported {
                format: "wim".into(),
                feature: "LZMS compression (.esd) — see task 20d".into(),
            });
        }

        let lookup_bytes = read_resource(
            &mut *inner,
            header.chunk_size,
            header.compressor,
            &header.offset_table,
        )?;
        let lookup_entries = parse_lookup_table(&lookup_bytes)?;

        let mut lookup: HashMap<[u8; 20], ResourceHeader> = HashMap::new();
        let mut metadata_rh: Option<ResourceHeader> = None;
        for e in &lookup_entries {
            if e.resource.is_metadata() {
                // Metadata resources appear in the lookup table in image
                // order; task 20a only surfaces image 1, so keep the first.
                if metadata_rh.is_none() {
                    metadata_rh = Some(e.resource);
                }
            } else {
                lookup.insert(e.hash, e.resource);
            }
        }
        let metadata_rh = metadata_rh.ok_or_else(|| {
            Error::Corrupt("wim: no metadata resource found in the lookup table".into())
        })?;

        let metadata_bytes = read_resource(
            &mut *inner,
            header.chunk_size,
            header.compressor,
            &metadata_rh,
        )?;
        let (entries, bodies) = build_dir_tree(&metadata_bytes, &lookup)?;

        Ok(Box::new(WimReader {
            inner,
            chunk_size: header.chunk_size,
            compressor: header.compressor,
            entries,
            bodies,
        }))
    }
}

/// Holds the seekable source, the flat entry list, and a parallel `bodies`
/// table (`Some(resource)` for a file with data; `None` for a directory or
/// an empty file) so `read_entry` can decode resources lazily, on demand.
struct WimReader {
    inner: Box<dyn ReadSeek>,
    chunk_size: u32,
    compressor: Option<Compressor>,
    entries: Vec<Entry>,
    bodies: Vec<Option<ResourceHeader>>,
}

impl ArchiveReader for WimReader {
    fn format(&self) -> FormatId {
        FormatId::Wim
    }

    fn entries(&mut self) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn read_entry(&mut self, idx: usize, out: &mut dyn Write) -> Result<()> {
        let Some(body) = self.bodies.get(idx) else {
            return Err(Error::InvalidIndex(idx));
        };
        let Some(rh) = body else {
            return Ok(()); // directory or empty file — no body
        };
        let data = read_resource(&mut *self.inner, self.chunk_size, self.compressor, rh)?;
        out.write_all(&data)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a syntactically valid 208-byte header with the given flags/
    /// chunk size/part fields; the two embedded resource headers are zeroed.
    fn header_bytes(flags: u32, chunk_size: u32, part_number: u16, total_parts: u16) -> Vec<u8> {
        let mut b = vec![0u8; HEADER_LEN];
        b[0..8].copy_from_slice(MAGIC);
        b[8..12].copy_from_slice(&(HEADER_LEN as u32).to_le_bytes());
        b[12..16].copy_from_slice(&0x0001_0D00u32.to_le_bytes());
        b[16..20].copy_from_slice(&flags.to_le_bytes());
        b[20..24].copy_from_slice(&chunk_size.to_le_bytes());
        b[40..42].copy_from_slice(&part_number.to_le_bytes());
        b[42..44].copy_from_slice(&total_parts.to_le_bytes());
        b[44..48].copy_from_slice(&1u32.to_le_bytes()); // dwImageCount
        b
    }

    #[test]
    fn header_parses_magic_and_chunk_size() {
        let b = header_bytes(FLAG_HEADER_COMPRESSION | FLAG_COMPRESS_XPRESS, 32768, 1, 1);
        let h = WimHeader::parse(&b).unwrap();
        assert_eq!(h.chunk_size, 32768);
        assert_eq!(h.compressor, Some(Compressor::Xpress));
        assert!(!h.spanned());
    }

    #[test]
    fn header_rejects_bad_magic() {
        let mut b = header_bytes(0, 0, 1, 1);
        b[0] = b'X';
        let err = WimHeader::parse(&b).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }

    #[test]
    fn header_rejects_truncated_input() {
        let err = WimHeader::parse(&[0u8; 32]).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }

    #[test]
    fn header_no_compression_flag_is_uncompressed() {
        let b = header_bytes(0, 0, 1, 1);
        let h = WimHeader::parse(&b).unwrap();
        assert_eq!(h.compressor, None);
    }

    #[test]
    fn header_detects_lzx_and_lzms() {
        let lzx = header_bytes(FLAG_HEADER_COMPRESSION | FLAG_COMPRESS_LZX, 32768, 1, 1);
        assert_eq!(
            WimHeader::parse(&lzx).unwrap().compressor,
            Some(Compressor::Lzx)
        );
        let lzms = header_bytes(FLAG_HEADER_COMPRESSION | FLAG_COMPRESS_LZMS, 32768, 1, 1);
        assert_eq!(
            WimHeader::parse(&lzms).unwrap().compressor,
            Some(Compressor::Lzms)
        );
    }

    #[test]
    fn header_ambiguous_compression_flags_is_corrupt() {
        let b = header_bytes(
            FLAG_HEADER_COMPRESSION | FLAG_COMPRESS_XPRESS | FLAG_COMPRESS_LZX,
            32768,
            1,
            1,
        );
        let err = WimHeader::parse(&b).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }

    #[test]
    fn header_spanned_via_flag_or_total_parts() {
        let by_flag = header_bytes(FLAG_SPANNED, 0, 1, 1);
        assert!(WimHeader::parse(&by_flag).unwrap().spanned());
        let by_count = header_bytes(0, 0, 1, 3);
        assert!(WimHeader::parse(&by_count).unwrap().spanned());
        let neither = header_bytes(0, 0, 1, 1);
        assert!(!WimHeader::parse(&neither).unwrap().spanned());
    }

    fn reshdr_bytes(size_on_disk: u64, flags: u8, offset: u64, original_size: u64) -> Vec<u8> {
        let raw = size_on_disk | ((flags as u64) << 56);
        let mut b = Vec::with_capacity(24);
        b.extend_from_slice(&raw.to_le_bytes());
        b.extend_from_slice(&offset.to_le_bytes());
        b.extend_from_slice(&original_size.to_le_bytes());
        b
    }

    #[test]
    fn resource_header_parses_size_flags_offset_original_size() {
        let b = reshdr_bytes(1234, 0x04, 5000, 9999);
        let rh = ResourceHeader::parse(&b).unwrap();
        assert_eq!(rh.size_on_disk, 1234);
        assert_eq!(rh.flags, 0x04);
        assert_eq!(rh.offset, 5000);
        assert_eq!(rh.original_size, 9999);
        assert!(rh.is_compressed());
        assert!(!rh.is_metadata());
    }

    #[test]
    fn resource_header_metadata_flag() {
        let b = reshdr_bytes(1, 0x02, 0, 1);
        let rh = ResourceHeader::parse(&b).unwrap();
        assert!(rh.is_metadata());
        assert!(!rh.is_compressed());
    }

    #[test]
    fn resource_header_size_on_disk_ignores_flag_byte() {
        // A size_on_disk that would collide with the flags byte if flags
        // weren't masked out (top byte all-ones is impossible in practice,
        // but this proves the 56-bit mask is applied, not just a plain read).
        let raw: u64 = 0x0400_0000_0000_1234; // flags=0x04, size=0x1234
        let mut b = Vec::with_capacity(24);
        b.extend_from_slice(&raw.to_le_bytes());
        b.extend_from_slice(&0u64.to_le_bytes());
        b.extend_from_slice(&0u64.to_le_bytes());
        let rh = ResourceHeader::parse(&b).unwrap();
        assert_eq!(rh.size_on_disk, 0x1234);
        assert_eq!(rh.flags, 0x04);
    }

    #[test]
    fn resource_header_rejects_truncated_input() {
        let err = ResourceHeader::parse(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }

    #[test]
    fn lookup_table_parses_entries() {
        let mut bytes = Vec::new();
        // Entry 0: plain data resource.
        bytes.extend_from_slice(&reshdr_bytes(100, 0x04, 1000, 200));
        bytes.extend_from_slice(&0u16.to_le_bytes()); // usPartNumber
        bytes.extend_from_slice(&1u32.to_le_bytes()); // dwRefCount
        bytes.extend_from_slice(&[0xAAu8; 20]); // hash
        // Entry 1: metadata resource.
        bytes.extend_from_slice(&reshdr_bytes(50, 0x02, 2000, 80));
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&[0xBBu8; 20]);

        let entries = parse_lookup_table(&bytes).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].hash, [0xAAu8; 20]);
        assert!(!entries[0].resource.is_metadata());
        assert_eq!(entries[1].hash, [0xBBu8; 20]);
        assert!(entries[1].resource.is_metadata());
    }

    #[test]
    fn lookup_table_rejects_size_not_multiple_of_50() {
        let err = parse_lookup_table(&[0u8; 49]).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }

    #[test]
    fn lookup_table_empty_is_empty() {
        assert!(parse_lookup_table(&[]).unwrap().is_empty());
    }

    #[test]
    fn id_is_wim() {
        assert_eq!(WimHandler.id(), FormatId::Wim);
    }

    #[test]
    fn probe_magic_is_magic() {
        assert_eq!(
            WimHandler.probe(MAGIC, Some("install.bin")),
            Confidence::MAGIC
        );
    }

    #[test]
    fn probe_wim_esd_swm_extensions_are_magic() {
        for name in ["install.wim", "IMAGE.ESD", "part.swm"] {
            assert_eq!(
                WimHandler.probe(b"\x00\x00\x00\x00", Some(name)),
                Confidence::MAGIC,
                "extension {name} should probe MAGIC"
            );
        }
    }

    #[test]
    fn probe_foreign_magic_no_extension_is_none() {
        assert_eq!(
            WimHandler.probe(b"PK\x03\x04", Some("a.zip")),
            Confidence::NONE
        );
    }

    #[test]
    fn probe_no_name_no_magic_is_none() {
        assert_eq!(
            WimHandler.probe(b"\x00\x00\x00\x00", None),
            Confidence::NONE
        );
    }

    // ── chunked resource decoding ───────────────────────────────────────

    #[test]
    fn decode_one_chunk_stored_when_sizes_match() {
        // "Compressed" size == uncompressed size → stored verbatim, no codec
        // invoked (Xpress here is a stand-in; any compressor would do).
        let data = b"not actually compressed".to_vec();
        let out = decode_one_chunk(&data, data.len(), Compressor::Xpress).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn decode_chunked_resource_single_chunk_stored() {
        let payload = b"hello wim\n".to_vec();
        let out =
            decode_chunked_resource(&payload, 32768, payload.len(), Compressor::Xpress).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn decode_chunked_resource_empty_is_empty() {
        let out = decode_chunked_resource(&[], 32768, 0, Compressor::Xpress).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn decode_chunked_resource_multi_chunk_stored() {
        // Two chunks of 4 bytes each, chunk_size=4, both stored verbatim
        // (compressed len == uncompressed len for each). Offset table is one
        // u32 entry (original_size=8 < 4 GiB) pointing past chunk 0.
        let chunk0 = b"ABCD";
        let chunk1 = b"WXYZ";
        let mut raw = Vec::new();
        raw.extend_from_slice(&(chunk0.len() as u32).to_le_bytes()); // table: chunk1 starts at 4
        raw.extend_from_slice(chunk0);
        raw.extend_from_slice(chunk1);

        let out = decode_chunked_resource(&raw, 4, 8, Compressor::Xpress).unwrap();
        assert_eq!(out, b"ABCDWXYZ");
    }

    #[test]
    fn decode_chunked_resource_last_chunk_shorter() {
        // original_size=6, chunk_size=4 → chunk0 is 4 bytes, chunk1 is 2.
        let chunk0 = b"ABCD";
        let chunk1 = b"XY";
        let mut raw = Vec::new();
        raw.extend_from_slice(&(chunk0.len() as u32).to_le_bytes());
        raw.extend_from_slice(chunk0);
        raw.extend_from_slice(chunk1);

        let out = decode_chunked_resource(&raw, 4, 6, Compressor::Xpress).unwrap();
        assert_eq!(out, b"ABCDXY");
    }

    #[test]
    fn decode_chunked_resource_rejects_short_offset_table() {
        // Claims 3 chunks (needs 2 table entries = 8 bytes) but supplies only 4.
        let raw = vec![0u8; 4];
        let err = decode_chunked_resource(&raw, 4, 12, Compressor::Xpress).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }

    #[test]
    fn decode_chunked_resource_rejects_bad_offset_ordering() {
        // Offset table entry points backwards (end < start is impossible for a
        // single entry, but an offset past the data end must be rejected).
        let mut raw = Vec::new();
        raw.extend_from_slice(&1_000_000u32.to_le_bytes()); // way past actual data
        raw.extend_from_slice(b"AB");
        let err = decode_chunked_resource(&raw, 4, 8, Compressor::Xpress).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }

    #[test]
    fn decode_lzx_chunk_delegates_to_newtua_mscompress() {
        // A minimal hand-built LZX "Uncompressed" block (kind=011, explicit
        // 16-bit size=3, then r=[1,1,1], then the 3 raw literal bytes
        // "abc"). Full derivation, byte-exact real-WIM-chunk coverage
        // (Huffman-coded blocks, the E8 filter) lives in
        // `newtua-mscompress`'s own test suite — this only checks that
        // `wim.rs` wires the call through correctly.
        let word0 = 0b0110_0000_0000_0000u16;
        let word1 = 0b0011_0000_0000_0000u16;
        let mut input = word0.to_le_bytes().to_vec();
        input.extend_from_slice(&word1.to_le_bytes());
        input.extend_from_slice(&1u32.to_le_bytes());
        input.extend_from_slice(&1u32.to_le_bytes());
        input.extend_from_slice(&1u32.to_le_bytes());
        input.extend_from_slice(b"abc");

        let decoded = decode_lzx_chunk(&input, 3).unwrap();
        assert_eq!(decoded, b"abc");
    }

    #[test]
    fn decode_lzx_chunk_maps_decoder_errors_to_corrupt() {
        let err = decode_lzx_chunk(&[], 2).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }

    #[test]
    fn decode_one_chunk_lzx_delegates_to_newtua_mscompress() {
        // Not stored (len mismatch) — must actually decode via the lzx
        // module now (task 20c), not stay Unsupported.
        let word0 = 0b0110_0000_0000_0000u16;
        let word1 = 0b0011_0000_0000_0000u16;
        let mut input = word0.to_le_bytes().to_vec();
        input.extend_from_slice(&word1.to_le_bytes());
        input.extend_from_slice(&1u32.to_le_bytes());
        input.extend_from_slice(&1u32.to_le_bytes());
        input.extend_from_slice(&1u32.to_le_bytes());
        input.extend_from_slice(b"abc");

        let decoded = decode_one_chunk(&input, 3, Compressor::Lzx).unwrap();
        assert_eq!(decoded, b"abc");
    }

    #[test]
    fn decode_one_chunk_lzms_is_unsupported() {
        let err = decode_one_chunk(b"compressed-ish", 100, Compressor::Lzms).unwrap_err();
        match err {
            Error::Unsupported { format, feature } => {
                assert_eq!(format, "wim");
                assert!(feature.to_ascii_lowercase().contains("lzms"));
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn decode_xpress_chunk_delegates_to_newtua_mscompress() {
        // A minimal hand-built XPRESS-Huffman block: a 256-byte code-length
        // table assigning length 1 to symbols 'A' (0x41) and 'B' (0x42),
        // followed by the two prefill words whose leading two bits ("01")
        // select 'A' then 'B'. Full derivation and byte-exact decode
        // coverage (literals, matches, length escapes, a real WIM chunk)
        // lives in `newtua-mscompress`'s own test suite — this only checks
        // that `wim.rs` wires the call through correctly.
        let mut lens = [0u8; 512];
        lens[0x41] = 1;
        lens[0x42] = 1;
        let mut packed = vec![0u8; 256];
        for k in 0..256 {
            packed[k] = (lens[2 * k] & 0x0F) | ((lens[2 * k + 1] & 0x0F) << 4);
        }
        packed.extend_from_slice(&[0x00, 0x40, 0x00, 0x00]);

        let decoded = decode_xpress_chunk(&packed, 2).unwrap();
        assert_eq!(decoded, b"AB");
    }

    #[test]
    fn decode_xpress_chunk_maps_decoder_errors_to_corrupt() {
        let err = decode_xpress_chunk(&[], 2).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }

    #[test]
    fn read_resource_uncompressed_reads_verbatim() {
        let mut backing = std::io::Cursor::new(b"XXXXhello wim\n".to_vec());
        let rh = ResourceHeader {
            size_on_disk: 10,
            flags: 0, // not compressed, not metadata
            offset: 4,
            original_size: 10,
        };
        let out = read_resource(&mut backing, 32768, None, &rh).unwrap();
        assert_eq!(out, b"hello wim\n");
    }

    #[test]
    fn read_resource_compressed_without_header_compressor_is_corrupt() {
        let mut backing = std::io::Cursor::new(vec![0u8; 20]);
        let rh = ResourceHeader {
            size_on_disk: 20,
            flags: ResourceHeader::FLAG_COMPRESSED,
            offset: 0,
            original_size: 100,
        };
        let err = read_resource(&mut backing, 32768, None, &rh).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }

    #[test]
    fn read_resource_short_read_is_corrupt() {
        let mut backing = std::io::Cursor::new(vec![0u8; 3]);
        let rh = ResourceHeader {
            size_on_disk: 10, // more than the backing buffer holds
            flags: 0,
            offset: 0,
            original_size: 10,
        };
        let err = read_resource(&mut backing, 32768, None, &rh).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }

    // ── metadata resource / directory tree ──────────────────────────────

    #[test]
    fn filetime_zero_is_none() {
        assert_eq!(filetime_to_systime(0), None);
    }

    #[test]
    fn filetime_epoch_matches_unix_epoch() {
        // 116_444_736_000_000_000 100ns-ticks == 1970-01-01T00:00:00Z exactly.
        assert_eq!(
            filetime_to_systime(116_444_736_000_000_000),
            Some(UNIX_EPOCH)
        );
    }

    #[test]
    fn filetime_one_second_after_epoch() {
        let ticks = 116_444_736_000_000_000 + 10_000_000; // +1s in 100ns units
        assert_eq!(
            filetime_to_systime(ticks),
            Some(UNIX_EPOCH + Duration::from_secs(1))
        );
    }

    #[test]
    fn decode_utf16le_ascii() {
        let bytes: Vec<u8> = "a.txt".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(decode_utf16le(&bytes).unwrap(), "a.txt");
    }

    #[test]
    fn decode_utf16le_rejects_odd_length() {
        let err = decode_utf16le(&[0x61]).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }

    /// Build one on-disk DIRENTRY (fixed 0x66-byte prefix + name + NUL,
    /// padded to 8 bytes), matching wimlib's `struct wim_dentry_on_disk`.
    /// `subdir_offset` is written directly (tests patch it after measuring
    /// sibling layout, when a forward reference is needed).
    fn build_dentry(name: &str, is_dir: bool, subdir_offset: u64, hash: [u8; 20]) -> Vec<u8> {
        let name_utf16: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let name_nbytes = name_utf16.len() as u16;
        let mut b = vec![0u8; DIRENTRY_FIXED_LEN];
        let attributes: u32 = if is_dir { FILE_ATTRIBUTE_DIRECTORY } else { 0 };
        b[8..12].copy_from_slice(&attributes.to_le_bytes());
        b[16..24].copy_from_slice(&subdir_offset.to_le_bytes());
        b[0x40..0x54].copy_from_slice(&hash);
        b[0x60..0x62].copy_from_slice(&0u16.to_le_bytes()); // StreamCount
        b[0x62..0x64].copy_from_slice(&0u16.to_le_bytes()); // ShortNameLength
        b[0x64..0x66].copy_from_slice(&name_nbytes.to_le_bytes());
        b.extend_from_slice(&name_utf16);
        if name_nbytes > 0 {
            b.extend_from_slice(&[0, 0]); // NUL terminator
        }
        while b.len() % 8 != 0 {
            b.push(0);
        }
        let length = b.len() as u64;
        b[0..8].copy_from_slice(&length.to_le_bytes());
        b
    }

    fn patch_subdir_offset(dentry: &mut [u8], offset: u64) {
        dentry[16..24].copy_from_slice(&offset.to_le_bytes());
    }

    fn terminator() -> Vec<u8> {
        0u64.to_le_bytes().to_vec()
    }

    fn security_block(total_length: u32, num_entries: u32) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&total_length.to_le_bytes());
        b.extend_from_slice(&num_entries.to_le_bytes());
        while b.len() % 8 != 0 {
            b.push(0);
        }
        b
    }

    #[test]
    fn security_block_len_rounds_up_to_8() {
        assert_eq!(security_block_len(&security_block(8, 0)).unwrap(), 8);
        let mut meta = security_block(20, 0);
        meta.resize(24, 0);
        assert_eq!(security_block_len(&meta).unwrap(), 24);
    }

    #[test]
    fn security_block_len_zero_total_length_is_minimum_8() {
        let meta = security_block(0, 0);
        assert_eq!(security_block_len(&meta).unwrap(), 8);
    }

    #[test]
    fn security_block_len_rejects_too_short_input() {
        let err = security_block_len(&[0u8; 4]).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }

    #[test]
    fn parse_dirent_terminator_is_none() {
        assert!(parse_dirent(&terminator(), 0).unwrap().is_none());
    }

    #[test]
    fn parse_dirent_reads_name_and_attributes() {
        let d = build_dentry("a.txt", false, 0, [0xAB; 20]);
        let (parsed, next) = parse_dirent(&d, 0).unwrap().unwrap();
        assert_eq!(parsed.name, "a.txt");
        assert!(!parsed.is_dir);
        assert_eq!(parsed.hash, [0xAB; 20]);
        assert_eq!(next, d.len());
    }

    #[test]
    fn parse_dirent_dir_attribute_sets_is_dir() {
        let d = build_dentry("sub", true, 999, [0u8; 20]);
        let (parsed, _) = parse_dirent(&d, 0).unwrap().unwrap();
        assert!(parsed.is_dir);
        assert_eq!(parsed.subdir_offset, 999);
    }

    #[test]
    fn parse_dirent_empty_name_root() {
        let d = build_dentry("", true, 8, [0u8; 20]);
        let (parsed, _) = parse_dirent(&d, 0).unwrap().unwrap();
        assert_eq!(parsed.name, "");
    }

    #[test]
    fn parse_dirent_rejects_truncated_fixed_prefix() {
        let err = parse_dirent(&[0, 0, 0, 0, 0, 0, 0, 50], 0).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }

    /// Build a full metadata resource: security block + root dentry (unnamed,
    /// subdir_offset pointing right after itself) + `children` bytes + a
    /// terminator, matching the sec-block-then-root-then-descendants layout
    /// wimlib actually writes.
    fn build_metadata(children: &[u8]) -> Vec<u8> {
        let sec = security_block(8, 0);
        let mut root = build_dentry("", true, 0, [0u8; 20]);
        let children_offset = (sec.len() + root.len()) as u64;
        patch_subdir_offset(&mut root, children_offset);

        let mut meta = sec;
        meta.extend_from_slice(&root);
        meta.extend_from_slice(children);
        meta.extend_from_slice(&terminator());
        meta
    }

    #[test]
    fn build_dir_tree_flat_files() {
        let hash_a = [0xAAu8; 20];
        let mut child_a = build_dentry("a.txt", false, 0, hash_a);
        // No forward references needed for a flat sibling list; each dentry
        // is self-contained, terminator comes after the last one.
        child_a.extend_from_slice(&terminator());
        let meta = build_metadata(&child_a);

        let mut lookup = HashMap::new();
        lookup.insert(
            hash_a,
            ResourceHeader {
                size_on_disk: 5,
                flags: 0,
                offset: 1000,
                original_size: 10,
            },
        );

        let (entries, bodies) = build_dir_tree(&meta, &lookup).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, Path::new("a.txt"));
        assert_eq!(entries[0].size, 10);
        assert!(!entries[0].is_dir());
        assert_eq!(bodies[0].unwrap().offset, 1000);
    }

    #[test]
    fn build_dir_tree_nested_directory() {
        let hash_b = [0xBBu8; 20];
        let mut leaf = build_dentry("b.txt", false, 0, hash_b);
        leaf.extend_from_slice(&terminator());

        let mut sub_dir = build_dentry("sub", true, 0, [0u8; 20]);
        // sub's children (leaf) sit right after root's own children list in
        // this test's layout; compute the absolute offset once everything
        // before it is known.
        let sec = security_block(8, 0);
        let mut root = build_dentry("", true, 0, [0u8; 20]);
        let root_children_offset = (sec.len() + root.len()) as u64;
        patch_subdir_offset(&mut root, root_children_offset);

        // root's children list = [sub_dir, terminator]; sub's children list
        // (leaf) is appended after that whole list.
        let mut root_children = Vec::new();
        let sub_dir_offset_within_children = 0usize;
        let _ = sub_dir_offset_within_children;
        let sub_children_abs_offset =
            root_children_offset as usize + sub_dir.len() + terminator().len();
        patch_subdir_offset(&mut sub_dir, sub_children_abs_offset as u64);
        root_children.extend_from_slice(&sub_dir);
        root_children.extend_from_slice(&terminator());

        let mut meta = sec;
        meta.extend_from_slice(&root);
        meta.extend_from_slice(&root_children);
        meta.extend_from_slice(&leaf);
        meta.extend_from_slice(&terminator());

        let mut lookup = HashMap::new();
        lookup.insert(
            hash_b,
            ResourceHeader {
                size_on_disk: 7,
                flags: 0,
                offset: 2000,
                original_size: 7,
            },
        );

        let (entries, bodies) = build_dir_tree(&meta, &lookup).unwrap();
        let paths: Vec<&Path> = entries.iter().map(|e| e.path.as_path()).collect();
        assert!(paths.contains(&Path::new("sub")));
        assert!(paths.contains(&Path::new("sub/b.txt")));
        let sub_idx = entries
            .iter()
            .position(|e| e.path == Path::new("sub"))
            .unwrap();
        assert!(entries[sub_idx].is_dir());
        assert!(bodies[sub_idx].is_none());
        let leaf_idx = entries
            .iter()
            .position(|e| e.path == Path::new("sub/b.txt"))
            .unwrap();
        assert!(bodies[leaf_idx].is_some());
    }

    #[test]
    fn build_dir_tree_zero_hash_is_empty_body() {
        let mut child = build_dentry("empty.txt", false, 0, [0u8; 20]);
        child.extend_from_slice(&terminator());
        let meta = build_metadata(&child);

        let (entries, bodies) = build_dir_tree(&meta, &HashMap::new()).unwrap();
        assert_eq!(entries[0].size, 0);
        assert!(bodies[0].is_none());
    }

    #[test]
    fn build_dir_tree_unknown_hash_is_corrupt() {
        let mut child = build_dentry("mystery.bin", false, 0, [0x77u8; 20]);
        child.extend_from_slice(&terminator());
        let meta = build_metadata(&child);

        let err = build_dir_tree(&meta, &HashMap::new()).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "got {err:?}");
    }

    #[test]
    fn build_dir_tree_root_only_no_children() {
        // subdir_offset left at 0 (via build_metadata's own root when
        // children slice is empty and only the terminator follows).
        let meta = build_metadata(&[]);
        let (entries, bodies) = build_dir_tree(&meta, &HashMap::new()).unwrap();
        assert!(entries.is_empty());
        assert!(bodies.is_empty());
    }
}
