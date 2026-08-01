//! The compression layer: the single-stream wrappers `detect.rs` unwraps before
//! it looks for an archive inside.
//!
//! Ten of them. Eight are recognised by byte magic in
//! [`crate::detect::detect_compressor`]; the two magic-less ones — Brotli and
//! bare LZMA1 — are recognised by extension only, in `detect_compressor_by_ext`,
//! because nothing in their first bytes distinguishes them from arbitrary data.
//!
//! **Concatenated members.** Most of these formats let two compressed files be
//! `cat`-ed together into one valid file, and parallel compressors — `pbzip2`,
//! which is what Keka runs for bzip2 — write one member per thread, so this is
//! the common case, not a curiosity. Every multi-member decoder here must span
//! them: `MultiGzDecoder` (gzip), `MultiBzDecoder` (bzip2),
//! `XzDecoder::new_multi_decoder` (xz), zstd's `Decoder` (spans frames on its
//! own) and `LzipReader` below, which drives `xz2::stream::Stream` by hand
//! precisely for that. The single-member constructors are the trap: `BzDecoder`
//! stops after the first member and drops the rest *without an error* — the
//! worst possible failure — while `XzDecoder::new` at least fails loudly on the
//! second stream.

use std::io::{Error, ErrorKind, Read, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compressor {
    Gzip,
    Bzip2,
    Xz,
    Zstd,
    /// Bare LZMA1, the "alone" container. Detected by the `.lzma` extension
    /// only — its header is coder properties plus a dictionary size, with no
    /// tag, so a content sniff would claim arbitrary data.
    Lzma,
    /// `compress(1)`'s LZW (`.Z`).
    Lzc,
    Lz4,
    /// Brotli (`.br`). Detected by extension only: the format has no magic.
    Brotli,
    /// Framed Snappy (the `framing2` stream format), what Keka calls SNAPPY.
    /// Raw, unframed Snappy is deliberately not supported: it has no magic.
    Snappy,
    /// lzip (`.lz`) — LZMA1 in lzip's own framing, possibly multi-member.
    Lzip,
}

pub fn decompressor(kind: Compressor, inner: Box<dyn Read>) -> Result<Box<dyn Read>> {
    match kind {
        Compressor::Gzip => Ok(Box::new(flate2::read::MultiGzDecoder::new(inner))),
        Compressor::Bzip2 => Ok(Box::new(bzip2::read::MultiBzDecoder::new(inner))),
        Compressor::Xz => Ok(Box::new(xz2::read::XzDecoder::new_multi_decoder(inner))),
        Compressor::Zstd => Ok(Box::new(zstd::stream::read::Decoder::new(inner)?)),
        Compressor::Lzma => {
            let stream = xz2::stream::Stream::new_lzma_decoder(u64::MAX)?;
            Ok(Box::new(xz2::read::XzDecoder::new_stream(inner, stream)))
        }
        Compressor::Lzc => Ok(Box::new(lzw_z::Decoder::new(inner))),
        Compressor::Lz4 => Ok(Box::new(lz4_flex::frame::FrameDecoder::new(inner))),
        Compressor::Brotli => Ok(Box::new(brotli_decompressor::Decompressor::new(
            inner, 4096,
        ))),
        Compressor::Snappy => Ok(Box::new(snap::read::FrameDecoder::new(inner))),
        Compressor::Lzip => Ok(Box::new(LzipReader::new(inner))),
    }
}

// ── lzip ──────────────────────────────────────────────────────────────────────

/// Magic of every lzip member header.
const LZIP_MAGIC: [u8; 4] = *b"LZIP";
/// Only version 1 is decoded; see [`LzipReader`].
const LZIP_VERSION: u8 = 1;
/// Member header: magic (4) + version (1) + coded dictionary size (1).
const LZIP_HEADER_LEN: usize = 6;
/// Member trailer: CRC32 (4) + uncompressed size (8) + member size (8).
const LZIP_TRAILER_LEN: usize = 20;
/// LZMA1 properties byte for lc=3, lp=0, pb=2 — the values lzip fixes.
/// `(pb * 5 + lp) * 9 + lc` = `(2 * 5 + 0) * 9 + 3` = 93.
const LZIP_LZMA_PROPS: u8 = 93;
/// Input buffer of the member loop. Must exceed both framing block sizes.
const LZIP_BUF: usize = 64 * 1024;

/// Reader for lzip (`.lz`) streams, including concatenated members.
///
/// **Why this decoder core.** lzip is LZMA1 data wrapped in its own framing:
/// a 6-byte header (`LZIP`, version, coded dictionary size), the raw LZMA1
/// stream ending in an end-of-stream marker, then a 20-byte trailer (CRC32,
/// uncompressed size, member size). The compressed body is exactly what the
/// LZMA1 decoder we already link (liblzma via `xz2`, the same one the `.lzma`,
/// deb and rpm paths use) reads — it only wants a different 13-byte preamble.
/// So instead of adding a dependency we strip lzip's header and synthesize the
/// "alone" header liblzma expects: properties byte, dictionary size, and an
/// unknown uncompressed size, which makes it stop at the end-of-stream marker.
/// This is the same header-surgery trick `decode_zip_lzma` (`src/format/zip.rs`)
/// already uses for ZIP method 14. Verified byte-for-byte against files from
/// `lzip 1.26` before being chosen — that check is `lzip_decodes_known_stream`
/// below and the fixtures in `tests/integration/lzip.rs`. A pure-Rust crate with
/// native lzip support (`lzma-rust2`) was the fallback plan and is not needed.
///
/// **Why the hand-written member loop** rather than `xz2::read::XzDecoder`:
/// lzip members concatenate like gzip's, and everything after the first member
/// would be silently dropped by a single-shot decoder — data loss reported as
/// success. `XzDecoder` reads ahead into a private buffer, so once its stream
/// ends there is no way to learn where the next member starts. Driving
/// `xz2::stream::Stream` by hand keeps the input accounting ours: `process`
/// reports exactly how many bytes it consumed, so at `StreamEnd` the trailer
/// and the next header are still in our buffer. (This is what `MultiGzDecoder`
/// does for gzip and why `.warc.gz` needs it.)
///
/// Only version 1 is accepted. Version 0 (lzip ≤ 0.5, 2008) has a different
/// trailer and no producer in circulation; claiming it would mean guessing.
struct LzipReader<R: Read> {
    inner: R,
    /// Raw input; `buf[pos..cap]` is read from `inner` but not yet consumed.
    buf: Vec<u8>,
    pos: usize,
    cap: usize,
    /// `inner` returned 0 — no more input will arrive.
    eof: bool,
    /// Synthesized "alone" header for the current member, fed to the decoder
    /// ahead of `buf`; `pending[pending_pos..]` is what is left of it.
    pending: Vec<u8>,
    pending_pos: usize,
    state: LzipState,
    /// Bytes the current member has decoded to, checked against its trailer.
    member_out: u64,
    /// Trailer bytes collected so far for the current member.
    trailer: Vec<u8>,
}

enum LzipState {
    /// Between members: a header must follow, or the input must end cleanly.
    Header,
    /// Decoding one member's LZMA1 stream.
    Body(Box<xz2::stream::Stream>),
    /// Skipping the member trailer; the payload is how many bytes are left.
    Trailer(usize),
    /// Input ended on a member boundary — nothing more to produce.
    Done,
    /// A previous `read` failed. Latched so a caller that keeps reading gets
    /// the error again instead of a silent EOF or a restart mid-stream.
    Failed,
}

fn corrupt(msg: &str) -> Error {
    Error::new(ErrorKind::InvalidData, format!("lzip: {msg}"))
}

impl<R: Read> LzipReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            buf: vec![0; LZIP_BUF],
            pos: 0,
            cap: 0,
            eof: false,
            pending: Vec::new(),
            pending_pos: 0,
            state: LzipState::Header,
            member_out: 0,
            trailer: Vec::with_capacity(LZIP_TRAILER_LEN),
        }
    }

    /// Buffer at least `n` unconsumed bytes, or as many as the input still has.
    /// Returns how many are available. `n` must not exceed [`LZIP_BUF`].
    fn fill_at_least(&mut self, n: usize) -> Result<usize> {
        debug_assert!(n <= LZIP_BUF);
        if self.pos > 0 {
            self.buf.copy_within(self.pos..self.cap, 0);
            self.cap -= self.pos;
            self.pos = 0;
        }
        while self.cap < n && !self.eof {
            match self.inner.read(&mut self.buf[self.cap..])? {
                0 => self.eof = true,
                k => self.cap += k,
            }
        }
        Ok(self.cap - self.pos)
    }

    /// Parse a member header from the buffer and arm the decoder for its body.
    /// Returns `false` when the input ended cleanly on a member boundary.
    fn start_member(&mut self) -> Result<bool> {
        let avail = self.fill_at_least(LZIP_HEADER_LEN)?;
        if avail == 0 {
            return Ok(false);
        }
        if avail < LZIP_HEADER_LEN {
            return Err(corrupt("truncated member header"));
        }
        let head = &self.buf[self.pos..self.pos + LZIP_HEADER_LEN];
        if head[..4] != LZIP_MAGIC {
            return Err(corrupt("member header magic mismatch"));
        }
        if head[4] != LZIP_VERSION {
            return Err(corrupt(&format!("unsupported format version {}", head[4])));
        }
        // Coded dictionary size: low 5 bits are a base-2 exponent, high 3 bits
        // are how many sixteenths of that base to subtract.
        let coded = head[5];
        let exponent = u32::from(coded & 0x1f);
        let sixteenths = u32::from(coded >> 5);
        if !(12..=29).contains(&exponent) {
            return Err(corrupt(&format!(
                "dictionary size exponent {exponent} outside 12..=29"
            )));
        }
        let base = 1u32 << exponent;
        let dict = base - (base / 16) * sixteenths;
        self.pos += LZIP_HEADER_LEN;

        // liblzma's "alone" header: properties, dictionary size, uncompressed
        // size. `u64::MAX` means unknown, i.e. decode until the end-of-stream
        // marker — which is what lzip members carry. The dictionary size is
        // rounded up to a power of two: lzip's sizes need not be one (7168 for
        // a 7 KiB input, say), and liblzma's stricter alone-decoder mode only
        // accepts 2^n or 2^n + 2^(n-1). A wider window never changes the
        // output, since the encoder simply never referenced that far back.
        let mut alone = Vec::with_capacity(13);
        alone.push(LZIP_LZMA_PROPS);
        alone.extend_from_slice(&dict.next_power_of_two().to_le_bytes());
        alone.extend_from_slice(&u64::MAX.to_le_bytes());
        self.pending = alone;
        self.pending_pos = 0;

        let stream = xz2::stream::Stream::new_lzma_decoder(u64::MAX)?;
        self.state = LzipState::Body(Box::new(stream));
        self.member_out = 0;
        self.trailer.clear();
        Ok(true)
    }

    /// Consume trailer bytes; on the last one, check the member's size field.
    fn advance_trailer(&mut self, left: usize) -> Result<()> {
        let avail = self.fill_at_least(1)?;
        if avail == 0 {
            return Err(corrupt("truncated member trailer"));
        }
        let take = left.min(avail);
        self.trailer
            .extend_from_slice(&self.buf[self.pos..self.pos + take]);
        self.pos += take;
        let left = left - take;
        if left > 0 {
            self.state = LzipState::Trailer(left);
            return Ok(());
        }
        // CRC32 is left to liblzma's own stream integrity checks; the size
        // field is free to verify here and catches a truncated or spliced
        // member that still decoded to something.
        let declared = u64::from_le_bytes(self.trailer[4..12].try_into().unwrap());
        if declared != self.member_out {
            return Err(corrupt(&format!(
                "member declares {declared} uncompressed bytes, decoded {}",
                self.member_out
            )));
        }
        self.state = LzipState::Header;
        Ok(())
    }
}

impl<R: Read> Read for LzipReader<R> {
    fn read(&mut self, out: &mut [u8]) -> Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let result = self.read_member_loop(out);
        if result.is_err() {
            self.state = LzipState::Failed;
        }
        result
    }
}

impl<R: Read> LzipReader<R> {
    fn read_member_loop(&mut self, out: &mut [u8]) -> Result<usize> {
        loop {
            match std::mem::replace(&mut self.state, LzipState::Header) {
                LzipState::Done => {
                    self.state = LzipState::Done;
                    return Ok(0);
                }
                LzipState::Failed => return Err(corrupt("stream already failed")),
                LzipState::Header => {
                    if !self.start_member()? {
                        self.state = LzipState::Done;
                        return Ok(0);
                    }
                }
                LzipState::Trailer(left) => self.advance_trailer(left)?,
                LzipState::Body(mut stream) => {
                    let from_pending = self.pending_pos < self.pending.len();
                    let input: &[u8] = if from_pending {
                        &self.pending[self.pending_pos..]
                    } else {
                        if self.pos == self.cap {
                            self.fill_at_least(1)?;
                        }
                        &self.buf[self.pos..self.cap]
                    };
                    if input.is_empty() {
                        return Err(corrupt("truncated member: no end-of-stream marker"));
                    }
                    let (in_before, out_before) = (stream.total_in(), stream.total_out());
                    let status = stream.process(input, out, xz2::stream::Action::Run)?;
                    let consumed = (stream.total_in() - in_before) as usize;
                    let produced = (stream.total_out() - out_before) as usize;
                    if from_pending {
                        self.pending_pos += consumed;
                    } else {
                        self.pos += consumed;
                    }
                    self.member_out += produced as u64;
                    match status {
                        xz2::stream::Status::StreamEnd => {
                            self.state = LzipState::Trailer(LZIP_TRAILER_LEN);
                        }
                        xz2::stream::Status::Ok => self.state = LzipState::Body(stream),
                        other => return Err(corrupt(&format!("decoder returned {other:?}"))),
                    }
                    if produced > 0 {
                        return Ok(produced);
                    }
                    if consumed == 0 && matches!(self.state, LzipState::Body(_)) {
                        // No input taken and no output made: the decoder cannot
                        // progress. Bail instead of spinning.
                        return Err(corrupt("decoder stalled"));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn gzip_bytes(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn gzip_roundtrip() {
        let payload = b"hello newtua";
        let compressed = gzip_bytes(payload);
        let mut r =
            decompressor(Compressor::Gzip, Box::new(std::io::Cursor::new(compressed))).unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn zstd_roundtrip() {
        let payload = b"hello zstd payload";
        let compressed = zstd::encode_all(&payload[..], 0).unwrap();
        let mut r =
            decompressor(Compressor::Zstd, Box::new(std::io::Cursor::new(compressed))).unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn corrupt_zstd_errors_on_read() {
        // Valid zstd magic followed by garbage — must error during read.
        let mut bytes = vec![0x28, 0xB5, 0x2F, 0xFD];
        bytes.extend_from_slice(&[0xFF; 32]);
        let mut r = decompressor(Compressor::Zstd, Box::new(std::io::Cursor::new(bytes))).unwrap();
        let mut out = Vec::new();
        assert!(r.read_to_end(&mut out).is_err());
    }

    #[test]
    fn zstd_multi_frame_reads_all_frames() {
        // zstd allows concatenated frames in one stream; the decoder must read all.
        let mut compressed = zstd::encode_all(&b"frame-one"[..], 0).unwrap();
        compressed.extend_from_slice(&zstd::encode_all(&b"frame-two"[..], 0).unwrap());
        let mut r =
            decompressor(Compressor::Zstd, Box::new(std::io::Cursor::new(compressed))).unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"frame-oneframe-two");
    }

    #[test]
    fn lzc_decodes_dot_z_stream() {
        // Hand-crafted non-block .Z (header 1f 9d 10 + literals 'A','B'),
        // independent of any fixture file.
        let bytes = vec![0x1f, 0x9d, 0x10, 0x41, 0x84, 0x00];
        let mut r = decompressor(Compressor::Lzc, Box::new(std::io::Cursor::new(bytes))).unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"AB");
    }

    #[test]
    fn lzma_roundtrip() {
        let payload = b"hello lzma payload";
        let opts = xz2::stream::LzmaOptions::new_preset(6).unwrap();
        let stream = xz2::stream::Stream::new_lzma_encoder(&opts).unwrap();
        let mut enc = xz2::write::XzEncoder::new_stream(Vec::new(), stream);
        enc.write_all(payload).unwrap();
        let compressed = enc.finish().unwrap();
        let mut r =
            decompressor(Compressor::Lzma, Box::new(std::io::Cursor::new(compressed))).unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn lz4_roundtrip() {
        use lz4_flex::frame::FrameEncoder;
        let payload = b"hello lz4 payload";
        let mut enc = FrameEncoder::new(Vec::new());
        enc.write_all(payload).unwrap();
        let compressed = enc.finish().unwrap();
        let mut r =
            decompressor(Compressor::Lz4, Box::new(std::io::Cursor::new(compressed))).unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn corrupt_lz4_errors_on_read() {
        // Valid LZ4 frame magic followed by garbage — must error during read.
        let mut bytes = vec![0x04, 0x22, 0x4D, 0x18];
        bytes.extend_from_slice(&[0xFF; 32]);
        let mut r = decompressor(Compressor::Lz4, Box::new(std::io::Cursor::new(bytes))).unwrap();
        let mut out = Vec::new();
        assert!(r.read_to_end(&mut out).is_err());
    }

    // A known-good Brotli stream that decodes to `BROTLI_HELLO_PLAIN`. newtua is
    // decode-only and never links a Brotli encoder (it is a heavy separate crate),
    // so instead of encoding-then-decoding — which would only test the `brotli`
    // crate — we decode this committed reference stream and assert our
    // `decompressor` arm yields the original bytes. The blob was produced once,
    // out of tree, by `brotli::CompressorWriter::new(buf, 4096, 11, 22)` over
    // `BROTLI_HELLO_PLAIN`; regenerate it the same way if the plaintext changes.
    const BROTLI_HELLO: &[u8] = &[
        0x1b, 0x43, 0x00, 0x80, 0xc5, 0x6e, 0x39, 0xad, 0x37, 0xaf, 0x24, 0x52, 0xea, 0x84, 0xe1,
        0x1f, 0x26, 0x72, 0xe0, 0xd0, 0x16, 0xe8, 0x3d, 0x30, 0x3c, 0x78, 0xc8, 0x5a, 0x3a, 0x89,
        0x49, 0xc8, 0xb1, 0xa3, 0xc3, 0xab, 0x44, 0xcb, 0x2f, 0x8a, 0x0d, 0xc8, 0x08, 0xa0, 0x23,
        0xe5, 0x7c, 0x30, 0xb5, 0x05, 0xd2, 0xf7, 0xaa, 0xc1, 0x18,
    ];
    const BROTLI_HELLO_PLAIN: &[u8] =
        b"hello brotli payload \xe2\x80\x94 the quick brown fox jumps over the lazy dog";

    #[test]
    fn brotli_decodes_known_stream() {
        let mut r = decompressor(
            Compressor::Brotli,
            Box::new(std::io::Cursor::new(BROTLI_HELLO)),
        )
        .unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, BROTLI_HELLO_PLAIN);
    }

    // Framed Snappy (framing2) produced by the reference tool Keka ships,
    // `snzip 1.0.5`, over `SNAPPY_HELLO_PLAIN`:
    //   /Applications/Keka.app/Contents/MacOS/Keka --ignore-file-access \
    //       --cli snzip -c hello.txt > hello.txt.sz
    // Decoding an outside-produced stream (rather than a round-trip through
    // `snap`'s own encoder) is what actually proves we read what Keka writes.
    const SNAPPY_HELLO: &[u8] = &[
        0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59, 0x01, 0x16, 0x00, 0x00, 0xe1,
        0xcb, 0xb1, 0xd2, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x73,
        0x6e, 0x61, 0x70, 0x70, 0x79, 0x0a,
    ];
    const SNAPPY_HELLO_PLAIN: &[u8] = b"hello from snappy\n";

    #[test]
    fn snappy_decodes_known_stream() {
        let mut r = decompressor(
            Compressor::Snappy,
            Box::new(std::io::Cursor::new(SNAPPY_HELLO)),
        )
        .unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, SNAPPY_HELLO_PLAIN);
    }

    // lzip streams produced by the reference tool Keka ships, `lzip 1.26`:
    //   printf 'hello from lzip\n' > hello.txt
    //   /Applications/Keka.app/Contents/MacOS/Keka --ignore-file-access \
    //       --cli lzip -k hello.txt          # → hello.txt.lz
    // As with Snappy, decoding an outside-produced stream (not a round-trip
    // through an encoder of ours — we have none) is what proves we read what
    // lzip writes. Dictionary byte `0c` here means 4 KiB.
    const LZIP_HELLO: &[u8] = &[
        0x4c, 0x5a, 0x49, 0x50, 0x01, 0x0c, 0x00, 0x34, 0x19, 0x49, 0xee, 0x8d, 0xe9, 0x12, 0xe6,
        0x14, 0x0e, 0xbf, 0xb9, 0x78, 0xc2, 0x8e, 0x45, 0x9b, 0x29, 0x9b, 0xf6, 0xff, 0xff, 0x92,
        0xca, 0x00, 0x00, 0x69, 0x1c, 0x6d, 0x0f, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x35, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    const LZIP_HELLO_PLAIN: &[u8] = b"hello from lzip\n";

    // Two independent lzip members concatenated, the way `cat a.lz b.lz` (and
    // `lzip` itself, appending to an existing file) produces them:
    //   printf 'member one\n' > one.txt; printf 'member two\n' > two.txt
    //   … --cli lzip -k one.txt two.txt
    //   cat one.txt.lz two.txt.lz > multi.txt.lz
    const LZIP_MULTI: &[u8] = &[
        0x4c, 0x5a, 0x49, 0x50, 0x01, 0x0c, 0x00, 0x36, 0x99, 0x49, 0xfd, 0xb6, 0xe2, 0x59, 0xc3,
        0x2b, 0x3d, 0x10, 0x73, 0x27, 0x5a, 0x63, 0xff, 0xff, 0xae, 0x0e, 0x00, 0x00, 0xdd, 0xf3,
        0x1d, 0x7f, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x4c, 0x5a, 0x49, 0x50, 0x01, 0x0c, 0x00, 0x36, 0x99, 0x49, 0xfd, 0xb6,
        0xe2, 0x59, 0xc3, 0x39, 0x92, 0x60, 0x9c, 0x4f, 0xd1, 0x3f, 0x7f, 0xff, 0xc9, 0x5c, 0x00,
        0x00, 0x36, 0x53, 0x1d, 0x11, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    const LZIP_MULTI_PLAIN: &[u8] = b"member one\nmember two\n";

    #[test]
    fn lzip_decodes_known_stream() {
        let mut r =
            decompressor(Compressor::Lzip, Box::new(std::io::Cursor::new(LZIP_HELLO))).unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, LZIP_HELLO_PLAIN);
    }

    #[test]
    fn lzip_multi_member_reads_all_members() {
        // The whole point of the manual member loop: a single-member decoder
        // would stop after "member one\n" and silently drop the rest.
        let mut r =
            decompressor(Compressor::Lzip, Box::new(std::io::Cursor::new(LZIP_MULTI))).unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, LZIP_MULTI_PLAIN);
    }

    #[test]
    fn lzip_reads_across_a_one_byte_output_buffer() {
        // `read` must make progress with a tiny output buffer and must not
        // lose the member boundary when a call ends exactly at one.
        let mut r =
            decompressor(Compressor::Lzip, Box::new(std::io::Cursor::new(LZIP_MULTI))).unwrap();
        let mut out = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            match r.read(&mut byte).unwrap() {
                0 => break,
                _ => out.push(byte[0]),
            }
        }
        assert_eq!(out, LZIP_MULTI_PLAIN);
    }

    #[test]
    fn truncated_lzip_errors_on_read() {
        // Cut inside the LZMA payload: the end-of-stream marker never arrives.
        let mut r = decompressor(
            Compressor::Lzip,
            Box::new(std::io::Cursor::new(&LZIP_HELLO[..20])),
        )
        .unwrap();
        let mut out = Vec::new();
        assert!(r.read_to_end(&mut out).is_err());
    }

    #[test]
    fn lzip_with_truncated_trailer_errors_on_read() {
        // Payload complete, trailer cut short — the member never closes, so
        // the size check can't run. Must be an error, not a short read.
        let mut r = decompressor(
            Compressor::Lzip,
            Box::new(std::io::Cursor::new(&LZIP_HELLO[..LZIP_HELLO.len() - 4])),
        )
        .unwrap();
        let mut out = Vec::new();
        assert!(r.read_to_end(&mut out).is_err());
    }

    #[test]
    fn lzip_with_lying_size_trailer_errors_on_read() {
        // Trailer says one byte more than the member actually decoded to.
        let mut bytes = LZIP_HELLO.to_vec();
        let n = bytes.len();
        bytes[n - 16] += 1; // first byte of the uncompressed-size field
        let mut r = decompressor(Compressor::Lzip, Box::new(std::io::Cursor::new(bytes))).unwrap();
        let mut out = Vec::new();
        assert!(r.read_to_end(&mut out).is_err());
    }

    #[test]
    fn lzip_keeps_erroring_after_the_first_failure() {
        // A caller that ignores the first error must not get a silent EOF (which
        // would look like a short but complete file) or a restart mid-stream.
        let mut r = decompressor(
            Compressor::Lzip,
            Box::new(std::io::Cursor::new(&LZIP_HELLO[..20])),
        )
        .unwrap();
        let mut sink = [0u8; 64];
        let mut saw_error = false;
        loop {
            match r.read(&mut sink) {
                Ok(0) => panic!("EOF after a failure instead of the error again"),
                Ok(_) => assert!(!saw_error, "produced data after a failure"),
                Err(_) => {
                    if saw_error {
                        break;
                    }
                    saw_error = true;
                }
            }
        }
    }

    #[test]
    fn lzip_with_bad_dictionary_exponent_errors_on_read() {
        // Coded dictionary size out of lzip's 2^12..2^29 range: reject before
        // asking the decoder to allocate anything.
        let mut bytes = LZIP_HELLO.to_vec();
        bytes[5] = 0x1f; // exponent 31
        let mut r = decompressor(Compressor::Lzip, Box::new(std::io::Cursor::new(bytes))).unwrap();
        let mut out = Vec::new();
        assert!(r.read_to_end(&mut out).is_err());
    }

    #[test]
    fn corrupt_snappy_errors_on_read() {
        // Keep the stream-identifier chunk intact, replace the data chunk with
        // garbage: the decoder must error, not panic or spin.
        let mut bytes = SNAPPY_HELLO[..10].to_vec();
        bytes.extend_from_slice(&[0xFF; 32]);
        let mut r =
            decompressor(Compressor::Snappy, Box::new(std::io::Cursor::new(bytes))).unwrap();
        let mut out = Vec::new();
        assert!(r.read_to_end(&mut out).is_err());
    }

    #[test]
    fn corrupt_brotli_errors_on_read() {
        // Brotli has no magic, so the "valid magic + garbage" trick used for
        // gzip/zstd/lz4 does not apply. Instead, feed a tiny prefix of a VALID
        // stream: too few bytes to be a complete brotli stream regardless of what
        // BROTLI_HELLO encodes, so the decoder always hits EOF before the ISLAST
        // marker and errors on read (UnexpectedEof). Robust-by-construction — not
        // tied to BROTLI_HELLO's length.
        let truncated = &BROTLI_HELLO[..4];
        let mut r = decompressor(
            Compressor::Brotli,
            Box::new(std::io::Cursor::new(truncated)),
        )
        .unwrap();
        let mut out = Vec::new();
        assert!(r.read_to_end(&mut out).is_err());
    }
}

#[cfg(test)]
mod full {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn bzip2_roundtrip() {
        let payload = b"bzip payload";
        let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
        e.write_all(payload).unwrap();
        let compressed = e.finish().unwrap();
        let mut r = decompressor(
            Compressor::Bzip2,
            Box::new(std::io::Cursor::new(compressed)),
        )
        .unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn xz_roundtrip() {
        let payload = b"xz payload";
        let mut e = xz2::write::XzEncoder::new(Vec::new(), 6);
        e.write_all(payload).unwrap();
        let compressed = e.finish().unwrap();
        let mut r =
            decompressor(Compressor::Xz, Box::new(std::io::Cursor::new(compressed))).unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, payload);
    }

    fn bzip2_bytes(data: &[u8]) -> Vec<u8> {
        let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn xz_bytes(data: &[u8]) -> Vec<u8> {
        let mut e = xz2::write::XzEncoder::new(Vec::new(), 6);
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn bzip2_multi_member_reads_all_members() {
        // What `pbzip2` writes — and Keka's default bzip2 path is pbzip2, so
        // every .bz2 it produces has one member per thread. A single-member
        // decoder stops after the first and drops the rest without an error.
        let mut compressed = bzip2_bytes(b"member one\n");
        compressed.extend_from_slice(&bzip2_bytes(b"member two\n"));
        compressed.extend_from_slice(&bzip2_bytes(b"member three\n"));
        let mut r = decompressor(
            Compressor::Bzip2,
            Box::new(std::io::Cursor::new(compressed)),
        )
        .unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"member one\nmember two\nmember three\n");
    }

    #[test]
    fn bzip2_with_garbage_after_a_member_errors_on_read() {
        // Reading further members must not turn a broken tail into success.
        let mut compressed = bzip2_bytes(b"good member\n");
        compressed.extend_from_slice(&[0xFF; 64]);
        let mut r = decompressor(
            Compressor::Bzip2,
            Box::new(std::io::Cursor::new(compressed)),
        )
        .unwrap();
        let mut out = Vec::new();
        assert!(r.read_to_end(&mut out).is_err());
    }

    #[test]
    fn xz_multi_stream_reads_all_streams() {
        // `cat a.xz b.xz` is a valid .xz file; a single-stream decoder rejects
        // it outright ("corrupt xz stream").
        let mut compressed = xz_bytes(b"stream one\n");
        compressed.extend_from_slice(&xz_bytes(b"stream two\n"));
        let mut r =
            decompressor(Compressor::Xz, Box::new(std::io::Cursor::new(compressed))).unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"stream one\nstream two\n");
    }

    #[test]
    fn xz_with_garbage_after_a_stream_errors_on_read() {
        let mut compressed = xz_bytes(b"good stream\n");
        compressed.extend_from_slice(&[0xFF; 64]);
        let mut r =
            decompressor(Compressor::Xz, Box::new(std::io::Cursor::new(compressed))).unwrap();
        let mut out = Vec::new();
        assert!(r.read_to_end(&mut out).is_err());
    }

    #[test]
    fn corrupt_gzip_errors_on_read() {
        let mut r = decompressor(
            Compressor::Gzip,
            Box::new(std::io::Cursor::new(vec![0xFF; 32])),
        )
        .unwrap();
        let mut out = Vec::new();
        assert!(r.read_to_end(&mut out).is_err());
    }
}
