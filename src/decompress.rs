use std::io::Read;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compressor {
    Gzip,
    Bzip2,
    Xz,
    Zstd,
    Lzma,
    Lzc,
    Lz4,
    Brotli,
}

pub fn decompressor(kind: Compressor, inner: Box<dyn Read>) -> std::io::Result<Box<dyn Read>> {
    match kind {
        Compressor::Gzip => Ok(Box::new(flate2::read::MultiGzDecoder::new(inner))),
        Compressor::Bzip2 => Ok(Box::new(bzip2::read::BzDecoder::new(inner))),
        Compressor::Xz => Ok(Box::new(xz2::read::XzDecoder::new(inner))),
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

    // A known-good Brotli stream. newtua is decode-only and never links a Brotli
    // encoder (it is a heavy separate crate), so instead of encoding-then-decoding
    // — which would only test the `brotli` crate — we decode a committed reference
    // stream and assert our `decompressor` arm yields the original bytes. The blob
    // was produced once, out of tree, by `brotli::CompressorWriter` (quality 11).
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

    #[test]
    fn corrupt_brotli_errors_on_read() {
        // Brotli has no magic, so the "valid magic + garbage" trick used for
        // gzip/zstd/lz4 does not apply. Instead, truncate a VALID stream to half:
        // an incomplete brotli stream cannot reach its ISLAST marker, so the
        // decoder errors on read (UnexpectedEof).
        let half = &BROTLI_HELLO[..BROTLI_HELLO.len() / 2];
        let mut r = decompressor(Compressor::Brotli, Box::new(std::io::Cursor::new(half))).unwrap();
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
