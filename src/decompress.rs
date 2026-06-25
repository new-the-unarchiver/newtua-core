use std::io::Read;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compressor {
    Gzip,
    Bzip2,
    Xz,
    Zstd,
    Lzma,
    Lzc,
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
