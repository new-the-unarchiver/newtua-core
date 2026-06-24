use std::io::Read;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compressor {
    Gzip,
    Bzip2,
    Xz,
}

pub fn decompressor(kind: Compressor, inner: Box<dyn Read>) -> std::io::Result<Box<dyn Read>> {
    match kind {
        Compressor::Gzip => Ok(Box::new(flate2::read::MultiGzDecoder::new(inner))),
        Compressor::Bzip2 => Ok(Box::new(bzip2::read::BzDecoder::new(inner))),
        Compressor::Xz => Ok(Box::new(xz2::read::XzDecoder::new(inner))),
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
