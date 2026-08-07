use std::io;

use byteorder::{LittleEndian, WriteBytesExt};

const MSZIP_SIGNATURE: u16 = 0x4B43; // "CK" stored little-endian
const MSZIP_SIGNATURE_LEN: usize = 2;
const DEFLATE_MAX_DICT_LEN: usize = 0x8000;

pub struct MsZipDecompressor {
    decompressor: flate2::Decompress,
    dictionary: Vec<u8>,
}

impl MsZipDecompressor {
    pub fn new() -> MsZipDecompressor {
        MsZipDecompressor {
            decompressor: flate2::Decompress::new(false),
            dictionary: Vec::with_capacity(DEFLATE_MAX_DICT_LEN),
        }
    }

    pub fn reset(&mut self) {
        self.decompressor.reset(true);
        self.dictionary = Vec::with_capacity(DEFLATE_MAX_DICT_LEN);
    }

    pub fn decompress_block(
        &mut self,
        data: &[u8],
        uncompressed_size: usize,
    ) -> io::Result<Vec<u8>> {
        // Check signature:
        if data.len() < MSZIP_SIGNATURE_LEN
            || ((data[0] as u16) | ((data[1] as u16) << 8)) != MSZIP_SIGNATURE
        {
            invalid_data!("MSZIP decompression failed: Invalid block signature");
        }
        let data = &data[MSZIP_SIGNATURE_LEN..];
        // Reset decompressor with appropriate dictionary:
        self.decompressor.reset(false);
        if !self.dictionary.is_empty() {
            // TODO: Avoid doing extra allocations/copies here.
            debug_assert!(self.dictionary.len() <= DEFLATE_MAX_DICT_LEN);
            let length = self.dictionary.len() as u16;
            let mut chunk: Vec<u8> = vec![0];
            chunk.write_u16::<LittleEndian>(length)?;
            chunk.write_u16::<LittleEndian>(!length)?;
            chunk.extend_from_slice(&self.dictionary);
            let mut out = Vec::with_capacity(self.dictionary.len());
            let flush = flate2::FlushDecompress::Sync;
            match self.decompressor.decompress_vec(&chunk, &mut out, flush) {
                Ok(flate2::Status::Ok) => {}
                _ => unreachable!(),
            }
        }
        // Decompress data:
        let mut out = Vec::<u8>::with_capacity(uncompressed_size);
        let flush = flate2::FlushDecompress::Finish;
        match self.decompressor.decompress_vec(data, &mut out, flush) {
            Ok(_) => {}
            Err(error) => {
                invalid_data!("MSZIP decompression failed: {}", error);
            }
        }
        if out.len() != uncompressed_size {
            invalid_data!(
                "MSZIP decompression failed: Incorrect uncompressed size \
                 (expected {}, was actually {})",
                uncompressed_size,
                out.len()
            );
        }
        // Update dictionary for next block:
        if out.len() >= DEFLATE_MAX_DICT_LEN {
            let start = out.len() - DEFLATE_MAX_DICT_LEN;
            self.dictionary = out[start..].to_vec();
        } else {
            let total = self.dictionary.len() + out.len();
            if total > DEFLATE_MAX_DICT_LEN {
                self.dictionary.drain(..(total - DEFLATE_MAX_DICT_LEN));
            }
            self.dictionary.extend_from_slice(&out);
        }
        debug_assert_eq!(self.dictionary.capacity(), DEFLATE_MAX_DICT_LEN);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::MsZipDecompressor;

    /// The one upstream test kept: a block of real MSZIP bytes and the text
    /// they decode to. It needs no compressor, which is the point — the rest of
    /// upstream's suite compressed with its own encoder and decoded the result,
    /// so it could only ever agree with itself.
    #[test]
    fn read_compressed_data() {
        let input: &[u8] = b"CK%\xcc\xd1\t\x031\x0c\x04\xd1V\xb6\x80#\x95\xa4\
              \t\xc5\x12\xc7\x82e\xfb,\xa9\xff\x18\xee{x\xf3\x9d\xdb\x1c\\Q\
              \x0e\x9d}n\x04\x13\xe2\x96\x17\xda\x1ca--kC\x94\x8b\xd18nX\xe7\
              \x89az\x00\x8c\x15>\x15i\xbe\x0e\xe6hTj\x8dD%\xba\xfc\xce\x1e\
              \x96\xef\xda\xe0r\x0f\x81t>%\x9f?\x12]-\x87";
        let expected: &[u8] = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed \
              do eiusmod tempor incididunt ut labore et dolore magna aliqua.";
        assert!(input.len() < expected.len());
        let mut decompressor = MsZipDecompressor::new();
        let output = decompressor
            .decompress_block(input, expected.len())
            .unwrap();
        assert_eq!(output, expected);
    }
}
