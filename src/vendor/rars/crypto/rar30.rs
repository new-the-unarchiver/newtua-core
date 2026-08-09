use aes::Aes128;
use aes::cipher::{BlockCipherDecrypt, KeyInit};
use sha1::{Digest, Sha1 as FastSha1};
use std::str;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const HASH_ROUNDS: u32 = 0x40000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    NonUtf8Password,
    UnalignedInput,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonUtf8Password => f.write_str("RAR 3.x password is not UTF-8"),
            Self::UnalignedInput => f.write_str("RAR 3.x AES input is not block aligned"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, ZeroizeOnDrop)]
pub struct Rar30Cipher {
    cipher: Aes128,
    iv: [u8; 16],
}

impl Rar30Cipher {
    pub fn new(password: &[u8], salt: Option<[u8; 8]>) -> Result<Self> {
        let (mut key, iv) = derive_key_iv(password, salt)?;
        let cipher = Aes128::new(&key.into());
        key.zeroize();
        Ok(Self { cipher, iv })
    }

    pub fn decrypt_in_place(&mut self, data: &mut [u8]) -> Result<()> {
        if !data.len().is_multiple_of(16) {
            return Err(Error::UnalignedInput);
        }
        for block in data.chunks_exact_mut(16) {
            self.decrypt_block(block);
        }
        Ok(())
    }

    fn decrypt_block(&mut self, block: &mut [u8]) {
        let ciphertext: [u8; 16] = block.try_into().expect("AES block size");
        let block: &mut [u8; 16] = block.try_into().expect("AES block size");
        self.cipher.decrypt_block(block.into());
        for (byte, iv_byte) in block.iter_mut().zip(self.iv) {
            *byte ^= iv_byte;
        }
        self.iv = ciphertext;
    }
}

fn derive_key_iv(password: &[u8], salt: Option<[u8; 8]>) -> Result<([u8; 16], [u8; 16])> {
    let mut raw = Zeroizing::new(Vec::with_capacity(password.len() * 2 + 8));
    let password = str::from_utf8(password).map_err(|_| Error::NonUtf8Password)?;
    for code_unit in password.encode_utf16() {
        raw.extend_from_slice(&code_unit.to_le_bytes());
    }
    if let Some(salt) = salt {
        raw.extend_from_slice(&salt);
    }

    // RAR 3.x mutates password/salt bytes only when the repeated KDF input
    // crosses complete SHA-1 blocks. The stock SHA-1 path is equivalent while
    // the password+salt material never fills a 64-byte block.
    if raw.len() < 64 {
        return Ok(derive_key_iv_fast(&raw));
    }

    Ok(derive_key_iv_slow(&mut raw))
}

fn derive_key_iv_slow(raw: &mut [u8]) -> ([u8; 16], [u8; 16]) {
    let raw_size = raw.len();
    let mut raw = Zeroizing::new(raw.to_vec());
    raw.resize(raw_size + 64, 0);
    let mut sha1 = FastSha1::new();
    let mut iv = [0; 16];
    let mut pos = 0u32;
    for i in 0..HASH_ROUNDS {
        sha1.update(&raw[..raw_size]);
        let end_pos = (pos + raw_size as u32) & !(64 - 1);
        if end_pos > pos + 64 {
            let mut cur_pos = (pos & !(64 - 1)) + 64;
            while cur_pos != end_pos {
                let offset = (cur_pos - pos) as usize;
                update_password_data_sha1(&mut raw[offset..offset + 64]);
                cur_pos += 64;
            }
        }
        pos = pos.wrapping_add(raw_size as u32);

        sha1.update([
            (i & 0xff) as u8,
            ((i >> 8) & 0xff) as u8,
            ((i >> 16) & 0xff) as u8,
        ]);
        pos = pos.wrapping_add(3);
        if i.is_multiple_of(HASH_ROUNDS / 16) {
            let digest = sha1.clone().finalize();
            iv[(i / (HASH_ROUNDS / 16)) as usize] = digest[19];
        }
    }

    let digest = sha1.finalize();
    let mut key = [0; 16];
    for (word_index, chunk) in digest[..16].chunks_exact(4).enumerate() {
        key[word_index * 4..word_index * 4 + 4]
            .copy_from_slice(&[chunk[3], chunk[2], chunk[1], chunk[0]]);
    }
    (key, iv)
}

fn update_password_data_sha1(data: &mut [u8]) {
    let mut w = [0u32; 80];
    for (i, chunk) in data.chunks_exact(4).take(16).enumerate() {
        w[i] = u32::from_be_bytes(chunk.try_into().expect("SHA-1 word size"));
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }
    for (i, word) in w[64..80].iter().enumerate() {
        data[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
}

fn derive_key_iv_fast(raw: &[u8]) -> ([u8; 16], [u8; 16]) {
    let mut sha1 = FastSha1::new();
    let mut iv = [0; 16];
    for i in 0..HASH_ROUNDS {
        sha1.update(raw);
        sha1.update([
            (i & 0xff) as u8,
            ((i >> 8) & 0xff) as u8,
            ((i >> 16) & 0xff) as u8,
        ]);
        if i.is_multiple_of(HASH_ROUNDS / 16) {
            let digest = sha1.clone().finalize();
            iv[(i / (HASH_ROUNDS / 16)) as usize] = digest[19];
        }
    }

    let digest = sha1.finalize();
    let mut key = [0; 16];
    for (word_index, chunk) in digest[..16].chunks_exact(4).enumerate() {
        key[word_index * 4..word_index * 4 + 4]
            .copy_from_slice(&[chunk[3], chunk[2], chunk[1], chunk[0]]);
    }
    (key, iv)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_kdf_material(password: &[u8], salt: Option<[u8; 8]>) -> Vec<u8> {
        let mut raw = Vec::with_capacity(password.len() * 2 + 8);
        let password = str::from_utf8(password).unwrap();
        for code_unit in password.encode_utf16() {
            raw.extend_from_slice(&code_unit.to_le_bytes());
        }
        if let Some(salt) = salt {
            raw.extend_from_slice(&salt);
        }
        raw
    }

    #[test]
    fn rejects_non_utf8_passwords() {
        assert!(matches!(
            Rar30Cipher::new(b"\xffpassword", None),
            Err(Error::NonUtf8Password)
        ));
    }

    #[test]
    fn rar30_fast_kdf_matches_reference_path_for_short_material() {
        for (password, salt) in [
            (b"".as_slice(), None),
            (b"password".as_slice(), Some(*b"rarsalt!")),
            ("páss".as_bytes(), Some([1, 2, 3, 4, 5, 6, 7, 8])),
        ] {
            let raw = raw_kdf_material(password, salt);
            assert!(
                raw.len() < 64,
                "case should exercise the fast-path precondition"
            );

            let fast = derive_key_iv_fast(&raw);
            let mut reference_raw = raw.clone();
            let reference = derive_key_iv_slow(&mut reference_raw);

            assert_eq!(fast, reference);
        }
    }
}
