use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
pub struct Rar13Cipher {
    key: [u8; 3],
}

pub struct Rar13DecryptReader<R> {
    inner: R,
    cipher: Rar13Cipher,
}

impl Rar13Cipher {
    pub fn new(password: &[u8]) -> Self {
        let mut key = [0u8; 3];
        for &byte in password {
            key[0] = key[0].wrapping_add(byte);
            key[1] ^= byte;
            key[2] = key[2].wrapping_add(byte).rotate_left(1);
        }
        Self { key }
    }

    pub fn decrypt_byte(&mut self, byte: u8) -> u8 {
        self.advance();
        byte.wrapping_sub(self.key[0])
    }

    fn advance(&mut self) {
        self.key[1] = self.key[1].wrapping_add(self.key[2]);
        self.key[0] = self.key[0].wrapping_add(self.key[1]);
    }
}

impl<R> Rar13DecryptReader<R> {
    pub fn new(inner: R, cipher: Rar13Cipher) -> Self {
        Self { inner, cipher }
    }
}

impl<R: std::io::Read> std::io::Read for Rar13DecryptReader<R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(out)?;
        for byte in &mut out[..read] {
            *byte = self.cipher.decrypt_byte(*byte);
        }
        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use super::{Rar13Cipher, Rar13DecryptReader};
    use std::io::Read;

    /// NEWTUA: расшифровка RAR 1.3 сходится с закреплённым потоком байт.
    ///
    /// Числа — из теста апстрима, где их получали шифрованием того же текста
    /// тут же, рядом. Шифратор ушёл вместе с писательской половиной, а числа
    /// остались, и так даже лучше: проверяется вход извне, а не то, что наш
    /// код согласен сам с собой.
    #[test]
    fn rar13_cipher_decrypts_a_pinned_stream() {
        const PINNED: [u8; 11] = [
            0x37, 0xcd, 0xaa, 0xbd, 0x10, 0x4e, 0x6f, 0x6e, 0xb5, 0x30, 0xe6,
        ];
        let mut out = Vec::new();
        Rar13DecryptReader::new(&PINNED[..], Rar13Cipher::new(b"password"))
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, b"hello world");
    }
}
