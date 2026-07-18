use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatId {
    Zip,
    Tar,
    Gzip,
    Bzip2,
    Xz,
    SevenZ,
    Rar,
    Cab,
    Ar,
    Deb,
    Cpio,
    Rpm,
    Xar,
    Msi,
    Iso,
    /// Self-extracting `.exe` — the handler reports the inner format via
    /// `TempBackedReader`; `Sfx` is used only by `SfxHandler::id()`.
    Sfx,
    /// WARC web archive (`.warc`, `.warc.gz`).
    Warc,
    /// A single decompressed file (no container format; e.g. plain `.gz`).
    Raw,
    // Zip-основанные форматы-бандлы (#16). Все открываются общим zip-движком;
    // отличается лишь рапортуемый подтип. Детект — по расширению + PK.
    Jar,
    Apk,
    Ipa,
    Epub,
    Docx,
    Xlsx,
    Pptx,
    Odt,
    Ods,
    Odp,
    /// Chrome-расширение: zip за заголовком `Cr24` (CRX2/CRX3).
    Crx,
    /// Пакет conda (`.conda`): внешний zip с `*.tar.zst`-членами; ридер
    /// разворачивает их и показывает слитое содержимое.
    Conda,
    /// SquashFS read-only filesystem image (`.squashfs` / `.sfs`); via backhand.
    Squashfs,
    /// AppImage single-file app: an ELF runtime with an appended SquashFS
    /// (Type 2) or ISO 9660 (Type 1) filesystem, read from the computed offset.
    AppImage,
    /// WIM (`.wim`/`.esd`/`.swm`) Windows install image: a SHA-1-addressed
    /// resource store plus a metadata resource holding the directory tree.
    Wim,
    /// HFS+/HFSX (Mac OS Extended) read-only filesystem: a bare volume (as
    /// produced by `newfs_hfs`) or the filesystem layer inside a DMG image.
    /// HFSX (case-sensitive) reports the same `FormatId` — the two differ only
    /// in signature/case-sensitivity, not in shape.
    HfsPlus,
    /// DMG (`.dmg`) Apple Disk Image, UDIF container: koly trailer + XML plist
    /// blkx/mish chunk tables, decoded into a raw disk image and handed to the
    /// filesystem layer inside (HFS+ or APFS).
    Dmg,
    /// APFS (Apple File System) read-only filesystem: a bare container (`NXSB`
    /// magic) or the filesystem layer inside a DMG image. Supports transparent
    /// `decmpfs` decompression, unlike the HFS+ handler.
    Apfs,
    // Legacy formats from the `newtua-formats` family (ports from XADMaster).
    // Thin adapters in `format/legacy/`; detection is extension-first with a
    // `recognize` confirmation.
    /// ARJ (`.arj`), Robert Jung's DOS archiver — `newtua-dos`.
    Arj,
    /// Zoo (`.zoo`), Rahul Dhesi's cross-platform archiver — `newtua-dos`.
    Zoo,
    /// LBR (`.lbr`), CP/M library container — `newtua-dos`.
    Lbr,
    /// Crunch (DOS/CP-M LZW cruncher container) — `newtua-dos`.
    Crunch,
    /// ARC (`.arc`/`.ark`/`.pak`/`.spark`), SEA's PC archiver — `newtua-dos`.
    Arc,
    /// Squeeze (`.sq`/`.qqq`), Huffman-coded CP/M & DOS file — `newtua-dos`.
    Squeeze,
    /// BinHex 4.0 (`.hqx`), 7-bit Mac transport encoding — `newtua-mac`.
    BinHex,
    /// MacBinary I/II/III (`.bin`), resource-fork container — `newtua-mac`.
    MacBinary,
    /// AppleSingle / AppleDouble fork-preserving encoding — `newtua-mac`.
    AppleSingle,
    /// Compact Pro (`.cpt`), early-90s Mac archiver — `newtua-mac`.
    CompactPro,
    /// PackIt (`.pit`), early Mac archiver — `newtua-mac`.
    PackIt,
    /// StuffIt classic (`.sit`), the dominant Mac archiver — `newtua-stuffit`.
    StuffIt,
    /// StuffIt 5 (`.sit`), later container incl. RC4/MD5 — `newtua-stuffit`.
    StuffIt5,
    /// StuffItX (`.sitx`), range-coded successor — `newtua-stuffit`.
    StuffItX,
    /// ALZip (`.alz`), ESTsoft's Korean archiver — `newtua-alz`.
    Alz,
    /// NSIS (`.exe`), contents of a Nullsoft installer — `newtua-nsis`.
    Nsis,
    /// Amiga LZX (`.lzx`), the Amiga archiver — `newtua-amiga`.
    Lzx,
    /// PowerPacker (`.pp`), Amiga single-file cruncher — `newtua-amiga`.
    PowerPacker,
    /// DMS (`.dms`), Disk Masher System floppy image — `newtua-amiga`.
    Dms,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Confidence(pub u8);

impl Confidence {
    pub const NONE: Confidence = Confidence(0);
    pub const MAGIC: Confidence = Confidence(100);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Dir,
    Symlink { target: std::path::PathBuf },
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub path_raw: Vec<u8>,
    pub path: PathBuf,
    pub kind: EntryKind,
    pub size: u64,
    pub mode: Option<u32>,
    pub is_encrypted: bool,
    pub modified: Option<SystemTime>,
}

impl Entry {
    /// True when this entry is a directory.
    pub fn is_dir(&self) -> bool {
        matches!(self.kind, EntryKind::Dir)
    }
}

#[derive(Debug, Clone, Default)]
pub struct OpenOptions {
    pub password: Option<String>,
    pub encoding_override: Option<String>,
}

/// Источник архива: либо seekable-файл, либо чистый поток.
pub enum Source {
    Seekable {
        inner: Box<dyn ReadSeek>,
        path: Option<PathBuf>,
    },
    Stream {
        inner: Box<dyn Read>,
        path: Option<PathBuf>,
    },
}

pub trait ReadSeek: Read + Seek {}
impl<T: Read + Seek> ReadSeek for T {}

impl Source {
    pub fn path(p: &Path) -> Result<Source> {
        let f = std::fs::File::open(p)?;
        Ok(Source::Seekable {
            inner: Box::new(f),
            path: Some(p.to_path_buf()),
        })
    }

    pub fn file_path(&self) -> Option<&Path> {
        match self {
            Source::Seekable { path, .. } | Source::Stream { path, .. } => path.as_deref(),
        }
    }

    /// Прочитать первые `n` байт, не нарушая последующее чтение (для seekable —
    /// откат в начало; для stream — буфер не возвращается, поэтому header
    /// читается только из seekable-источников).
    pub fn peek_header(&mut self, n: usize) -> Result<Vec<u8>> {
        match self {
            Source::Seekable { inner, .. } => {
                let mut buf = vec![0u8; n];
                let read = read_up_to(inner, &mut buf)?;
                buf.truncate(read);
                inner.seek(SeekFrom::Start(0))?;
                Ok(buf)
            }
            Source::Stream { .. } => Err(Error::UnknownFormat),
        }
    }
}

fn read_up_to(r: &mut dyn Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

pub trait FormatHandler {
    fn id(&self) -> FormatId;
    fn probe(&self, header: &[u8], name: Option<&str>) -> Confidence;
    fn open(&self, src: Source, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>>;
}

pub trait ArchiveReader {
    fn format(&self) -> FormatId;
    fn entries(&mut self) -> Result<&[Entry]>;
    fn read_entry(&mut self, idx: usize, out: &mut dyn Write) -> Result<()>;

    /// Проверить, что архив можно расшифровать заданным паролем, НЕ извлекая
    /// файлы. Оркестратор (`extract_all`) вызывает это до начала записи на
    /// диск, чтобы ошибка пароля поднималась наверх единообразно для всех
    /// форматов и не оставляла частичных файлов.
    ///
    /// Контракт:
    /// - нет зашифрованных записей           → `Ok(())`
    /// - есть зашифрованная, пароль не задан → `Err(Error::Encrypted)`
    /// - пароль задан, но неверный           → `Err(Error::WrongPassword)`
    /// - пароль верный (или шифрования нет)   → `Ok(())`
    ///
    /// Значение по умолчанию — `Ok(())`, для форматов без шифрования
    /// (tar, ar, cab, gzip, raw).
    fn verify_password(&mut self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confidence_ordering() {
        assert!(Confidence::MAGIC > Confidence::NONE);
        assert_eq!(Confidence::NONE, Confidence(0));
    }

    #[test]
    fn open_options_default_is_empty() {
        let o = OpenOptions::default();
        assert!(o.password.is_none());
        assert!(o.encoding_override.is_none());
    }

    #[test]
    fn entry_construction() {
        let e = Entry {
            path_raw: b"a.txt".to_vec(),
            path: std::path::PathBuf::from("a.txt"),
            kind: EntryKind::File,
            size: 5,
            mode: None,
            is_encrypted: false,
            modified: None,
        };
        assert_eq!(e.size, 5);
        assert!(!e.is_dir());
    }
}
