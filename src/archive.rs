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
    /// Java web application archive (`.war`).
    War,
    /// Windows app package (`.appx`).
    Appx,
    /// Mozilla browser extension / add-on (`.xpi`).
    Xpi,
    /// Chrome extension: zip following the `Cr24` header (CRX2/CRX3).
    Crx,
    /// Conda package (`.conda`): an outer zip containing `*.tar.zst` members;
    /// the reader unpacks them and presents their merged contents.
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
    /// WPRESS (`.wpress`): the WordPress site dump written by the All-in-One WP
    /// Migration plugin — fixed-length text headers, bodies stored raw.
    Wpress,
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
    /// Matched by file extension alone, with no content signature to confirm it
    /// (the format's magic lives past the registry's 512-byte header peek).
    /// Below `MAGIC` on purpose: a genuine content-magic match for another
    /// format must win, so an extension guess never shadows it.
    pub const EXTENSION: Confidence = Confidence(50);
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
    /// This entry is the *resource fork* of the file named by `path`, not the
    /// file itself.
    ///
    /// A file on classic Mac OS held two independent byte streams: the data
    /// fork and the resource fork. The second one carried the icon, the fonts,
    /// the dialogs — for a picture or an application it is most of the file, and
    /// for some files the data fork is empty and the resource fork is all there
    /// is. The archive formats of that era (StuffIt, BinHex, MacBinary,
    /// AppleSingle, PackIt, Compact Pro) store both, and report them as two
    /// entries **sharing one name**, told apart only by this flag.
    ///
    /// Dropping it is silent data loss: the file appears, opens as garbage or
    /// as nothing, and no error is ever raised. `extract_all` therefore writes a
    /// fork the way Apple itself does — into the file's own resource fork where
    /// the filesystem has one, and beside it as `._name` (AppleDouble) where it
    /// does not.
    ///
    /// Always `false` outside the legacy Mac formats.
    pub is_resource_fork: bool,
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

/// Archive source: either a seekable file or a plain stream.
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

    /// Read the first `n` bytes without disturbing subsequent reads (for
    /// seekable sources — rewinds back to the start; for streams — the buffer
    /// isn't returned, so the header can only be read from seekable sources).
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

/// Что делать с очередной записью пакетного прохода — решает приёмник.
pub enum SinkStep {
    /// Тело записи нужно: обработчик передаёт его в [`EntrySink::write_body`],
    /// а затем обязан позвать [`EntrySink::end`].
    Body,
    /// Тело не нужно. Обработчик к этой записи больше не возвращается:
    /// `end` для неё **не** зовётся, весь учёт приёмник уже сделал сам.
    /// Так проходят каталоги и ссылки — у них тела нет вовсе.
    Skip,
    /// Прекратить проход. Записи, дописанные до этого, остаются.
    Stop,
}

/// Приёмник пакетного чтения: куда идут тела записей и что с ними вышло.
///
/// Живёт на стороне того, кто распаковывает (`extract_all`), а зовёт его
/// обработчик формата изнутри своего прохода по архиву. Отсюда и порядок
/// вызовов — `begin` → `write_body`* → `end` на каждую запись, строго по одной
/// зараз: последовательный носитель иначе и не умеет.
pub trait EntrySink {
    /// Приготовиться к записи `idx` и сказать, нужно ли её тело.
    fn begin(&mut self, idx: usize) -> Result<SinkStep>;

    /// Очередной кусок тела текущей записи.
    fn write_body(&mut self, buf: &[u8]) -> Result<()>;

    /// Тело текущей записи кончилось. `outcome` — `Ok(())`, если оно дошло
    /// целиком, иначе причина. Возврат `false` прекращает проход.
    fn end(&mut self, idx: usize, outcome: Result<()>) -> Result<bool>;
}

/// Мост от [`EntrySink`] к обычному `Write`, чтобы обработчик мог лить тело
/// через `std::io::copy`.
///
/// Настоящая ошибка приёмника хранится отдельно: `io::Error` донёс бы только
/// её текст, а наверх нужен наш `Error` — по нему решают, отменили распаковку
/// или она сломалась.
pub struct SinkWriter<'a> {
    sink: &'a mut dyn EntrySink,
    err: Option<Error>,
}

impl<'a> SinkWriter<'a> {
    pub fn new(sink: &'a mut dyn EntrySink) -> Self {
        Self { sink, err: None }
    }

    /// Ошибка приёмника, если она была. Её и надо отдать в `end`, а не ту,
    /// что вернул `io::copy`.
    pub fn take_err(&mut self) -> Option<Error> {
        self.err.take()
    }
}

impl Write for SinkWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.sink.write_body(buf) {
            Ok(()) => Ok(buf.len()),
            Err(e) => {
                self.err = Some(e);
                Err(std::io::Error::other("entry sink rejected the body"))
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub trait ArchiveReader {
    fn format(&self) -> FormatId;
    fn entries(&mut self) -> Result<&[Entry]>;
    /// Write entry `idx`'s body to `out`.
    ///
    /// `out` should not report [`std::io::ErrorKind::InvalidData`]: handlers
    /// read that kind as "the archive says something impossible" and turn it
    /// into [`Error::Corrupt`], so a sink that borrows the kind for its own
    /// validation gets its complaint reported as a damaged archive. Every sink
    /// in this crate obeys that — `SinkWriter` returns `io::Error::other` — but
    /// the trait is public, so it is written down rather than assumed.
    fn read_entry(&mut self, idx: usize, out: &mut dyn Write) -> Result<()>;

    /// Прочитать несколько записей за один проход по архиву.
    ///
    /// Зачем отдельный метод, если есть `read_entry`. Под частью форматов лежит
    /// **последовательный** поток: 7z со сплошным блоком, RAR, папка CAB. Там
    /// «дай запись номер N» означает «распакуй всё, что лежит до неё», и цикл
    /// по `read_entry` превращает распаковку в квадратичную — на семнадцати
    /// тысячах значков это сорок пять минут против восьми секунд у `7zz`
    /// (замеры: `.claude/PERF-2026-08-06-findings.md`). Здесь носителю говорят
    /// сразу весь список, и он проходит архив один раз.
    ///
    /// `indices` идут **по возрастанию и без повторов** — это порядок заголовка,
    /// он же естественный порядок носителя.
    ///
    /// Обратное приёмнику **не обещано**: обработчик волен обойти записи в том
    /// порядке, в каком они лежат, а не в каком их спросили. Так делает CAB —
    /// внутри папки он идёт по смещениям, а список файлов вправе с ними не
    /// совпадать. Приёмник поэтому обязан вести учёт по номеру записи, который
    /// приходит в `begin`/`end`, а не по счётчику вызовов.
    ///
    /// Реализация по умолчанию — цикл по `read_entry`, то есть ровно нынешнее
    /// поведение. Переопределять её нужно только там, где проход по архиву
    /// стоит дорого; форматам с произвольным доступом (zip, tar, wim, xar,
    /// squashfs, iso и прочим) она подходит как есть.
    fn read_entries(&mut self, indices: &[usize], sink: &mut dyn EntrySink) -> Result<()> {
        read_entries_one_by_one(self, indices, sink)
    }

    /// Verify that the archive can be decrypted with the given password,
    /// WITHOUT extracting any files. The orchestrator (`extract_all`) calls
    /// this before it starts writing to disk, so a password error surfaces
    /// uniformly across all formats and never leaves partial files behind.
    ///
    /// Contract:
    /// - no encrypted entries                       → `Ok(())`
    /// - an encrypted entry, no password given       → `Err(Error::Encrypted)`
    /// - a password given, but wrong                 → `Err(Error::WrongPassword)`
    /// - the password is correct (or no encryption)  → `Ok(())`
    ///
    /// Defaults to `Ok(())`, for formats without encryption
    /// (tar, ar, cab, gzip, raw).
    fn verify_password(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Пройти записи по одной через `read_entry` — тело реализации `read_entries`
/// по умолчанию.
///
/// Отдельной функцией, потому что переопределивший `read_entries` не может
/// позвать умолчание: носителю с произвольным доступом бывает нужно что-то
/// сделать до обхода, а сам обход оставить прежним (так делает HFS+, который
/// сообщает своему источнику байтов, что сейчас прочитают весь том). Без этого
/// цикл пришлось бы переписать у каждого такого — и он бы разошёлся.
pub(crate) fn read_entries_one_by_one<R: ArchiveReader + ?Sized>(
    reader: &mut R,
    indices: &[usize],
    sink: &mut dyn EntrySink,
) -> Result<()> {
    for &idx in indices {
        match sink.begin(idx)? {
            SinkStep::Stop => return Ok(()),
            SinkStep::Skip => continue,
            SinkStep::Body => {}
        }
        let mut w = SinkWriter::new(sink);
        let outcome = reader.read_entry(idx, &mut w);
        // Ошибка приёмника важнее ошибки чтения: отмену видно только по ней.
        let outcome = match w.take_err() {
            Some(e) => Err(e),
            None => outcome,
        };
        if !sink.end(idx, outcome)? {
            return Ok(());
        }
    }
    Ok(())
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
            is_resource_fork: false,
        };
        assert_eq!(e.size, 5);
        assert!(!e.is_dir());
    }
}
