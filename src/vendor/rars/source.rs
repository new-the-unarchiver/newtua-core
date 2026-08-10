use crate::vendor::rars::error::{Error, Result};
use std::fs::File;
use std::io::{BufReader, Cursor, Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

const READ_BUFFER_SIZE: usize = 64 * 1024;

/// Откуда читаются байты архива.
///
/// NEWTUA: `allow(dead_code)` — `Memory` не создаёт никто. Движок открывает
/// RAR только по пути (`FormatHandler::open` отказывает потоковому источнику:
/// многотомный набор надо уметь перечитывать), а разбор из памяти был у
/// апстрима отдельной точкой входа, и она ушла как недостижимая. Само
/// разветвление остаётся: без него источник перестал бы быть источником.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) enum ArchiveSource {
    Memory(Arc<[u8]>),
    File(Arc<FileSource>),
}

/// Файл архива и один открытый дескриптор к нему.
///
/// NEWTUA: дескриптор переживает запись (тикет 30, этап Е3).
///
/// Апстрим звал `File::open` на **каждую** запись, и на сплошном архиве из
/// 8000 мелких файлов это 8000 открытий с закрытиями: в профиле после снятия
/// копии словаря на `__open`/`__lseek`/`close` приходилось около двух третей
/// времени процесса. Открытие даром: файл всё время один и тот же.
///
/// Дескриптор один, а читателей изредка бывает несколько сразу — так собирает
/// разрезанную между томами запись `fragment_reader`. Поэтому это не «всегда
/// один файл», а склад на одно место: занято — открываем новый, освободилось —
/// кладём обратно. Возврат делает `Drop`, так что забыть его нельзя.
///
/// Замок здесь не ради многопоточности, а чтобы источник остался `Send`
/// и `Sync`, каким был: `ArchiveSource` доезжает до вызывающего внутри
/// `Box<dyn ArchiveReader>`, и молча отнять у него это свойство значило бы
/// сломать чужую сборку, ничего не сломав в своей. Он всегда свободен —
/// берётся и отпускается в пределах одного вызова.
#[derive(Debug)]
pub(crate) struct FileSource {
    path: Arc<PathBuf>,
    idle: Mutex<Option<File>>,
}

impl FileSource {
    fn new(path: Arc<PathBuf>) -> Self {
        Self {
            path,
            idle: Mutex::new(None),
        }
    }

    /// Дескриптор, установленный на `start`.
    fn reader_at(&self, start: u64) -> Result<PooledFile<'_>> {
        let taken = self
            .idle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let file = match taken {
            Some(file) => file,
            None => File::open(self.path.as_ref())?,
        };
        let mut pooled = PooledFile {
            file: Some(file),
            idle: &self.idle,
        };
        pooled.seek(SeekFrom::Start(start))?;
        Ok(pooled)
    }
}

/// Дескриптор, взятый со склада [`FileSource`] и возвращаемый туда же.
#[derive(Debug)]
struct PooledFile<'a> {
    file: Option<File>,
    idle: &'a Mutex<Option<File>>,
}

impl PooledFile<'_> {
    fn file(&mut self) -> &mut File {
        self.file.as_mut().expect("дескриптор на месте до Drop")
    }
}

impl Read for PooledFile<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file().read(buf)
    }
}

impl Seek for PooledFile<'_> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.file().seek(pos)
    }
}

impl Drop for PooledFile<'_> {
    fn drop(&mut self) {
        let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
        if idle.is_none() {
            *idle = self.file.take();
        }
    }
}

impl ArchiveSource {
    pub(crate) fn file(path: Arc<PathBuf>) -> Self {
        Self::File(Arc::new(FileSource::new(path)))
    }

    pub(crate) fn copy_range_to(&self, range: Range<usize>, writer: &mut dyn Write) -> Result<()> {
        match self {
            Self::Memory(data) => {
                let data = data.get(range).ok_or(Error::TooShort)?;
                writer.write_all(data)?;
            }
            Self::File(source) => {
                let file = source.reader_at(range.start as u64)?;
                let mut limited = file.take(range.len() as u64);
                std::io::copy(&mut limited, writer)?;
            }
        }
        Ok(())
    }

    /// NEWTUA: файловый поток буферизован.
    ///
    /// Апстрим отдавал голый дескриптор, и это было терпимо, пока упакованное
    /// тело читалось одним `read_to_end`. Тикет 29 пустил его потоком, а
    /// разбор блоков RAR 5 читает по два-три байта — без буфера это системный
    /// вызов на каждое поле заголовка.
    pub(crate) fn range_reader(&self, range: Range<usize>) -> Result<Box<dyn Read + '_>> {
        match self {
            Self::Memory(data) => {
                let data = data.get(range).ok_or(Error::TooShort)?;
                Ok(Box::new(Cursor::new(data)))
            }
            Self::File(source) => {
                let file = source.reader_at(range.start as u64)?;
                // NEWTUA: буфер не крупнее самого диапазона. У сплошного архива
                // из мелких файлов запись — это сотня-другая байт, а буфер на
                // 64 КиБ выделялся под каждую.
                let capacity = READ_BUFFER_SIZE.min(range.len().max(1));
                Ok(Box::new(BufReader::with_capacity(
                    capacity,
                    file.take(range.len() as u64),
                )))
            }
        }
    }
}
