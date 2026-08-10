use crate::vendor::rars::error::{Error, Result};
use std::fs::File;
use std::io::{BufReader, Cursor, Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::PathBuf;
use std::sync::Arc;

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
    File(Arc<PathBuf>),
}

impl ArchiveSource {
    pub(crate) fn copy_range_to(&self, range: Range<usize>, writer: &mut dyn Write) -> Result<()> {
        match self {
            Self::Memory(data) => {
                let data = data.get(range).ok_or(Error::TooShort)?;
                writer.write_all(data)?;
            }
            Self::File(path) => {
                let mut file = File::open(path.as_ref())?;
                file.seek(SeekFrom::Start(range.start as u64))?;
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
            Self::File(path) => {
                let mut file = File::open(path.as_ref())?;
                file.seek(SeekFrom::Start(range.start as u64))?;
                Ok(Box::new(BufReader::with_capacity(
                    READ_BUFFER_SIZE,
                    file.take(range.len() as u64),
                )))
            }
        }
    }
}
