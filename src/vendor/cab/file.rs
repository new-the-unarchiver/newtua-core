use std::io::{self, Read};
use std::slice;

use byteorder::{LittleEndian, ReadBytesExt};

use super::consts;
use super::string::read_null_terminated_name;

/// An iterator over the file entries in a folder.
#[derive(Clone)]
pub struct FileEntries<'a> {
    pub(crate) iter: slice::Iter<'a, FileEntry>,
}

/// Metadata about one file stored in a cabinet.
#[derive(Debug, Clone)]
pub struct FileEntry {
    /// The name exactly as stored — bytes, not a string. See [`FileEntry::name`].
    name: Vec<u8>,
    /// Set when the cabinet declares this name to be UTF-8.
    name_is_utf8: bool,
    /// The two packed MS-DOS words, exactly as the cabinet stores them.
    date: u16,
    time: u16,
    uncompressed_size: u32,
    pub(crate) folder_index: u16,
    pub(crate) uncompressed_offset: u32,
}

impl<'a> Iterator for FileEntries<'a> {
    type Item = &'a FileEntry;

    fn next(&mut self) -> Option<&'a FileEntry> {
        self.iter.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl ExactSizeIterator for FileEntries<'_> {}

impl FileEntry {
    /// The stored name, as the bytes the cabinet holds.
    ///
    /// **Deliberately not a `String`.** A CAB name is UTF-8 only when the entry
    /// says so; otherwise it is in whatever Windows code page the packer ran
    /// under. Upstream ran every name through `String::from_utf8_lossy`, which
    /// turns each unrecognised byte into U+FFFD and cannot be undone — a
    /// Russian or Japanese file name came out as a row of question marks. The
    /// engine has one place that decides an encoding for a whole archive at
    /// once (`encoding::decode_names`), and it needs the bytes to do it.
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    /// Whether the cabinet declares this name to be UTF-8.
    ///
    /// Upstream parsed this bit and then ignored it (its own TODO). It is worth
    /// honouring: a cabinet that says "UTF-8" should not have its names guessed
    /// at by a charset detector.
    pub fn name_is_utf8(&self) -> bool {
        self.name_is_utf8
    }

    /// The stored timestamp as the two raw MS-DOS words, `(date, time)`.
    ///
    /// **Deliberately not converted here.** Upstream handed back a
    /// `time::PrimitiveDateTime`; the engine converts timestamps at the edge
    /// where it knows which timezone to read a wall clock in, exactly as it
    /// does for every other format of that era (see `src/datetime.rs`). Handing
    /// the words over raw also took the `time` crate out of the build.
    pub fn dos_date_time(&self) -> (u16, u16) {
        (self.date, self.time)
    }

    /// Returns the total size of the file when decompressed, in bytes.
    pub fn uncompressed_size(&self) -> u32 {
        self.uncompressed_size
    }

    /// Where this file starts within its folder's decompressed stream.
    pub fn uncompressed_offset(&self) -> u32 {
        self.uncompressed_offset
    }
}

pub(crate) fn parse_file_entry<R: Read>(mut reader: R) -> io::Result<FileEntry> {
    let uncompressed_size = reader.read_u32::<LittleEndian>()?;
    let uncompressed_offset = reader.read_u32::<LittleEndian>()?;
    let folder_index = reader.read_u16::<LittleEndian>()?;
    let date = reader.read_u16::<LittleEndian>()?;
    let time = reader.read_u16::<LittleEndian>()?;
    // Of the attribute word (read-only, hidden, system, archive, exec) only the
    // "name is UTF-8" bit is kept: the DOS attributes describe a Windows file
    // the engine does not reproduce.
    let attributes = reader.read_u16::<LittleEndian>()?;
    let name = read_null_terminated_name(&mut reader)?;
    Ok(FileEntry {
        name,
        name_is_utf8: (attributes & consts::ATTR_NAME_IS_UTF) != 0,
        folder_index,
        date,
        time,
        uncompressed_size,
        uncompressed_offset,
    })
}
