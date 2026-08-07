use std::io::{self, Read};
use std::slice;

use byteorder::{LittleEndian, ReadBytesExt};

use super::string::read_null_terminated_string;

/// An iterator over the file entries in a folder.
#[derive(Clone)]
pub struct FileEntries<'a> {
    pub(crate) iter: slice::Iter<'a, FileEntry>,
}

/// Metadata about one file stored in a cabinet.
#[derive(Debug, Clone)]
pub struct FileEntry {
    name: String,
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
    /// Returns the name of the file.
    pub fn name(&self) -> &str {
        &self.name
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
    // The attribute word (read-only, hidden, system, archive, exec, and a
    // "name is UTF-8" bit) is read past and dropped: none of it describes
    // something the engine reproduces on extraction, and upstream's own string
    // reader ignored the encoding bit too.
    let _attributes = reader.read_u16::<LittleEndian>()?;
    let name = read_null_terminated_string(&mut reader)?;
    Ok(FileEntry {
        name,
        folder_index,
        date,
        time,
        uncompressed_size,
        uncompressed_offset,
    })
}
