use std::cell::RefCell;
use std::io::{self, Read, Seek, SeekFrom};

use byteorder::{LittleEndian, ReadBytesExt};

use super::consts;
use super::file::parse_file_entry;
use super::folder::{FolderEntries, FolderEntry, FolderReader, parse_folder_entry};
use super::string::skip_null_terminated_string;

pub(crate) trait ReadSeek: Read + Seek {}
impl<R: Read + Seek> ReadSeek for R {}

/// A structure for reading a cabinet file.
pub struct Cabinet<R: ?Sized> {
    pub(crate) inner: CabinetInner<R>,
}

pub(crate) struct CabinetInner<R: ?Sized> {
    data_reserve_size: u8,
    folders: Vec<FolderEntry>,
    reader: RefCell<R>,
}

impl<R: Read + Seek> Cabinet<R> {
    /// Open an existing cabinet file.
    pub fn new(mut reader: R) -> io::Result<Cabinet<R>> {
        let signature = reader.read_u32::<LittleEndian>()?;
        if signature != consts::FILE_SIGNATURE {
            invalid_data!("Not a cabinet file (invalid file signature)");
        }
        let _reserved1 = reader.read_u32::<LittleEndian>()?;
        let total_size = reader.read_u32::<LittleEndian>()?;
        if total_size > consts::MAX_TOTAL_CAB_SIZE {
            invalid_data!(
                "Cabinet total size field is too large \
                 ({} bytes; max is {} bytes)",
                total_size,
                consts::MAX_TOTAL_CAB_SIZE
            );
        }
        let _reserved2 = reader.read_u32::<LittleEndian>()?;
        let first_file_offset = reader.read_u32::<LittleEndian>()?;
        let _reserved3 = reader.read_u32::<LittleEndian>()?;
        let minor_version = reader.read_u8()?;
        let major_version = reader.read_u8()?;
        if major_version > consts::VERSION_MAJOR
            || major_version == consts::VERSION_MAJOR && minor_version > consts::VERSION_MINOR
        {
            invalid_data!(
                "Version {}.{} cabinet files are not supported",
                major_version,
                minor_version
            );
        }
        let num_folders = reader.read_u16::<LittleEndian>()? as usize;
        let num_files = reader.read_u16::<LittleEndian>()?;
        let flags = reader.read_u16::<LittleEndian>()?;
        // Cabinet set id and index — which set this cabinet belongs to and its
        // place in it. Read past: a cabinet set spans several files, and the
        // engine opens one file at a time.
        let _cabinet_set_id = reader.read_u16::<LittleEndian>()?;
        let _cabinet_set_index = reader.read_u16::<LittleEndian>()?;
        let mut header_reserve_size = 0u16;
        let mut folder_reserve_size = 0u8;
        let mut data_reserve_size = 0u8;
        if (flags & consts::FLAG_RESERVE_PRESENT) != 0 {
            header_reserve_size = reader.read_u16::<LittleEndian>()?;
            folder_reserve_size = reader.read_u8()?;
            data_reserve_size = reader.read_u8()?;
        }
        // Header reserve area: read past for the same reason as the folder's.
        if header_reserve_size > 0 {
            let mut discard = vec![0u8; header_reserve_size as usize];
            reader.read_exact(&mut discard)?;
        }
        // Names of the previous and next cabinet in the set, plus the disk each
        // sits on. Read past: the engine opens one cabinet at a time.
        if (flags & consts::FLAG_PREV_CABINET) != 0 {
            skip_null_terminated_string(&mut reader)?;
            skip_null_terminated_string(&mut reader)?;
        }
        if (flags & consts::FLAG_NEXT_CABINET) != 0 {
            skip_null_terminated_string(&mut reader)?;
            skip_null_terminated_string(&mut reader)?;
        }
        let mut folders = Vec::with_capacity(num_folders);
        for _ in 0..num_folders {
            let entry = parse_folder_entry(&mut reader, folder_reserve_size as usize)?;
            folders.push(entry);
        }
        reader.seek(SeekFrom::Start(first_file_offset as u64))?;
        // Each file entry is filed under its folder and nowhere else. Upstream
        // also kept a flat copy of the list, to resolve a file by name; nothing
        // reads files by name any more, so the copy went with it.
        for _ in 0..num_files {
            let entry = parse_file_entry(&mut reader)?;
            let folder_index = entry.folder_index as usize;
            if folder_index >= folders.len() {
                invalid_data!("File entry folder index out of bounds");
            }
            folders[folder_index].files.push(entry);
        }
        Ok(Cabinet {
            inner: CabinetInner {
                data_reserve_size,
                folders,
                reader: RefCell::new(reader),
            },
        })
    }

    /// Returns an iterator over the folder entries in this cabinet.
    pub fn folder_entries(&self) -> FolderEntries<'_> {
        FolderEntries {
            iter: self.inner.folders.iter(),
        }
    }

    /// Open folder `index` for one sequential pass over its decompressed
    /// stream.
    ///
    /// **This is the whole reason the crate is vendored.** Upstream exposed
    /// only `read_file(name)`, which built a fresh folder decoder and seeked
    /// from the folder's start on every call — so extracting a folder of N
    /// files decoded it N times over, and the cost of an extraction grew with
    /// the square of the file count. Handed the reader itself, the caller keeps
    /// one alive for the whole folder and walks it once.
    ///
    /// Takes `&self`, not `&mut self`: the underlying handle already lives
    /// behind a `RefCell`, so the borrow checker was the only thing insisting
    /// on exclusivity, and a `&mut` here would stop the caller holding a folder
    /// reader while reading its own entry list.
    pub fn open_folder(&self, index: usize) -> io::Result<FolderReader<'_, R>> {
        if index >= self.inner.folders.len() {
            invalid_input!(
                "Folder index {} is out of range (cabinet has {} folders)",
                index,
                self.inner.folders.len()
            );
        }

        let me: &Cabinet<dyn ReadSeek> = self;
        FolderReader::new(me, &self.inner.folders[index], self.inner.data_reserve_size)
    }
}

impl<R: ?Sized + Read> Read for &CabinetInner<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.borrow_mut().read(buf)
    }
}

impl<R: ?Sized + Seek> Seek for &CabinetInner<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.reader.borrow_mut().seek(pos)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read};

    use super::Cabinet;

    /// Whole decompressed stream of folder `index`.
    fn folder_bytes(cabinet: &Cabinet<Cursor<&[u8]>>, index: usize) -> Vec<u8> {
        let mut data = Vec::new();
        cabinet
            .open_folder(index)
            .unwrap()
            .read_to_end(&mut data)
            .unwrap();
        data
    }

    /// One file's bytes, addressed the way the engine addresses them: by its
    /// position in the folder, not by name.
    fn file_bytes(cabinet: &Cabinet<Cursor<&[u8]>>, folder: usize, file: usize) -> Vec<u8> {
        let entry = cabinet
            .folder_entries()
            .nth(folder)
            .unwrap()
            .file_entries()
            .nth(file)
            .unwrap();
        let (offset, size) = (
            entry.uncompressed_offset() as u64,
            entry.uncompressed_size() as u64,
        );
        let mut reader = cabinet.open_folder(folder).unwrap();
        reader.seek_to_uncompressed_offset(offset).unwrap();
        let mut data = Vec::new();
        reader.take(size).read_to_end(&mut data).unwrap();
        data
    }

    #[test]
    fn read_uncompressed_cabinet_with_one_file() {
        let binary: &[u8] = b"MSCF\0\0\0\0\x59\0\0\0\0\0\0\0\
            \x2c\0\0\0\0\0\0\0\x03\x01\x01\0\x01\0\0\0\x34\x12\0\0\
            \x43\0\0\0\x01\0\0\0\
            \x0e\0\0\0\0\0\0\0\0\0\x6c\x22\xba\x59\x01\0hi.txt\0\
            \x4c\x1a\x2e\x7f\x0e\0\x0e\0Hello, world!\n";
        assert_eq!(binary.len(), 0x59);
        let cabinet = Cabinet::new(Cursor::new(binary)).unwrap();
        assert_eq!(cabinet.folder_entries().len(), 1);

        let file = cabinet
            .folder_entries()
            .next()
            .unwrap()
            .file_entries()
            .next()
            .unwrap();
        assert_eq!(file.name(), b"hi.txt");
        // 1997-03-12 11:13:52 as the two packed MS-DOS words. Converting them
        // is the caller's job now, so the test checks the words themselves.
        assert_eq!(file.dos_date_time(), (0x226c, 0x59ba));

        assert_eq!(folder_bytes(&cabinet, 0), b"Hello, world!\n");
        assert_eq!(file_bytes(&cabinet, 0, 0), b"Hello, world!\n");
    }

    #[test]
    fn read_uncompressed_cabinet_with_two_files() {
        let binary: &[u8] = b"MSCF\0\0\0\0\x80\0\0\0\0\0\0\0\
            \x2c\0\0\0\0\0\0\0\x03\x01\x01\0\x02\0\0\0\x34\x12\0\0\
            \x5b\0\0\0\x01\0\0\0\
            \x0e\0\0\0\0\0\0\0\0\0\x6c\x22\xe7\x59\x01\0hi.txt\0\
            \x0f\0\0\0\x0e\0\0\0\0\0\x6c\x22\xe7\x59\x01\0bye.txt\0\
            \0\0\0\0\x1d\0\x1d\0Hello, world!\nSee you later!\n";
        assert_eq!(binary.len(), 0x80);
        let cabinet = Cabinet::new(Cursor::new(binary)).unwrap();

        assert_eq!(
            folder_bytes(&cabinet, 0),
            b"Hello, world!\nSee you later!\n"
        );
        assert_eq!(file_bytes(&cabinet, 0, 0), b"Hello, world!\n");
        assert_eq!(file_bytes(&cabinet, 0, 1), b"See you later!\n");
    }

    #[test]
    fn read_uncompressed_cabinet_with_two_data_blocks() {
        let binary: &[u8] = b"MSCF\0\0\0\0\x61\0\0\0\0\0\0\0\
            \x2c\0\0\0\0\0\0\0\x03\x01\x01\0\x01\0\0\0\x34\x12\0\0\
            \x43\0\0\0\x02\0\0\0\
            \x0e\0\0\0\0\0\0\0\0\0\x6c\x22\xba\x59\x01\0hi.txt\0\
            \0\0\0\0\x06\0\x06\0Hello,\
            \0\0\0\0\x08\0\x08\0 world!\n";
        assert_eq!(binary.len(), 0x61);
        let cabinet = Cabinet::new(Cursor::new(binary)).unwrap();
        assert_eq!(cabinet.folder_entries().len(), 1);

        assert_eq!(folder_bytes(&cabinet, 0), b"Hello, world!\n");
        assert_eq!(file_bytes(&cabinet, 0, 0), b"Hello, world!\n");
    }

    #[test]
    fn read_mszip_cabinet_with_one_file() {
        let binary: &[u8] = b"MSCF\0\0\0\0\x61\0\0\0\0\0\0\0\
            \x2c\0\0\0\0\0\0\0\x03\x01\x01\0\x01\0\0\0\x34\x12\0\0\
            \x43\0\0\0\x01\0\x01\0\
            \x0e\0\0\0\0\0\0\0\0\0\x6c\x22\xe7\x59\x01\0hi.txt\0\
            \0\0\0\0\x16\0\x0e\0\
            CK\xf3H\xcd\xc9\xc9\xd7Q(\xcf/\xcaIQ\xe4\x02\x00$\xf2\x04\x94";
        assert_eq!(binary.len(), 0x61);
        let cabinet = Cabinet::new(Cursor::new(binary)).unwrap();
        assert_eq!(cabinet.folder_entries().len(), 1);

        assert_eq!(folder_bytes(&cabinet, 0), b"Hello, world!\n");
        assert_eq!(file_bytes(&cabinet, 0, 0), b"Hello, world!\n");
    }

    #[test]
    fn read_mszip_cabinet_with_two_files() {
        let binary: &[u8] = b"MSCF\0\0\0\0\x88\0\0\0\0\0\0\0\
            \x2c\0\0\0\0\0\0\0\x03\x01\x01\0\x02\0\0\0\x34\x12\0\0\
            \x5b\0\0\0\x01\0\x01\0\
            \x0e\0\0\0\0\0\0\0\0\0\x6c\x22\xe7\x59\x01\0hi.txt\0\
            \x0f\0\0\0\x0e\0\0\0\0\0\x6c\x22\xe7\x59\x01\0bye.txt\0\
            \0\0\0\0\x25\0\x1d\0CK\xf3H\xcd\xc9\xc9\xd7Q(\xcf/\xcaIQ\xe4\
            \nNMU\xa8\xcc/U\xc8I,I-R\xe4\x02\x00\x93\xfc\t\x91";
        assert_eq!(binary.len(), 0x88);
        let cabinet = Cabinet::new(Cursor::new(binary)).unwrap();

        assert_eq!(
            folder_bytes(&cabinet, 0),
            b"Hello, world!\nSee you later!\n"
        );
        assert_eq!(file_bytes(&cabinet, 0, 0), b"Hello, world!\n");
        assert_eq!(file_bytes(&cabinet, 0, 1), b"See you later!\n");
    }

    #[test]
    fn read_lzx_cabinet_with_two_files() {
        let binary: &[u8] = b"\x4d\x53\x43\x46\x00\x00\x00\x00\x97\x00\x00\x00\x00\x00\x00\
            \x00\x2c\x00\x00\x00\x00\x00\x00\x00\x03\x01\x01\x00\x02\x00\
            \x00\x00\x2d\x05\x00\x00\x5b\x00\x00\x00\x01\x00\x03\x13\x0f\
            \x00\x00\x00\x00\x00\x00\x00\x00\x00\x21\x53\x0d\xb2\x20\x00\
            \x68\x69\x2e\x74\x78\x74\x00\x10\x00\x00\x00\x0f\x00\x00\x00\
            \x00\x00\x21\x53\x0b\xb2\x20\x00\x62\x79\x65\x2e\x74\x78\x74\
            \x00\x5c\xef\x2a\xc7\x34\x00\x1f\x00\x5b\x80\x80\x8d\x00\x30\
            \xf0\x01\x10\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x48\
            \x65\x6c\x6c\x6f\x2c\x20\x77\x6f\x72\x6c\x64\x21\x0d\x0a\x53\
            \x65\x65\x20\x79\x6f\x75\x20\x6c\x61\x74\x65\x72\x21\x0d\x0a\
            \x00";
        assert_eq!(binary.len(), 0x97);
        let cabinet = Cabinet::new(Cursor::new(binary)).unwrap();

        assert_eq!(
            folder_bytes(&cabinet, 0),
            b"Hello, world!\r\nSee you later!\r\n"
        );
        assert_eq!(file_bytes(&cabinet, 0, 0), b"Hello, world!\r\n");
        assert_eq!(file_bytes(&cabinet, 0, 1), b"See you later!\r\n");
    }

    #[test]
    fn read_uncompressed_cabinet_with_non_ascii_filename() {
        let binary: &[u8] = b"MSCF\0\0\0\0\x55\0\0\0\0\0\0\0\
            \x2c\0\0\0\0\0\0\0\x03\x01\x01\0\x01\0\0\0\0\0\0\0\
            \x44\0\0\0\x01\0\0\0\
            \x09\0\0\0\0\0\0\0\0\0\x6c\x22\xba\x59\xa0\0\xe2\x98\x83.txt\0\
            \x3d\x0f\x08\x56\x09\0\x09\0Snowman!\n";
        assert_eq!(binary.len(), 0x55);
        let cabinet = Cabinet::new(Cursor::new(binary)).unwrap();

        let file = cabinet
            .folder_entries()
            .next()
            .unwrap()
            .file_entries()
            .next()
            .unwrap();
        assert_eq!(file.name(), "\u{2603}.txt".as_bytes());
        assert!(file.name_is_utf8(), "this cabinet sets the UTF-8 name bit");
        assert_eq!(file_bytes(&cabinet, 0, 0), b"Snowman!\n");
    }

    #[test]
    fn folder_index_out_of_range_is_rejected() {
        let binary: &[u8] = b"MSCF\0\0\0\0\x59\0\0\0\0\0\0\0\
            \x2c\0\0\0\0\0\0\0\x03\x01\x01\0\x01\0\0\0\x34\x12\0\0\
            \x43\0\0\0\x01\0\0\0\
            \x0e\0\0\0\0\0\0\0\0\0\x6c\x22\xba\x59\x01\0hi.txt\0\
            \x4c\x1a\x2e\x7f\x0e\0\x0e\0Hello, world!\n";
        let cabinet = Cabinet::new(Cursor::new(binary)).unwrap();
        assert!(cabinet.open_folder(1).is_err());
    }
}
