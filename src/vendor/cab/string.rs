use std::io::{self, Read};

use byteorder::ReadBytesExt;

use super::consts;

/// Read a NUL-terminated *name* from a cabinet header, as bytes.
///
/// Upstream returned a `String` built with `from_utf8_lossy` and took an
/// `is_utf8` flag it then ignored (its TODO). Both are gone: a name whose bytes
/// are not UTF-8 must survive as bytes until something that knows the archive's
/// encoding looks at the whole set of them.
pub(crate) fn read_null_terminated_name<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::<u8>::with_capacity(consts::MAX_STRING_SIZE);
    loop {
        let byte = reader.read_u8()?;
        if byte == 0 {
            break;
        } else if bytes.len() == consts::MAX_STRING_SIZE {
            invalid_data!(
                "String longer than maximum of {} bytes",
                consts::MAX_STRING_SIZE
            );
        }
        bytes.push(byte);
    }
    Ok(bytes)
}

/// Read a NUL-terminated header string that is not a file name.
///
/// Only the previous/next cabinet names use this, and they are read past
/// without being kept — a cabinet set spans several files and the engine opens
/// one at a time. Lossy is fine for something nobody looks at; what matters is
/// that the reader ends up in the right place.
pub(crate) fn skip_null_terminated_string<R: Read>(reader: &mut R) -> io::Result<()> {
    read_null_terminated_name(reader).map(|_| ())
}
