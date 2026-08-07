use std::io::{self, Read};

use byteorder::ReadBytesExt;

use super::consts;

/// Read a NUL-terminated name from a cabinet header.
///
/// Upstream took an `is_utf8` flag and ignored it (its TODO). It is gone here
/// rather than kept as a lie: the caller is the one that knows what to do with
/// a name whose bytes are not UTF-8, and today `format/cab.rs` takes this
/// lossy string as the entry name. See `VENDORED.md` for why that is recorded
/// as a limitation and not fixed inside this module.
pub(crate) fn read_null_terminated_string<R: Read>(reader: &mut R) -> io::Result<String> {
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
    Ok(String::from_utf8_lossy(&bytes).to_string())
}
