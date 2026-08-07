/// `return Err(InvalidData)` — the archive says something impossible.
///
/// The kind matters beyond this module: `format/cab.rs` turns `InvalidData`
/// into `Error::Corrupt` and everything else into `Error::Io`, so "the cabinet
/// is damaged" and "the disk is full" stay different news for the person
/// extracting.
macro_rules! invalid_data {
    ($e:expr) => {
        return Err(::std::io::Error::new(::std::io::ErrorKind::InvalidData, $e))
    };
    ($fmt:expr, $($arg:tt)+) => {
        return Err(::std::io::Error::new(
            ::std::io::ErrorKind::InvalidData,
            format!($fmt, $($arg)+),
        ))
    };
}

/// `return Err(InvalidInput)` — the caller asked for something out of range.
macro_rules! invalid_input {
    ($e:expr) => {
        return Err(::std::io::Error::new(::std::io::ErrorKind::InvalidInput, $e))
    };
    ($fmt:expr, $($arg:tt)+) => {
        return Err(::std::io::Error::new(
            ::std::io::ErrorKind::InvalidInput,
            format!($fmt, $($arg)+),
        ))
    };
}
