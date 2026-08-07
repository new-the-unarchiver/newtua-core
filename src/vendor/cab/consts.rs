pub const FILE_SIGNATURE: u32 = 0x4643534d; // "MSCF" stored little-endian

pub const VERSION_MAJOR: u8 = 1;
pub const VERSION_MINOR: u8 = 3;

pub const MAX_TOTAL_CAB_SIZE: u32 = 0x7fffffff;
pub const MAX_STRING_SIZE: usize = 255;

// Header flags:
pub const FLAG_PREV_CABINET: u16 = 0x1;
pub const FLAG_NEXT_CABINET: u16 = 0x2;
pub const FLAG_RESERVE_PRESENT: u16 = 0x4;
