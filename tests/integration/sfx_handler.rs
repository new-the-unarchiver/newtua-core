/// Integration tests for SFX-EXE detection (format handler Task #10).
///
/// Approach: we construct synthetic SFX fixtures in-process:
///   [PE-stub bytes] ++ [real zip archive bytes]
///
/// The positive test uses a minimal but goblin-parseable PE stub (derived from
/// a known tiny PE structure), so the overlay-offset path is exercised and the
/// embedded `PK` magic placed before the overlay is skipped.
///
/// The negative test uses an MZ prefix with NO recognized archive magic appended,
/// which must return `Err(UnknownFormat)` from `detect::open`.
use newtua_core::{FormatId, OpenOptions};
use std::io::Write;

/// Build a tiny in-memory zip containing one file `hello.txt` = b"hi".
fn make_zip_bytes() -> Vec<u8> {
    let mut buf = std::io::Cursor::new(Vec::<u8>::new());
    {
        let mut w = zip::ZipWriter::new(&mut buf);
        let opts: zip::write::FileOptions<()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        w.start_file("hello.txt", opts).unwrap();
        w.write_all(b"hi").unwrap();
        w.finish().unwrap();
    }
    buf.into_inner()
}

/// Build a minimal valid PE that goblin can parse.
///
/// Layout (all little-endian):
///   [0x00] DOS header (64 bytes): MZ magic + e_lfanew = 64
///   [0x40] PE signature: "PE\0\0"
///   [0x44] COFF header (20 bytes): Machine=0x014C (i386), NumberOfSections=1,
///            TimeDateStamp=0, PointerToSymbolTable=0, NumberOfSymbols=0,
///            SizeOfOptionalHeader=96, Characteristics=0x010F
///   [0x58] Optional header (96 bytes, PE32): Magic=0x010B, ...
///   [0xB8] Section table (1 entry, 40 bytes): .text section,
///            VirtualSize=0x10, VirtualAddress=0x1000,
///            SizeOfRawData=0x200, PointerToRawData=0x200
///   [0xE0..0x400] Padding / stub code (fills to PointerToRawData=0x200=512)
///   [0x200..0x400] Raw section data (512 bytes of zeros)
///
/// The PE image ends at overlay_start = PointerToRawData + SizeOfRawData
///   = 0x200 + 0x200 = 0x400 (1024 bytes).
///
/// We embed a FAKE `PK\x03\x04` at offset 0x100 (inside the stub/section), and
/// the REAL zip starts at offset 0x400 (the overlay). The handler must skip the
/// false magic and open the real zip.
fn make_pe_stub_with_false_magic() -> Vec<u8> {
    let mut pe = vec![0u8; 0x400]; // 1024 bytes

    // DOS header: MZ magic at 0, e_lfanew at offset 60 = 0x40
    pe[0] = b'M';
    pe[1] = b'Z';
    // e_lfanew (little-endian u32 at offset 60)
    pe[60] = 0x40;
    pe[61] = 0x00;
    pe[62] = 0x00;
    pe[63] = 0x00;

    // PE signature at 0x40
    pe[0x40] = b'P';
    pe[0x41] = b'E';
    pe[0x42] = 0x00;
    pe[0x43] = 0x00;

    // COFF header at 0x44 (20 bytes)
    // Machine = 0x014C (i386)
    pe[0x44] = 0x4C;
    pe[0x45] = 0x01;
    // NumberOfSections = 1
    pe[0x46] = 0x01;
    pe[0x47] = 0x00;
    // TimeDateStamp = 0 (4 bytes)
    // PointerToSymbolTable = 0 (4 bytes)
    // NumberOfSymbols = 0 (4 bytes)
    // SizeOfOptionalHeader = 96 = 0x60
    pe[0x54] = 0x60;
    pe[0x55] = 0x00;
    // Characteristics = 0x010F (executable, 32-bit, no relocations stripped etc.)
    pe[0x56] = 0x0F;
    pe[0x57] = 0x01;

    // Optional header at 0x58 (96 bytes)
    // Magic = 0x010B (PE32)
    pe[0x58] = 0x0B;
    pe[0x59] = 0x01;
    // MajorLinkerVersion, MinorLinkerVersion = 0
    // SizeOfCode = 0x200
    pe[0x5C] = 0x00;
    pe[0x5D] = 0x02;
    // SizeOfInitializedData, SizeOfUninitializedData = 0
    // AddressOfEntryPoint = 0x1000
    pe[0x64] = 0x00;
    pe[0x65] = 0x10;
    // BaseOfCode = 0x1000
    pe[0x68] = 0x00;
    pe[0x69] = 0x10;
    // BaseOfData = 0
    // ImageBase = 0x00400000
    pe[0x70] = 0x00;
    pe[0x71] = 0x00;
    pe[0x72] = 0x40;
    pe[0x73] = 0x00;
    // SectionAlignment = 0x1000
    pe[0x74] = 0x00;
    pe[0x75] = 0x10;
    // FileAlignment = 0x200
    pe[0x78] = 0x00;
    pe[0x79] = 0x02;
    // MajorOSVersion = 4
    pe[0x7C] = 0x04;
    // SizeOfImage = 0x2000
    pe[0x90] = 0x00;
    pe[0x91] = 0x20;
    // SizeOfHeaders = 0x200
    pe[0x94] = 0x00;
    pe[0x95] = 0x02;
    // Subsystem = 2 (GUI)
    pe[0xA4] = 0x02;
    // NumberOfRvaAndSizes = 16
    pe[0xA8] = 0x10;

    // Section table at 0xB8 (0x44 + 20 + 96 = 0xB8): 40 bytes
    // Name = ".text\0\0\0"
    pe[0xB8] = b'.';
    pe[0xB9] = b't';
    pe[0xBA] = b'e';
    pe[0xBB] = b'x';
    pe[0xBC] = b't';
    // VirtualSize = 0x10
    pe[0xC0] = 0x10;
    // VirtualAddress = 0x1000
    pe[0xC4] = 0x00;
    pe[0xC5] = 0x10;
    // SizeOfRawData = 0x200
    pe[0xC8] = 0x00;
    pe[0xC9] = 0x02;
    // PointerToRawData = 0x200
    pe[0xCC] = 0x00;
    pe[0xCD] = 0x02;
    // Characteristics = 0x60000020 (code, executable, readable)
    pe[0xD8] = 0x20;
    pe[0xD9] = 0x00;
    pe[0xDA] = 0x00;
    pe[0xDB] = 0x60;

    // Plant a FALSE PK magic at offset 0x100 (inside the stub, before overlay).
    pe[0x100] = b'P';
    pe[0x101] = b'K';
    pe[0x102] = 0x03;
    pe[0x103] = 0x04;

    pe
}

/// Positive test: SFX fixture = [parseable PE stub with false PK inside] ++ [real zip]
///
/// Verifies:
/// - `detect::open` succeeds and returns an inner zip reader
/// - `format()` reports `FormatId::Zip` (NOT `FormatId::Sfx`)
/// - `entries()` finds `hello.txt`
/// - `read_entry(0, ...)` returns b"hi"
#[test]
fn sfx_exe_with_goblin_floor_opens_inner_zip() {
    let pe_stub = make_pe_stub_with_false_magic();
    let zip_bytes = make_zip_bytes();

    let mut sfx = Vec::new();
    sfx.extend_from_slice(&pe_stub);
    sfx.extend_from_slice(&zip_bytes);

    // Write to a temp file with .exe extension.
    let tmp = tempfile::Builder::new().suffix(".exe").tempfile().unwrap();
    std::fs::write(tmp.path(), &sfx).unwrap();

    let opts = OpenOptions::default();
    let mut reader = newtua_core::detect::open(tmp.path(), &opts).unwrap();

    // Inner format must be Zip, NOT Sfx.
    assert_eq!(
        reader.format(),
        FormatId::Zip,
        "format() must delegate to inner zip reader"
    );

    let entries = reader.entries().unwrap();
    assert_eq!(entries.len(), 1, "expected exactly one entry");
    assert_eq!(
        entries[0].path.to_str().unwrap(),
        "hello.txt",
        "entry name mismatch"
    );

    let mut out = Vec::new();
    reader.read_entry(0, &mut out).unwrap();
    assert_eq!(out, b"hi", "extracted content mismatch");
}

/// Negative test: MZ prefix with NO recognized archive magic → UnknownFormat.
#[test]
fn mz_without_archive_magic_is_unknown_format() {
    // Build a buffer: MZ header + random filler, no PK/7z/rar/cab magic.
    let mut data = vec![0u8; 512];
    data[0] = b'M';
    data[1] = b'Z';
    // Fill with something that won't accidentally match any magic.
    for b in data[2..].iter_mut() {
        *b = 0xCC;
    }

    let tmp = tempfile::Builder::new().suffix(".exe").tempfile().unwrap();
    std::fs::write(tmp.path(), &data).unwrap();

    let opts = OpenOptions::default();
    let result = newtua_core::detect::open(tmp.path(), &opts);
    assert!(
        matches!(result, Err(newtua_core::Error::UnknownFormat)),
        "expected Err(UnknownFormat)"
    );
}
