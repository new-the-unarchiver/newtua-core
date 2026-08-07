//! Quantum decoding for CAB folders.
//!
//! **Ported from XADMaster's `XADQuantumHandle.m`** (© MacPaw Inc.,
//! LGPL-2.1-or-later — the same lineage this crate is LGPL for). The method was
//! created by David Stafford and adapted by Microsoft; the public description
//! everyone works from is Matthew Russotto's.
//!
//! Not a codec in the usual sense: there is no Huffman table and no entropy
//! header. A 16-bit arithmetic coder reads symbols from nine adaptive models
//! whose frequencies are updated after every symbol, so the decoder's state
//! depends on every symbol before it — which is why a Quantum folder cannot be
//! entered halfway.
//!
//! **What is bounded, and why.** Two CVEs have been filed against the reference
//! decoder — an infinite loop (CVE-2014-9556) and an over-long block
//! (CVE-2018-18584) — and both come from numbers the archive supplies. Every
//! such number is checked here: a match may not reach further back than the
//! bytes actually decoded, may not run past the end of the block, and the
//! bitstream refuses to invent bits once the block's data is spent. The two
//! archives from those reports are in `tests/integration/cab_handler.rs`.

use std::io;

use newtua_common::bitreader::BitReaderMsb;
use newtua_common::lzss::LzssWindow;

/// A CAB block never decodes to more than this, and every block of a folder but
/// the last decodes to exactly this much — the reference implementation says so
/// outright, and both it and XADMaster realign the coder on that boundary. It
/// is what makes "one block, one arithmetic coder" correct.
const FRAME_SIZE: usize = 32_768;

/// Starting point of each match-offset slot. Slot count depends on the window.
const OFFSET_BASE: [u32; 42] = [
    0x00000, 0x00001, 0x00002, 0x00003, 0x00004, 0x00006, 0x00008, 0x0000c, 0x00010, 0x00018,
    0x00020, 0x00030, 0x00040, 0x00060, 0x00080, 0x000c0, 0x00100, 0x00180, 0x00200, 0x00300,
    0x00400, 0x00600, 0x00800, 0x00c00, 0x01000, 0x01800, 0x02000, 0x03000, 0x04000, 0x06000,
    0x08000, 0x0c000, 0x10000, 0x18000, 0x20000, 0x30000, 0x40000, 0x60000, 0x80000, 0xc0000,
    0x100000, 0x180000,
];

/// How many raw bits follow each offset slot.
const OFFSET_EXTRA_BITS: [u8; 42] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14, 15, 15, 16, 16, 17, 17, 18, 18, 19, 19,
];

/// Starting point of each match-length slot (selector 6 only).
const LENGTH_BASE: [u32; 27] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x12, 0x16, 0x1a, 0x1e, 0x26,
    0x2e, 0x36, 0x3e, 0x4e, 0x5e, 0x6e, 0x7e, 0x9e, 0xbe, 0xde, 0xfe,
];

/// How many raw bits follow each length slot.
const LENGTH_EXTRA_BITS: [u8; 27] = [
    0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];

/// The block's bit stream, most significant bit first.
///
/// A thin skin over the family's shared [`BitReaderMsb`], and the skin earns
/// its keep: the shared reader answers `None` when the data runs out, while
/// this decoder must **refuse** at that moment rather than read on. A reader
/// that keeps answering past the end of the data lets a truncated block decode
/// forever — precisely CVE-2014-9556 — and lets a damaged archive produce
/// content out of nothing. Keeping that decision here means it is made once,
/// not remembered at each of the six call sites.
struct Bits<'a> {
    inner: BitReaderMsb<&'a [u8]>,
}

impl<'a> Bits<'a> {
    fn new(data: &'a [u8]) -> Self {
        Bits {
            inner: BitReaderMsb::new(data),
        }
    }

    /// Read `count` bits (`count` ≤ 24, and Quantum never asks for more than
    /// the 19 an offset slot can carry).
    fn bits(&mut self, count: u8) -> io::Result<u32> {
        match self.inner.read(count)? {
            Some(value) => Ok(value),
            None => invalid_data!("Quantum block ends in the middle of a symbol"),
        }
    }

    fn bit(&mut self) -> io::Result<u32> {
        self.bits(1)
    }
}

/// One adaptive frequency model.
///
/// `symbols` is kept ordered by falling cumulative frequency, and
/// `symbols[0].cumfreq` is therefore the total. The extra trailing entry is a
/// sentinel holding zero, so the loops never need a bounds test.
struct Model {
    shifts_left: i32,
    /// `(symbol, cumulative frequency)`, `len()` is symbol count + 1.
    symbols: Vec<(u16, u16)>,
}

impl Model {
    fn new(count: usize) -> Model {
        let mut model = Model {
            shifts_left: 0,
            symbols: vec![(0, 0); count + 1],
        };
        model.reset();
        model
    }

    fn reset(&mut self) {
        let count = self.symbols.len() - 1;
        self.shifts_left = 4;
        for (i, slot) in self.symbols.iter_mut().enumerate().take(count) {
            *slot = (i as u16, (count - i) as u16);
        }
        self.symbols[count] = (0, 0);
    }

    fn count(&self) -> usize {
        self.symbols.len() - 1
    }

    fn total_frequency(&self) -> u16 {
        self.symbols[0].1
    }

    /// Make the symbol just decoded more likely, and rescale when the total
    /// would overflow the coder's 16-bit arithmetic.
    fn update(&mut self, index: usize) {
        for slot in self.symbols.iter_mut().take(index) {
            slot.1 += 8;
        }
        if self.symbols[0].1 <= 3800 {
            return;
        }

        self.shifts_left -= 1;
        if self.shifts_left != 0 {
            // Halve every frequency, keeping the sequence strictly falling so
            // no symbol is ever squeezed out of the range entirely.
            for i in (0..self.count()).rev() {
                self.symbols[i].1 >>= 1;
                if self.symbols[i].1 <= self.symbols[i + 1].1 {
                    self.symbols[i].1 = self.symbols[i + 1].1 + 1;
                }
            }
        } else {
            // Every fiftieth rescale, re-sort the table so the symbols seen
            // most often sit at the front and the search above finds them
            // first. Frequencies go to individual counts and back to
            // cumulative ones around the sort.
            self.shifts_left = 50;
            let count = self.count();
            for i in 0..count {
                self.symbols[i].1 = (self.symbols[i].1 - self.symbols[i + 1].1 + 1) >> 1;
            }

            // **This exchange sort is not a slow way to write `sort_by_key`.**
            // The encoder re-sorted its own table at this exact moment, and the
            // two must land on the same order or every symbol after this point
            // decodes to something else. Equal frequencies are common, so how
            // ties are broken is part of the format — libmspack says as much
            // where it does this: "this must be an inplace selection sort, or a
            // sort with the same (in)stability characteristics". A library sort
            // would pass every test built from small archives and quietly
            // mangle a large one.
            for i in 0..count.saturating_sub(1) {
                for j in i + 1..count {
                    if self.symbols[i].1 < self.symbols[j].1 {
                        self.symbols.swap(i, j);
                    }
                }
            }

            for i in (0..count).rev() {
                self.symbols[i].1 += self.symbols[i + 1].1;
            }
        }
    }
}

/// The 16-bit arithmetic decoder. One per CAB block.
struct Coder {
    low: u16,
    high: u16,
    code: u16,
}

impl Coder {
    fn new(bits: &mut Bits<'_>) -> io::Result<Coder> {
        Ok(Coder {
            low: 0,
            high: 0xFFFF,
            code: bits.bits(16)? as u16,
        })
    }

    fn frequency(&self, total: u16) -> u16 {
        let range = u32::from(self.high.wrapping_sub(self.low)) + 1;
        let freq = (u32::from(self.code.wrapping_sub(self.low)) + 1) * u32::from(total) - 1;
        (freq / range) as u16
    }

    fn remove(
        &mut self,
        cumfreq_hi: u16,
        cumfreq_lo: u16,
        total: u16,
        bits: &mut Bits<'_>,
    ) -> io::Result<()> {
        let range = u32::from(self.high.wrapping_sub(self.low)) + 1;
        self.high = self
            .low
            .wrapping_add((u32::from(cumfreq_hi) * range / u32::from(total)) as u16)
            .wrapping_sub(1);
        self.low = self
            .low
            .wrapping_add((u32::from(cumfreq_lo) * range / u32::from(total)) as u16);

        loop {
            if (self.low & 0x8000) != (self.high & 0x8000) {
                if (self.low & 0x4000) != 0 && (self.high & 0x4000) == 0 {
                    // Straddling the midpoint: fold the second-highest bit away
                    // rather than let the range collapse to nothing.
                    self.code ^= 0x4000;
                    self.low &= 0x3FFF;
                    self.high |= 0x4000;
                } else {
                    return Ok(());
                }
            }
            self.low <<= 1;
            self.high = (self.high << 1) | 1;
            self.code = (self.code << 1) | bits.bit()? as u16;
        }
    }

    /// Decode one symbol from `model` and let the model learn from it.
    fn symbol(&mut self, model: &mut Model, bits: &mut Bits<'_>) -> io::Result<u16> {
        let total = model.total_frequency();
        if total == 0 {
            invalid_data!("Quantum model has no frequency left");
        }
        let freq = self.frequency(total);

        let mut i = 1;
        while i < model.count() {
            if model.symbols[i].1 <= freq {
                break;
            }
            i += 1;
        }

        let symbol = model.symbols[i - 1].0;
        let (hi, lo) = (model.symbols[i - 1].1, model.symbols[i].1);
        self.remove(hi, lo, total, bits)?;
        model.update(i);
        Ok(symbol)
    }
}

/// Decodes the Quantum folders of a cabinet.
///
/// The window and the models live for the whole folder — a folder is one solid
/// stream, and a match may reach back into an earlier block. The arithmetic
/// coder does not: it starts afresh from each block's first sixteen bits.
pub struct QuantumDecompressor {
    /// The sliding window, and with it the count of bytes decoded so far —
    /// which is the bound on how far a match may reach back. Without that bound
    /// a match into never-written window space would hand back zeroes as though
    /// they were content.
    ///
    /// Shared with the rest of the family rather than hand-rolled: it is a port
    /// of the same XADMaster `LZSS.c` that this decoder's donor calls.
    window: LzssWindow,
    window_size: usize,
    selector: Model,
    literal: [Model; 4],
    offset4: Model,
    offset5: Model,
    offset6: Model,
    length6: Model,
}

impl QuantumDecompressor {
    /// `window_bits` is the memory field of the folder's compression type,
    /// which the header parser has already limited to 10..=21.
    pub fn new(window_bits: u16) -> QuantumDecompressor {
        let slots = usize::from(window_bits) * 2;
        let window_size = 1usize << window_bits;
        QuantumDecompressor {
            window: LzssWindow::new(window_size),
            window_size,
            selector: Model::new(7),
            literal: [
                Model::new(64),
                Model::new(64),
                Model::new(64),
                Model::new(64),
            ],
            offset4: Model::new(slots.min(24)),
            offset5: Model::new(slots.min(36)),
            offset6: Model::new(slots),
            length6: Model::new(27),
        }
    }

    pub fn reset(&mut self) {
        self.window = LzssWindow::new(self.window_size);
        self.selector.reset();
        for model in &mut self.literal {
            model.reset();
        }
        self.offset4.reset();
        self.offset5.reset();
        self.offset6.reset();
        self.length6.reset();
    }

    /// Decode one CAB data block into exactly `uncompressed_size` bytes.
    pub fn decompress_block(
        &mut self,
        data: &[u8],
        uncompressed_size: usize,
    ) -> io::Result<Vec<u8>> {
        if uncompressed_size > FRAME_SIZE {
            invalid_data!(
                "Quantum block claims {} bytes, more than the {} a frame holds",
                uncompressed_size,
                FRAME_SIZE
            );
        }
        let mut bits = Bits::new(data);
        let mut coder = Coder::new(&mut bits)?;
        let mut out = Vec::with_capacity(uncompressed_size);

        while out.len() < uncompressed_size {
            let selector = coder.symbol(&mut self.selector, &mut bits)?;
            if selector < 4 {
                let index = usize::from(selector);
                let sym = coder.symbol(&mut self.literal[index], &mut bits)?;
                self.emit_literal((sym + selector * 64) as u8, &mut out);
                continue;
            }

            let (length, offset) = match selector {
                4 => (3, self.decode_offset(&mut coder, &mut bits, 4)?),
                5 => (4, self.decode_offset(&mut coder, &mut bits, 5)?),
                6 => {
                    let slot = usize::from(coder.symbol(&mut self.length6, &mut bits)?);
                    // The model cannot return a slot it was not built with, but
                    // the table lookup is written so that a future change to the
                    // model size cannot turn into an out-of-bounds read.
                    let (base, extra) = (
                        *LENGTH_BASE.get(slot).ok_or_else(|| bad_slot("length"))?,
                        LENGTH_EXTRA_BITS[slot],
                    );
                    let length = base + bits.bits(extra)? + 5;
                    (length, self.decode_offset(&mut coder, &mut bits, 6)?)
                }
                _ => invalid_data!("Quantum selector {} does not exist", selector),
            };

            self.emit_match(offset, length, uncompressed_size, &mut out)?;
        }

        Ok(out)
    }

    fn decode_offset(
        &mut self,
        coder: &mut Coder,
        bits: &mut Bits<'_>,
        selector: u8,
    ) -> io::Result<u32> {
        let model = match selector {
            4 => &mut self.offset4,
            5 => &mut self.offset5,
            _ => &mut self.offset6,
        };
        let slot = usize::from(coder.symbol(model, bits)?);
        let base = *OFFSET_BASE.get(slot).ok_or_else(|| bad_slot("offset"))?;
        Ok(base + bits.bits(OFFSET_EXTRA_BITS[slot])? + 1)
    }

    fn emit_literal(&mut self, byte: u8, out: &mut Vec<u8>) {
        self.window.emit_literal(byte, out);
    }

    /// Check a back-reference and, if it is sound, let the window copy it.
    ///
    /// Every number here came from the archive, so every one is bounded. The
    /// copy itself is the window's business — including the overlapping case
    /// (`offset < length`), which is how a run of repeated bytes is encoded.
    fn emit_match(
        &mut self,
        offset: u32,
        length: u32,
        uncompressed_size: usize,
        out: &mut Vec<u8>,
    ) -> io::Result<()> {
        let offset = offset as usize;
        if offset > self.window_size {
            invalid_data!(
                "Quantum match reaches {} bytes back, past the {}-byte window",
                offset,
                self.window_size
            );
        }
        if offset as u64 > self.window.position() {
            invalid_data!(
                "Quantum match reaches {} bytes back, before the start of the folder",
                offset
            );
        }
        if out.len() + length as usize > uncompressed_size {
            // libmspack calls this "overshot frame alignment" and refuses; a
            // match that runs past the end of the block cannot come from data
            // a compressor produced.
            invalid_data!(
                "Quantum match of {} bytes runs past the end of the block",
                length
            );
        }

        self.window.emit_match(offset, length as usize, out);
        Ok(())
    }
}

fn bad_slot(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("Quantum {what} slot is outside the table"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The model, driven hard enough to re-sort itself hundreds of times, must
    /// land exactly where the reference lands.
    ///
    /// **Why this test has to exist.** The re-sort happens on every fiftieth
    /// rescale of the frequencies, which a small archive never reaches — and
    /// the only Quantum archives in existence are small, because nothing has
    /// written the format in twenty years. So the branch that decides how
    /// equal frequencies are ordered, and therefore what every following symbol
    /// decodes to, is invisible to every fixture we have.
    ///
    /// The expected tables were produced by an independent transliteration of
    /// libmspack's `qtmd_update_model` (C) — while the code under test came
    /// from XADMaster (Objective-C). Two lineages agreeing is worth something;
    /// a decoder agreeing with itself is not.
    ///
    /// That transliteration is kept, not thrown away:
    /// `tests/fixtures/quantum_model_reference.py` regenerates these tables and
    /// prints them in the shape below.
    #[test]
    fn the_model_matches_the_reference_after_hundreds_of_rescales() {
        // The same linear congruential sequence the reference script used.
        fn drive(entries: usize, steps: usize) -> Model {
            let mut model = Model::new(entries);
            let mut state: u64 = 12345;
            for _ in 0..steps {
                state = (state * 1_103_515_245 + 12345) & 0x7FFF_FFFF;
                model.update(1 + state as usize % entries);
            }
            model
        }

        /// `(symbol count, steps driven, expected shifts_left, expected table)`
        type Case = (usize, usize, i32, &'static [(u16, u16)]);

        let cases: &[Case] = &[
            (
                7,
                60_000,
                3,
                &[
                    (2, 2135),
                    (4, 1809),
                    (5, 1520),
                    (6, 1223),
                    (0, 842),
                    (3, 547),
                    (1, 254),
                    (0, 0),
                ],
            ),
            (
                42,
                120_000,
                1,
                &[
                    (25, 2471),
                    (31, 2427),
                    (11, 2354),
                    (14, 2317),
                    (39, 2261),
                    (32, 2174),
                    (0, 2108),
                    (7, 2055),
                    (34, 2001),
                    (4, 1956),
                    (35, 1891),
                    (9, 1829),
                    (12, 1792),
                    (38, 1701),
                    (6, 1652),
                    (22, 1624),
                    (16, 1570),
                    (26, 1524),
                    (19, 1468),
                    (1, 1424),
                    (15, 1359),
                    (20, 1297),
                    (5, 1265),
                    (18, 1195),
                    (10, 1143),
                    (36, 1075),
                    (27, 1017),
                    (3, 949),
                    (33, 885),
                    (24, 821),
                    (40, 759),
                    (21, 705),
                    (41, 658),
                    (17, 593),
                    (37, 524),
                    (13, 448),
                    (29, 375),
                    (28, 313),
                    (8, 252),
                    (2, 217),
                    (30, 145),
                    (23, 75),
                    (0, 0),
                ],
            ),
        ];

        for &(entries, steps, shifts_left, expected) in cases {
            let model = drive(entries, steps);
            assert_eq!(
                model.symbols, expected,
                "таблица модели на {entries} символах"
            );
            assert_eq!(model.shifts_left, shifts_left, "счётчик пересчётов");
        }
    }

    #[test]
    fn a_fresh_model_is_ordered_by_falling_frequency() {
        let model = Model::new(7);
        assert_eq!(model.total_frequency(), 7);
        for i in 0..7 {
            assert_eq!(model.symbols[i], (i as u16, (7 - i) as u16));
        }
        // The sentinel is what lets the symbol search run without a bounds test.
        assert_eq!(model.symbols[7], (0, 0));
    }

    #[test]
    fn bits_are_read_most_significant_first() {
        let mut bits = Bits::new(&[0b1011_0000, 0xFF]);
        assert_eq!(bits.bits(4).unwrap(), 0b1011);
        assert_eq!(bits.bits(0).unwrap(), 0, "asking for no bits reads nothing");
        assert_eq!(bits.bits(8).unwrap(), 0b0000_1111);
    }

    #[test]
    fn a_spent_bitstream_refuses_rather_than_inventing_zeroes() {
        let mut bits = Bits::new(&[0x00]);
        assert!(bits.bits(8).is_ok());
        let err = bits.bit().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_match_before_the_start_of_the_folder_is_refused() {
        let mut qtm = QuantumDecompressor::new(10);
        let mut out = Vec::new();
        // Nothing has been decoded, so there is nothing three bytes back.
        let err = qtm.emit_match(3, 3, 100, &mut out).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_match_running_past_the_block_end_is_refused() {
        let mut qtm = QuantumDecompressor::new(10);
        let mut out = Vec::new();
        qtm.emit_literal(b'a', &mut out);
        let err = qtm.emit_match(1, 10, 4, &mut out).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn an_overlapping_match_repeats_the_run() {
        let mut qtm = QuantumDecompressor::new(10);
        let mut out = Vec::new();
        qtm.emit_literal(b'x', &mut out);
        // Offset 1, length 4: the classic run — each byte copied is the one
        // just written.
        qtm.emit_match(1, 4, 8, &mut out).unwrap();
        assert_eq!(out, b"xxxxx");
    }

    #[test]
    fn a_block_bigger_than_a_frame_is_refused() {
        let mut qtm = QuantumDecompressor::new(10);
        let err = qtm.decompress_block(&[0, 0], FRAME_SIZE + 1).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
