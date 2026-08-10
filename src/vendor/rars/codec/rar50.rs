use super::filters::{self, DeltaErrorMessages};
use super::{Error, Result};
use std::collections::VecDeque;
use std::io::Read;

pub const LEVEL_TABLE_SIZE: usize = 20;
pub const MAIN_TABLE_SIZE: usize = 306;
pub const DISTANCE_TABLE_SIZE_50: usize = 64;
pub const DISTANCE_TABLE_SIZE_70: usize = 80;
pub const ALIGN_TABLE_SIZE: usize = 16;
pub const LENGTH_TABLE_SIZE: usize = 44;

const MAX_INITIAL_OUTPUT_CAPACITY: usize = 1024 * 1024;
const STREAM_FLUSH_THRESHOLD: usize = 64 * 1024;

/// Longest match RAR 5 can encode: length slot 43 with all extra bits set,
/// plus the maximum distance bonus.
const MAX_LZ_MATCH: usize = 4100;
/// Zero-initialised bytes kept past the decode frontier so match copying can
/// write whole eight-byte chunks without a length check per chunk.
const COPY_SLACK: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressedBlockHeader {
    pub flags: u8,
    pub is_last: bool,
    pub has_tables: bool,
    pub final_byte_bits: u8,
    pub payload_size: usize,
    pub payload_bits: usize,
}

struct OwnedCompressedBlock {
    header: CompressedBlockHeader,
    payload: Vec<u8>,
}

#[derive(Debug)]
#[doc(hidden)]
pub enum StreamDecodeError<E> {
    Decode(Error),
    FilteredMember,
    Sink(E),
}

impl<E> From<Error> for StreamDecodeError<E> {
    fn from(error: Error) -> Self {
        Self::Decode(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum DecodedChunk<'a> {
    Bytes(&'a [u8]),
    Repeated { byte: u8, len: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableLengths {
    pub main: Vec<u8>,
    pub distance: Vec<u8>,
    pub align: Vec<u8>,
    pub length: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DecodeTables {
    pub main: HuffmanTable,
    pub distance: HuffmanTable,
    pub align: HuffmanTable,
    pub length: HuffmanTable,
    pub align_mode: bool,
}

impl DecodeTables {
    pub fn from_lengths(lengths: &TableLengths) -> Result<Self> {
        let align_mode = lengths
            .align
            .iter()
            .any(|&length| length != 0 && length != 4);
        Ok(Self {
            main: HuffmanTable::from_lengths(&lengths.main)?,
            distance: HuffmanTable::from_lengths(&lengths.distance)?,
            align: HuffmanTable::from_lengths(&lengths.align)?,
            length: HuffmanTable::from_lengths(&lengths.length)?,
            align_mode,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeMode {
    LiteralOnly,
    Lz,
    LzNoFilters,
}

impl DecodeMode {
    fn uses_lz(self) -> bool {
        matches!(self, Self::Lz | Self::LzNoFilters)
    }

    fn applies_filters(self) -> bool {
        matches!(self, Self::Lz)
    }
}

pub fn read_level_lengths(input: &[u8]) -> Result<([u8; LEVEL_TABLE_SIZE], usize)> {
    let mut bits = BitReader::new(input);
    let mut lengths = [0; LEVEL_TABLE_SIZE];
    let mut pos = 0;
    while pos < LEVEL_TABLE_SIZE {
        let length = bits.read_bits(4)? as u8;
        if length == 15 {
            let zero_count = bits.read_bits(4)? as usize;
            if zero_count == 0 {
                lengths[pos] = 15;
                pos += 1;
            } else {
                let count = zero_count + 2;
                for _ in 0..count {
                    if pos >= LEVEL_TABLE_SIZE {
                        break;
                    }
                    lengths[pos] = 0;
                    pos += 1;
                }
            }
        } else {
            lengths[pos] = length;
            pos += 1;
        }
    }
    Ok((lengths, bits.bit_pos))
}

pub fn table_length_count(algorithm_version: u8) -> Result<usize> {
    match algorithm_version {
        0 => Ok(MAIN_TABLE_SIZE + DISTANCE_TABLE_SIZE_50 + ALIGN_TABLE_SIZE + LENGTH_TABLE_SIZE),
        1 => Ok(MAIN_TABLE_SIZE + DISTANCE_TABLE_SIZE_70 + ALIGN_TABLE_SIZE + LENGTH_TABLE_SIZE),
        _ => Err(Error::InvalidData(
            "RAR 5 unknown compression algorithm version",
        )),
    }
}

pub fn read_table_lengths(input: &[u8], algorithm_version: u8) -> Result<(TableLengths, usize)> {
    let table_size = table_length_count(algorithm_version)?;
    let (level_lengths, level_bits) = read_level_lengths(input)?;
    let level_decoder = HuffmanTable::from_lengths(&level_lengths)?;
    let mut bits = BitReader::new(input);
    bits.bit_pos = level_bits;

    let mut lengths = Vec::with_capacity(table_size);
    while lengths.len() < table_size {
        let number = level_decoder.decode(&mut bits)?;
        match number {
            0..=15 => lengths.push(number as u8),
            16 | 17 => {
                if lengths.is_empty() {
                    return Err(Error::InvalidData(
                        "RAR 5 table repeats missing previous length",
                    ));
                }
                let count = if number == 16 {
                    3 + bits.read_bits(3)? as usize
                } else {
                    11 + bits.read_bits(7)? as usize
                };
                let previous = *lengths.last().unwrap();
                for _ in 0..count {
                    if lengths.len() >= table_size {
                        break;
                    }
                    lengths.push(previous);
                }
            }
            18 | 19 => {
                let count = if number == 18 {
                    3 + bits.read_bits(3)? as usize
                } else {
                    11 + bits.read_bits(7)? as usize
                };
                for _ in 0..count {
                    if lengths.len() >= table_size {
                        break;
                    }
                    lengths.push(0);
                }
            }
            _ => return Err(Error::InvalidData("RAR 5 invalid level-table symbol")),
        }
    }

    let distance_size = match algorithm_version {
        0 => DISTANCE_TABLE_SIZE_50,
        1 => DISTANCE_TABLE_SIZE_70,
        _ => unreachable!("validated by table_length_count"),
    };
    let distance_start = MAIN_TABLE_SIZE;
    let align_start = distance_start + distance_size;
    let length_start = align_start + ALIGN_TABLE_SIZE;

    Ok((
        TableLengths {
            main: lengths[..distance_start].to_vec(),
            distance: lengths[distance_start..align_start].to_vec(),
            align: lengths[align_start..length_start].to_vec(),
            length: lengths[length_start..].to_vec(),
        },
        bits.bit_pos,
    ))
}

#[derive(Debug, Clone)]
pub struct Unpack50Decoder {
    tables: Option<DecodeTables>,
    reps: [usize; 4],
    last_length: usize,
    history: Vec<u8>,
}

impl Unpack50Decoder {
    pub fn new() -> Self {
        Self {
            tables: None,
            reps: [0; 4],
            last_length: 0,
            history: Vec::new(),
        }
    }

    /// NEWTUA: `allow(dead_code)` — распаковка из среза больше не зовётся.
    /// Упакованное тело у нас приходит потоком (тикет 29), а «хранимой» записи
    /// декодер не нужен вовсе, так что единственный вызывающий отпал. Метод —
    /// апстримовский и остаётся дословным: это `Cursor` плюс версия для
    /// потока, и удалять его значило бы разойтись с апстримом ради трёх строк.
    #[allow(dead_code)]
    pub fn decode_member_with_dictionary(
        &mut self,
        input: &[u8],
        algorithm_version: u8,
        output_size: usize,
        dictionary_size: usize,
        solid: bool,
        mode: DecodeMode,
    ) -> Result<Vec<u8>> {
        let mut input = std::io::Cursor::new(input);
        self.decode_member_from_reader_with_dictionary(
            &mut input,
            algorithm_version,
            output_size,
            dictionary_size,
            solid,
            mode,
        )
    }

    pub fn decode_member_from_reader_with_dictionary(
        &mut self,
        input: &mut impl Read,
        algorithm_version: u8,
        output_size: usize,
        dictionary_size: usize,
        solid: bool,
        mode: DecodeMode,
    ) -> Result<Vec<u8>> {
        if dictionary_size == 0 {
            return Err(Error::InvalidData("RAR 5 dictionary size is zero"));
        }
        if !solid {
            self.reset();
        }

        // `output` stays zero-extended a little past `pos`, the decode
        // frontier, so literals are plain stores and match copies never
        // reallocate; the tail is trimmed before returning.
        let mut output = Vec::with_capacity(output_size.min(MAX_INITIAL_OUTPUT_CAPACITY));
        let mut pos = 0usize;
        let mut filters = Vec::new();

        loop {
            let block = read_compressed_block(input)?;
            let payload = block.payload.as_slice();
            let mut payload_bit_pos = 0;
            if block.header.has_tables {
                let (lengths, table_bits) = read_table_lengths(payload, algorithm_version)?;
                self.tables = Some(DecodeTables::from_lengths(&lengths)?);
                payload_bit_pos = table_bits;
            }
            let tables = self
                .tables
                .take()
                .ok_or(Error::InvalidData("RAR 5 block reuses missing tables"))?;
            let mut bits = BitReader::new(payload);
            bits.bit_pos = payload_bit_pos;

            while bits.bit_pos < block.header.payload_bits && pos < output_size {
                ensure_copy_room(&mut output, pos, output_size);
                let symbol = tables.main.decode(&mut bits)?;
                match symbol {
                    0..=255 => {
                        output[pos] = symbol as u8;
                        pos += 1;
                    }
                    256 if mode.uses_lz() => {
                        filters.push(read_filter(&mut bits, pos)?);
                    }
                    257 if mode.uses_lz() => {
                        if self.last_length != 0 {
                            self.copy_match(
                                &mut output,
                                &mut pos,
                                self.reps[0],
                                self.last_length,
                                output_size,
                                dictionary_size,
                            )?;
                        }
                    }
                    258..=261 if mode.uses_lz() => {
                        let rep_index = symbol - 258;
                        let distance = self.reps[rep_index];
                        if distance == 0 {
                            return Err(Error::InvalidData(
                                "RAR 5 repeat distance is not initialized",
                            ));
                        }
                        let length_slot = tables.length.decode(&mut bits)?;
                        let length_extra = bits.read_bits(length_slot_extra_bits(length_slot)?)?;
                        let length = slot_to_length(length_slot, length_extra)?;
                        self.reps[..=rep_index].rotate_right(1);
                        self.reps[0] = distance;
                        self.last_length = length;
                        self.copy_match(
                            &mut output,
                            &mut pos,
                            distance,
                            length,
                            output_size,
                            dictionary_size,
                        )?;
                    }
                    262.. if mode.uses_lz() => {
                        let length_slot = symbol - 262;
                        let length_extra = bits.read_bits(length_slot_extra_bits(length_slot)?)?;
                        let mut length = slot_to_length(length_slot, length_extra)?;
                        let distance_slot = tables.distance.decode(&mut bits)?;
                        let distance_bit_count = distance_slot_bit_count(distance_slot)?;
                        let distance_extra = if distance_bit_count >= 4 && tables.align_mode {
                            let high = bits.read_bits((distance_bit_count - 4) as u8)?;
                            let low = tables.align.decode(&mut bits)? as u32;
                            (high << 4) | low
                        } else {
                            bits.read_bits(distance_bit_count as u8)?
                        };
                        let distance = slot_to_distance(distance_slot, distance_extra)?;
                        length += length_bonus(distance);
                        self.reps.rotate_right(1);
                        self.reps[0] = distance;
                        self.last_length = length;
                        self.copy_match(
                            &mut output,
                            &mut pos,
                            distance,
                            length,
                            output_size,
                            dictionary_size,
                        )?;
                    }
                    _ if mode == DecodeMode::LiteralOnly => {
                        return Err(Error::InvalidData(
                            "RAR 5 literal-only decoder encountered non-literal symbol",
                        ));
                    }
                    _ => {
                        return Err(Error::InvalidData(
                            "RAR 5 decoder encountered unsupported control symbol",
                        ));
                    }
                }
            }

            self.tables = Some(tables);
            if block.header.is_last || pos >= output_size {
                break;
            }
        }

        if pos == output_size {
            output.truncate(output_size);
            // NEWTUA: в окно уходит только хвост длиной со словарь, и берётся
            // он тоже хвостом. Апстрим сперва клонировал **весь**
            // нефильтрованный выход, потом дописывал в историю его целиком и
            // лишь затем обрезал её до словаря — на файле в 300 МБ со словарём
            // в 32 МиБ это два лишних экземпляра записи в пике (тикет 29).
            // Что именно попадает в окно, не меняется: у фильтрованной записи
            // это по-прежнему нефильтрованные байты, а `apply_filters` длину
            // не меняет, так что хвост до фильтров равен хвосту после.
            let tail_start = output.len().saturating_sub(dictionary_size);
            let history_output = if mode.applies_filters() && !filters.is_empty() {
                Some(output[tail_start..].to_vec())
            } else {
                None
            };
            if mode.applies_filters() {
                apply_filters(&mut output, &filters)?;
            }
            let tail = history_output
                .as_deref()
                .unwrap_or_else(|| &output[tail_start..]);
            self.history.extend_from_slice(tail);
            if self.history.len() > dictionary_size {
                let discard = self.history.len() - dictionary_size;
                self.history.drain(..discard);
            }
            Ok(output)
        } else {
            Err(Error::NeedMoreInput)
        }
    }

    pub fn decode_member_from_reader_with_dictionary_to_sink<E>(
        &mut self,
        input: &mut impl Read,
        algorithm_version: u8,
        output_size: usize,
        dictionary_size: usize,
        solid: bool,
        mut sink: impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        if dictionary_size == 0 {
            return Err(Error::InvalidData("RAR 5 dictionary size is zero").into());
        }
        if !solid {
            self.reset();
        }

        // VecDeque grows as decoded bytes arrive, so using the declared
        // dictionary here does not allocate a potentially huge RAR 7 window
        // up front. It does, however, retain every byte that a legal match may
        // reference instead of silently truncating the window at 64 MiB.
        let history_limit = dictionary_size;
        if self.history.len() > history_limit {
            let discard = self.history.len() - history_limit;
            self.history.drain(..discard);
        }
        let mut output = StreamingOutput::new(
            std::mem::take(&mut self.history),
            output_size,
            dictionary_size,
            history_limit,
        );

        loop {
            let block = read_compressed_block(input)?;
            let payload = block.payload.as_slice();
            let mut payload_bit_pos = 0;
            if block.header.has_tables {
                let (lengths, table_bits) = read_table_lengths(payload, algorithm_version)?;
                self.tables = Some(DecodeTables::from_lengths(&lengths)?);
                payload_bit_pos = table_bits;
            }
            let tables = self
                .tables
                .take()
                .ok_or(Error::InvalidData("RAR 5 block reuses missing tables"))?;
            let mut bits = BitReader::new(payload);
            bits.bit_pos = payload_bit_pos;

            while bits.bit_pos < block.header.payload_bits && output.written() < output_size {
                let symbol = tables.main.decode(&mut bits)?;
                match symbol {
                    0..=255 => output.push(symbol as u8, &mut sink)?,
                    256 => {
                        return Err(StreamDecodeError::FilteredMember);
                    }
                    257 => {
                        if self.last_length != 0 {
                            output.copy_match(self.reps[0], self.last_length, &mut sink)?;
                        }
                    }
                    258..=261 => {
                        let rep_index = symbol - 258;
                        let distance = self.reps[rep_index];
                        if distance == 0 {
                            return Err(Error::InvalidData(
                                "RAR 5 repeat distance is not initialized",
                            )
                            .into());
                        }
                        let length_slot = tables.length.decode(&mut bits)?;
                        let length_extra = bits.read_bits(length_slot_extra_bits(length_slot)?)?;
                        let length = slot_to_length(length_slot, length_extra)?;
                        self.reps[..=rep_index].rotate_right(1);
                        self.reps[0] = distance;
                        self.last_length = length;
                        output.copy_match(distance, length, &mut sink)?;
                    }
                    262.. => {
                        let length_slot = symbol - 262;
                        let length_extra = bits.read_bits(length_slot_extra_bits(length_slot)?)?;
                        let mut length = slot_to_length(length_slot, length_extra)?;
                        let distance_slot = tables.distance.decode(&mut bits)?;
                        let distance_bit_count = distance_slot_bit_count(distance_slot)?;
                        let distance_extra = if distance_bit_count >= 4 && tables.align_mode {
                            let high = bits.read_bits((distance_bit_count - 4) as u8)?;
                            let low = tables.align.decode(&mut bits)? as u32;
                            (high << 4) | low
                        } else {
                            bits.read_bits(distance_bit_count as u8)?
                        };
                        let distance = slot_to_distance(distance_slot, distance_extra)?;
                        length += length_bonus(distance);
                        self.reps.rotate_right(1);
                        self.reps[0] = distance;
                        self.last_length = length;
                        output.copy_match(distance, length, &mut sink)?;
                    }
                }
            }

            self.tables = Some(tables);
            if block.header.is_last || output.written() >= output_size {
                break;
            }
        }

        if output.written() == output_size {
            output.finish(&mut sink)?;
            self.history = output.into_history();
            Ok(())
        } else {
            Err(Error::NeedMoreInput.into())
        }
    }

    fn reset(&mut self) {
        self.tables = None;
        self.reps = [0; 4];
        self.last_length = 0;
        self.history.clear();
    }

    // Самая горячая функция распаковки RAR 5 — на неё приходилась треть
    // времени, и её нынешний вид получен замерами (правки 1, 4 и 5 из
    // VENDORED.md). Два разрешения здесь по разным причинам, и путать их не
    // надо: `ptr_arg` — про удобство вызывающего, который ведёт один растущий
    // буфер, машинная работа от среза не изменится; `explicit_counter_loop` —
    // про горячий цикл, а его трогать можно только с замером в руках, не по
    // подсказке.
    #[allow(clippy::ptr_arg, clippy::explicit_counter_loop)]
    fn copy_match(
        &self,
        output: &mut Vec<u8>,
        pos: &mut usize,
        distance: usize,
        length: usize,
        output_limit: usize,
        dictionary_size: usize,
    ) -> Result<()> {
        if distance > dictionary_size {
            return Err(Error::InvalidData(
                "RAR 5 match distance exceeds dictionary",
            ));
        }
        if distance == 0 || distance > self.history.len() + *pos {
            return Err(Error::InvalidData("RAR 5 match distance exceeds window"));
        }
        if pos.checked_add(length).is_none_or(|end| end > output_limit) {
            return Err(Error::InvalidData("RAR 5 match exceeds output limit"));
        }
        let mut remaining = length;
        if distance > *pos {
            // The head of the match lies in a previous member of a solid
            // stream; the rest, if any, continues from the start of `output`.
            let history_distance = distance - *pos;
            let index = self.history.len() - history_distance;
            let take = remaining.min(history_distance);
            output[*pos..*pos + take].copy_from_slice(&self.history[index..index + take]);
            *pos += take;
            remaining -= take;
            if remaining == 0 {
                return Ok(());
            }
        }
        let end = *pos + remaining;
        if distance == 1 {
            // A one-byte repeat is a fill, not a copy.
            let byte = output[*pos - 1];
            output[*pos..end].fill(byte);
        } else if distance >= remaining {
            // Non-overlapping, the typical case: split borrows let the chunk
            // loop run without a bounds check per chunk.
            let start = *pos - distance;
            let (head, tail) = output.split_at_mut(*pos);
            let src = &head[start..start + remaining];
            let dst = &mut tail[..remaining];
            if remaining >= 64 {
                // Long enough that one bulk copy beats chunking.
                dst.copy_from_slice(src);
            } else {
                let mut src_chunks = src.chunks_exact(8);
                let mut dst_chunks = dst.chunks_exact_mut(8);
                for (to, from) in dst_chunks.by_ref().zip(src_chunks.by_ref()) {
                    let from: &[u8; 8] = from.try_into().expect("chunk is eight bytes");
                    to.copy_from_slice(from);
                }
                for (to, from) in dst_chunks
                    .into_remainder()
                    .iter_mut()
                    .zip(src_chunks.remainder())
                {
                    *to = *from;
                }
            }
        } else if distance >= COPY_SLACK {
            // Overlapped by more than a chunk: whole eight-byte chunks,
            // overshooting into the slack kept past the frontier. A chunk's
            // source is written by the time it is read.
            let mut src = *pos - distance;
            let mut dst = *pos;
            while dst < end {
                let chunk: [u8; 8] = output[src..src + 8]
                    .try_into()
                    .expect("chunk is eight bytes");
                output[dst..dst + 8].copy_from_slice(&chunk);
                src += 8;
                dst += 8;
            }
        } else {
            // Overlapped closer than a chunk: byte order is load-bearing.
            let mut src = *pos - distance;
            for dst in *pos..end {
                output[dst] = output[src];
                src += 1;
            }
        }
        *pos = end;
        Ok(())
    }
}

/// Keeps `output` zero-extended to `COPY_SLACK` bytes past everything the next
/// symbol may write, growing by doubling so reallocation stays amortised.
fn ensure_copy_room(output: &mut Vec<u8>, pos: usize, output_size: usize) {
    let needed = (pos + MAX_LZ_MATCH).min(output_size) + COPY_SLACK;
    if output.len() < needed {
        let doubled = output
            .len()
            .max(MAX_INITIAL_OUTPUT_CAPACITY)
            .saturating_mul(2);
        let target = doubled.clamp(needed, output_size + COPY_SLACK);
        output.resize(target, 0);
    }
}

struct StreamingOutput {
    history: VecDeque<u8>,
    pending: Vec<u8>,
    written: usize,
    output_limit: usize,
    dictionary_size: usize,
    history_limit: usize,
    all_zero: bool,
}

impl StreamingOutput {
    fn new(
        history: Vec<u8>,
        output_limit: usize,
        dictionary_size: usize,
        history_limit: usize,
    ) -> Self {
        Self {
            all_zero: history.iter().all(|&byte| byte == 0),
            history: history.into(),
            pending: Vec::with_capacity(STREAM_FLUSH_THRESHOLD),
            written: 0,
            output_limit,
            dictionary_size,
            history_limit,
        }
    }

    fn written(&self) -> usize {
        self.written
    }

    fn push<E>(
        &mut self,
        byte: u8,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        if self.written >= self.output_limit {
            return Err(Error::InvalidData("RAR 5 match exceeds output limit").into());
        }
        if byte != 0 {
            self.all_zero = false;
        }
        self.pending.push(byte);
        self.written += 1;
        if self.pending.len() >= STREAM_FLUSH_THRESHOLD {
            self.flush(sink)?;
        }
        Ok(())
    }

    fn push_repeated<E>(
        &mut self,
        byte: u8,
        mut count: usize,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        if self
            .written
            .checked_add(count)
            .is_none_or(|end| end > self.output_limit)
        {
            return Err(Error::InvalidData("RAR 5 match exceeds output limit").into());
        }
        if byte != 0 {
            self.all_zero = false;
        }
        while count > 0 {
            let available = STREAM_FLUSH_THRESHOLD - self.pending.len();
            let take = count.min(available.max(1));
            let old_len = self.pending.len();
            self.pending.resize(old_len + take, byte);
            self.written += take;
            count -= take;
            if self.pending.len() >= STREAM_FLUSH_THRESHOLD {
                self.flush(sink)?;
            }
        }
        Ok(())
    }

    fn push_zeroes<E>(
        &mut self,
        count: usize,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        if self
            .written
            .checked_add(count)
            .is_none_or(|end| end > self.output_limit)
        {
            return Err(Error::InvalidData("RAR 5 match exceeds output limit").into());
        }
        self.flush(sink)?;
        sink(DecodedChunk::Repeated {
            byte: 0,
            len: count,
        })
        .map_err(StreamDecodeError::Sink)?;
        self.written += count;
        if self.history.is_empty() && self.history_limit != 0 {
            self.history.push_back(0);
        }
        Ok(())
    }

    fn copy_match<E>(
        &mut self,
        distance: usize,
        length: usize,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        if distance > self.dictionary_size {
            return Err(Error::InvalidData("RAR 5 match distance exceeds dictionary").into());
        }
        if self.all_zero && distance <= self.written + self.history.len() {
            return self.push_zeroes(length, sink);
        }
        if distance == 0 || distance > self.history.len() + self.pending.len() {
            return Err(Error::InvalidData("RAR 5 match distance exceeds window").into());
        }
        if self
            .written
            .checked_add(length)
            .is_none_or(|end| end > self.output_limit)
        {
            return Err(Error::InvalidData("RAR 5 match exceeds output limit").into());
        }
        if distance == 1 {
            let byte = self.byte_at_distance(1)?;
            return self.push_repeated(byte, length, sink);
        }
        for _ in 0..length {
            let byte = self.byte_at_distance(distance)?;
            self.push(byte, sink)?;
        }
        Ok(())
    }

    fn byte_at_distance(&self, distance: usize) -> Result<u8> {
        if distance <= self.pending.len() {
            Ok(self.pending[self.pending.len() - distance])
        } else {
            let history_distance = distance - self.pending.len();
            if history_distance > self.history.len() {
                return Err(Error::InvalidData("RAR 5 match distance exceeds window"));
            }
            Ok(*self
                .history
                .get(self.history.len() - history_distance)
                .ok_or(Error::InvalidData("RAR 5 match distance exceeds window"))?)
        }
    }

    fn flush<E>(
        &mut self,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        if self.pending.is_empty() {
            return Ok(());
        }
        sink(DecodedChunk::Bytes(&self.pending)).map_err(StreamDecodeError::Sink)?;
        self.history.extend(self.pending.iter().copied());
        self.pending.clear();
        while self.history.len() > self.history_limit {
            self.history.pop_front();
        }
        Ok(())
    }

    fn finish<E>(
        &mut self,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        self.flush(sink)
    }

    fn into_history(self) -> Vec<u8> {
        self.history.into()
    }
}

fn read_compressed_block(input: &mut impl Read) -> Result<OwnedCompressedBlock> {
    let mut fixed = [0u8; 2];
    input
        .read_exact(&mut fixed)
        .map_err(|_| Error::NeedMoreInput)?;
    let flags = fixed[0];
    let checksum = fixed[1];
    let size_bytes_len = match (flags >> 3) & 0x03 {
        0 => 1,
        1 => 2,
        2 => 3,
        _ => return Err(Error::InvalidData("RAR 5 block size length is invalid")),
    };
    let mut size_bytes = [0u8; 3];
    input
        .read_exact(&mut size_bytes[..size_bytes_len])
        .map_err(|_| Error::NeedMoreInput)?;

    let actual = size_bytes[..size_bytes_len]
        .iter()
        .fold(checksum ^ flags, |acc, &byte| acc ^ byte);
    if actual != 0x5a {
        return Err(Error::InvalidData("RAR 5 block header checksum mismatch"));
    }

    let payload_size = size_bytes[..size_bytes_len]
        .iter()
        .enumerate()
        .fold(0usize, |acc, (index, &byte)| {
            acc | (usize::from(byte) << (index * 8))
        });
    let mut payload = vec![0; payload_size];
    input
        .read_exact(&mut payload)
        .map_err(|_| Error::NeedMoreInput)?;
    let final_byte_bits = ((flags & 0x07) + 1).min(8);
    let payload_bits = if payload_size == 0 {
        0
    } else {
        (payload_size - 1) * 8 + usize::from(final_byte_bits)
    };

    Ok(OwnedCompressedBlock {
        header: CompressedBlockHeader {
            flags,
            is_last: flags & 0x40 != 0,
            has_tables: flags & 0x80 != 0,
            final_byte_bits,
            payload_size,
            payload_bits,
        },
        payload,
    })
}

impl Default for Unpack50Decoder {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingFilter {
    start: usize,
    length: usize,
    filter_type: FilterType,
    channels: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilterType {
    Delta,
    E8,
    E8E9,
    Arm,
}

fn read_filter(bits: &mut BitReader<'_>, current_pos: usize) -> Result<PendingFilter> {
    let offset = read_filter_data(bits)? as usize;
    let length = read_filter_data(bits)? as usize;
    let filter_type = match bits.read_bits(3)? {
        0 => FilterType::Delta,
        1 => FilterType::E8,
        2 => FilterType::E8E9,
        3 => FilterType::Arm,
        _ => return Err(Error::InvalidData("RAR 5 filter type is unsupported")),
    };
    let channels = if filter_type == FilterType::Delta {
        bits.read_bits(5)? as usize + 1
    } else {
        0
    };
    Ok(PendingFilter {
        start: current_pos
            .checked_add(offset)
            .ok_or(Error::InvalidData("RAR 5 filter start overflows"))?,
        length,
        filter_type,
        channels,
    })
}

fn read_filter_data(bits: &mut BitReader<'_>) -> Result<u32> {
    let byte_count = bits.read_bits(2)? as usize + 1;
    let mut data = 0;
    for index in 0..byte_count {
        data |= bits.read_bits(8)? << (index * 8);
    }
    Ok(data)
}

fn apply_filters(output: &mut [u8], filters: &[PendingFilter]) -> Result<()> {
    for filter in filters {
        let end = filter
            .start
            .checked_add(filter.length)
            .ok_or(Error::InvalidData("RAR 5 filter range overflows"))?;
        let data = output
            .get_mut(filter.start..end)
            .ok_or(Error::InvalidData("RAR 5 filter range exceeds output"))?;
        match filter.filter_type {
            FilterType::Delta => {
                let decoded = filters::delta_decode(data, filter.channels, rar50_delta_messages())?;
                data.copy_from_slice(&decoded);
            }
            FilterType::E8 => e8e9_decode(data, filter.start as u32, false),
            FilterType::E8E9 => e8e9_decode(data, filter.start as u32, true),
            FilterType::Arm => arm_decode(data, filter.start as u32),
        }
    }
    Ok(())
}

fn rar50_delta_messages() -> DeltaErrorMessages {
    DeltaErrorMessages {
        invalid_channels: "RAR 5 DELTA filter channel count is invalid",
        zero_channels: "RAR 5 DELTA filter has zero channels",
        truncated_source: "RAR 5 DELTA filter source is truncated",
    }
}

fn e8e9_decode(data: &mut [u8], file_offset: u32, include_e9: bool) {
    if data.len() <= 4 {
        return;
    }
    let cmp_mask = if include_e9 { 0xfe } else { 0xff };
    let opcode_limit = data.len() - 4;
    let mut opcode_pos = 0usize;
    while let Some(pos) = super::fast::next_x86_opcode(data, opcode_pos, opcode_limit, cmp_mask) {
        let cur_pos = pos + 1;
        let offset = file_offset.wrapping_add(cur_pos as u32) % X86_FILTER_FILE_SIZE;
        let addr = u32::from_le_bytes([
            data[cur_pos],
            data[cur_pos + 1],
            data[cur_pos + 2],
            data[cur_pos + 3],
        ]);
        let new_addr = if addr & 0x8000_0000 != 0 {
            (addr.wrapping_add(offset) & 0x8000_0000 == 0)
                .then(|| addr.wrapping_add(X86_FILTER_FILE_SIZE))
        } else {
            (addr.wrapping_sub(X86_FILTER_FILE_SIZE) & 0x8000_0000 != 0)
                .then(|| addr.wrapping_sub(offset))
        };
        if let Some(value) = new_addr {
            data[cur_pos..cur_pos + 4].copy_from_slice(&value.to_le_bytes());
        }
        opcode_pos = pos + 5;
    }
}

const X86_FILTER_FILE_SIZE: u32 = 0x0100_0000;

fn arm_decode(data: &mut [u8], file_offset: u32) {
    let mut pos = 0usize;
    while pos + 3 < data.len() {
        if data[pos + 3] == 0xeb {
            let mut offset = u32::from(data[pos])
                | (u32::from(data[pos + 1]) << 8)
                | (u32::from(data[pos + 2]) << 16);
            offset = offset.wrapping_sub(file_offset.wrapping_add(pos as u32) / 4);
            data[pos] = offset as u8;
            data[pos + 1] = (offset >> 8) as u8;
            data[pos + 2] = (offset >> 16) as u8;
        }
        pos += 4;
    }
}

fn length_slot_extra_bits(slot: usize) -> Result<u8> {
    if slot < 8 {
        Ok(0)
    } else {
        let bit_count = (slot >> 2) - 1;
        if bit_count > 24 {
            Err(Error::InvalidData("RAR 5 length slot is too large"))
        } else {
            Ok(bit_count as u8)
        }
    }
}

fn length_bonus(distance: usize) -> usize {
    usize::from(distance > 0x100) + usize::from(distance > 0x2000) + usize::from(distance > 0x40000)
}

pub fn slot_to_length(slot: usize, extra_bits: u32) -> Result<usize> {
    if slot < 8 {
        return Ok(slot + 2);
    }
    let bit_count = (slot >> 2) - 1;
    if bit_count > 24 {
        return Err(Error::InvalidData("RAR 5 length slot is too large"));
    }
    let max_extra = if bit_count == 32 {
        u32::MAX
    } else {
        (1u32 << bit_count) - 1
    };
    if extra_bits > max_extra {
        return Err(Error::InvalidData("RAR 5 length extra bits exceed slot"));
    }
    Ok((((4 | (slot & 3)) << bit_count) | extra_bits as usize) + 2)
}

pub fn distance_slot_bit_count(slot: usize) -> Result<usize> {
    if slot < 4 {
        Ok(0)
    } else {
        let bit_count = (slot - 2) >> 1;
        if bit_count > 31 {
            Err(Error::InvalidData("RAR 5 distance slot is too large"))
        } else {
            Ok(bit_count)
        }
    }
}

pub fn slot_to_distance(slot: usize, extra_bits: u32) -> Result<usize> {
    if slot < 4 {
        return Ok(slot + 1);
    }
    let bit_count = distance_slot_bit_count(slot)?;
    let max_extra = if bit_count == 32 {
        u32::MAX
    } else {
        (1u32 << bit_count) - 1
    };
    if extra_bits > max_extra {
        return Err(Error::InvalidData("RAR 5 distance extra bits exceed slot"));
    }
    Ok((((2 | (slot & 1)) << bit_count) | extra_bits as usize) + 1)
}

/// Width of the one-lookup decode table; codes longer than this take the
/// per-length scan below.
const QUICK_BITS: usize = 10;

#[derive(Debug, Clone)]
pub struct HuffmanTable {
    symbols: Vec<HuffmanSymbol>,
    first_code: [u16; 16],
    first_index: [usize; 16],
    counts: [u16; 16],
    /// Indexed by the next `QUICK_BITS` bits of input; a non-zero entry packs
    /// `symbol << 4 | code_length` for codes no longer than `QUICK_BITS`.
    quick: Vec<u32>,
}

#[derive(Debug, Clone)]
struct HuffmanSymbol {
    code: u16,
    len: u8,
    symbol: usize,
}

impl HuffmanTable {
    pub fn from_lengths(lengths: &[u8]) -> Result<Self> {
        let mut count = [0u16; 16];
        for &length in lengths {
            if length > 15 {
                return Err(Error::InvalidData("RAR 5 Huffman length is too large"));
            }
            if length != 0 {
                count[length as usize] += 1;
            }
        }
        validate_huffman_counts(&count)?;

        let mut first_code = [0u16; 16];
        let mut next_code = [0u16; 16];
        let mut code = 0u16;
        for length in 1..=15 {
            code = (code + count[length - 1]) << 1;
            first_code[length] = code;
            next_code[length] = code;
        }

        let mut first_index = [0usize; 16];
        let mut index = 0usize;
        for length in 1..=15 {
            first_index[length] = index;
            index += usize::from(count[length]);
        }

        let mut symbols = Vec::new();
        for (symbol, &length) in lengths.iter().enumerate() {
            if length == 0 {
                continue;
            }
            let code = next_code[length as usize];
            next_code[length as usize] += 1;
            symbols.push(HuffmanSymbol {
                code,
                len: length,
                symbol,
            });
        }
        symbols.sort_by_key(|item| (item.len, item.code, item.symbol));

        let mut quick = vec![0u32; 1 << QUICK_BITS];
        for item in &symbols {
            let len = usize::from(item.len);
            if len <= QUICK_BITS {
                let shift = QUICK_BITS - len;
                let start = usize::from(item.code) << shift;
                let entry = ((item.symbol as u32) << 4) | len as u32;
                quick[start..start + (1 << shift)].fill(entry);
            }
        }

        Ok(Self {
            symbols,
            first_code,
            first_index,
            counts: count,
            quick,
        })
    }

    fn decode(&self, bits: &mut BitReader<'_>) -> Result<usize> {
        if self.symbols.is_empty() {
            return Err(Error::InvalidData("RAR 5 empty Huffman table"));
        }
        // With four whole bytes ahead at least 17 bits remain, so no code can
        // run out of input and the availability checks disappear from the
        // typical path.
        let byte = bits.bit_pos / 8;
        let bit = bits.bit_pos % 8;
        if let Some(bytes) = bits.input.get(byte..byte + 4) {
            let word = u32::from_be_bytes(bytes.try_into().expect("slice is four bytes"));
            let bitfield = (word << bit) >> 17;
            let entry = self.quick[(bitfield >> (15 - QUICK_BITS)) as usize];
            if entry != 0 {
                bits.bit_pos += (entry & 0x0f) as usize;
                return Ok((entry >> 4) as usize);
            }
            for len in QUICK_BITS + 1..=15 {
                let count = self.counts[len];
                if count != 0 {
                    let code = (bitfield >> (15 - len)) as u16;
                    let offset = code.wrapping_sub(self.first_code[len]);
                    if offset < count {
                        bits.bit_pos += len;
                        let index = self.first_index[len] + usize::from(offset);
                        return Ok(self.symbols[index].symbol);
                    }
                }
            }
            return Err(Error::InvalidData("RAR 5 invalid Huffman code"));
        }
        self.decode_near_end(bits)
    }

    /// The last bytes of a block: peeks are zero-padded, so a "match" past
    /// the real bits means the bit-by-bit reader would have run out, and the
    /// availability checks stay exactly as strict as before.
    #[cold]
    fn decode_near_end(&self, bits: &mut BitReader<'_>) -> Result<usize> {
        let available = bits.input.len() * 8 - bits.bit_pos;
        let bitfield = bits.peek15();
        for len in 1..=15 {
            let count = self.counts[len];
            if count != 0 {
                let code = (bitfield >> (15 - len)) as u16;
                let offset = code.wrapping_sub(self.first_code[len]);
                if offset < count {
                    if len > available {
                        return Err(Error::NeedMoreInput);
                    }
                    bits.bit_pos += len;
                    let index = self.first_index[len] + usize::from(offset);
                    return Ok(self.symbols[index].symbol);
                }
            }
        }
        if available < 15 {
            Err(Error::NeedMoreInput)
        } else {
            Err(Error::InvalidData("RAR 5 invalid Huffman code"))
        }
    }
}

struct BitReader<'a> {
    input: &'a [u8],
    bit_pos: usize,
}

impl<'a> BitReader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, bit_pos: 0 }
    }

    /// Returns the next 15 bits without consuming them, zero-padded past the
    /// end of the buffer.
    fn peek15(&self) -> u32 {
        let byte = self.bit_pos / 8;
        let bit = self.bit_pos % 8;
        let word = if let Some(bytes) = self.input.get(byte..byte + 4) {
            u32::from_be_bytes(bytes.try_into().expect("slice is four bytes"))
        } else {
            let mut word = 0u32;
            for (index, &item) in self.input.get(byte..).unwrap_or(&[]).iter().enumerate() {
                word |= u32::from(item) << (24 - 8 * index);
            }
            word
        };
        (word << bit) >> 17
    }

    fn read_bits(&mut self, count: u8) -> Result<u32> {
        if count > 32 {
            return Err(Error::InvalidData("RAR 5 bit read is too wide"));
        }
        let end = self
            .bit_pos
            .checked_add(usize::from(count))
            .ok_or(Error::NeedMoreInput)?;
        if end > self.input.len() * 8 {
            return Err(Error::NeedMoreInput);
        }
        if count == 0 {
            return Ok(0);
        }

        // One wide load and two shifts instead of a per-bit loop.
        let byte = self.bit_pos / 8;
        let bit = self.bit_pos % 8;
        let word = if let Some(bytes) = self.input.get(byte..byte + 8) {
            u64::from_be_bytes(bytes.try_into().expect("slice is eight bytes"))
        } else {
            let mut word = 0u64;
            for (index, &item) in self.input[byte..].iter().enumerate() {
                word |= u64::from(item) << (56 - 8 * index);
            }
            word
        };
        self.bit_pos = end;
        Ok(((word << bit) >> (64 - u32::from(count))) as u32)
    }
}

fn validate_huffman_counts(count: &[u16; 16]) -> Result<()> {
    let mut available = 1i32;
    for &len_count in count.iter().skip(1) {
        available = (available << 1) - i32::from(len_count);
        if available < 0 {
            return Err(Error::InvalidData("RAR 5 oversubscribed Huffman table"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_level_lengths_with_literal_fifteen() {
        let mut nibbles = vec![1, 2, 15, 0, 3, 4];
        nibbles.resize(LEVEL_TABLE_SIZE + 1, 0);

        let (lengths, bits) = read_level_lengths(&pack_nibbles(&nibbles)).unwrap();

        assert_eq!(&lengths[..6], &[1, 2, 15, 3, 4, 0]);
        assert_eq!(bits, LEVEL_TABLE_SIZE * 4 + 4);
    }

    #[test]
    fn reads_level_lengths_with_zero_run_at_current_position() {
        let mut nibbles = vec![7, 15, 3, 2];
        nibbles.resize(LEVEL_TABLE_SIZE - 3, 0);

        let (lengths, bits) = read_level_lengths(&pack_nibbles(&nibbles)).unwrap();

        assert_eq!(lengths[0], 7);
        assert_eq!(&lengths[1..6], &[0, 0, 0, 0, 0]);
        assert_eq!(lengths[6], 2);
        assert_eq!(bits, (LEVEL_TABLE_SIZE - 3) * 4);
    }

    fn pack_nibbles(nibbles: &[u8]) -> Vec<u8> {
        nibbles
            .chunks(2)
            .map(|chunk| {
                let high = chunk[0] & 0x0f;
                let low = chunk.get(1).copied().unwrap_or(0) & 0x0f;
                (high << 4) | low
            })
            .collect()
    }

    #[test]
    fn reads_rar70_table_length_count() {
        assert_eq!(
            table_length_count(1).unwrap(),
            MAIN_TABLE_SIZE + DISTANCE_TABLE_SIZE_70 + ALIGN_TABLE_SIZE + LENGTH_TABLE_SIZE
        );
    }

    #[test]
    fn rejects_oversubscribed_rar50_huffman_tables() {
        assert!(matches!(
            HuffmanTable::from_lengths(&[1, 1, 1]),
            Err(Error::InvalidData("RAR 5 oversubscribed Huffman table"))
        ));
    }

    #[test]
    fn detects_rar50_align_mode_when_align_lengths_are_not_uniform_four() {
        let mut align = vec![4; ALIGN_TABLE_SIZE];
        align[0] = 0;
        align[3] = 3;
        let lengths = TableLengths {
            main: vec![1, 1],
            distance: vec![1, 1],
            align,
            length: vec![1, 1],
        };

        let tables = DecodeTables::from_lengths(&lengths).unwrap();

        assert!(tables.align_mode);
    }

    #[test]
    fn decodes_length_slots() {
        assert_eq!(slot_to_length(0, 0).unwrap(), 2);
        assert_eq!(slot_to_length(7, 0).unwrap(), 9);
        assert_eq!(slot_to_length(8, 0).unwrap(), 10);
        assert_eq!(slot_to_length(8, 1).unwrap(), 11);
        assert_eq!(slot_to_length(11, 1).unwrap(), 17);
        assert_eq!(slot_to_length(12, 3).unwrap(), 21);
    }

    #[test]
    fn decodes_distance_slots() {
        assert_eq!(slot_to_distance(0, 0).unwrap(), 1);
        assert_eq!(slot_to_distance(3, 0).unwrap(), 4);
        assert_eq!(distance_slot_bit_count(4).unwrap(), 1);
        assert_eq!(slot_to_distance(4, 0).unwrap(), 5);
        assert_eq!(slot_to_distance(4, 1).unwrap(), 6);
        assert_eq!(distance_slot_bit_count(10).unwrap(), 4);
        assert_eq!(slot_to_distance(10, 15).unwrap(), 48);
    }

    #[test]
    fn bit_reader_accepts_large_rar5_distance_extras() {
        let mut bits = BitReader::new(&[0xff, 0x00, 0xaa, 0x55]);

        assert_eq!(bits.read_bits(32).unwrap(), 0xff00_aa55);
        assert_eq!(
            bits.read_bits(1),
            Err(Error::NeedMoreInput),
            "32-bit reads must not leave a partial cursor state"
        );
    }

    #[test]
    fn rejects_match_distance_beyond_dictionary() {
        let decoder = Unpack50Decoder::new();
        let mut output = b"ABCD".to_vec();
        let mut pos = output.len();
        ensure_copy_room(&mut output, pos, 5);

        assert_eq!(
            decoder.copy_match(&mut output, &mut pos, 4, 1, 5, 3),
            Err(Error::InvalidData(
                "RAR 5 match distance exceeds dictionary"
            ))
        );
    }

    #[test]
    fn streaming_window_accepts_match_beyond_old_64_mib_cap() {
        const OLD_STREAM_HISTORY_LIMIT: usize = 64 * 1024 * 1024;
        let distance = OLD_STREAM_HISTORY_LIMIT + 1;
        let history = vec![b'A'; distance];
        let mut output = StreamingOutput::new(history, 1, distance, distance);
        let mut decoded = Vec::new();

        output
            .copy_match(distance, 1, &mut |chunk| {
                match chunk {
                    DecodedChunk::Bytes(bytes) => decoded.extend_from_slice(bytes),
                    DecodedChunk::Repeated { byte, len } => {
                        decoded.extend(std::iter::repeat_n(byte, len));
                    }
                }
                Ok::<(), std::io::Error>(())
            })
            .unwrap();
        output
            .finish(&mut |chunk| {
                match chunk {
                    DecodedChunk::Bytes(bytes) => decoded.extend_from_slice(bytes),
                    DecodedChunk::Repeated { byte, len } => {
                        decoded.extend(std::iter::repeat_n(byte, len));
                    }
                }
                Ok::<(), std::io::Error>(())
            })
            .unwrap();

        assert_eq!(decoded, b"A");
    }

    #[test]
    fn streaming_window_rejects_match_beyond_declared_dictionary() {
        let mut output = StreamingOutput::new(vec![b'A'; 8], 1, 7, 8);

        assert!(matches!(
            output.copy_match(8, 1, &mut |_| Ok::<(), std::io::Error>(())),
            Err(StreamDecodeError::Decode(Error::InvalidData(
                "RAR 5 match distance exceeds dictionary"
            )))
        ));
    }
}
