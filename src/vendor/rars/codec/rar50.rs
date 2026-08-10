use super::filters::{self, DeltaErrorMessages};
use super::{Error, Result};
use std::collections::VecDeque;
use std::io::Read;
use std::ops::Range;
use std::sync::Arc;

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
/// NEWTUA: потолок на длину блока фильтра — столько же, сколько у `unrar`
/// (`MAX_FILTER_BLOCK_SIZE` в `unpack.hpp`). Это же и потолок на то, сколько
/// потоковый путь придерживает ради фильтра (тикет 34).
const MAX_FILTER_BLOCK_SIZE: usize = 0x40_0000;
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

// NEWTUA: `Clone` снят намеренно (тикет 34). Обе точки, где декодер
// копировался целиком — а с ним и словарное окно, — убраны; без `Clone` их
// нельзя вернуть молча.
#[derive(Debug)]
pub struct Unpack50Decoder {
    /// NEWTUA: таблицы под счётчиком ссылок (тикет 34, найдено `/simplify`).
    ///
    /// Точка отката обязана запомнить их вместе с окном, а `DecodeTables` —
    /// это четыре таблицы Хаффмана с быстрым индексом на 1024 записи каждая,
    /// около 23 КБ и восемь выделений на копию. На запись. Таблицы нигде не
    /// правятся на месте, только подменяются целиком, так что счётчик ссылок
    /// делает снимок бесплатным.
    tables: Option<Arc<DecodeTables>>,
    reps: [usize; 4],
    last_length: usize,
    /// NEWTUA: окно словаря — кольцо, а не `Vec` (тикет 34, найдено `/simplify`).
    ///
    /// Апстрим держал его в `Vec` и срезал начало через `drain`, а это сдвиг
    /// всего окна — на **каждую** запись, как только суммарный выход перерос
    /// словарь. Ровно та квадратичная болезнь, что лечил тикет 30, только
    /// прячется она на архивах крупнее словаря: сплошной архив из 4000 файлов
    /// на 74 МБ при словаре в 32 МиБ шёл ×8,9 к libunrar там, где тот же вид
    /// под словарём идёт ×0,47. У кольца срез начала стоит O(1).
    ///
    /// Заодно исчезла пересборка: потоковый путь брал окно себе и возвращал
    /// обратно через `Vec` ⇄ `VecDeque`, и обратный ход стоил O(окна) на
    /// запись, потому что после первого же среза начало кольца не в нуле.
    history: VecDeque<u8>,
    /// NEWTUA: «в окне одни нули» — признак, который несёт сам декодер, а не
    /// вычисляется заново на каждую запись (тикет 34).
    ///
    /// Потоковый путь пользуется им ради быстрой выдачи нулей, и раньше он
    /// пересчитывал его проходом по всему окну при входе. На сплошном архиве из
    /// 8000 мелких файлов с окном в 16 МиБ это 8000 проходов по окну — та же
    /// квадратичная болезнь, что и клон словаря, только в другом месте: при
    /// опущенном пороге распаковка становилась в 64 раза медленнее.
    ///
    /// Признак осторожный: срезанное с начала окна его не поднимает обратно.
    /// Ошибиться в эту сторону значит потерять ускорение, а не байты.
    history_all_zero: bool,
    /// NEWTUA: байты, ушедшие с начала окна с тех пор, как взята точка отката.
    /// `None` — точки отката нет и запоминать нечего. См. [`Unpack50Checkpoint`].
    discarded: Option<VecDeque<u8>>,
}

/// NEWTUA: точка отката декодера — вместо копии всего декодера (тикет 30).
///
/// Апстрим брал `decoder.clone()` перед каждой записью, а декодер носит внутри
/// словарное окно: на сплошном архиве из 8000 мелких файлов с окном в 16 МиБ
/// это порядка 50 ГБ пересылки памяти и квадратичный рост по числу записей.
/// Здесь запоминается только то, что меняется: длина окна и три мелких поля.
///
/// Окно между точкой отката и откатом **только дописывается в конец**, поэтому
/// прежнее состояние — это первые `history_len` байт. Единственное исключение —
/// обрезка с начала (`drop_history_front`), и она свои байты сохраняет, так что
/// полное окно всегда равно `discarded ++ history`.
#[derive(Debug)]
pub struct Unpack50Checkpoint {
    tables: Option<Arc<DecodeTables>>,
    reps: [usize; 4],
    last_length: usize,
    history_len: usize,
    history_all_zero: bool,
}

impl Unpack50Decoder {
    pub fn new() -> Self {
        Self {
            tables: None,
            reps: [0; 4],
            last_length: 0,
            history: VecDeque::new(),
            history_all_zero: true,
            discarded: None,
        }
    }

    /// NEWTUA: взять точку отката. O(1) по размеру окна.
    pub fn checkpoint(&mut self) -> Unpack50Checkpoint {
        self.discarded = Some(VecDeque::new());
        Unpack50Checkpoint {
            tables: self.tables.clone(),
            reps: self.reps,
            last_length: self.last_length,
            history_len: self.history.len(),
            history_all_zero: self.history_all_zero,
        }
    }

    /// NEWTUA: точка отката больше не нужна — запись принята.
    pub fn forget_checkpoint(&mut self) {
        self.discarded = None;
    }

    /// NEWTUA: вернуть декодер в состояние, снятое [`Self::checkpoint`].
    ///
    /// Путь редкий: он берётся, только если целостность записи не сошлась
    /// после применения фильтров.
    pub fn roll_back(&mut self, checkpoint: Unpack50Checkpoint) {
        self.tables = checkpoint.tables;
        self.reps = checkpoint.reps;
        self.last_length = checkpoint.last_length;
        self.history_all_zero = checkpoint.history_all_zero;
        // Путь редкий, так что берётся самая короткая форма: полное окно —
        // это `discarded ++ history`, а прежнее состояние — его начало.
        let mut history = self.discarded.take().unwrap_or_default();
        history.append(&mut self.history);
        history.truncate(checkpoint.history_len);
        self.history = history;
    }

    /// NEWTUA: срезать `count` байт с начала окна, сохранив их для отката.
    fn drop_history_front(&mut self, count: usize) {
        // NEWTUA: срез всего окна при пустом складе — это перенос, а не копия.
        // Случай не редкий: так уходит окно у **каждой** несплошной записи
        // (`reset`), и копировать там было бы окно на запись.
        if count == self.history.len()
            && let Some(discarded) = &mut self.discarded
            && discarded.is_empty()
        {
            *discarded = std::mem::take(&mut self.history);
            return;
        }
        let dropped = self.history.drain(..count);
        if let Some(discarded) = &mut self.discarded {
            discarded.extend(dropped);
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
                self.tables = Some(Arc::new(DecodeTables::from_lengths(&lengths)?));
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
            self.history_all_zero = self.history_all_zero && tail.iter().all(|&byte| byte == 0);
            self.history.extend(tail);
            if self.history.len() > dictionary_size {
                let discard = self.history.len() - dictionary_size;
                self.drop_history_front(discard);
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
        // NEWTUA: точка отката и потоковый путь не пересекаются — окно уезжает
        // в `StreamingOutput`, и запомненная длина стала бы враньём. Держится
        // это на порядке ветвлений в `rar50/extract.rs::write_file_to`, то есть
        // в другом файле; здесь стоит проверка, чтобы порядок нельзя было
        // поменять молча.
        debug_assert!(
            self.discarded.is_none(),
            "потоковый путь не должен идти под точкой отката"
        );
        let history_limit = dictionary_size;
        if self.history.len() > history_limit {
            let discard = self.history.len() - history_limit;
            self.drop_history_front(discard);
        }
        let mut output = StreamingOutput::new(
            std::mem::take(&mut self.history),
            self.history_all_zero,
            output_size,
            dictionary_size,
            history_limit,
        );

        // NEWTUA: окно возвращается декодеру при любом исходе (тикет 34).
        //
        // Раньше вызывающий страховался от неудачи копией всего декодера, а
        // копия декодера — это копия окна на каждую запись, то есть ровно тот
        // квадратичный рост, который лечил тикет 30. Здесь окно уходит из
        // декодера на время распаковки и возвращается назад независимо от того,
        // чем она кончилась, — страховать больше нечего.
        let result = self.decode_blocks_to_sink(
            input,
            algorithm_version,
            output_size,
            &mut output,
            &mut sink,
        );
        self.history_all_zero = output.all_zero;
        self.history = output.into_history();
        result
    }

    fn decode_blocks_to_sink<E>(
        &mut self,
        input: &mut impl Read,
        algorithm_version: u8,
        output_size: usize,
        output: &mut StreamingOutput,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        loop {
            let block = read_compressed_block(input)?;
            let payload = block.payload.as_slice();
            let mut payload_bit_pos = 0;
            if block.header.has_tables {
                let (lengths, table_bits) = read_table_lengths(payload, algorithm_version)?;
                self.tables = Some(Arc::new(DecodeTables::from_lengths(&lengths)?));
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
                    0..=255 => output.push(symbol as u8, sink)?,
                    // NEWTUA: фильтр больше не повод отказаться (тикет 34).
                    // Он объявлен впереди своего блока, поэтому выдача просто
                    // придерживает блок и преобразует его целиком.
                    256 => output.add_filter(read_filter(&mut bits, output.written())?)?,
                    257 => {
                        if self.last_length != 0 {
                            output.copy_match(self.reps[0], self.last_length, sink)?;
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
                        output.copy_match(distance, length, sink)?;
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
                        output.copy_match(distance, length, sink)?;
                    }
                }
            }

            self.tables = Some(tables);
            if block.header.is_last || output.written() >= output_size {
                break;
            }
        }

        if output.written() == output_size {
            output.finish(sink)
        } else {
            Err(Error::NeedMoreInput.into())
        }
    }

    fn reset(&mut self) {
        self.tables = None;
        self.reps = [0; 4];
        self.last_length = 0;
        self.history_all_zero = true;
        // NEWTUA: окно уходит целиком, и уходит оно с начала — значит, для
        // точки отката его надо сперва запомнить, как и при обрезке.
        self.drop_history_front(self.history.len());
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
            let (from_head, from_tail) = ring_parts(&self.history, index, take);
            output[*pos..*pos + from_head.len()].copy_from_slice(from_head);
            output[*pos + from_head.len()..*pos + take].copy_from_slice(from_tail);
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
    /// NEWTUA: ступень выдачи с фильтрами (тикет 34).
    ///
    /// Объявленные, но ещё не отработавшие фильтры — в порядке появления.
    filters: VecDeque<PendingFilter>,
    /// Байты текущего блока фильтра, придержанные до его конца. Не больше
    /// [`MAX_FILTER_BLOCK_SIZE`].
    held: Vec<u8>,
    /// Конец последнего принятого блока — им проверяется, что блоки идут
    /// вперёд, теми же словами, что и на буферизованном пути.
    last_block_end: usize,
}

impl StreamingOutput {
    fn new(
        history: VecDeque<u8>,
        all_zero: bool,
        output_limit: usize,
        dictionary_size: usize,
        history_limit: usize,
    ) -> Self {
        Self {
            all_zero,
            history,
            // NEWTUA: место под самое длинное совпадение сверх порога сброса.
            // Совпадение переносится одним куском и потому может перешагнуть
            // порог; сброс происходит после него, а не посередине, и тогда
            // смещения внутри `pending` не разъезжаются под ногами.
            pending: Vec::with_capacity(STREAM_FLUSH_THRESHOLD + MAX_LZ_MATCH),
            written: 0,
            output_limit,
            dictionary_size,
            history_limit,
            filters: VecDeque::new(),
            held: Vec::new(),
            last_block_end: 0,
        }
    }

    fn written(&self) -> usize {
        self.written
    }

    /// NEWTUA: принять объявленный фильтр (тикет 34).
    ///
    /// Границы проверяются теми же словами, что на буферизованном пути, — иначе
    /// один путь принял бы архив, который другой отвергает, и фаззер поймал бы
    /// это как расхождение.
    fn add_filter(&mut self, filter: PendingFilter) -> Result<()> {
        if accept_filter_block(&filter, &mut self.last_block_end, self.output_limit)?.is_some() {
            self.filters.push_back(filter);
        }
        Ok(())
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
        // NEWTUA: быстрый путь для нулей выдаёт приёмнику напрямую, минуя
        // `pending`, — то есть минуя и ступень фильтров (тикет 34). Пока есть
        // что фильтровать, им пользоваться нельзя; тогда нули пойдут обычной
        // дорогой. Запись, которая вся из нулей **и** с фильтром, — случай
        // умозрительный, так что терять тут нечего.
        if self.all_zero
            && self.filters.is_empty()
            && self.held.is_empty()
            && distance <= self.written + self.history.len()
        {
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

        // NEWTUA: совпадение переносится кусками, а не по байту (тикет 30, Е4).
        //
        // Апстрим звал здесь `byte_at_distance` и `push` на каждый байт, и это
        // была вся разница с буферизованным путём: в профиле на этот цикл
        // приходилось 44 % времени, а весь потоковый путь отставал от
        // буферизованного в ×1,49. Порядок байтов не меняется — сперва то, что
        // лежит в истории, затем то, что уже накоплено в `pending`, ровно как
        // читал прежний цикл.
        //
        // `all_zero` тут не трогаем намеренно: сюда можно попасть, только если
        // он уже ложь, — иначе совпадение перехватила бы проверка выше.
        let mut remaining = length;
        if distance > self.pending.len() {
            let history_distance = distance - self.pending.len();
            let take = remaining.min(history_distance);
            let start = self.history.len() - history_distance;
            self.extend_pending_from_history(start, take);
            remaining -= take;
        }
        if remaining > 0 {
            // Здесь `distance <= pending.len()`, и источник лежит в `pending`.
            // Наложение (совпадение длиннее расстояния) разворачивается само:
            // с каждым оборотом доступный кусок растёт на только что дописанное.
            let start = self.pending.len() - distance;
            while remaining > 0 {
                let take = remaining.min(self.pending.len() - start);
                self.pending.extend_from_within(start..start + take);
                remaining -= take;
            }
        }
        self.written += length;
        if self.pending.len() >= STREAM_FLUSH_THRESHOLD {
            self.flush(sink)?;
        }
        Ok(())
    }

    /// NEWTUA: `take` байт истории, начиная с `start`, дописать в `pending`.
    fn extend_pending_from_history(&mut self, start: usize, take: usize) {
        let (from_head, from_tail) = ring_parts(&self.history, start, take);
        self.pending.extend_from_slice(from_head);
        self.pending.extend_from_slice(from_tail);
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
        // NEWTUA: окно получает **нефильтрованные** байты, приёмник —
        // фильтрованные (тикет 34). Так же поступает и `unrar`: он копирует
        // блок из окна и преобразует копию, потому что окно ещё понадобится
        // будущим совпадениям. Поэтому история пополняется здесь, до ступени.
        self.history.extend(&self.pending);
        // NEWTUA: окно срезается одним куском. Апстрим снимал по байту, а
        // `flush` зовётся раз на 64 КиБ — после того как окно набралось, это
        // 65 536 `pop_front` на вызов и сотни миллионов на большом файле.
        if self.history.len() > self.history_limit {
            let over = self.history.len() - self.history_limit;
            self.history.drain(..over);
        }
        // Буфер вынимается и возвращается: ступени нужен и он, и `self`.
        // Ёмкость при этом уезжает вместе с ним и приезжает обратно.
        let pending = std::mem::take(&mut self.pending);
        let result = self.emit(&pending, sink);
        self.pending = pending;
        self.pending.clear();
        result
    }

    /// NEWTUA: ступень выдачи (тикет 34).
    ///
    /// До начала блока фильтра байты уходят приёмнику как есть; внутри блока
    /// придерживаются, а когда блок собран целиком — преобразуются и уходят.
    /// Начало блока всегда впереди текущей позиции (`start = pos + offset`),
    /// поэтому «догонять» уже выданное не приходится ни разу.
    fn emit<E>(
        &mut self,
        bytes: &[u8],
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        // Позиция первого байта `bytes` в записи. Отдельного счётчика выданного
        // не нужно: `pending` уже вынут, значит всё, кроме него, ступень прошла.
        let mut pos = self.written - bytes.len();
        let mut rest = bytes;
        while !rest.is_empty() {
            let Some(&filter) = self.filters.front() else {
                sink(DecodedChunk::Bytes(rest)).map_err(StreamDecodeError::Sink)?;
                return Ok(());
            };
            if pos < filter.start {
                let take = (filter.start - pos).min(rest.len());
                sink(DecodedChunk::Bytes(&rest[..take])).map_err(StreamDecodeError::Sink)?;
                pos += take;
                rest = &rest[take..];
                continue;
            }
            let take = (filter.start + filter.length - pos).min(rest.len());
            self.held.extend_from_slice(&rest[..take]);
            pos += take;
            rest = &rest[take..];
            if self.held.len() == filter.length {
                self.filters.pop_front();
                apply_one_filter(&mut self.held, &filter)?;
                sink(DecodedChunk::Bytes(&self.held)).map_err(StreamDecodeError::Sink)?;
                self.held.clear();
            }
        }
        Ok(())
    }

    fn finish<E>(
        &mut self,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        self.flush(sink)?;
        // NEWTUA: недособранный блок фильтра означает, что он выходит за конец
        // записи, — а это `add_filter` уже отверг бы. Проверка на случай, если
        // когда-нибудь отвергать перестанет.
        if !self.held.is_empty() || !self.filters.is_empty() {
            return Err(Error::InvalidData("RAR 5 filter range exceeds output").into());
        }
        Ok(())
    }

    fn into_history(self) -> VecDeque<u8> {
        self.history
    }
}

/// NEWTUA: `len` байт кольца, начиная с `start`, двумя сплошными кусками.
///
/// `VecDeque` и есть кольцо, а `as_slices` отдаёт его двумя кусками; больше
/// двух их не бывает по построению. Помощник отдаёт куски, а не копирует их
/// сам: приёмники у двух путей разные — в буферизованном это готовый срез
/// выхода, в потоковом дописывание в конец `pending`, — и общая «скопируй
/// сюда» заставила бы потоковый путь сперва обнулить место под копию. Лишний
/// проход по каждому байту совпадения; замер показал 8 % на большой записи.
fn ring_parts(ring: &VecDeque<u8>, start: usize, len: usize) -> (&[u8], &[u8]) {
    let (head, tail) = ring.as_slices();
    if start < head.len() {
        let from_head = len.min(head.len() - start);
        (&head[start..start + from_head], &tail[..len - from_head])
    } else {
        let start = start - head.len();
        (&tail[start..start + len], &[])
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
    // NEWTUA: блок длиннее потолка — это не фильтр (тикет 34).
    //
    // Длина читается как 32-битное число, то есть по формату блок вправе
    // заявить хоть 4 ГБ, и потоковому пути пришлось бы столько придержать.
    // `unrar` берёт то же число и поступает так же (`unpack50.cpp`:
    // `if (Filter.BlockLength>MAX_FILTER_BLOCK_SIZE) Filter.BlockLength=0`),
    // то есть роняет фильтр, а не отказывает. `rar` таких блоков не пишет;
    // если данные фильтр правда требовали, отказ придёт от CRC.
    let length = if length > MAX_FILTER_BLOCK_SIZE {
        0
    } else {
        length
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

/// NEWTUA: границы блока фильтра — одни на оба пути (тикет 34).
///
/// Потоковый путь физически не может того, что буферизованный делает даром:
/// вернуться к уже выданным байтам. Значит, запрещённое одному запрещено обоим,
/// иначе пути разойдутся — а расхождение здесь не отказ, а порча. Проверка
/// вынесена сюда, чтобы обе стороны спрашивали её одними словами.
///
/// `previous_end` — конец предыдущего непустого блока; блоки обязаны идти
/// вперёд и не налезать друг на друга. `rar` иначе и не пишет.
fn accept_filter_block(
    filter: &PendingFilter,
    previous_end: &mut usize,
    output_len: usize,
) -> Result<Option<Range<usize>>> {
    let end = filter
        .start
        .checked_add(filter.length)
        .ok_or(Error::InvalidData("RAR 5 filter range overflows"))?;
    if filter.start < *previous_end {
        return Err(Error::InvalidData(
            "RAR 5 filter blocks overlap or run backwards",
        ));
    }
    if end > output_len {
        return Err(Error::InvalidData("RAR 5 filter range exceeds output"));
    }
    if filter.length == 0 {
        return Ok(None);
    }
    *previous_end = end;
    Ok(Some(filter.start..end))
}

/// NEWTUA: преобразование одного блока. Общее тело для обоих путей (тикет 34).
///
/// `start` нужен только как смещение блока в файле — от него считают адреса
/// фильтры E8/E9 и ARM.
fn apply_one_filter(data: &mut [u8], filter: &PendingFilter) -> Result<()> {
    match filter.filter_type {
        FilterType::Delta => {
            let decoded = filters::delta_decode(data, filter.channels, rar50_delta_messages())?;
            data.copy_from_slice(&decoded);
        }
        FilterType::E8 => e8e9_decode(data, filter.start as u32, false),
        FilterType::E8E9 => e8e9_decode(data, filter.start as u32, true),
        FilterType::Arm => arm_decode(data, filter.start as u32),
    }
    Ok(())
}

fn apply_filters(output: &mut [u8], filters: &[PendingFilter]) -> Result<()> {
    let mut previous_end = 0;
    let output_len = output.len();
    for filter in filters {
        let Some(block) = accept_filter_block(filter, &mut previous_end, output_len)? else {
            continue;
        };
        apply_one_filter(&mut output[block], filter)?;
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
    let opcode_limit = data.len() - 4;
    let mut opcode_pos = 0usize;
    while let Some(pos) = super::fast::next_x86_opcode(data, opcode_pos, opcode_limit, include_e9) {
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

    /// NEWTUA: приёмник, собирающий выданное в один буфер.
    ///
    /// Тот же `match` по куску был выписан в модуле четырежды; после правок
    /// тикета 34 стало бы шесть раз.
    fn collecting_sink(
        got: &mut Vec<u8>,
    ) -> impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), std::convert::Infallible> {
        move |chunk| {
            match chunk {
                DecodedChunk::Bytes(bytes) => got.extend_from_slice(bytes),
                DecodedChunk::Repeated { byte, len } => got.extend(std::iter::repeat_n(byte, len)),
            }
            Ok(())
        }
    }

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
        let mut output = StreamingOutput::new(history.into(), false, 1, distance, distance);
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
        let mut output = StreamingOutput::new(vec![b'A'; 8].into(), false, 1, 7, 8);

        assert!(matches!(
            output.copy_match(8, 1, &mut |_| Ok::<(), std::io::Error>(())),
            Err(StreamDecodeError::Decode(Error::InvalidData(
                "RAR 5 match distance exceeds dictionary"
            )))
        ));
    }

    // NEWTUA: точка отката (тикет 30). Её путь редкий — он берётся, только если
    // целостность записи не сошлась после фильтров, — и потому не встречается
    // ни в корпусе, ни в сверке с `unar`. Здесь он проверяется прямо: поля
    // видны, потому что тесты лежат в том же модуле.

    fn decoder_with_window(window: Vec<u8>) -> Unpack50Decoder {
        let mut decoder = Unpack50Decoder::new();
        decoder.history = window.into();
        decoder.reps = [11, 22, 33, 44];
        decoder.last_length = 7;
        decoder
    }

    #[test]
    fn roll_back_restores_the_window_after_it_grew() {
        let mut decoder = decoder_with_window((0..100u8).collect());
        let before = decoder.history.clone();

        let checkpoint = decoder.checkpoint();
        decoder.history.extend([200; 50]);
        decoder.reps = [0; 4];
        decoder.last_length = 0;
        decoder.roll_back(checkpoint);

        assert_eq!(decoder.history, before);
        assert_eq!(decoder.reps, [11, 22, 33, 44]);
        assert_eq!(decoder.last_length, 7);
    }

    #[test]
    fn roll_back_restores_the_window_after_it_was_trimmed_from_the_front() {
        // Тот самый случай, ради которого `truncate` в одиночку не годится:
        // байты ушли с начала, и вернуть их может только сохранённая копия.
        let mut decoder = decoder_with_window((0..100u8).collect());
        let before = decoder.history.clone();

        let checkpoint = decoder.checkpoint();
        decoder.history.extend([200; 50]);
        decoder.drop_history_front(80);
        decoder.roll_back(checkpoint);

        assert_eq!(decoder.history, before);
    }

    #[test]
    fn roll_back_restores_the_window_after_a_non_solid_member_reset_it() {
        // `!solid` уносит окно целиком, и уносит с начала.
        let mut decoder = decoder_with_window((0..100u8).collect());
        let before = decoder.history.clone();

        let checkpoint = decoder.checkpoint();
        decoder.reset();
        decoder.history.extend([7; 10]);
        decoder.roll_back(checkpoint);

        assert_eq!(decoder.history, before);
        assert_eq!(decoder.last_length, 7);
    }

    #[test]
    fn a_forgotten_checkpoint_stops_saving_what_the_window_drops() {
        let mut decoder = decoder_with_window((0..100u8).collect());

        decoder.checkpoint();
        decoder.forget_checkpoint();
        decoder.drop_history_front(10);

        assert!(decoder.discarded.is_none());
        assert_eq!(decoder.history.len(), 90);
    }

    // NEWTUA: совпадение, читающее историю через шов кольца (тикет 30, Е4).

    #[test]
    fn a_match_reads_history_across_the_seam_of_the_ring() {
        let mut history: VecDeque<u8> = VecDeque::with_capacity(32);
        history.extend(0..32u8);
        for _ in 0..10 {
            let byte = history.pop_front().expect("окно не пусто");
            history.push_back(byte);
        }
        assert!(
            !history.as_slices().1.is_empty(),
            "тест бессмыслен, если кольцо не свёрнуто: проверить раскладку VecDeque"
        );
        let expected: Vec<u8> = history.iter().copied().collect();

        let mut output = StreamingOutput::new(VecDeque::new(), false, 64, 64, 32);
        output.history = history;
        let mut got = Vec::new();
        let mut sink = collecting_sink(&mut got);
        output
            .copy_match(32, 32, &mut sink)
            .expect("совпадение целиком внутри окна");
        output.finish(&mut sink).expect("сброс остатка");
        drop(sink);

        assert_eq!(got, expected);
    }

    #[test]
    fn a_match_longer_than_its_distance_repeats_the_pattern() {
        let mut output = StreamingOutput::new(vec![1, 2, 3].into(), false, 32, 64, 32);
        let mut got = Vec::new();
        let mut sink = collecting_sink(&mut got);
        output.copy_match(3, 8, &mut sink).expect("наложение");
        output.finish(&mut sink).expect("сброс остатка");
        drop(sink);

        assert_eq!(got, vec![1, 2, 3, 1, 2, 3, 1, 2]);
    }
}
