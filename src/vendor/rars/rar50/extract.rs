use super::{Archive, ExtractedEntryMeta, FileHeader, FileRedirection, Rar50KeyCache, blake2sp};
use crate::vendor::rars::codec::rar50::{
    DecodeMode, DecodedChunk, StreamDecodeError, Unpack50Decoder,
};
use crate::vendor::rars::crc32::{Crc32, crc32};
use crate::vendor::rars::crypto::rar50::{Rar50Cipher, Rar50Keys};
use crate::vendor::rars::error::{Error, Result};
use crate::vendor::rars::volume_extract::{ChainedReader, SplitVolumeState, SplitVolumeStep};
use std::io::{Cursor, Read, Write};

// NEWTUA: порог сменил смысл (тикет 34). Он больше не значит «выше этой черты
// фильтры не работают» — теперь работают на обоих путях. Он значит только «ниже
// этой черты держим запись в памяти целиком», и держим ради одного: повторной
// распаковки без фильтров от точки отката, если целостность не сошлась
// (`write_file_to`). У потокового пути такой сети нет и быть не может — байты
// уже ушли приёмнику.
//
// Мегабайт выбран числом. Парно, один и тот же код с двумя порогами: на
// крупной записи поток стоит **+2…3 % процессорного времени** (и до +10 % по
// стене), а пик памяти на записи в 300 МБ падает с 347 до 79 МБ — вчетверо за
// три процента. На тысячах мелких записей поток, наоборот, быстрее (×0,86…
// ×0,92), но они и так остаются ниже черты. Что ниже черты — стоит не больше
// полутора мегабайт.
#[cfg(not(test))]
const BUFFERED_DECODE_LIMIT: u64 = 1024 * 1024;
// Тесты держат порог крошечным нарочно: иначе потоковый путь в них почти не
// исполнялся бы, а он — половина кода распаковки RAR 5.
#[cfg(test)]
const BUFFERED_DECODE_LIMIT: u64 = 1024;

impl FileHeader {
    fn crypto_with_password(
        &self,
        key_cache: &Rar50KeyCache,
        password: Option<&[u8]>,
    ) -> Result<Option<Rar50Keys>> {
        if !self.encrypted {
            return Ok(None);
        }
        if let Some(crypto) = &self.crypto {
            return Ok(Some(crypto.keys.clone()));
        }
        let password = password.ok_or(Error::NeedPassword)?;
        let encryption = self.encryption.as_ref().ok_or(Error::InvalidHeader(
            "RAR 5 encrypted file is missing encryption record",
        ))?;
        if encryption.version != 0 {
            return Err(Error::UnsupportedFeature {
                version: crate::vendor::rars::version::ArchiveVersion::Rar50,
                feature: "RAR 5 unknown file encryption version",
            });
        }
        // NEWTUA (тикет 33): ключ выводится один раз на архив, а не на запись.
        // Оглавление читается сперва без пароля (`format/rar.rs`), поэтому
        // `self.crypto` выше почти всегда пуст, и до кэша дело доходило каждый
        // раз заново.
        let keys = key_cache.derive(password, encryption.salt, encryption.kdf_count)?;
        if let Some(check_value) = encryption.check_value {
            keys.check_password(&check_value)
                .map_err(super::map_rar50_crypto_error)?;
        }
        Ok(Some(keys))
    }

    fn encryption_iv(&self) -> Result<[u8; 16]> {
        if let Some(crypto) = &self.crypto {
            return Ok(crypto.iv);
        }
        self.encryption
            .as_ref()
            .map(|encryption| encryption.iv)
            .ok_or(Error::InvalidHeader(
                "RAR 5 encrypted file is missing encryption record",
            ))
    }

    fn packed_data_with_password(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Option<Rar50Keys>)> {
        let (mut reader, keys) = self.packed_reader_with_password(archive, password)?;
        let mut packed = Vec::new();
        reader.read_to_end(&mut packed)?;
        Ok((packed, keys))
    }

    fn packed_reader_with_password<'a>(
        &self,
        archive: &'a Archive,
        password: Option<&[u8]>,
    ) -> Result<(Box<dyn Read + 'a>, Option<Rar50Keys>)> {
        let reader = archive.range_reader(self.block.data_range.clone())?;
        if !self.encrypted {
            return Ok((reader, None));
        }
        if !self.packed_size().is_multiple_of(16) {
            return Err(Error::InvalidHeader(
                "RAR 5 encrypted file payload is not block aligned",
            ));
        }
        let keys = self
            .crypto_with_password(&archive.key_cache, password)?
            .ok_or(Error::InvalidHeader(
                "RAR 5 encrypted file is missing encryption keys",
            ))?;
        let reader =
            Rar50DecryptingReader::new(reader, keys.key, self.encryption_iv()?, self.packed_size());
        Ok((Box::new(reader), Some(keys)))
    }

    fn verify_integrity_with_keys(&self, data: &[u8], keys: Option<&Rar50Keys>) -> Result<()> {
        if let Some(expected) = self.data_crc32 {
            let actual = crc32(data);
            let actual = if self.uses_hash_mac() {
                let keys = keys.ok_or(Error::InvalidHeader(
                    "RAR 5 encrypted hash MAC needs encryption keys",
                ))?;
                keys.mac_crc32(actual)
            } else {
                actual
            };
            if actual != expected {
                return Err(Error::Crc32Mismatch { expected, actual });
            }
        }

        let Some(hash) = &self.hash else {
            return Ok(());
        };
        match hash.hash_type {
            0 if hash.data.len() == 32 => {
                let actual = blake2sp::hash(data);
                let actual = if self.uses_hash_mac() {
                    let keys = keys.ok_or(Error::InvalidHeader(
                        "RAR 5 encrypted hash MAC needs encryption keys",
                    ))?;
                    keys.mac_hash32(actual)
                } else {
                    actual
                };
                if constant_time_eq(&hash.data, &actual) {
                    Ok(())
                } else {
                    Err(Error::HashMismatch { hash_type: 0 })
                }
            }
            0 => Err(Error::InvalidHeader(
                "RAR 5 BLAKE2sp hash record has invalid length",
            )),
            _ => Ok(()),
        }
    }

    fn verify_streaming_integrity(
        &self,
        crc: Crc32,
        hash: Option<([u8; 32], blake2sp::Hasher)>,
        keys: Option<&Rar50Keys>,
    ) -> Result<()> {
        if let Some(expected) = self.data_crc32 {
            let actual = if self.uses_hash_mac() {
                let keys = keys.ok_or(Error::InvalidHeader(
                    "RAR 5 encrypted hash MAC needs encryption keys",
                ))?;
                keys.mac_crc32(crc.finish())
            } else {
                crc.finish()
            };
            if actual != expected {
                return Err(Error::Crc32Mismatch { expected, actual });
            }
        }

        if let Some((expected, hasher)) = hash {
            let actual = if self.uses_hash_mac() {
                let keys = keys.ok_or(Error::InvalidHeader(
                    "RAR 5 encrypted hash MAC needs encryption keys",
                ))?;
                keys.mac_hash32(hasher.finalize())
            } else {
                hasher.finalize()
            };
            if !constant_time_eq(&expected, &actual) {
                return Err(Error::HashMismatch { hash_type: 0 });
            }
        }
        Ok(())
    }

    pub fn metadata(&self) -> ExtractedEntryMeta {
        ExtractedEntryMeta {
            name: self.name.clone(),
            file_time: self.mtime.unwrap_or(0),
            attr: self.attributes,
            host_os: self.host_os,
            is_directory: self.is_directory(),
        }
    }

    pub fn write_to(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
        out: &mut impl Write,
    ) -> Result<()> {
        let mut session = DecoderSession::new_with_password(password, BUFFERED_DECODE_LIMIT);
        session.write_file_to(archive, self, out)
    }

    fn decoded_data_with_decoder(
        &self,
        archive: &Archive,
        decoder: &mut Unpack50Decoder,
        password: Option<&[u8]>,
    ) -> Result<DecodedData> {
        self.decoded_data_with_mode(archive, decoder, password, DecodeMode::Lz)
    }

    /// NEWTUA: упакованное тело больше не читается в память целиком.
    ///
    /// Апстрим звал `read_to_end` и клал рядом с распакованной записью ещё и
    /// упакованную — на файле в 300 МБ это лишняя сотня мегабайт пика
    /// (тикет 29). Декодер и так умеет читать поток, а «хранимая» запись сюда
    /// не доходит: у неё свой потоковый путь (`write_stored_to`).
    fn decoded_data_with_mode(
        &self,
        archive: &Archive,
        decoder: &mut Unpack50Decoder,
        password: Option<&[u8]>,
        mode: DecodeMode,
    ) -> Result<DecodedData> {
        if self.is_stored() {
            let (packed, keys) = self.packed_data_with_password(archive, password)?;
            let data = self.decode_packed_with_decoder_mode(&packed, decoder, mode)?;
            return Ok(DecodedData { data, keys });
        }
        let (mut packed, keys) = self.packed_reader_with_password(archive, password)?;
        let data = self.decode_packed_reader_with_decoder_mode(&mut packed, decoder, mode)?;
        Ok(DecodedData { data, keys })
    }

    /// Распаковать сжатую запись, читая упакованное тело потоком.
    ///
    /// NEWTUA: сюда сведён общий хвост распаковки — и с потока, и из памяти.
    /// «Хранимая» запись остаётся у соседа: ей нужно тело целиком.
    fn decode_packed_reader_with_decoder_mode(
        &self,
        packed: &mut impl Read,
        decoder: &mut Unpack50Decoder,
        mode: DecodeMode,
    ) -> Result<Vec<u8>> {
        if self.unpacked_size == 0 && self.packed_size() == 0 {
            return Ok(Vec::new());
        }

        let info = self.decoded_compression_info()?;
        let dictionary_size = usize::try_from(info.dictionary_size).map_err(|_| {
            Error::InvalidHeader("RAR 5 dictionary size overflows host address size")
        })?;
        let output_size = checked_unpacked_size(self.unpacked_size)?;
        match decoder.decode_member_from_reader_with_dictionary(
            packed,
            info.algorithm_version,
            output_size,
            dictionary_size,
            info.solid,
            mode,
        ) {
            Ok(data) => Ok(data),
            Err(error) => self.map_truncated_unverified_payload(error),
        }
    }

    /// Распаковать запись, упакованное тело которой уже в памяти.
    ///
    /// NEWTUA: сжатая запись сюда больше не приходит — она читается потоком
    /// (`decode_packed_reader_with_decoder_mode`). Осталась «хранимая»: её
    /// проверки длины и набивки требуют тела целиком.
    fn decode_packed_with_decoder_mode(
        &self,
        packed: &[u8],
        decoder: &mut Unpack50Decoder,
        mode: DecodeMode,
    ) -> Result<Vec<u8>> {
        if self.is_stored() {
            if self.encrypted {
                let unpacked_size = usize::try_from(self.unpacked_size).map_err(|_| {
                    Error::InvalidHeader("RAR 5 unpacked size overflows host address size")
                })?;
                if packed.len() < unpacked_size {
                    return Err(Error::InvalidHeader(
                        "RAR 5 encrypted stored file is shorter than unpacked size",
                    ));
                }
                if packed[unpacked_size..].iter().any(|&byte| byte != 0) {
                    return Err(Error::InvalidHeader(
                        "RAR 5 encrypted stored file has non-zero padding",
                    ));
                }
                return Ok(packed[..unpacked_size].to_vec());
            }
            if packed.len() as u64 != self.unpacked_size {
                return Err(Error::InvalidHeader(
                    "RAR 5 stored file has mismatched packed and unpacked sizes",
                ));
            }
            return Ok(packed.to_vec());
        }
        if self.unpacked_size == 0 && packed.is_empty() {
            return Ok(Vec::new());
        }
        // NEWTUA: дальше — общий с потоковым близнецом хвост. Двух путей
        // распаковки тут нет и у апстрима: его `decode_member_with_dictionary`
        // сама заворачивает срез в `Cursor` и зовёт версию для потока.
        self.decode_packed_reader_with_decoder_mode(&mut Cursor::new(packed), decoder, mode)
    }

    fn map_truncated_unverified_payload(
        &self,
        error: crate::vendor::rars::codec::Error,
    ) -> Result<Vec<u8>> {
        if matches!(error, crate::vendor::rars::codec::Error::NeedMoreInput)
            && self.data_crc32.is_none()
            && self.hash.is_none()
        {
            return Ok(Vec::new());
        }
        Err(Error::from(error))
    }

    fn stream_packed_with_decoder<R: Read>(
        &self,
        packed: &mut R,
        keys: Option<&Rar50Keys>,
        decoder: &mut Unpack50Decoder,
        writer: &mut dyn Write,
    ) -> Result<()> {
        if self.is_stored() {
            return Err(Error::InvalidHeader(
                "RAR 5 stored file does not use streaming compressed decode",
            ));
        }

        let info = self.decoded_compression_info()?;
        let dictionary_size = usize::try_from(info.dictionary_size).map_err(|_| {
            Error::InvalidHeader("RAR 5 dictionary size overflows host address size")
        })?;
        let output_size = usize::try_from(self.unpacked_size)
            .map_err(|_| Error::InvalidHeader("RAR 5 unpacked size overflows host address size"))?;
        let mut crc = Crc32::new();
        let mut hash = streaming_hash_verifier(self)?;
        decoder
            .decode_member_from_reader_with_dictionary_to_sink(
                packed,
                info.algorithm_version,
                output_size,
                dictionary_size,
                info.solid,
                |chunk| match chunk {
                    DecodedChunk::Bytes(chunk) => {
                        crc.update(chunk);
                        if let Some((_, hasher)) = &mut hash {
                            hasher.update(chunk);
                        }
                        writer.write_all(chunk)
                    }
                    DecodedChunk::Repeated { byte, len } => {
                        write_repeated_chunk(writer, &mut crc, &mut hash, byte, len)
                    }
                },
            )
            .map_err(|error| match error {
                StreamDecodeError::Decode(error) => Error::from(error),
                StreamDecodeError::Sink(error) => Error::from(error),
            })?;
        self.verify_streaming_integrity(crc, hash, keys)
    }

    fn write_stored_to(
        &self,
        archive: &Archive,
        password: Option<&[u8]>,
        writer: &mut dyn Write,
    ) -> Result<()> {
        let (mut reader, keys) = self
            .packed_reader_with_password(archive, password)
            .map_err(|error| self.entry_error("decoding", error))?;
        let mut crc = Crc32::new();
        let mut hash =
            streaming_hash_verifier(self).map_err(|error| self.entry_error("decoding", error))?;
        let mut written = 0u64;
        let mut buf = [0u8; 64 * 1024];

        loop {
            let count = reader
                .read(&mut buf)
                .map_err(Error::from)
                .map_err(|error| self.entry_error("decoding", error))?;
            if count == 0 {
                break;
            }
            let remaining =
                usize::try_from(self.unpacked_size.saturating_sub(written)).unwrap_or(usize::MAX);
            let chunk_len = count.min(remaining);
            let chunk = &buf[..chunk_len];
            if self.encrypted && buf[chunk_len..count].iter().any(|&byte| byte != 0) {
                return Err(self.entry_error(
                    "decoding",
                    Error::InvalidHeader("RAR 5 encrypted stored file has non-zero padding"),
                ));
            }
            written = written
                .checked_add(chunk.len() as u64)
                .ok_or(Error::InvalidHeader("RAR 5 stored size overflows"))
                .map_err(|error| self.entry_error("decoding", error))?;
            crc.update(chunk);
            if let Some((_, hasher)) = &mut hash {
                hasher.update(chunk);
            }
            writer
                .write_all(chunk)
                .map_err(Error::from)
                .map_err(|error| self.entry_error("writing", error))?;
        }

        if written != self.unpacked_size {
            return Err(self.entry_error(
                "decoding",
                Error::InvalidHeader("RAR 5 stored file has mismatched packed and unpacked sizes"),
            ));
        }
        self.verify_streaming_integrity(crc, hash, keys.as_ref())
            .map_err(|error| self.entry_error("verifying", error))
    }

    fn entry_error(&self, operation: &'static str, error: Error) -> Error {
        error.at_entry(self.name.clone(), operation)
    }
}

fn write_repeated_chunk(
    writer: &mut dyn Write,
    crc: &mut Crc32,
    hash: &mut Option<([u8; 32], blake2sp::Hasher)>,
    byte: u8,
    mut len: usize,
) -> std::io::Result<()> {
    let buffer = [byte; 64 * 1024];
    while len > 0 {
        let take = len.min(buffer.len());
        let chunk = &buffer[..take];
        writer.write_all(chunk)?;
        if byte == 0 {
            crc.update_zeroes(take as u64);
        } else {
            crc.update(chunk);
        }
        if let Some((_, hasher)) = hash.as_mut() {
            hasher.update(chunk);
        }
        len -= take;
    }
    Ok(())
}

struct DecodedData {
    data: Vec<u8>,
    keys: Option<Rar50Keys>,
}

struct DecoderSession<'a> {
    decoder: Unpack50Decoder,
    password: Option<&'a [u8]>,
    buffered_decode_limit: u64,
}

impl<'a> DecoderSession<'a> {
    fn new_with_password(password: Option<&'a [u8]>, buffered_decode_limit: u64) -> Self {
        Self {
            decoder: Unpack50Decoder::new(),
            password,
            buffered_decode_limit,
        }
    }

    fn write_file_to(
        &mut self,
        archive: &Archive,
        file: &FileHeader,
        writer: &mut dyn Write,
    ) -> Result<()> {
        if file.is_stored() {
            return file.write_stored_to(archive, self.password, writer);
        }
        if file.should_stream_decode(self.buffered_decode_limit) {
            return self.stream_file_to(archive, file, writer);
        }
        // NEWTUA: точка отката вместо копии декодера (тикет 30). Апстрим брал
        // здесь `self.decoder.clone()`, а декодер носит внутри словарное окно —
        // на сплошном архиве это копия окна перед **каждой** записью и
        // квадратичный рост по их числу. Откат нужен почти никогда, а платился
        // всегда.
        let checkpoint = self.decoder.checkpoint();
        let decoded = self
            .decoded_file_data(archive, file)
            .map_err(|error| file.entry_error("decoding", error))?;
        let decoded = match file.verify_integrity_with_keys(&decoded.data, decoded.keys.as_ref()) {
            Ok(()) => {
                self.decoder.forget_checkpoint();
                decoded
            }
            Err(filtered_error) => {
                self.decoder.roll_back(checkpoint);
                let unfiltered = file
                    .decoded_data_with_mode(
                        archive,
                        &mut self.decoder,
                        self.password,
                        DecodeMode::LzNoFilters,
                    )
                    .map_err(|error| file.entry_error("decoding", error))?;
                file.verify_integrity_with_keys(&unfiltered.data, unfiltered.keys.as_ref())
                    .map_err(|_| file.entry_error("verifying", filtered_error))?;
                unfiltered
            }
        };
        writer
            .write_all(&decoded.data)
            .map_err(Error::from)
            .map_err(|error| file.entry_error("writing", error))
    }

    fn stream_file_to(
        &mut self,
        archive: &Archive,
        file: &FileHeader,
        writer: &mut dyn Write,
    ) -> Result<()> {
        // NEWTUA: копии декодера здесь больше нет (тикет 34). Она страховала от
        // неудачи посреди записи, а стоила копии словарного окна на **каждую**
        // запись — при опущенном пороге это делало сплошной архив из мелких
        // файлов в 48 раз медленнее. Окно теперь возвращается декодеру и при
        // неудаче тоже, внутри самого кодека.
        let (mut packed, keys) = file
            .packed_reader_with_password(archive, self.password)
            .map_err(|error| file.entry_error("reading", error))?;
        file.stream_packed_with_decoder(&mut packed, keys.as_ref(), &mut self.decoder, writer)
            .map_err(|error| file.entry_error("decoding", error))
    }

    fn decoded_file_data(&mut self, archive: &Archive, file: &FileHeader) -> Result<DecodedData> {
        file.decoded_data_with_decoder(archive, &mut self.decoder, self.password)
    }

    fn split_decryptor(
        &self,
        split: &PendingSplitRefs,
        volumes: &[Archive],
    ) -> Result<Option<SplitDecryptor>> {
        split.split_decryptor(volumes, self.password)
    }

    fn decode_split(
        &mut self,
        volumes: &[Archive],
        split: &PendingSplitRefs,
        final_file: &FileHeader,
        decryptor: Option<&SplitDecryptor>,
    ) -> Result<Vec<u8>> {
        final_file.decode_split_with_decoder(volumes, split, &mut self.decoder, decryptor)
    }
}

impl FileHeader {
    fn should_stream_decode(&self, buffered_decode_limit: u64) -> bool {
        !self.is_stored() && self.unpacked_size > buffered_decode_limit
    }
}

fn rar50_buffered_decode_limit(options: crate::vendor::rars::ArchiveReadOptions<'_>) -> u64 {
    options
        .rar50_buffered_decode_limit
        .unwrap_or(BUFFERED_DECODE_LIMIT)
}

/// NEWTUA: писарь получил время жизни (`'w`) — см. `rar13::extract_volumes_to`.
pub fn extract_volumes_to_with_redirections<'w, F, R>(
    volumes: &[Archive],
    options: crate::vendor::rars::ArchiveReadOptions<'_>,
    mut open: F,
    mut redirect: R,
) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write + 'w>>,
    R: FnMut(&ExtractedEntryMeta, &FileRedirection) -> Result<()>,
{
    extract_volumes_to_impl(volumes, options, &mut open, &mut redirect, true)
}

fn extract_volumes_to_impl<'w, F, R>(
    volumes: &[Archive],
    options: crate::vendor::rars::ArchiveReadOptions<'_>,
    open: &mut F,
    redirect: &mut R,
    emit_redirections: bool,
) -> Result<()>
where
    F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write + 'w>>,
    R: FnMut(&ExtractedEntryMeta, &FileRedirection) -> Result<()>,
{
    if volumes.is_empty() {
        return Err(Error::InvalidHeader("RAR 5 volume set is empty"));
    }

    let password = options.password;
    let mut split = SplitVolumeState::new();
    let buffered_decode_limit = rar50_buffered_decode_limit(options);
    let mut session = DecoderSession::new_with_password(password, buffered_decode_limit);

    for (volume_index, archive) in volumes.iter().enumerate() {
        for (file_index, file) in archive.files().enumerate() {
            match split.advance(file.is_split_before(), file.is_split_after()) {
                SplitVolumeStep::Regular => {
                    if let Some(redirection) = &file.redirection {
                        if emit_redirections {
                            redirect(&file.metadata(), redirection)?;
                        }
                        continue;
                    }
                    let meta = file.metadata();
                    let mut writer = open(&meta)?;
                    if !meta.is_directory {
                        session.write_file_to(archive, file, &mut writer)?;
                    }
                }
                SplitVolumeStep::Start => {
                    validate_split_fragment(file, password)?;
                    split.begin(PendingSplitRefs::new(file, volume_index, file_index));
                }
                SplitVolumeStep::Continue(current) => {
                    validate_split_continuation_refs(current, file, password)?;
                    current.append(volume_index, file_index);
                }
                SplitVolumeStep::Finish(mut completed) => {
                    validate_split_continuation_refs(&completed, file, password)?;
                    completed.append(volume_index, file_index);
                    completed.write_to(volumes, file, &mut session, &mut *open)?;
                }
                SplitVolumeStep::MissingFirst => {
                    return Err(Error::InvalidHeader(
                        "RAR 5 split entry is missing its first part",
                    ));
                }
                SplitVolumeStep::Interrupted => {
                    return Err(Error::InvalidHeader(
                        "RAR 5 split entry is interrupted by a regular entry",
                    ));
                }
            }
        }
    }

    if split.is_pending() {
        return Err(Error::InvalidHeader("RAR 5 split entry is incomplete"));
    }

    Ok(())
}

fn validate_split_fragment(file: &FileHeader, password: Option<&[u8]>) -> Result<()> {
    if file.is_directory() {
        return Err(Error::InvalidHeader(
            "RAR 5 split directory entry is invalid",
        ));
    }
    if file.encrypted && password.is_none() && file.crypto.is_none() {
        return Err(Error::NeedPassword);
    }
    Ok(())
}

fn validate_split_continuation_refs(
    pending: &PendingSplitRefs,
    file: &FileHeader,
    password: Option<&[u8]>,
) -> Result<()> {
    validate_split_fragment(file, password)?;
    if file.name != pending.name {
        return Err(Error::InvalidHeader("RAR 5 split entry name changed"));
    }
    if file.compression_info != pending.compression_info {
        return Err(Error::InvalidHeader(
            "RAR 5 split entry compression info changed",
        ));
    }
    if file.encrypted != pending.encrypted {
        return Err(Error::InvalidHeader(
            "RAR 5 split entry encryption flag changed",
        ));
    }
    Ok(())
}

struct PendingSplitRefs {
    name: Vec<u8>,
    fragments: Vec<(usize, usize)>,
    file_time: u32,
    attr: u64,
    host_os: u64,
    compression_info: u64,
    encrypted: bool,
}

impl PendingSplitRefs {
    fn new(file: &FileHeader, volume_index: usize, file_index: usize) -> Self {
        Self {
            name: file.name.clone(),
            fragments: vec![(volume_index, file_index)],
            file_time: file.mtime.unwrap_or(0),
            attr: file.attributes,
            host_os: file.host_os,
            compression_info: file.compression_info,
            encrypted: file.encrypted,
        }
    }

    fn append(&mut self, volume_index: usize, file_index: usize) {
        self.fragments.push((volume_index, file_index));
    }

    fn write_to<'w, F>(
        self,
        volumes: &[Archive],
        final_file: &FileHeader,
        session: &mut DecoderSession<'_>,
        open: &mut F,
    ) -> Result<()>
    where
        F: FnMut(&ExtractedEntryMeta) -> Result<Box<dyn Write + 'w>>,
    {
        let decryptor = session.split_decryptor(&self, volumes)?;
        let meta = ExtractedEntryMeta {
            name: self.name.clone(),
            file_time: self.file_time,
            attr: self.attr,
            host_os: self.host_os,
            is_directory: false,
        };
        let mut writer = open(&meta)?;
        if final_file.is_stored() {
            return self
                .write_stored_to(volumes, final_file, decryptor.as_ref(), &mut writer)
                .map_err(|error| final_file.entry_error("extracting", error));
        }

        let data = session
            .decode_split(volumes, &self, final_file, decryptor.as_ref())
            .map_err(|error| final_file.entry_error("decoding", error))?;
        final_file
            .verify_integrity_with_keys(&data, decryptor.as_ref().map(|decryptor| &decryptor.keys))
            .map_err(|error| final_file.entry_error("verifying", error))?;
        writer
            .write_all(&data)
            .map_err(Error::from)
            .map_err(|error| final_file.entry_error("writing", error))?;
        Ok(())
    }

    fn write_stored_to(
        &self,
        volumes: &[Archive],
        final_file: &FileHeader,
        decryptor: Option<&SplitDecryptor>,
        writer: &mut dyn Write,
    ) -> Result<()> {
        let mut reader = self.fragment_reader(volumes, decryptor)?;
        let mut crc = Crc32::new();
        let mut hash = streaming_hash_verifier(final_file)?;
        let mut written = 0u64;
        let mut buf = [0u8; 64 * 1024];

        loop {
            let count = reader.read(&mut buf)?;
            if count == 0 {
                break;
            }
            let chunk = if final_file.encrypted {
                let remaining = usize::try_from(final_file.unpacked_size.saturating_sub(written))
                    .unwrap_or(usize::MAX);
                let chunk_len = count.min(remaining);
                if buf[chunk_len..count].iter().any(|&byte| byte != 0) {
                    return Err(Error::InvalidHeader(
                        "RAR 5 encrypted stored split file has non-zero padding",
                    ));
                }
                &buf[..chunk_len]
            } else {
                &buf[..count]
            };
            written = written
                .checked_add(chunk.len() as u64)
                .ok_or(Error::InvalidHeader("RAR 5 stored split size overflows"))?;
            crc.update(chunk);
            if let Some((_, hasher)) = &mut hash {
                hasher.update(chunk);
            }
            writer.write_all(chunk)?;
        }

        if written != final_file.unpacked_size {
            return Err(Error::InvalidHeader(
                "RAR 5 stored split file has mismatched packed and unpacked sizes",
            ));
        }
        if let Some(expected) = final_file.data_crc32 {
            let actual = if final_file.encrypted {
                let decryptor = decryptor.ok_or(Error::InvalidHeader(
                    "RAR 5 encrypted split CRC needs encryption keys",
                ))?;
                decryptor.keys.mac_crc32(crc.finish())
            } else {
                crc.finish()
            };
            if actual != expected {
                return Err(Error::Crc32Mismatch { expected, actual });
            }
        }
        if let Some((expected, hasher)) = hash {
            let actual = if final_file.encrypted {
                let decryptor = decryptor.ok_or(Error::InvalidHeader(
                    "RAR 5 encrypted split hash needs encryption keys",
                ))?;
                decryptor.keys.mac_hash32(hasher.finalize())
            } else {
                hasher.finalize()
            };
            if !constant_time_eq(&expected, &actual) {
                return Err(Error::HashMismatch { hash_type: 0 });
            }
        }
        Ok(())
    }

    fn split_decryptor(
        &self,
        volumes: &[Archive],
        password: Option<&[u8]>,
    ) -> Result<Option<SplitDecryptor>> {
        if !self.encrypted {
            return Ok(None);
        }
        let (volume_index, file_index) = self.fragments[0];
        let archive = volumes
            .get(volume_index)
            .ok_or(Error::InvalidHeader("RAR 5 split volume is missing"))?;
        let file = archive
            .files()
            .nth(file_index)
            .ok_or(Error::InvalidHeader("RAR 5 split entry is missing"))?;
        let keys = file
            .crypto_with_password(&archive.key_cache, password)?
            .ok_or(Error::InvalidHeader(
                "RAR 5 encrypted split file is missing encryption keys",
            ))?;
        Ok(Some(SplitDecryptor {
            keys,
            iv: file.encryption_iv()?,
        }))
    }

    fn fragment_reader<'a>(
        &self,
        volumes: &'a [Archive],
        decryptor: Option<&SplitDecryptor>,
    ) -> Result<Box<dyn Read + 'a>> {
        let mut readers = Vec::with_capacity(self.fragments.len());
        let mut packed_size = 0u64;
        for &(volume_index, file_index) in &self.fragments {
            let archive = volumes
                .get(volume_index)
                .ok_or(Error::InvalidHeader("RAR 5 split volume is missing"))?;
            let file = archive
                .files()
                .nth(file_index)
                .ok_or(Error::InvalidHeader("RAR 5 split entry is missing"))?;
            packed_size = packed_size.saturating_add(file.packed_size());
            readers.push(archive.range_reader(file.block.data_range.clone())?);
        }
        let chained = ChainedReader::new(readers);
        if let Some(decryptor) = decryptor {
            Ok(Box::new(Rar50DecryptingReader::new(
                chained,
                decryptor.keys.key,
                decryptor.iv,
                packed_size,
            )))
        } else {
            Ok(Box::new(chained))
        }
    }
}

struct SplitDecryptor {
    keys: Rar50Keys,
    iv: [u8; 16],
}

fn streaming_hash_verifier(file: &FileHeader) -> Result<Option<([u8; 32], blake2sp::Hasher)>> {
    let Some(hash) = &file.hash else {
        return Ok(None);
    };
    match hash.hash_type {
        0 if hash.data.len() == 32 => {
            let mut expected = [0u8; 32];
            expected.copy_from_slice(&hash.data);
            Ok(Some((expected, blake2sp::Hasher::new())))
        }
        0 => Err(Error::InvalidHeader(
            "RAR 5 BLAKE2sp hash record has invalid length",
        )),
        _ => Ok(None),
    }
}

fn checked_unpacked_size(size: u64) -> Result<usize> {
    usize::try_from(size)
        .map_err(|_| Error::InvalidHeader("RAR 5 unpacked size overflows host address size"))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&left, &right) in left.iter().zip(right) {
        diff |= left ^ right;
    }
    diff == 0
}

impl FileHeader {
    fn decode_split_with_decoder(
        &self,
        volumes: &[Archive],
        split: &PendingSplitRefs,
        decoder: &mut Unpack50Decoder,
        decryptor: Option<&SplitDecryptor>,
    ) -> Result<Vec<u8>> {
        if self.is_stored() {
            let mut data = Vec::new();
            let mut reader = split.fragment_reader(volumes, decryptor)?;
            reader.read_to_end(&mut data)?;
            if data.len() as u64 != self.unpacked_size {
                return Err(Error::InvalidHeader(
                    "RAR 5 stored split file has mismatched packed and unpacked sizes",
                ));
            }
            return Ok(data);
        }

        let info = self.decoded_compression_info()?;
        let dictionary_size = usize::try_from(info.dictionary_size).map_err(|_| {
            Error::InvalidHeader("RAR 5 dictionary size overflows host address size")
        })?;
        let mut reader = split.fragment_reader(volumes, decryptor)?;
        let output_size = checked_unpacked_size(self.unpacked_size)?;
        decoder
            .decode_member_from_reader_with_dictionary(
                &mut reader,
                info.algorithm_version,
                output_size,
                dictionary_size,
                info.solid,
                DecodeMode::Lz,
            )
            .map_err(Error::from)
    }
}

/// NEWTUA: расшифровка идёт целым буфером, а не блоком AES (тикет 30, Е5).
///
/// Апстрим держал здесь ровно 16 байт и на каждые 64 КиБ упакованного тела
/// делал 4096 заходов в `fill_buffer`. Читатель этот стоит **снаружи** буфера
/// источника, так что буфер его не спасал. `decrypt_in_place` принимает любую
/// длину, кратную 16, и в режиме CBC цепочка от длины куска не зависит: разбор
/// на блоки внутри неё тот же самый.
const DECRYPT_BUFFER_SIZE: usize = 16 * 1024;

struct Rar50DecryptingReader<R> {
    inner: R,
    cipher: Rar50Cipher,
    buffer: Vec<u8>,
    pos: usize,
    len: usize,
}

impl<R: Read> Rar50DecryptingReader<R> {
    fn new(inner: R, key: [u8; 32], iv: [u8; 16], packed_size: u64) -> Self {
        // NEWTUA: буфер не крупнее самого тела. У сплошного зашифрованного
        // архива запись — это сотня-другая байт, а полный буфер выделялся бы
        // (и обнулялся) под каждую.
        let size = usize::try_from(packed_size)
            .unwrap_or(DECRYPT_BUFFER_SIZE)
            .clamp(16, DECRYPT_BUFFER_SIZE);
        Self {
            inner,
            cipher: Rar50Cipher::new(key, iv),
            buffer: vec![0; size.next_multiple_of(16)],
            pos: 0,
            len: 0,
        }
    }

    fn fill_buffer(&mut self) -> std::io::Result<bool> {
        let mut read = 0;
        while read < self.buffer.len() {
            let count = self.inner.read(&mut self.buffer[read..])?;
            if count == 0 {
                break;
            }
            read += count;
        }
        if read == 0 {
            return Ok(false);
        }
        if !read.is_multiple_of(16) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "truncated RAR 5 encrypted stream",
            ));
        }
        self.cipher
            .decrypt_in_place(&mut self.buffer[..read])
            .map_err(super::map_rar50_crypto_error)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
        self.pos = 0;
        self.len = read;
        Ok(true)
    }
}

impl<R: Read> Read for Rar50DecryptingReader<R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.pos == self.len && !self.fill_buffer()? {
            return Ok(0);
        }
        let count = out.len().min(self.len - self.pos);
        out[..count].copy_from_slice(&self.buffer[self.pos..self.pos + count]);
        self.pos += count;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        ArchiveSource, Block, BlockHeader, FileEncryption, FileHash, HEAD_FILE, HFL_SPLIT_AFTER,
        HFL_SPLIT_BEFORE, MainHeader,
    };
    use super::*;

    use std::io::Cursor;

    use std::sync::Arc;

    fn plain_file(name: &[u8], data: &[u8], hash: Option<FileHash>) -> FileHeader {
        FileHeader {
            block: empty_block(HEAD_FILE, 0, 0..0),
            file_flags: 0,
            unpacked_size: data.len() as u64,
            attributes: 0x20,
            mtime: None,
            data_crc32: None,
            compression_info: 0,
            host_os: 2,
            name: name.to_vec(),
            hash,
            redirection: None,
            service_data: None,
            encrypted: false,
            encryption: None,
            crypto: None,
        }
    }

    #[test]
    fn streaming_crc32_zero_advance_matches_byte_update() {
        let mut bytewise = Crc32::new();
        bytewise.update(&vec![0; 100_000]);

        let mut skipped = Crc32::new();
        skipped.update_zeroes(100_000);

        assert_eq!(skipped.finish(), bytewise.finish());
    }

    #[test]
    fn repeated_chunk_does_not_advance_crc_after_sink_error() {
        struct FailingWriter;

        impl Write for FailingWriter {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("sink failed"))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut writer = FailingWriter;
        let mut crc = Crc32::new();
        let expected = Crc32::new().finish();

        assert!(write_repeated_chunk(&mut writer, &mut crc, &mut None, 0, 1024).is_err());
        assert_eq!(crc.finish(), expected);
    }

    #[test]
    fn encrypted_stored_decode_rejects_nonzero_discarded_padding() {
        let mut file = plain_file(b"secret.txt", b"secret", None);
        file.encrypted = true;
        file.unpacked_size = 6;
        let mut decoder = Unpack50Decoder::new();

        assert_eq!(
            file.decode_packed_with_decoder_mode(b"secret\0\0", &mut decoder, DecodeMode::Lz)
                .unwrap(),
            b"secret"
        );
        assert!(matches!(
            file.decode_packed_with_decoder_mode(b"secret\0\x01", &mut decoder, DecodeMode::Lz),
            Err(Error::InvalidHeader(
                "RAR 5 encrypted stored file has non-zero padding"
            ))
        ));
    }

    #[test]
    fn checked_unpacked_size_rejects_values_above_host_usize() {
        assert_eq!(checked_unpacked_size(123).unwrap(), 123usize);

        let overflowing = usize::MAX as u128 + 1;
        if overflowing <= u64::MAX as u128 {
            assert!(checked_unpacked_size(overflowing as u64).is_err());
        }
    }

    #[test]
    fn constant_time_hash_comparison_keeps_hash_validation_behaviour() {
        let data = b"hash me";
        let file = FileHeader {
            block: empty_block(HEAD_FILE, 0, 0..0),
            file_flags: 0,
            unpacked_size: data.len() as u64,
            attributes: 0x20,
            mtime: None,
            data_crc32: None,
            compression_info: 0,
            host_os: 2,
            name: b"hash.txt".to_vec(),
            hash: Some(FileHash {
                hash_type: 0,
                data: blake2sp::hash(data).to_vec(),
            }),
            redirection: None,
            service_data: None,
            encrypted: false,
            encryption: None,
            crypto: None,
        };

        file.verify_integrity_with_keys(data, None).unwrap();

        let mut wrong = file;
        wrong.hash.as_mut().unwrap().data[31] ^= 0x01;
        assert!(matches!(
            wrong.verify_integrity_with_keys(data, None),
            Err(Error::HashMismatch { hash_type: 0 })
        ));
    }

    #[test]
    fn verify_integrity_rejects_bad_blake2sp_length_and_ignores_unknown_hash_type() {
        let data = b"hash me";
        let mut bad_length = plain_file(
            b"a.txt",
            data,
            Some(FileHash {
                hash_type: 0,
                data: vec![0u8; 16],
            }),
        );
        assert!(matches!(
            bad_length.verify_integrity_with_keys(data, None),
            Err(Error::InvalidHeader(_))
        ));

        bad_length.hash.as_mut().unwrap().hash_type = 99;
        bad_length.hash.as_mut().unwrap().data = vec![0u8; 32];
        bad_length.verify_integrity_with_keys(data, None).unwrap();
    }

    #[test]
    fn streaming_hash_verifier_rejects_bad_blake2sp_length_and_ignores_unknown_hash_type() {
        let mut file = plain_file(
            b"a.txt",
            b"",
            Some(FileHash {
                hash_type: 0,
                data: vec![0u8; 16],
            }),
        );
        assert!(matches!(
            streaming_hash_verifier(&file),
            Err(Error::InvalidHeader(_))
        ));

        file.hash.as_mut().unwrap().hash_type = 7;
        file.hash.as_mut().unwrap().data = vec![0u8; 32];
        assert!(matches!(streaming_hash_verifier(&file), Ok(None)));

        let nohash = plain_file(b"a.txt", b"", None);
        assert!(matches!(streaming_hash_verifier(&nohash), Ok(None)));
    }

    #[test]
    fn crypto_with_password_short_circuits_for_unencrypted_or_unsupported_versions() {
        let cache = Rar50KeyCache::default();
        let plain = plain_file(b"a.txt", b"", None);
        assert!(plain.crypto_with_password(&cache, None).unwrap().is_none());
        assert!(
            plain
                .crypto_with_password(&cache, Some(b"pw"))
                .unwrap()
                .is_none()
        );

        let mut missing = plain_file(b"a.txt", b"", None);
        missing.encrypted = true;
        assert!(matches!(
            missing.crypto_with_password(&cache, None),
            Err(Error::NeedPassword)
        ));
        assert!(matches!(
            missing.crypto_with_password(&cache, Some(b"pw")),
            Err(Error::InvalidHeader(_))
        ));

        let mut bad_version = plain_file(b"a.txt", b"", None);
        bad_version.encrypted = true;
        bad_version.encryption = Some(FileEncryption {
            version: 1,
            flags: 0,
            kdf_count: 0,
            salt: [0u8; 16],
            iv: [0u8; 16],
            check_value: None,
        });
        assert!(matches!(
            bad_version.crypto_with_password(&cache, Some(b"pw")),
            Err(Error::UnsupportedFeature { .. })
        ));
    }

    #[test]
    fn crypto_with_password_handles_missing_check_value() {
        let mut file = plain_file(b"a.txt", b"", None);
        file.encrypted = true;
        file.encryption = Some(FileEncryption {
            version: 0,
            flags: 0,
            kdf_count: 0,
            salt: [0u8; 16],
            iv: [0u8; 16],
            check_value: None,
        });
        let cache = Rar50KeyCache::default();
        assert!(
            file.crypto_with_password(&cache, Some(b"pw"))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn decode_packed_rejects_stored_size_mismatch() {
        let mut decoder = Unpack50Decoder::new();

        let mut file = plain_file(b"a.txt", &[0u8; 32], None);
        file.unpacked_size = 32;
        let short = vec![0u8; 16];
        assert!(matches!(
            file.decode_packed_with_decoder_mode(&short, &mut decoder, DecodeMode::Lz),
            Err(Error::InvalidHeader(_))
        ));

        let mut encrypted = plain_file(b"b.txt", &[0u8; 32], None);
        encrypted.encrypted = true;
        encrypted.unpacked_size = 32;
        let too_short = vec![0u8; 16];
        assert!(matches!(
            encrypted.decode_packed_with_decoder_mode(&too_short, &mut decoder, DecodeMode::Lz),
            Err(Error::InvalidHeader(_))
        ));

        let exact = vec![0u8; 64];
        let trimmed = encrypted
            .decode_packed_with_decoder_mode(&exact, &mut decoder, DecodeMode::Lz)
            .unwrap();
        assert_eq!(trimmed.len(), encrypted.unpacked_size as usize);
    }

    #[test]
    fn verify_streaming_integrity_validates_crc_and_hash() {
        let payload = b"streaming";
        let crc_value = crc32(payload);
        let hash_value = blake2sp::hash(payload);

        let mut file = plain_file(b"s.txt", payload, None);
        file.data_crc32 = Some(crc_value);
        file.hash = Some(FileHash {
            hash_type: 0,
            data: hash_value.to_vec(),
        });

        let make_state = || {
            let mut crc = Crc32::new();
            crc.update(payload);
            let mut hasher = blake2sp::Hasher::new();
            hasher.update(payload);
            (crc, Some((hash_value, hasher)))
        };

        let (crc, hash) = make_state();
        file.verify_streaming_integrity(crc, hash, None).unwrap();

        let (crc, hash) = make_state();
        let mut bad = file.clone();
        bad.data_crc32 = Some(crc_value ^ 0x1);
        assert!(matches!(
            bad.verify_streaming_integrity(crc, hash, None),
            Err(Error::Crc32Mismatch { .. })
        ));

        let (crc, _) = make_state();
        let mut wrong_expected = hash_value;
        wrong_expected[0] ^= 0xff;
        let mut hasher = blake2sp::Hasher::new();
        hasher.update(payload);
        let mut bad_hash = file.clone();
        bad_hash.data_crc32 = None;
        assert!(matches!(
            bad_hash.verify_streaming_integrity(crc, Some((wrong_expected, hasher)), None),
            Err(Error::HashMismatch { hash_type: 0 })
        ));

        let empty = plain_file(b"e.txt", b"", None);
        empty
            .verify_streaming_integrity(Crc32::new(), None, None)
            .unwrap();
    }

    #[test]
    fn write_repeated_chunk_updates_crc_hash_and_writer() {
        let mut writer = Vec::new();
        let mut crc_zero = Crc32::new();
        let mut hash = Some(([0u8; 32], blake2sp::Hasher::new()));
        write_repeated_chunk(&mut writer, &mut crc_zero, &mut hash, 0, 70_000).unwrap();
        assert_eq!(writer.len(), 70_000);
        let zero_crc = crc_zero.finish();

        let mut bytewise = Crc32::new();
        bytewise.update(&vec![0u8; 70_000]);
        assert_eq!(zero_crc, bytewise.finish());

        let mut writer = Vec::new();
        let mut crc_ff = Crc32::new();
        let mut hash_none: Option<([u8; 32], blake2sp::Hasher)> = None;
        write_repeated_chunk(&mut writer, &mut crc_ff, &mut hash_none, 0xff, 1024).unwrap();
        assert_eq!(writer, vec![0xffu8; 1024]);
    }

    #[test]
    fn map_rar50_crypto_error_translates_kdf_count() {
        assert!(matches!(
            super::super::map_rar50_crypto_error(
                crate::vendor::rars::crypto::rar50::Error::KdfCountTooLarge
            ),
            Error::UnsupportedFeature { .. }
        ));
        assert!(matches!(
            super::super::map_rar50_crypto_error(
                crate::vendor::rars::crypto::rar50::Error::BadPassword
            ),
            Error::WrongPasswordOrCorruptData
        ));
    }

    #[test]
    fn constant_time_eq_returns_false_for_length_mismatch() {
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
    }

    fn empty_block(
        header_type: u64,
        flags: u64,
        data_range: std::ops::Range<usize>,
    ) -> BlockHeader {
        BlockHeader {
            header_crc: 0,
            header_size: 0,
            header_type,
            flags,
            extra_area_size: None,
            data_size: Some(data_range.len() as u64),
            offset: 0,
            header_range: 0..0,
            data_range,
        }
    }

    fn split_fragment_file(name: &[u8], hfl_flags: u64) -> FileHeader {
        FileHeader {
            block: empty_block(HEAD_FILE, hfl_flags, 0..0),
            file_flags: 0,
            unpacked_size: 0,
            attributes: 0x20,
            mtime: None,
            data_crc32: None,
            compression_info: 0,
            host_os: 2,
            name: name.to_vec(),
            hash: None,
            redirection: None,
            service_data: None,
            encrypted: false,
            encryption: None,
            crypto: None,
        }
    }

    fn archive_with_blocks(blocks: Vec<Block>, source: Vec<u8>) -> Archive {
        let bytes: Arc<[u8]> = Arc::from(source.into_boxed_slice());
        Archive {
            sfx_offset: 0,
            main: MainHeader {
                block: empty_block(1, 0, 0..0),
                archive_flags: 0,
                volume_number: None,
                extras: Vec::new(),
            },
            blocks,
            source: ArchiveSource::Memory(bytes),
            key_cache: Rar50KeyCache::default(),
        }
    }

    fn never_open(_meta: &ExtractedEntryMeta) -> Result<Box<dyn Write>> {
        panic!("open should not be invoked for this test");
    }

    #[test]
    fn validate_split_fragment_rejects_directories_and_demands_password_for_encrypted() {
        let mut dir = split_fragment_file(b"d", HFL_SPLIT_AFTER);
        dir.file_flags = 0x0001;
        assert!(matches!(
            validate_split_fragment(&dir, None),
            Err(Error::InvalidHeader(_))
        ));

        let mut encrypted = split_fragment_file(b"a.txt", HFL_SPLIT_AFTER);
        encrypted.encrypted = true;
        assert!(matches!(
            validate_split_fragment(&encrypted, None),
            Err(Error::NeedPassword)
        ));
        validate_split_fragment(&encrypted, Some(b"pw")).unwrap();

        let plain = split_fragment_file(b"a.txt", HFL_SPLIT_AFTER);
        validate_split_fragment(&plain, None).unwrap();
    }

    #[test]
    fn validate_split_continuation_refs_rejects_property_drift_between_fragments() {
        let first = split_fragment_file(b"a.txt", HFL_SPLIT_AFTER);
        let pending = PendingSplitRefs::new(&first, 0, 0);

        let renamed = split_fragment_file(b"b.txt", HFL_SPLIT_BEFORE);
        assert!(matches!(
            validate_split_continuation_refs(&pending, &renamed, None),
            Err(Error::InvalidHeader(_))
        ));

        let mut new_compression = split_fragment_file(b"a.txt", HFL_SPLIT_BEFORE);
        new_compression.compression_info = 0x123;
        assert!(matches!(
            validate_split_continuation_refs(&pending, &new_compression, None),
            Err(Error::InvalidHeader(_))
        ));

        let mut new_encryption = split_fragment_file(b"a.txt", HFL_SPLIT_BEFORE);
        new_encryption.encrypted = true;
        assert!(matches!(
            validate_split_continuation_refs(&pending, &new_encryption, Some(b"pw")),
            Err(Error::InvalidHeader(_))
        ));

        let same = split_fragment_file(b"a.txt", HFL_SPLIT_BEFORE);
        validate_split_continuation_refs(&pending, &same, None).unwrap();
    }

    #[test]
    fn extract_volumes_to_with_redirections_reports_redirection_entries() {
        let mut redirect = plain_file(b"link", b"", None);
        redirect.redirection = Some(super::super::FileRedirection {
            redirection_type: 5,
            flags: 0,
            target_name: b"target".to_vec(),
        });
        let volumes = vec![archive_with_blocks(vec![Block::File(redirect)], Vec::new())];
        let mut seen = Vec::new();
        extract_volumes_to_with_redirections(
            &volumes,
            crate::vendor::rars::ArchiveReadOptions::default(),
            never_open,
            |meta, redirection| {
                seen.push((meta.name.clone(), redirection.target_name.clone()));
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(seen, vec![(b"link".to_vec(), b"target".to_vec())]);
    }

    #[test]
    fn stream_packed_with_decoder_rejects_stored_files() {
        let file = plain_file(b"stored.txt", b"hello", None);
        assert!(file.is_stored());
        let mut decoder = Unpack50Decoder::new();
        let mut out: Vec<u8> = Vec::new();
        let err = file
            .stream_packed_with_decoder(
                &mut Cursor::new(Vec::<u8>::new()),
                None,
                &mut decoder,
                &mut out,
            )
            .unwrap_err();
        assert!(
            matches!(err, Error::InvalidHeader(msg) if msg.contains("does not use streaming")),
            "expected streaming-rejection error, got {err:?}"
        );
    }

    #[test]
    fn pending_split_refs_write_stored_to_rejects_unpacked_size_mismatch() {
        let payload: &[u8] = b"unmatched-size payload";
        let mut first = split_fragment_file(b"a.txt", HFL_SPLIT_AFTER);
        first.block.data_range = 0..payload.len();
        first.block.data_size = Some(payload.len() as u64);
        first.unpacked_size = (payload.len() + 5) as u64; // mismatch
        let final_file = first.clone();
        let pending = PendingSplitRefs::new(&first, 0, 0);
        let volumes = vec![archive_with_blocks(
            vec![Block::File(first)],
            payload.to_vec(),
        )];

        let mut out: Vec<u8> = Vec::new();
        let err = pending
            .write_stored_to(&volumes, &final_file, None, &mut out)
            .unwrap_err();
        assert!(
            matches!(err, Error::InvalidHeader(msg) if msg.contains("mismatched packed and unpacked")),
            "expected size mismatch error, got {err:?}"
        );
    }

    #[test]
    fn pending_split_refs_write_stored_to_rejects_crc_mismatch_on_unencrypted() {
        let payload: &[u8] = b"crc-mismatch payload";
        let mut first = split_fragment_file(b"a.txt", HFL_SPLIT_AFTER);
        first.block.data_range = 0..payload.len();
        first.block.data_size = Some(payload.len() as u64);
        first.unpacked_size = payload.len() as u64;
        first.data_crc32 = Some(crc32(payload).wrapping_add(1));
        let final_file = first.clone();
        let pending = PendingSplitRefs::new(&first, 0, 0);
        let volumes = vec![archive_with_blocks(
            vec![Block::File(first)],
            payload.to_vec(),
        )];

        let mut out: Vec<u8> = Vec::new();
        let err = pending
            .write_stored_to(&volumes, &final_file, None, &mut out)
            .unwrap_err();
        assert!(
            matches!(err, Error::Crc32Mismatch { .. }),
            "expected CRC mismatch, got {err:?}"
        );
    }

    #[test]
    fn pending_split_refs_write_stored_to_rejects_hash_mismatch_on_unencrypted() {
        let payload: &[u8] = b"hash-mismatch payload";
        let mut wrong_hash = blake2sp::hash(payload);
        wrong_hash[0] ^= 0xff;

        let mut first = split_fragment_file(b"a.txt", HFL_SPLIT_AFTER);
        first.block.data_range = 0..payload.len();
        first.block.data_size = Some(payload.len() as u64);
        first.unpacked_size = payload.len() as u64;
        first.data_crc32 = Some(crc32(payload));
        first.hash = Some(FileHash {
            hash_type: 0,
            data: wrong_hash.to_vec(),
        });
        let final_file = first.clone();
        let pending = PendingSplitRefs::new(&first, 0, 0);
        let volumes = vec![archive_with_blocks(
            vec![Block::File(first)],
            payload.to_vec(),
        )];

        let mut out: Vec<u8> = Vec::new();
        let err = pending
            .write_stored_to(&volumes, &final_file, None, &mut out)
            .unwrap_err();
        assert!(
            matches!(err, Error::HashMismatch { hash_type: 0 }),
            "expected hash mismatch, got {err:?}"
        );
    }

    #[test]
    fn decoded_data_with_mode_dispatches_through_decode_packed_for_stored_files() {
        let payload = b"decoded_data_with_mode stored payload";
        let mut file = plain_file(b"a.txt", payload, None);
        file.block.data_range = 0..payload.len();
        file.block.data_size = Some(payload.len() as u64);
        file.unpacked_size = payload.len() as u64;

        let archive = archive_with_blocks(vec![Block::File(file.clone())], payload.to_vec());
        let mut decoder = Unpack50Decoder::new();
        let decoded = file
            .decoded_data_with_mode(&archive, &mut decoder, None, DecodeMode::Lz)
            .unwrap();
        assert_eq!(decoded.data, payload);
        assert!(decoded.keys.is_none());

        // LzNoFilters dispatches through the same stored short-circuit.
        let mut decoder = Unpack50Decoder::new();
        let decoded = file
            .decoded_data_with_mode(&archive, &mut decoder, None, DecodeMode::LzNoFilters)
            .unwrap();
        assert_eq!(decoded.data, payload);
    }

    #[test]
    fn map_truncated_unverified_payload_swallows_need_more_input_when_no_integrity_record() {
        let mut file = plain_file(b"a.txt", b"", None);
        file.data_crc32 = None;
        file.hash = None;
        assert!(
            file.map_truncated_unverified_payload(crate::vendor::rars::codec::Error::NeedMoreInput)
                .unwrap()
                .is_empty()
        );

        file.data_crc32 = Some(0);
        assert!(
            file.map_truncated_unverified_payload(crate::vendor::rars::codec::Error::NeedMoreInput)
                .is_err()
        );
    }

    #[test]
    fn encryption_iv_falls_back_to_encryption_record_and_errors_when_missing() {
        let mut with_record = plain_file(b"a.txt", b"", None);
        with_record.encrypted = true;
        with_record.encryption = Some(FileEncryption {
            version: 0,
            flags: 0,
            kdf_count: 0,
            salt: [0u8; 16],
            iv: [5u8; 16],
            check_value: None,
        });
        assert_eq!(with_record.encryption_iv().unwrap(), [5u8; 16]);

        let missing = plain_file(b"a.txt", b"", None);
        assert!(matches!(
            missing.encryption_iv(),
            Err(Error::InvalidHeader(_))
        ));
    }
}
