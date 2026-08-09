use super::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FilterOp {
    E8,
    E8E9,
    Delta { channels: usize },
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct DeltaErrorMessages {
    pub invalid_channels: &'static str,
    pub zero_channels: &'static str,
    pub truncated_source: &'static str,
}

pub(crate) fn decode_in_place(
    op: FilterOp,
    data: &mut Vec<u8>,
    file_offset: u32,
    messages: DeltaErrorMessages,
) -> Result<()> {
    match op {
        FilterOp::E8 => e8e9_decode(data, file_offset, false),
        FilterOp::E8E9 => e8e9_decode(data, file_offset, true),
        FilterOp::Delta { channels } => {
            *data = delta_decode(data, channels, messages)?;
        }
    }
    Ok(())
}

pub(crate) fn e8e9_decode(data: &mut [u8], file_offset: u32, include_e9: bool) {
    if data.len() <= 4 {
        return;
    }
    let cmp_mask = if include_e9 { 0xfe } else { 0xff };
    let opcode_limit = data.len() - 4;
    let mut opcode_pos = 0usize;
    while let Some(pos) = super::fast::next_x86_opcode(data, opcode_pos, opcode_limit, cmp_mask) {
        let cur_pos = pos + 1;
        let offset = file_offset.wrapping_add(cur_pos as u32);
        let addr = u32::from_le_bytes([
            data[cur_pos],
            data[cur_pos + 1],
            data[cur_pos + 2],
            data[cur_pos + 3],
        ]);
        let new_addr = if addr < 0x0100_0000 {
            Some(addr.wrapping_sub(offset))
        } else if addr & 0x8000_0000 != 0 && addr.wrapping_add(offset) & 0x8000_0000 == 0 {
            Some(addr.wrapping_add(0x0100_0000))
        } else {
            None
        };
        if let Some(value) = new_addr {
            data[cur_pos..cur_pos + 4].copy_from_slice(&value.to_le_bytes());
        }
        opcode_pos = pos + 5;
    }
}

pub(crate) fn delta_decode(
    data: &[u8],
    channels: usize,
    messages: DeltaErrorMessages,
) -> Result<Vec<u8>> {
    if channels == 0 {
        return Err(Error::InvalidData(messages.zero_channels));
    }
    if channels > 32 {
        return Err(Error::InvalidData(messages.invalid_channels));
    }
    let mut out = vec![0u8; data.len()];
    let mut src = 0usize;
    for channel in 0..channels {
        let mut prev = 0u8;
        let mut dest = channel;
        while dest < out.len() {
            let byte = *data
                .get(src)
                .ok_or(Error::InvalidData(messages.truncated_source))?;
            prev = prev.wrapping_sub(byte);
            out[dest] = prev;
            src += 1;
            dest += channels;
        }
    }
    Ok(out)
}

impl DeltaErrorMessages {
    #[cfg(test)]
    pub(crate) const fn generic() -> Self {
        Self {
            invalid_channels: "DELTA filter channel count is invalid",
            zero_channels: "DELTA filter has zero channels",
            truncated_source: "DELTA filter source is truncated",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delta_decode_rejects_channel_counts_above_writer_limit() {
        let mut filtered = vec![0; 64];

        assert_eq!(
            decode_in_place(
                FilterOp::Delta { channels: 33 },
                &mut filtered,
                0,
                DeltaErrorMessages::generic(),
            ),
            Err(Error::InvalidData("DELTA filter channel count is invalid"))
        );
    }
}
