use bytes::{BufMut, BytesMut};
use crc::{Crc, CRC_16_IBM_SDLC};
use thiserror::Error;

const CRC16: Crc<u16> = Crc::<u16>::new(&CRC_16_IBM_SDLC);
const MAGIC: u8 = 0x5a;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportFrame {
    pub service_id: u8,
    pub command_id: u8,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SliceState {
    Unsliced,
    First(u8),
    Middle(u8),
    Last(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedSlice {
    pub state: SliceState,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("bad magic")]
    BadMagic,
    #[error("bad crc")]
    BadCrc,
    #[error("frame too short")]
    Truncated,
    #[error("slice missing header")]
    MissingSliceHeader,
}

#[derive(Debug, Default)]
pub struct SliceReassembler {
    current: Option<(u8, u8, Vec<u8>, u8)>,
}

impl SliceReassembler {
    pub fn push(&mut self, slice: EncodedSlice) -> Result<Option<TransportFrame>, FrameError> {
        match slice.state {
            SliceState::Unsliced => decode_slice(&slice.bytes).map(Some),
            SliceState::First(index) => {
                let frame = decode_slice(&slice.bytes)?;
                self.current = Some((frame.service_id, frame.command_id, frame.payload, index));
                Ok(None)
            }
            SliceState::Middle(index) => {
                let (_, _, payload, expected) = self
                    .current
                    .as_mut()
                    .ok_or(FrameError::MissingSliceHeader)?;
                if index <= *expected {
                    return Err(FrameError::MissingSliceHeader);
                }
                *expected = index;
                payload.extend_from_slice(&decode_continuation(&slice.bytes)?);
                Ok(None)
            }
            SliceState::Last(index) => {
                let (service_id, command_id, mut payload, expected) =
                    self.current.take().ok_or(FrameError::MissingSliceHeader)?;
                if index <= expected {
                    return Err(FrameError::MissingSliceHeader);
                }
                payload.extend_from_slice(&decode_continuation(&slice.bytes)?);
                Ok(Some(TransportFrame {
                    service_id,
                    command_id,
                    payload,
                }))
            }
        }
    }
}

pub fn encode_frame(frame: &TransportFrame, slice_size: usize) -> Vec<EncodedSlice> {
    let mut full_payload = vec![frame.service_id, frame.command_id];
    full_payload.extend_from_slice(&frame.payload);

    if full_payload.len() + 6 <= slice_size {
        return vec![EncodedSlice {
            state: SliceState::Unsliced,
            bytes: encode_slice(0x00, 0, &full_payload),
        }];
    }

    let mut out = Vec::new();
    let max_chunk = slice_size.saturating_sub(7).max(1);
    let mut offset = 0;
    let mut index = 0u8;
    while offset < full_payload.len() {
        let end = (offset + max_chunk).min(full_payload.len());
        let chunk = &full_payload[offset..end];
        let (state, body) = if offset == 0 {
            (0x01, chunk.to_vec())
        } else if end == full_payload.len() {
            (0x03, chunk[0..].to_vec())
        } else {
            (0x02, chunk[0..].to_vec())
        };
        out.push(EncodedSlice {
            state: match state {
                0x01 => SliceState::First(index),
                0x02 => SliceState::Middle(index),
                _ => SliceState::Last(index),
            },
            bytes: encode_slice(state, index, &body),
        });
        offset = end;
        index = index.wrapping_add(1);
    }
    out
}

pub fn parse_stream(
    buf: &mut BytesMut,
    reassembler: &mut SliceReassembler,
) -> Result<Vec<TransportFrame>, FrameError> {
    let mut frames = Vec::new();
    loop {
        if buf.len() < 5 {
            break;
        }
        if buf[0] != MAGIC {
            return Err(FrameError::BadMagic);
        }
        let body_len = u16::from_be_bytes([buf[1], buf[2]]) as usize;
        let total_len = 3 + body_len + 2;
        if buf.len() < total_len {
            break;
        }
        let packet = buf.split_to(total_len).to_vec();
        let slice = inspect_slice(&packet)?;
        if let Some(frame) = reassembler.push(slice)? {
            frames.push(frame);
        }
    }
    Ok(frames)
}

fn inspect_slice(bytes: &[u8]) -> Result<EncodedSlice, FrameError> {
    if bytes.len() < 8 {
        return Err(FrameError::Truncated);
    }
    if bytes[0] != MAGIC {
        return Err(FrameError::BadMagic);
    }
    validate_crc(bytes)?;
    let state = bytes[3];
    let index = bytes[4];
    Ok(EncodedSlice {
        state: match state {
            0x00 => SliceState::Unsliced,
            0x01 => SliceState::First(index),
            0x02 => SliceState::Middle(index),
            0x03 => SliceState::Last(index),
            _ => return Err(FrameError::Truncated),
        },
        bytes: bytes.to_vec(),
    })
}

fn encode_slice(state: u8, index: u8, body: &[u8]) -> Vec<u8> {
    let mut out = BytesMut::with_capacity(body.len() + 7);
    out.put_u8(MAGIC);
    out.put_u16((body.len() + 2) as u16);
    out.put_u8(state);
    out.put_u8(index);
    out.extend_from_slice(body);
    let crc = CRC16.checksum(&out[3..]);
    out.put_u16(crc);
    out.to_vec()
}

fn decode_slice(bytes: &[u8]) -> Result<TransportFrame, FrameError> {
    if bytes.len() < 10 {
        return Err(FrameError::Truncated);
    }
    validate_crc(bytes)?;
    Ok(TransportFrame {
        service_id: bytes[5],
        command_id: bytes[6],
        payload: bytes[7..bytes.len() - 2].to_vec(),
    })
}

fn decode_continuation(bytes: &[u8]) -> Result<Vec<u8>, FrameError> {
    if bytes.len() < 8 {
        return Err(FrameError::Truncated);
    }
    validate_crc(bytes)?;
    Ok(bytes[5..bytes.len() - 2].to_vec())
}

fn validate_crc(bytes: &[u8]) -> Result<(), FrameError> {
    let crc = u16::from_be_bytes([bytes[bytes.len() - 2], bytes[bytes.len() - 1]]);
    let computed = CRC16.checksum(&bytes[3..bytes.len() - 2]);
    if crc == computed {
        Ok(())
    } else {
        Err(FrameError::BadCrc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_unsliced() {
        let frame = TransportFrame {
            service_id: 1,
            command_id: 8,
            payload: vec![1, 2, 3],
        };
        let slices = encode_frame(&frame, 64);
        let mut buf = BytesMut::new();
        let mut reassembler = SliceReassembler::default();
        for slice in slices {
            buf.extend_from_slice(&slice.bytes);
        }
        let decoded = parse_stream(&mut buf, &mut reassembler).unwrap();
        assert_eq!(decoded, vec![frame]);
    }
}
