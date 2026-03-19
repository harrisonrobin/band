use bytes::{BufMut, BytesMut};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Open = 0x01,
    OpenAck = 0x02,
    DataToBuds = 0x03,
    Close = 0x04,
    DataFromBuds = 0x05,
    Ping = 0x09,
    ResponseFromBuds = 0x0e,
    Unknown0x10 = 0x10,
    StateSnapshot = 0x87,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaestroFrame {
    pub frame_type: u8,
    pub channel: u8,
    pub flags: u8,
    pub payload: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("truncated maestro frame")]
    Truncated,
}

pub fn encode_frame(frame_type: u8, channel: u8, flags: u8, payload: &[u8]) -> Vec<u8> {
    if payload.len() == 1 {
        return vec![frame_type, channel, payload[0]];
    }
    let mut out = BytesMut::with_capacity(4 + payload.len());
    out.put_u8(frame_type);
    out.put_u8(channel);
    out.put_u8(flags);
    out.put_u8(payload.len() as u8);
    out.extend_from_slice(payload);
    out.to_vec()
}

pub fn parse_frame(buf: &[u8]) -> Option<(MaestroFrame, usize)> {
    if buf.len() < 3 {
        return None;
    }
    if buf.len() == 3 || (buf.len() > 3 && buf[2] != 0x00 && buf[3] > buf.len() as u8) {
        return Some((
            MaestroFrame {
                frame_type: buf[0],
                channel: buf[1],
                flags: 0,
                payload: vec![buf[2]],
            },
            3,
        ));
    }
    if buf.len() < 4 {
        return None;
    }
    let len = buf[3] as usize;
    if buf.len() < 4 + len {
        return None;
    }
    Some((
        MaestroFrame {
            frame_type: buf[0],
            channel: buf[1],
            flags: buf[2],
            payload: buf[4..4 + len].to_vec(),
        },
        4 + len,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_standard() {
        let bytes = encode_frame(0x03, 10, 0, &[1, 2, 3]);
        let (frame, consumed) = parse_frame(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(frame.payload, vec![1, 2, 3]);
    }
}
