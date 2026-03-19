use bytes::BytesMut;

use crate::maestro::frame::{parse_frame, MaestroFrame};

#[derive(Default)]
pub struct Reassembler {
    buffer: BytesMut,
}

impl Reassembler {
    pub fn push(&mut self, bytes: &[u8]) -> Vec<MaestroFrame> {
        self.buffer.extend_from_slice(bytes);
        let mut frames = Vec::new();
        loop {
            match parse_frame(&self.buffer) {
                Some((frame, consumed)) => {
                    self.buffer.advance(consumed);
                    frames.push(frame);
                }
                None => break,
            }
        }
        frames
    }
}

trait Advance {
    fn advance(&mut self, cnt: usize);
}

impl Advance for BytesMut {
    fn advance(&mut self, cnt: usize) {
        let _ = self.split_to(cnt);
    }
}
