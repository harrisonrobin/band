#[derive(Debug, Clone)]
pub struct KeepaliveState {
    next_seq: u8,
}

impl Default for KeepaliveState {
    fn default() -> Self {
        Self { next_seq: 0 }
    }
}

impl KeepaliveState {
    pub fn next_ping(&mut self) -> [u8; 2] {
        let payload = [0x38, self.next_seq];
        self.next_seq = self.next_seq.wrapping_add(1);
        payload
    }

    pub fn is_pong(payload: &[u8]) -> bool {
        payload.first().copied() == Some(0x01)
    }
}
