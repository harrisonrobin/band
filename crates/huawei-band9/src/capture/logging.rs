use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct FrameLog {
    pub timestamp_ms: u128,
    pub direction: &'static str,
    pub characteristic: &'static str,
    pub raw: Vec<u8>,
    pub detail: String,
}

impl FrameLog {
    pub fn new(
        direction: &'static str,
        characteristic: &'static str,
        raw: Vec<u8>,
        detail: impl Into<String>,
    ) -> Self {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        Self {
            timestamp_ms,
            direction,
            characteristic,
            raw,
            detail: detail.into(),
        }
    }
}
