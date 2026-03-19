#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EarState {
    #[default]
    BothOut,
    RightIn,
    LeftIn,
    BothIn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LidState {
    Closed,
    Open,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchEvent {
    Left,
    Right,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WearTouchEvent {
    Lid(LidState),
    Ear(EarState),
    Touch(TouchEvent),
    GestureComplete(u8),
    PrimaryBud(bool),
}

pub fn parse_wear_touch(payload: &[u8]) -> Vec<WearTouchEvent> {
    if payload.len() < 2 || payload[0] != 0x0a {
        return Vec::new();
    }
    let inner_len = payload[1] as usize;
    if payload.len() < 2 + inner_len {
        return Vec::new();
    }
    let inner = &payload[2..2 + inner_len];
    let mut events = Vec::new();
    let mut i = 0usize;
    while i < inner.len() {
        match inner[i] {
            0x01 if i + 1 < inner.len() => {
                events.push(WearTouchEvent::Lid(if inner[i + 1] == 0 {
                    LidState::Closed
                } else {
                    LidState::Open
                }));
                i += 2;
            }
            0x03 if i + 1 < inner.len() => {
                let state = match inner[i + 1] {
                    1 => EarState::RightIn,
                    2 => EarState::LeftIn,
                    3 => EarState::BothIn,
                    _ => EarState::BothOut,
                };
                events.push(WearTouchEvent::Ear(state));
                i += 2;
            }
            0x04 if i + 1 < inner.len() => {
                events.push(WearTouchEvent::PrimaryBud(inner[i + 1] != 0));
                i += 2;
            }
            0x05 => {
                events.push(WearTouchEvent::Touch(TouchEvent::Left));
                i += 1;
            }
            0x06 => {
                events.push(WearTouchEvent::Touch(TouchEvent::Right));
                i += 1;
            }
            0x0b if i + 1 < inner.len() => {
                events.push(WearTouchEvent::GestureComplete(inner[i + 1]));
                i += 2;
            }
            0x1f => {
                events.push(WearTouchEvent::GestureComplete(0x1f));
                i += 1;
            }
            _ => i += 1,
        }
    }
    events
}
