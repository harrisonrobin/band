use crate::maestro::protobuf::{decode_fields, ProtoValue};

use super::ch9_wear_touch::EarState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudSide {
    Left,
    Right,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatteryUpdate {
    pub bud_side: BudSide,
    pub bud_percent: u8,
    pub in_case: bool,
    pub case_percent: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GestureEvent {
    Tap,
    DoubleTap,
    TripleTap,
    LongPress,
    Unknown,
}

#[derive(Debug, Clone, Default)]
pub struct GestureClassifier {
    pub pending_proto_hint: Option<GestureEvent>,
}

impl GestureClassifier {
    pub fn note_ch3_payload(&mut self, payload: &[u8]) {
        if let Ok(fields) = decode_fields(payload) {
            for field in fields {
                if field.number == 1 {
                    if let ProtoValue::Varint(1) = field.value {
                        self.pending_proto_hint = Some(GestureEvent::LongPress);
                    }
                    if let ProtoValue::Varint(2) = field.value {
                        self.pending_proto_hint = Some(GestureEvent::Tap);
                    }
                }
            }
        }
    }

    pub fn classify_from_discriminator(&self, discrim: u8) -> GestureEvent {
        match discrim {
            0x14 => GestureEvent::Tap,
            0x16 => GestureEvent::DoubleTap,
            0x15 => GestureEvent::TripleTap,
            0x1f => GestureEvent::LongPress,
            _ => self.pending_proto_hint.unwrap_or(GestureEvent::Unknown),
        }
    }
}

pub fn parse_battery(payload: &[u8], last_ear_state: EarState) -> Option<BatteryUpdate> {
    if payload.len() != 3 || payload[0] != 0xe4 {
        return None;
    }
    let bud_side = match last_ear_state {
        EarState::LeftIn => BudSide::Left,
        EarState::RightIn => BudSide::Right,
        _ => BudSide::Unknown,
    };
    Some(BatteryUpdate {
        bud_side,
        bud_percent: payload[1] & 0x7f,
        in_case: payload[1] & 0x80 != 0,
        case_percent: (payload[2] != 0xff).then_some(payload[2]),
    })
}
