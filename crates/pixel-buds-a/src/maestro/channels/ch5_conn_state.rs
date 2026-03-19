use crate::maestro::protobuf::{decode_fields, ProtoValue};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Idle,
    Connected,
    Reconnecting,
    Streaming,
    Unknown(u64),
}

pub fn parse_connection_state(payload: &[u8]) -> Option<ConnectionState> {
    let fields = decode_fields(payload).ok()?;
    for field in fields {
        if field.number == 1 {
            if let ProtoValue::Varint(value) = field.value {
                return Some(match value {
                    0 => ConnectionState::Idle,
                    1 => ConnectionState::Connected,
                    3 => ConnectionState::Reconnecting,
                    4 => ConnectionState::Streaming,
                    other => ConnectionState::Unknown(other),
                });
            }
        }
    }
    None
}
