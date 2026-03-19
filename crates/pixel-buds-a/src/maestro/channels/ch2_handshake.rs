use crate::maestro::protobuf::{decode_fields, ProtoValue};

#[derive(Debug, Clone, Default)]
pub struct HandshakeState {
    pub model: Option<String>,
    pub sample_rate_hz: Option<u32>,
    pub bit_depth: Option<u32>,
    pub capability_bitmap: Option<Vec<u8>>,
}

pub fn build_init_payload(timestamp_ms: u64, tz_offset_minutes: i64) -> Vec<u8> {
    let mut payload = Vec::new();
    encode_varint_field(&mut payload, 1, 6);
    encode_varint_field(&mut payload, 2, timestamp_ms);
    encode_varint_field(&mut payload, 3, tz_offset_minutes as u64);
    encode_varint_field(&mut payload, 14, 2);
    payload
}

pub fn parse_ack_payload(payload: &[u8], state: &mut HandshakeState) {
    if payload.len() == 6 {
        state.capability_bitmap = Some(payload.to_vec());
        return;
    }
    if let Ok(fields) = decode_fields(payload) {
        for field in fields {
            match (field.number, field.value) {
                (1, ProtoValue::Bytes(bytes)) => {
                    state.model = Some(String::from_utf8_lossy(&bytes).to_string())
                }
                (4, ProtoValue::Varint(value)) => state.sample_rate_hz = Some(value as u32),
                (7, ProtoValue::Varint(value)) => state.bit_depth = Some(value as u32),
                _ => {}
            }
        }
    }
}

fn encode_varint_field(out: &mut Vec<u8>, field_number: u32, value: u64) {
    encode_varint(out, ((field_number as u64) << 3) | 0);
    encode_varint(out, value);
}

fn encode_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}
