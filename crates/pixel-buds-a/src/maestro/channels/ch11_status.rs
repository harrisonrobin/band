use crate::maestro::protobuf::{decode_fields, ProtoValue};

#[derive(Debug, Clone, Default)]
pub struct DeviceStatus {
    pub seq_num: Option<u64>,
    pub audio_mode: Option<u64>,
    pub wear_state: Option<u64>,
    pub conn_mask: Option<u64>,
    pub tick_us: Option<u64>,
}

pub fn parse_status(payload: &[u8]) -> Option<DeviceStatus> {
    let mut status = DeviceStatus::default();
    let fields = decode_fields(payload).ok()?;
    for field in fields {
        match (field.number, field.value) {
            (2, ProtoValue::Varint(value)) => status.seq_num = Some(value),
            (5, ProtoValue::Varint(value)) => status.audio_mode = Some(value),
            (6, ProtoValue::Varint(value)) => status.wear_state = Some(value),
            (11, ProtoValue::Varint(value)) => status.conn_mask = Some(value),
            (12, ProtoValue::Varint(value)) => status.tick_us = Some(value),
            _ => {}
        }
    }
    Some(status)
}
