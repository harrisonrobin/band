use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoValue {
    Varint(u64),
    Bytes(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtoField {
    pub number: u32,
    pub value: ProtoValue,
}

#[derive(Debug, Error)]
pub enum ProtoError {
    #[error("truncated protobuf")]
    Truncated,
}

pub fn decode_fields(mut bytes: &[u8]) -> Result<Vec<ProtoField>, ProtoError> {
    let mut fields = Vec::new();
    while !bytes.is_empty() {
        let (key, key_len) = decode_varint(bytes)?;
        bytes = &bytes[key_len..];
        let field_number = (key >> 3) as u32;
        let wire_type = key & 0x07;
        match wire_type {
            0 => {
                let (value, len) = decode_varint(bytes)?;
                fields.push(ProtoField {
                    number: field_number,
                    value: ProtoValue::Varint(value),
                });
                bytes = &bytes[len..];
            }
            2 => {
                let (len, len_len) = decode_varint(bytes)?;
                bytes = &bytes[len_len..];
                if bytes.len() < len as usize {
                    return Err(ProtoError::Truncated);
                }
                fields.push(ProtoField {
                    number: field_number,
                    value: ProtoValue::Bytes(bytes[..len as usize].to_vec()),
                });
                bytes = &bytes[len as usize..];
            }
            _ => return Err(ProtoError::Truncated),
        }
    }
    Ok(fields)
}

pub fn decode_varint(bytes: &[u8]) -> Result<(u64, usize), ProtoError> {
    let mut value = 0u64;
    let mut shift = 0u32;
    for (idx, byte) in bytes.iter().enumerate() {
        value |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, idx + 1));
        }
        shift += 7;
    }
    Err(ProtoError::Truncated)
}
