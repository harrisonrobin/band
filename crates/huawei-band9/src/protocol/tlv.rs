use std::collections::BTreeMap;

use bytes::{BufMut, BytesMut};
use thiserror::Error;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tlv {
    entries: BTreeMap<u8, Vec<Vec<u8>>>,
}

#[derive(Debug, Error)]
pub enum TlvError {
    #[error("truncated tlv")]
    Truncated,
}

impl Tlv {
    pub fn push_bytes(&mut self, tag: u8, value: impl Into<Vec<u8>>) {
        self.entries.entry(tag).or_default().push(value.into());
    }

    pub fn push_u8(&mut self, tag: u8, value: u8) {
        self.push_bytes(tag, vec![value]);
    }

    pub fn push_u16(&mut self, tag: u8, value: u16) {
        self.push_bytes(tag, value.to_be_bytes().to_vec());
    }

    pub fn push_u32(&mut self, tag: u8, value: u32) {
        self.push_bytes(tag, value.to_be_bytes().to_vec());
    }

    pub fn get_first(&self, tag: u8) -> Option<&[u8]> {
        self.entries
            .get(&tag)
            .and_then(|v| v.first())
            .map(Vec::as_slice)
    }

    pub fn get_u8(&self, tag: u8) -> Option<u8> {
        self.get_first(tag).and_then(|v| v.first().copied())
    }

    pub fn get_u16(&self, tag: u8) -> Option<u16> {
        let bytes = self.get_first(tag)?;
        (bytes.len() >= 2).then(|| u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    pub fn get_u32(&self, tag: u8) -> Option<u32> {
        let bytes = self.get_first(tag)?;
        (bytes.len() >= 4).then(|| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::new();
        for (tag, values) in &self.entries {
            for value in values {
                out.put_u8(*tag);
                out.put_u16(value.len() as u16);
                out.extend_from_slice(value);
            }
        }
        out.to_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TlvError> {
        let mut offset = 0usize;
        let mut tlv = Tlv::default();
        while offset < bytes.len() {
            if offset + 3 > bytes.len() {
                return Err(TlvError::Truncated);
            }
            let tag = bytes[offset];
            let len = u16::from_be_bytes([bytes[offset + 1], bytes[offset + 2]]) as usize;
            offset += 3;
            if offset + len > bytes.len() {
                return Err(TlvError::Truncated);
            }
            tlv.push_bytes(tag, bytes[offset..offset + len].to_vec());
            offset += len;
        }
        Ok(tlv)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let mut tlv = Tlv::default();
        tlv.push_u8(1, 2);
        tlv.push_u16(2, 3);
        let encoded = tlv.encode();
        let decoded = Tlv::decode(&encoded).unwrap();
        assert_eq!(decoded.get_u8(1), Some(2));
        assert_eq!(decoded.get_u16(2), Some(3));
    }
}
