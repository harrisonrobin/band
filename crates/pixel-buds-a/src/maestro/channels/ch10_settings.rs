#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SettingId {
    InEarDetect,
    UsageDiagnostics,
    AdaptiveSound,
    UnknownF7,
    FirmwareAutoUpdate,
    UnknownF10,
    TouchControls,
    UnknownF12,
    VolumeEq,
    BassEqLevel,
    Unknown(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingSnapshot {
    pub setting: SettingId,
    pub value: u8,
}

pub fn parse_snapshot(payload: &[u8]) -> Option<SettingSnapshot> {
    if payload.len() < 4 || payload[..2] != [0x1a, 0x02] {
        return None;
    }
    let setting = match payload[2] {
        0x08 => SettingId::InEarDetect,
        0x18 => SettingId::UsageDiagnostics,
        0x28 => SettingId::AdaptiveSound,
        0x38 => SettingId::UnknownF7,
        0x40 => SettingId::FirmwareAutoUpdate,
        0x50 => SettingId::UnknownF10,
        0x58 => SettingId::TouchControls,
        0x60 => SettingId::UnknownF12,
        0x68 => SettingId::VolumeEq,
        0x70 => SettingId::BassEqLevel,
        other => SettingId::Unknown(other),
    };
    Some(SettingSnapshot {
        setting,
        value: payload[3],
    })
}

pub fn build_toggle(setting: SettingId, value: u8) -> Vec<u8> {
    let tag = match setting {
        SettingId::InEarDetect => 0x08,
        SettingId::UsageDiagnostics => 0x18,
        SettingId::AdaptiveSound => 0x28,
        SettingId::UnknownF7 => 0x38,
        SettingId::FirmwareAutoUpdate => 0x40,
        SettingId::UnknownF10 => 0x50,
        SettingId::TouchControls => 0x58,
        SettingId::UnknownF12 => 0x60,
        SettingId::VolumeEq => 0x68,
        SettingId::BassEqLevel => 0x70,
        SettingId::Unknown(tag) => tag,
    };
    vec![0x1a, 0x02, tag, value]
}
