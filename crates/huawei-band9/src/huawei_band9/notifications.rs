use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProductInfo {
    pub hardware_version: Option<String>,
    pub software_version: Option<String>,
    pub serial_number: Option<String>,
    pub product_model: Option<String>,
    pub package_name: Option<String>,
    pub device_name: Option<String>,
    pub region_code: Option<String>,
    pub ota_signature_length: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BatteryStatus {
    pub level: Option<u8>,
    pub component_levels: Vec<u8>,
    pub component_states: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeviceEvent {
    Battery(BatteryStatus),
    Product(ProductInfo),
    CapabilityBytes(Vec<u8>),
    Raw {
        service_id: u8,
        command_id: u8,
        payload: Vec<u8>,
    },
}
