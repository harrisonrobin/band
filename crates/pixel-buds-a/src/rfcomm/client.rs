use anyhow::{bail, Result};
use bluer::Device;

#[derive(Debug, Clone, Copy)]
pub struct RfcommDescriptor {
    pub server_channel: u8,
    pub dlci: u8,
}

impl RfcommDescriptor {
    pub fn from_server_channel(server_channel: u8) -> Self {
        Self {
            server_channel,
            dlci: server_channel.saturating_mul(2),
        }
    }
}

pub async fn discover_maestro_descriptor(_device: &Device) -> Result<RfcommDescriptor> {
    Ok(RfcommDescriptor::from_server_channel(13))
}

pub async fn connect_maestro(
    _device: &Device,
    descriptor: RfcommDescriptor,
) -> Result<RfcommDescriptor> {
    if descriptor.dlci == 0 {
        bail!("invalid maestro dlci")
    }
    Ok(descriptor)
}
