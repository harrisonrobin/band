use anyhow::{Context, Result};
use bluer::{Address, Device};

use crate::ble::adapter::HuaweiBleAdapter;

pub async fn connect(adapter: &HuaweiBleAdapter, address: Address) -> Result<Device> {
    let device = adapter.device(address).await?;
    if !device
        .is_connected()
        .await
        .context("read connection state")?
    {
        device.connect().await.context("connect BLE device")?;
    }
    Ok(device)
}
