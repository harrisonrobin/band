use anyhow::Result;

use crate::huawei_band9::{
    capabilities::{ExpandCapabilities, SupportedCommands, SupportedServices},
    notifications::{BatteryStatus, ProductInfo},
    session::HuaweiBand9Session,
};

#[derive(Debug, Clone)]
pub struct BootstrapSnapshot {
    pub product_info: ProductInfo,
    pub battery: BatteryStatus,
    pub supported_services: SupportedServices,
    pub supported_commands: SupportedCommands,
    pub expand_capabilities: Option<ExpandCapabilities>,
}

impl HuaweiBand9Session {
    pub async fn bootstrap(&mut self) -> Result<BootstrapSnapshot> {
        let product_info = self.get_product_info().await?;
        self.sync_time().await?;
        let battery = self.get_battery().await?;
        let supported_services = self.get_supported_services().await?;
        let supported_commands = self.get_supported_commands(&supported_services).await?;
        let expand_capabilities = self.get_expand_capabilities(&supported_commands).await?;
        Ok(BootstrapSnapshot {
            product_info,
            battery,
            supported_services,
            supported_commands,
            expand_capabilities,
        })
    }
}
