use std::collections::BTreeMap;

use anyhow::{anyhow, Context, Result};
use bluer::{gatt::remote::Characteristic, Device};
use futures::StreamExt;
use uuid::Uuid;

pub const HUAWEI_SERVICE_UUID: Uuid = Uuid::from_u128(0x0000FE8600001000800000805F9B34FB);
pub const HUAWEI_WRITE_UUID: Uuid = Uuid::from_u128(0x0000FE0100001000800000805F9B34FB);
pub const HUAWEI_NOTIFY_UUID: Uuid = Uuid::from_u128(0x0000FE0200001000800000805F9B34FB);

#[derive(Clone)]
pub struct HuaweiGatt {
    pub write: Characteristic,
    pub notify: Characteristic,
}

impl HuaweiGatt {
    pub async fn discover(device: &Device) -> Result<Self> {
        let mut chars = BTreeMap::new();
        let mut services = device.services().await.context("enumerate services")?;
        while let Some(service) = services.next().await {
            let service = service.context("read service")?;
            if service.uuid().await.context("read service uuid")? != HUAWEI_SERVICE_UUID {
                continue;
            }
            let mut characteristics = service
                .characteristics()
                .await
                .context("enumerate characteristics")?;
            while let Some(ch) = characteristics.next().await {
                let ch = ch.context("read characteristic")?;
                chars.insert(ch.uuid().await.context("read characteristic uuid")?, ch);
            }
        }

        let write = chars
            .remove(&HUAWEI_WRITE_UUID)
            .ok_or_else(|| anyhow!("Huawei FE01 write characteristic not found"))?;
        let notify = chars
            .remove(&HUAWEI_NOTIFY_UUID)
            .ok_or_else(|| anyhow!("Huawei FE02 notify characteristic not found"))?;
        Ok(Self { write, notify })
    }
}
