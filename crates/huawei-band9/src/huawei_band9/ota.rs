use anyhow::Result;

use crate::huawei_band9::session::HuaweiBand9Session;

impl HuaweiBand9Session {
    pub async fn prepare_ota_placeholder(&mut self) -> Result<()> {
        Ok(())
    }
}
