use anyhow::Result;

use crate::huawei_band9::session::HuaweiBand9Session;

impl HuaweiBand9Session {
    pub async fn sync_weather_placeholder(&mut self) -> Result<()> {
        Ok(())
    }
}
