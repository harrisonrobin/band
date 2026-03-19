use anyhow::{Context, Result};
use bluer::{Adapter, Address, Device, Session};

#[derive(Clone)]
pub struct HuaweiBleAdapter {
    session: Session,
    adapter: Adapter,
}

impl HuaweiBleAdapter {
    pub async fn new(adapter_name: Option<&str>) -> Result<Self> {
        let session = Session::new().await.context("create BlueZ session")?;
        let adapter = if let Some(name) = adapter_name {
            session.adapter(name).context("open named adapter")?
        } else {
            session
                .default_adapter()
                .await
                .context("open default adapter")?
        };

        adapter.set_powered(true).await.context("power adapter")?;
        Ok(Self { session, adapter })
    }

    pub fn adapter(&self) -> &Adapter {
        &self.adapter
    }

    pub fn session(&self) -> &Session {
        &self.session
    }

    pub async fn device(&self, address: Address) -> Result<Device> {
        self.adapter.device(address).context("lookup BlueZ device")
    }
}
