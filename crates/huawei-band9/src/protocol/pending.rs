use std::{collections::HashMap, sync::Arc};

use anyhow::{anyhow, Result};
use tokio::sync::{oneshot, Mutex};

use crate::protocol::frame::TransportFrame;

type Key = (u8, u8);

#[derive(Clone, Default)]
pub struct PendingRequests {
    inner: Arc<Mutex<HashMap<Key, oneshot::Sender<TransportFrame>>>>,
}

impl PendingRequests {
    pub async fn register(
        &self,
        service_id: u8,
        command_id: u8,
    ) -> oneshot::Receiver<TransportFrame> {
        let (tx, rx) = oneshot::channel();
        self.inner.lock().await.insert((service_id, command_id), tx);
        rx
    }

    pub async fn resolve(&self, frame: TransportFrame) -> Result<bool> {
        if let Some(tx) = self
            .inner
            .lock()
            .await
            .remove(&(frame.service_id, frame.command_id))
        {
            tx.send(frame)
                .map_err(|_| anyhow!("pending request dropped"))?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
