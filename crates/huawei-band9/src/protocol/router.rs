use anyhow::Result;
use tokio::sync::broadcast;

use crate::protocol::{frame::TransportFrame, pending::PendingRequests};

#[derive(Clone)]
pub struct Router {
    pending: PendingRequests,
    async_tx: broadcast::Sender<TransportFrame>,
}

impl Router {
    pub fn new() -> Self {
        let (async_tx, _) = broadcast::channel(128);
        Self {
            pending: PendingRequests::default(),
            async_tx,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<TransportFrame> {
        self.async_tx.subscribe()
    }

    pub async fn register(
        &self,
        service_id: u8,
        command_id: u8,
    ) -> tokio::sync::oneshot::Receiver<TransportFrame> {
        self.pending.register(service_id, command_id).await
    }

    pub async fn route(&self, frame: TransportFrame) -> Result<()> {
        if !self.pending.resolve(frame.clone()).await? {
            let _ = self.async_tx.send(frame);
        }
        Ok(())
    }
}
