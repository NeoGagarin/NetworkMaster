use crate::{CollectionPlan, NetFactory, TargetGate};
use async_trait::async_trait;
use nm_core::{Device, DeviceFamily, DeviceResult};
use nm_creds::CredArena;
use nm_store::AuditSink;
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
#[derive(Clone, Debug)]
pub struct CollectEvent {
    pub device: nm_core::DeviceId,
    pub state: String,
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub per_command_timeout: Duration,
    pub per_device_budget: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            per_command_timeout: Duration::from_secs(20),
            per_device_budget: Duration::from_secs(120),
        }
    }
}
pub struct CollectCtx {
    pub gate: Arc<TargetGate>,
    pub creds: Arc<CredArena>,
    pub audit: AuditSink,
    pub cancel: CancellationToken,
    pub net: Arc<dyn NetFactory>,
    pub limits: Limits,
    pub events: Option<tokio::sync::mpsc::Sender<CollectEvent>>,
    pub partial: Arc<std::sync::Mutex<std::collections::HashMap<nm_core::DeviceId, DeviceResult>>>,
}
impl CollectCtx {
    pub fn save_partial(&self, result: &DeviceResult) {
        if let Ok(mut partial) = self.partial.lock() {
            partial.insert(result.device_id, result.clone());
        }
    }
    pub async fn progress(&self, device: nm_core::DeviceId, state: String) {
        if let Some(events) = &self.events {
            let _ = events.send(CollectEvent { device, state }).await;
        }
    }
}
#[derive(Debug, thiserror::Error)]
pub enum CollectError {
    #[error("collection cancelled")]
    Cancelled,
    #[error("device unreachable: {0}")]
    Unreachable(String),
    #[error("authentication failed")]
    AuthFailed,
    #[error("parse: {0}")]
    Parse(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
#[async_trait]
pub trait Collector: Send + Sync {
    fn family(&self) -> DeviceFamily;
    fn plan(&self, device: &Device) -> CollectionPlan;
    async fn collect(
        &self,
        ctx: &CollectCtx,
        device: &Device,
    ) -> Result<DeviceResult, CollectError>;
}
