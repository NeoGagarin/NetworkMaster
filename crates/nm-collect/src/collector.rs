use crate::{CollectionPlan, NetFactory, TargetGate};
use async_trait::async_trait;
use nm_core::{Device, DeviceFamily, DeviceResult};
use nm_creds::CredArena;
use nm_store::AuditSink;
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

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
