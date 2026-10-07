use crate::{CollectionPlan, NetFactory, TargetGate};
use async_trait::async_trait;
use nm_core::{Device, DeviceFamily, DeviceResult};
use nm_creds::CredArena;
use nm_store::AuditSink;
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
/// Progress reported by a collector while it works on one device.
#[derive(Clone, Debug)]
pub enum CollectEvent {
    /// Free-text state for display, such as `running mca-status`.
    State {
        device: nm_core::DeviceId,
        state: String,
    },
    /// The device offers only deprecated SSH algorithms and needs explicit opt-in.
    LegacyRequired {
        device: nm_core::DeviceId,
        algorithms: Vec<String>,
    },
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// TCP connect, key exchange and authentication together.
    pub connect_timeout: Duration,
    /// One allowlisted command, from exec to channel close.
    pub per_command_timeout: Duration,
    /// Everything for one device, including connection.
    pub per_device_budget: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            // Group1 Diffie-Hellman on a loaded 32 MB radio can take well over
            // the per-command budget, so connection gets its own.
            connect_timeout: Duration::from_secs(45),
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
        self.emit(CollectEvent::State { device, state }).await;
    }
    /// Report that collection stopped because the device needs the legacy SSH opt-in.
    pub async fn legacy_required(&self, device: nm_core::DeviceId, algorithms: Vec<String>) {
        self.emit(CollectEvent::LegacyRequired { device, algorithms })
            .await;
    }
    async fn emit(&self, event: CollectEvent) {
        if let Some(events) = &self.events {
            let _ = events.send(event).await;
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
