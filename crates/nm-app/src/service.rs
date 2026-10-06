use crate::{AppError, CredArena, JobEvent, JobRunner, Result, SecretMaterial};
use nm_collect::{CollectCtx, Collector, DenyAllNet, Limits, NetFactory, RealNet, TargetGate};
use nm_core::{
    Actor, AuditAction, AuditEvent, CredentialProfile, DeviceFamily, StorageMode, Timestamp,
};
use nm_store::{
    repo::{DeviceFilter, DeviceRepo, ProfileRepo, SettingsRepo},
    AuditSink, Db,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Default)]
pub struct AppConfig {
    pub data_dir: Option<PathBuf>,
    pub deny_network: bool,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub theme: ThemeChoice,
    pub ascii: bool,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThemeChoice {
    #[default]
    Dark,
    HighContrast,
    NoColor,
}
#[derive(Default)]
pub struct CollectorRegistry {
    collectors: HashMap<DeviceFamily, Arc<dyn Collector>>,
}
impl CollectorRegistry {
    pub fn register(&mut self, collector: Arc<dyn Collector>) {
        self.collectors.insert(collector.family(), collector);
    }
    pub fn get(&self, family: DeviceFamily) -> Option<&Arc<dyn Collector>> {
        self.collectors.get(&family)
    }
    pub fn is_empty(&self) -> bool {
        self.collectors.is_empty()
    }
}
pub struct AppService {
    pub db: Db,
    pub creds: Arc<CredArena>,
    pub collectors: CollectorRegistry,
    pub jobs: JobRunner,
    pub settings: Settings,
    pub audit: AuditSink,
    pub data_dir: PathBuf,
    pub net: Arc<dyn NetFactory>,
    job_events: Option<mpsc::Receiver<JobEvent>>,
    deny_network: bool,
}
impl AppService {
    /// Requires a Tokio runtime for the job and audit workers. Opening performs no DNS or network IO.
    pub fn open(config: AppConfig) -> Result<Self> {
        let data_dir = config.data_dir.unwrap_or_else(nm_store::paths::data_dir);
        let db = Db::open(&data_dir.join("netmaster.db"))?;
        let settings = SettingsRepo::new(&db).get("app")?.unwrap_or_default();
        let audit = AuditSink::new(db.clone(), 256);
        let (jobs, events) = JobRunner::new(128);
        let deny_network =
            config.deny_network || std::env::var("NETMASTER_NET").is_ok_and(|v| v == "deny");
        let net: Arc<dyn NetFactory> = if deny_network {
            Arc::new(DenyAllNet)
        } else {
            Arc::new(RealNet::new(Arc::new(TargetGate::default())))
        };
        Ok(Self {
            db,
            creds: Arc::new(CredArena::new()),
            collectors: CollectorRegistry::default(),
            jobs,
            settings,
            audit,
            data_dir,
            net,
            job_events: Some(events),
            deny_network,
        })
    }
    pub fn take_job_events(&mut self) -> Option<mpsc::Receiver<JobEvent>> {
        self.job_events.take()
    }
    pub async fn collect_context(&self, cancel: CancellationToken) -> Result<CollectCtx> {
        let enrolled = DeviceRepo::new(&self.db).list(&DeviceFilter {
            enrolled: Some(true),
            ..DeviceFilter::default()
        })?;
        // Deny mode also skips DNS; an offline dry-run must not emit DNS traffic.
        let gate = Arc::new(if self.deny_network {
            TargetGate::default()
        } else {
            TargetGate::new(&enrolled).await
        });
        let net: Arc<dyn NetFactory> = if self.deny_network {
            Arc::new(DenyAllNet)
        } else {
            Arc::new(RealNet::new(gate.clone()))
        };
        Ok(CollectCtx {
            gate,
            creds: self.creds.clone(),
            audit: self.audit.clone(),
            cancel,
            net,
            limits: Limits::default(),
        })
    }
    pub async fn add_credential(
        &self,
        profile: &CredentialProfile,
        secret: SecretMaterial,
    ) -> Result<()> {
        if profile.storage != StorageMode::SessionOnly {
            return Err(crate::CredsError::NotImplemented.into());
        }
        if !secret.matches(&profile.kind) {
            return Err(crate::CredsError::KindMismatch.into());
        }
        ProfileRepo::new(&self.db).insert(profile)?;
        self.creds.insert(profile.id, secret)?;
        self.record(
            AuditAction::CredentialCreated,
            profile.id.to_string(),
            serde_json::json!({"storage":"session-only"}),
        )
        .await?;
        self.audit.flush().await?;
        Ok(())
    }
    pub async fn forget_all_credentials(&self) -> Result<()> {
        self.creds.forget_all()?;
        self.record(
            AuditAction::CredentialForgotten,
            "all".into(),
            serde_json::json!({"storage":"session-only"}),
        )
        .await?;
        self.audit.flush().await?;
        Ok(())
    }
    pub async fn record(
        &self,
        action: AuditAction,
        target: String,
        detail: serde_json::Value,
    ) -> Result<()> {
        self.audit
            .append(AuditEvent {
                ts: Timestamp::now(),
                actor: Actor::Cli,
                action,
                target,
                detail,
                bytes_out: 0,
                bytes_in: 0,
            })
            .await
            .map_err(AppError::from)
    }
    pub async fn shutdown(&self) -> Result<()> {
        self.jobs.cancel_active();
        self.creds.forget_all()?;
        self.audit.flush().await?;
        Ok(())
    }
}
impl Drop for AppService {
    fn drop(&mut self) {
        self.jobs.cancel_active();
        let _ = self.creds.forget_all();
    }
}
