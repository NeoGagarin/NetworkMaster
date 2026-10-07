use crate::{CollectorRegistry, Job, JobCtx, JobError, JobEvent, JobOutcome};
use async_trait::async_trait;
use futures_util::{stream::FuturesUnordered, StreamExt};
use nm_collect::{CollectCtx, CollectError};
use nm_core::{
    Actor, AuditAction, AuditEvent, Device, DeviceResult, DeviceRole, Outcome, Snapshot,
    SnapshotId, Timestamp,
};
use nm_store::{repo::SnapshotRepo, AuditSink, Db};
use std::result::Result;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Semaphore;

pub struct ScanJob {
    pub devices: Vec<Device>,
    pub dry_run: bool,
    pub data_dir: std::path::PathBuf,
    pub global: usize,
    pub per_site: usize,
    pub db: Db,
    pub audit: AuditSink,
    pub collectors: CollectorRegistry,
    pub ctx: Option<CollectCtx>,
}
fn error(e: impl std::fmt::Display) -> JobError {
    JobError::Failed(e.to_string())
}
fn failed(device: &Device, outcome: Outcome, reason: String) -> DeviceResult {
    let mut r = if device.family == nm_core::DeviceFamily::EdgeOs {
        nm_collect_ubiquiti::edgeos::collector::empty_result(device)
    } else {
        nm_collect_ubiquiti::airos::collector::empty_result(device)
    };
    r.outcome = outcome;
    r.coverage.missing = r.coverage.expected.clone();
    r.coverage.errors.insert("collection".into(), reason);
    r
}
#[async_trait]
impl Job for ScanJob {
    fn handles_cancellation(&self) -> bool {
        true
    }
    async fn run(mut self, job: JobCtx) -> Result<JobOutcome, JobError> {
        self.devices.retain(|d| d.enrolled);
        self.devices.sort_by_key(|d| {
            (
                match d.role {
                    Some(DeviceRole::Controller) => 0,
                    Some(DeviceRole::Router | DeviceRole::Gateway) => 1,
                    Some(DeviceRole::Station) => 3,
                    _ => 2,
                },
                d.id,
            )
        });
        let total = self.devices.len();
        let _ = job.events.send(JobEvent::Started { total }).await;
        if self.global == 0 || self.per_site == 0 {
            return Err(error("concurrency must be greater than zero"));
        }
        if self.dry_run {
            for device in &self.devices {
                if job.cancel.is_cancelled() {
                    return Ok(JobOutcome::Cancelled);
                }
                let collector = self
                    .collectors
                    .get(device.family)
                    .ok_or_else(|| error(format!("no collector for {:?}", device.family)))?;
                let plan = collector.plan(device);
                for action in &plan.0 {
                    let line = nm_collect::CollectionPlan(vec![action.clone()])
                        .to_string()
                        .trim_end()
                        .to_owned();
                    let command = match action.action {
                        nm_collect::Action::SshCommand(c) => Some(c.as_str()),
                        _ => None,
                    };
                    self.audit
                        .append(AuditEvent {
                            ts: Timestamp::now(),
                            actor: Actor::Collector,
                            action: AuditAction::DryRun,
                            target: device.id.to_string(),
                            detail: serde_json::json!({"plan":line,"command":command}),
                            bytes_out: 0,
                            bytes_in: 0,
                        })
                        .await
                        .map_err(error)?;
                    let _ = job.events.send(JobEvent::Log(line)).await;
                }
            }
            self.audit.flush().await.map_err(error)?;
            return Ok(JobOutcome::Completed);
        }
        let mut ctx = self
            .ctx
            .take()
            .ok_or_else(|| error("missing collection context"))?;
        ctx.cancel = job.cancel.clone();
        let (progress, mut receive) = tokio::sync::mpsc::channel(128);
        ctx.events = Some(progress);
        let ctx = Arc::new(ctx);
        let snapshot = Snapshot {
            id: SnapshotId::new(),
            started_at: Timestamp::now(),
            finished_at: None,
            device_results: vec![],
            findings: vec![],
        };
        let repo = SnapshotRepo::new(&self.db);
        let hash = hex::encode(crate::inventory::inventory_hash(&self.devices));
        repo.create(&snapshot, &hash, "").map_err(error)?;
        self.audit
            .append(AuditEvent {
                ts: Timestamp::now(),
                actor: Actor::Collector,
                action: AuditAction::ScanStarted,
                target: snapshot.id.to_string(),
                detail: serde_json::json!({"devices":total,"inventory_hash":hash}),
                bytes_in: 0,
                bytes_out: 0,
            })
            .await
            .map_err(error)?;
        let global = Arc::new(Semaphore::new(self.global));
        let mut sites = HashMap::new();
        let mut pending = FuturesUnordered::new();
        for device in self.devices {
            let site = sites
                .entry(device.site)
                .or_insert_with(|| Arc::new(Semaphore::new(self.per_site)))
                .clone();
            let global = global.clone();
            let ctx = ctx.clone();
            let collector = self.collectors.get(device.family).cloned();
            let events = job.events.clone();
            pending.push(async move {
                let run=async {
                    // Acquire the site permit first: one busy tower cannot consume
                    // every global slot while waiting for its local limit.
                    let _site=site.acquire().await.map_err(|_|CollectError::Cancelled)?;
                    let _global=global.acquire().await.map_err(|_|CollectError::Cancelled)?;
                    if ctx.cancel.is_cancelled(){return Err(CollectError::Cancelled);}
                    let _=events.send(JobEvent::DeviceStarted(device.id)).await;
                    let Some(collector)=collector else {return Err(CollectError::Unreachable("no collector for device family".into()));};
                    if let Ok(result) = tokio::time::timeout(ctx.limits.per_device_budget,collector.collect(&ctx,&device)).await { result } else {let mut result=ctx.partial.lock().ok().and_then(|p|p.get(&device.id).cloned()).unwrap_or_else(||failed(&device,Outcome::Partial(vec![]),"device budget expired".into()));let missing:Vec<_>=result.coverage.expected.iter().filter(|c|!result.coverage.collected.contains(c)&&!result.coverage.skipped.contains_key(*c)).cloned().collect();result.coverage.missing.clone_from(&missing);result.coverage.errors.insert("budget".into(),"device budget expired".into());result.outcome=Outcome::Partial(missing);Ok(result)}
                };
                let result=tokio::select! {biased;result=run=>result,()=ctx.cancel.cancelled()=>Err(CollectError::Cancelled)};
                match result {
                    Ok(result)=>result,
                    Err(CollectError::Cancelled)=>{let mut result=ctx.partial.lock().ok().and_then(|p|p.get(&device.id).cloned()).unwrap_or_else(||failed(&device,Outcome::Cancelled,"cancelled".into()));result.outcome=Outcome::Cancelled;result.coverage.missing=result.coverage.expected.iter().filter(|c|!result.coverage.collected.contains(c)&&!result.coverage.skipped.contains_key(*c)).cloned().collect();result},
                    Err(CollectError::AuthFailed)=>failed(&device,Outcome::AuthFailed,"authentication failed".into()),
                    Err(e)=>failed(&device,Outcome::Unreachable,e.to_string()),
                }
            });
        }
        let (mut done, mut ok, mut partial, mut failed_count) = (0, 0, 0, 0);
        while !pending.is_empty() {
            tokio::select! {
                Some(event)=receive.recv()=>{let _=job.events.send(JobEvent::DeviceState {device:event.device,state:event.state}).await;},
                Some(result)=pending.next()=>{
                    match result.outcome {Outcome::Ok=>ok+=1,Outcome::Partial(_)|Outcome::Cancelled=>partial+=1,_=>failed_count+=1}
                    repo.insert_device_result(snapshot.id,&result).map_err(error)?;for raw in &result.raw {repo.insert_raw_artifact(snapshot.id,result.device_id,raw).map_err(error)?;}
                    done+=1;let _=job.events.send(JobEvent::DeviceFinished(result.device_id,result.outcome)).await;let _=job.events.send(JobEvent::Progress {done,total}).await;
                },
            }
        }
        repo.finish(snapshot.id, Timestamp::now()).map_err(error)?;
        let settings: crate::Settings = nm_store::repo::SettingsRepo::new(&self.db)
            .get("app")
            .map_err(error)?
            .unwrap_or_default();
        if settings.auto_analyze {
            let dir = &self.data_dir;
            if let Err(e) = crate::analyze::AnalyzeService::new(&self.db, dir).run(snapshot.id) {
                let _ = job
                    .events
                    .send(JobEvent::Log(format!("Analysis failed: {e}")))
                    .await;
            }
        }
        self.audit.append(AuditEvent {ts:Timestamp::now(),actor:Actor::Collector,action:AuditAction::ScanFinished,target:snapshot.id.to_string(),detail:serde_json::json!({"ok":ok,"partial":partial,"failed":failed_count,"cancelled":job.cancel.is_cancelled()}),bytes_in:0,bytes_out:0}).await.map_err(error)?;
        self.audit.flush().await.map_err(error)?;
        Ok(JobOutcome::Scan {
            snapshot_id: snapshot.id,
            ok,
            partial,
            failed: failed_count,
        })
    }
}
