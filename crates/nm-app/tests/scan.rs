use async_trait::async_trait;
use nm_app::{
    inventory::InventoryService, AppConfig, AppService, Job, JobCtx, JobEvent, JobOutcome,
};
use nm_collect::{CollectCtx, CollectError, CollectionPlan, Collector};
use nm_core::*;
use nm_store::repo::{DeviceFilter, DeviceRepo, SnapshotRepo};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;
struct Fake {
    active: Arc<AtomicUsize>,
    high: Arc<AtomicUsize>,
    sleep: Duration,
}
#[async_trait]
impl Collector for Fake {
    fn family(&self) -> DeviceFamily {
        DeviceFamily::AirOs
    }
    fn plan(&self, _: &Device) -> CollectionPlan {
        CollectionPlan::default()
    }
    async fn collect(
        &self,
        ctx: &CollectCtx,
        d: &Device,
    ) -> std::result::Result<DeviceResult, CollectError> {
        struct Guard(Arc<AtomicUsize>);
        impl Drop for Guard {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let n = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        let _guard = Guard(self.active.clone());
        self.high.fetch_max(n, Ordering::SeqCst);
        let mut result = nm_collect_ubiquiti::airos::collector::empty_result(d);
        result.facts.system.hostname = Some("kept-progress".into());
        ctx.save_partial(&result);
        tokio::time::sleep(self.sleep).await;
        result
            .coverage
            .collected
            .clone_from(&result.coverage.expected);
        Ok(result)
    }
}
fn service() -> (tempfile::TempDir, AppService, Vec<Device>) {
    let dir = tempfile::tempdir().unwrap();
    let svc = AppService::open(AppConfig {
        data_dir: Some(dir.path().into()),
        deny_network: true,
    })
    .unwrap();
    let inventory = InventoryService::new(&svc.db);
    for i in 1..=10 {
        let site = if i % 2 == 0 { "Tower A" } else { "Tower B" };
        let d = inventory
            .add_manual(
                format!("192.0.2.{i}").parse().unwrap(),
                DeviceFamily::AirOs,
                None,
                Some(site),
            )
            .unwrap();
        inventory.enroll(&[d.id]).unwrap();
    }
    let devices = DeviceRepo::new(&svc.db)
        .list(&DeviceFilter::default())
        .unwrap();
    (dir, svc, devices)
}
async fn drain_job(job: nm_app::scan::ScanJob, cancel: CancellationToken) -> JobOutcome {
    let (events, mut recv) = tokio::sync::mpsc::channel(128);
    let reader = tokio::spawn(async move { while recv.recv().await.is_some() {} });
    let result = job.run(JobCtx { cancel, events }).await.unwrap();
    reader.await.unwrap();
    result
}
#[tokio::test]
async fn limits_global_and_per_site_without_starvation() {
    let (_dir, mut svc, devices) = service();
    let high = Arc::new(AtomicUsize::new(0));
    svc.collectors.register(Arc::new(Fake {
        active: Arc::default(),
        high: high.clone(),
        sleep: Duration::from_millis(30),
    }));
    let cancel = CancellationToken::new();
    let job = svc
        .scan_job(devices, false, 8, 2, cancel.clone())
        .await
        .unwrap();
    assert!(matches!(
        drain_job(job, cancel).await,
        JobOutcome::Scan {
            ok: 10,
            partial: 0,
            failed: 0,
            ..
        }
    ));
    assert_eq!(high.load(Ordering::SeqCst), 4);
    svc.shutdown().await.unwrap();
}
#[tokio::test]
async fn budget_preserves_progress() {
    let (_dir, mut svc, devices) = service();
    svc.collectors.register(Arc::new(Fake {
        active: Arc::default(),
        high: Arc::default(),
        sleep: Duration::from_secs(5),
    }));
    let cancel = CancellationToken::new();
    let mut job = svc
        .scan_job(devices, false, 8, 2, cancel.clone())
        .await
        .unwrap();
    job.ctx.as_mut().unwrap().limits.per_device_budget = Duration::from_millis(20);
    let outcome = drain_job(job, cancel).await;
    let JobOutcome::Scan {
        snapshot_id,
        partial: 10,
        ..
    } = outcome
    else {
        panic!("{outcome:?}")
    };
    let snapshot = SnapshotRepo::new(&svc.db)
        .get(snapshot_id)
        .unwrap()
        .unwrap();
    assert!(snapshot
        .device_results
        .iter()
        .all(|r| r.facts.system.hostname.as_deref() == Some("kept-progress")));
    svc.shutdown().await.unwrap();
}
#[tokio::test]
async fn cancellation_finishes_snapshot_and_marks_remaining_devices() {
    let (_dir, mut svc, devices) = service();
    svc.collectors.register(Arc::new(Fake {
        active: Arc::default(),
        high: Arc::default(),
        sleep: Duration::from_millis(50),
    }));
    let cancel = CancellationToken::new();
    let job = svc
        .scan_job(devices, false, 2, 1, cancel.clone())
        .await
        .unwrap();
    let mut events = svc.take_job_events().unwrap();
    let handle = svc.jobs.spawn(job).unwrap();
    let mut finished = 0;
    while let Some(event) = events.recv().await {
        if matches!(event, JobEvent::DeviceFinished(_, Outcome::Ok)) {
            finished += 1;
            if finished == 2 {
                handle.cancel();
                break;
            }
        }
    }
    let reader = tokio::spawn(async move { while events.recv().await.is_some() {} });
    let outcome = handle.done.await.unwrap();
    let JobOutcome::Scan { snapshot_id, .. } = outcome else {
        panic!("{outcome:?}")
    };
    let snapshot = SnapshotRepo::new(&svc.db)
        .get(snapshot_id)
        .unwrap()
        .unwrap();
    assert!(snapshot.finished_at.is_some());
    assert_eq!(snapshot.device_results.len(), 10);
    assert!(snapshot
        .device_results
        .iter()
        .any(|r| r.outcome == Outcome::Ok));
    assert!(snapshot
        .device_results
        .iter()
        .any(|r| r.outcome == Outcome::Cancelled));
    reader.abort();
    svc.shutdown().await.unwrap();
}
#[tokio::test]
async fn dry_run_constructs_no_context_or_snapshot() {
    let (_dir, svc, devices) = service();
    let cancel = CancellationToken::new();
    let job = svc
        .scan_job(devices, true, 8, 2, cancel.clone())
        .await
        .unwrap();
    assert!(job.ctx.is_none());
    assert_eq!(drain_job(job, cancel).await, JobOutcome::Completed);
    assert!(SnapshotRepo::new(&svc.db).list().unwrap().is_empty());
    let audit = nm_store::repo::AuditRepo::new(&svc.db).tail(200).unwrap();
    assert_eq!(audit.len(), 140);
    assert!(audit.iter().all(|a| a.action == AuditAction::DryRun));
    svc.shutdown().await.unwrap();
}
