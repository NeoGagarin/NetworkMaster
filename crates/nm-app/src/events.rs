use nm_core::{DeviceId, Outcome, SnapshotId};
use serde::Serialize;
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum JobOutcome {
    Completed,
    Cancelled,
    Failed(String),
    Scan {
        snapshot_id: SnapshotId,
        ok: usize,
        partial: usize,
        failed: usize,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum JobEvent {
    Started { total: usize },
    DeviceStarted(DeviceId),
    DeviceState { device: DeviceId, state: String },
    DeviceFinished(DeviceId, Outcome),
    Progress { done: usize, total: usize },
    Log(String),
    Finished(JobOutcome),
    Cancelled,
    Failed(String),
}
