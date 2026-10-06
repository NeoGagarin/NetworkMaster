use nm_core::{DeviceId, Outcome};
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobOutcome {
    Completed,
    Cancelled,
    Failed(String),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobEvent {
    Started { total: usize },
    DeviceStarted(DeviceId),
    DeviceFinished(DeviceId, Outcome),
    Progress { done: usize, total: usize },
    Log(String),
    Finished(JobOutcome),
    Cancelled,
    Failed(String),
}
