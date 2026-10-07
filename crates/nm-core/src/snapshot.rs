use crate::{DeviceFacts, DeviceId, Finding, SnapshotId, Timestamp};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    pub id: SnapshotId,
    pub started_at: Timestamp,
    /// None while collection is running; a timestamp is recorded when finished.
    pub finished_at: Option<Timestamp>,
    pub device_results: Vec<DeviceResult>,
    pub findings: Vec<Finding>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeviceResult {
    pub device_id: DeviceId,
    pub outcome: Outcome,
    pub facts: DeviceFacts,
    pub raw: Vec<RawArtifact>,
    pub coverage: Coverage,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    Ok,
    AuthFailed,
    Unreachable,
    Partial(Vec<String>),
    ParseError,
    Cancelled,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawArtifact {
    pub kind: ArtifactKind,
    pub name: String,
    pub bytes: Vec<u8>,
    pub sha256: [u8; 32],
    pub redacted: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactKind {
    Json,
    Text,
    Config,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Coverage {
    pub expected: Vec<String>,
    pub collected: Vec<String>,
    /// Operational commands omitted because a configured protocol is absent.
    pub skipped: std::collections::BTreeMap<String, String>,
    pub missing: Vec<String>,
    pub sources: std::collections::BTreeMap<String, String>,
    pub errors: std::collections::BTreeMap<String, String>,
}
