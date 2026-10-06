use crate::Timestamp;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub ts: Timestamp,
    pub actor: Actor,
    pub action: AuditAction,
    pub target: String,
    pub detail: serde_json::Value,
    pub bytes_out: u64,
    pub bytes_in: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Actor {
    Cli,
    Tui,
    Collector,
    Ai,
    Mcp,
    System,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditAction {
    SshConnect,
    SshCommand,
    HttpRequest,
    UdpProbe,
    AiRequest,
    AiToolCall,
    CredentialCreated,
    CredentialForgotten,
    ScanStarted,
    ScanFinished,
    DryRun,
    Export,
    McpServe,
}
