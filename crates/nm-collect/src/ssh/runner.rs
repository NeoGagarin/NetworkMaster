use super::{SshError, SshSession};
use crate::SshCommand;
use nm_core::{Actor, AuditAction, AuditEvent, Timestamp};
use russh::ChannelMsg;
use std::time::{Duration, Instant};
pub const OUTPUT_LIMIT: usize = 4 * 1024 * 1024;
pub struct CommandOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit: Option<u32>,
    pub duration: Duration,
    pub truncated: bool,
}
impl SshSession {
    pub async fn run(&mut self, command: SshCommand) -> Result<CommandOutput, SshError> {
        let started = Instant::now();
        let audit_event = AuditEvent {
            ts: Timestamp::now(),
            actor: Actor::Collector,
            action: AuditAction::SshCommand,
            target: self.device.to_string(),
            detail: serde_json::json!({"command": command.as_str(), "exit": null}),
            bytes_out: u64::try_from(command.as_str().len()).unwrap_or(u64::MAX),
            bytes_in: 0,
        };
        let reservation = self.audit.reserve(audit_event).await?;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit = None;
        let mut truncated = false;
        let cancel = self.cancel.clone();
        let future = async {
            let mut channel = self.session.channel_open_session().await?;
            channel.exec(true, command.as_str()).await?;
            while let Some(message) = channel.wait().await {
                match message {
                    ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, ext: 0 } => {
                        append(&mut stdout, &stderr, &data, &mut truncated);
                    }
                    ChannelMsg::ExtendedData { data, .. } => {
                        append(&mut stderr, &stdout, &data, &mut truncated);
                    }
                    ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
                    ChannelMsg::Close => break,
                    _ => {}
                }
                if truncated {
                    channel.close().await?;
                    break;
                }
            }
            Ok::<(), SshError>(())
        };
        let result = tokio::select! { ()=cancel.cancelled()=>Err(SshError::Cancelled), result=tokio::time::timeout(self.timeout,future)=>result.map_err(|_|SshError::Timeout).and_then(|r|r) };
        let duration = started.elapsed();
        reservation.complete(AuditEvent { ts:Timestamp::now(),actor:Actor::Collector,action:AuditAction::SshCommand,target:self.device.to_string(),detail:serde_json::json!({"command":command.as_str(),"exit":exit,"duration_ms":duration.as_millis(),"truncated":truncated,"error":result.as_ref().err().map(ToString::to_string)}),bytes_out:u64::try_from(command.as_str().len()).unwrap_or(u64::MAX),bytes_in:u64::try_from(stdout.len()+stderr.len()).unwrap_or(u64::MAX) });
        result?;
        Ok(CommandOutput {
            stdout,
            stderr,
            exit,
            duration,
            truncated,
        })
    }
    pub async fn close(&self) -> Result<(), SshError> {
        self.session
            .disconnect(
                russh::Disconnect::ByApplication,
                "collection finished",
                "en",
            )
            .await?;
        Ok(())
    }
}
fn append(target: &mut Vec<u8>, other: &[u8], data: &[u8], truncated: &mut bool) {
    let room = OUTPUT_LIMIT.saturating_sub(target.len() + other.len());
    target.extend_from_slice(&data[..data.len().min(room)]);
    *truncated |= data.len() > room;
}
