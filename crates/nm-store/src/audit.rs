use crate::{repo::AuditRepo, Db, Result, StoreError};
use nm_core::AuditEvent;
use std::time::Instant;
use tokio::sync::{mpsc, oneshot};

enum Message {
    Append(AuditEvent),
    Flush(oneshot::Sender<std::result::Result<(), String>>),
}
/// Bounded, ordered queue with SQLite work confined to a single blocking writer.
#[derive(Clone)]
pub struct AuditSink {
    sender: mpsc::Sender<Message>,
}
impl AuditSink {
    /// Reserve ordered queue space before starting an operation. Dropping the
    /// reservation records interruption even when its future is cancelled.
    pub async fn reserve(&self, event: AuditEvent) -> Result<AuditReservation> {
        let permit = self
            .sender
            .clone()
            .reserve_owned()
            .await
            .map_err(|_| StoreError::AuditClosed)?;
        Ok(AuditReservation {
            permit: Some(permit),
            event: Some(event),
            started: Instant::now(),
        })
    }
    pub fn new(db: Db, capacity: usize) -> Self {
        let (sender, mut receiver) = mpsc::channel(capacity.max(1));
        tokio::task::spawn_blocking(move || {
            let mut failure: Option<String> = None;
            while let Some(message) = receiver.blocking_recv() {
                match message {
                    Message::Append(event) => {
                        if failure.is_none() {
                            if let Err(error) = AuditRepo::new(&db).append(&event) {
                                failure = Some(error.to_string());
                            }
                        }
                    }
                    Message::Flush(done) => {
                        let _ = done.send(failure.clone().map_or(Ok(()), Err));
                    }
                }
            }
        });
        Self { sender }
    }
    /// Backpressure may await queue space, but never executes SQLite on a collector task.
    pub async fn append(&self, event: AuditEvent) -> Result<()> {
        self.sender
            .send(Message::Append(event))
            .await
            .map_err(|_| StoreError::AuditClosed)
    }
    /// A barrier: all earlier events are durable, or a writer error is surfaced.
    pub async fn flush(&self) -> Result<()> {
        let (done, receive) = oneshot::channel();
        self.sender
            .send(Message::Flush(done))
            .await
            .map_err(|_| StoreError::AuditClosed)?;
        receive
            .await
            .map_err(|_| StoreError::AuditClosed)?
            .map_err(StoreError::AuditWriter)
    }
}

pub struct AuditReservation {
    permit: Option<mpsc::OwnedPermit<Message>>,
    event: Option<AuditEvent>,
    started: Instant,
}
impl AuditReservation {
    pub fn complete(mut self, event: AuditEvent) {
        self.event = Some(event);
        self.send();
    }
    fn send(&mut self) {
        if let (Some(permit), Some(event)) = (self.permit.take(), self.event.take()) {
            permit.send(Message::Append(event));
        }
    }
}
impl Drop for AuditReservation {
    fn drop(&mut self) {
        if let Some(event) = &mut self.event {
            event.detail["error"] = "operation interrupted".into();
            event.detail["duration_ms"] = serde_json::json!(self.started.elapsed().as_millis());
        }
        self.send();
    }
}
