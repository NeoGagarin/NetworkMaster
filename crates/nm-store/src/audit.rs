use crate::{repo::AuditRepo, Db, Result, StoreError};
use nm_core::AuditEvent;
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
