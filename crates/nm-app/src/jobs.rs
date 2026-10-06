use crate::{JobEvent, JobOutcome};
use async_trait::async_trait;
use nm_core::JobId;
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

#[derive(Debug, thiserror::Error)]
pub enum JobError {
    #[error("a job is already running")]
    Busy,
    #[error("job runner lock poisoned")]
    Poisoned,
    #[error("job failed: {0}")]
    Failed(String),
}
pub struct JobCtx {
    pub cancel: CancellationToken,
    pub events: mpsc::Sender<JobEvent>,
}
#[async_trait]
pub trait Job: Send + 'static {
    async fn run(self, ctx: JobCtx) -> std::result::Result<JobOutcome, JobError>;
}
pub struct JobHandle {
    pub id: JobId,
    cancel: CancellationToken,
    pub done: oneshot::Receiver<JobOutcome>,
}
impl JobHandle {
    pub fn cancel(&self) {
        self.cancel.cancel();
    }
}
struct Active {
    id: JobId,
    cancel: CancellationToken,
}
#[derive(Clone)]
pub struct JobRunner {
    active: Arc<Mutex<Option<Active>>>,
    events: mpsc::Sender<JobEvent>,
}
// Releases admission even when a job panics or its task is dropped.
struct Permit {
    id: JobId,
    active: Arc<Mutex<Option<Active>>>,
}
impl Drop for Permit {
    fn drop(&mut self) {
        if let Ok(mut active) = self.active.lock() {
            if active.as_ref().is_some_and(|a| a.id == self.id) {
                active.take();
            }
        }
    }
}
impl JobRunner {
    pub fn new(capacity: usize) -> (Self, mpsc::Receiver<JobEvent>) {
        let (events, receiver) = mpsc::channel(capacity.max(1));
        (
            Self {
                active: Arc::new(Mutex::new(None)),
                events,
            },
            receiver,
        )
    }
    pub fn is_active(&self) -> bool {
        self.active.lock().is_ok_and(|a| a.is_some())
    }
    pub fn cancel_active(&self) {
        if let Ok(active) = self.active.lock() {
            if let Some(active) = active.as_ref() {
                active.cancel.cancel();
            }
        }
    }
    pub fn spawn<J: Job>(&self, job: J) -> std::result::Result<JobHandle, JobError> {
        let id = JobId::new();
        let cancel = CancellationToken::new();
        {
            let mut active = self.active.lock().map_err(|_| JobError::Poisoned)?;
            if active.is_some() {
                return Err(JobError::Busy);
            }
            *active = Some(Active {
                id,
                cancel: cancel.clone(),
            });
        }
        let permit = Permit {
            id,
            active: self.active.clone(),
        };
        let ctx = JobCtx {
            cancel: cancel.clone(),
            events: self.events.clone(),
        };
        let events = self.events.clone();
        let cancelled = cancel.clone();
        let (done, receive) = oneshot::channel();
        tokio::spawn(async move {
            let outcome = tokio::select! {
                biased;
                () = cancelled.cancelled() => JobOutcome::Cancelled,
                result = job.run(ctx) => result.unwrap_or_else(|e| JobOutcome::Failed(e.to_string())),
            };
            let event = match &outcome {
                JobOutcome::Cancelled => JobEvent::Cancelled,
                JobOutcome::Failed(error) => JobEvent::Failed(error.clone()),
                JobOutcome::Completed => JobEvent::Finished(outcome.clone()),
            };
            drop(permit);
            // The completion handle must not wait on a full event queue; the
            // terminal event remains queued for delivery instead of being lost.
            let _ = done.send(outcome);
            let _ = events.send(event).await;
        });
        Ok(JobHandle {
            id,
            cancel,
            done: receive,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    struct SleepJob;
    #[async_trait]
    impl Job for SleepJob {
        async fn run(self, ctx: JobCtx) -> std::result::Result<JobOutcome, JobError> {
            ctx.events
                .send(JobEvent::Started { total: 1 })
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            Ok(JobOutcome::Completed)
        }
    }
    #[tokio::test]
    async fn cancellation_and_single_job_admission() {
        let (runner, mut events) = JobRunner::new(8);
        let handle = runner.spawn(SleepJob).unwrap();
        assert_eq!(events.recv().await, Some(JobEvent::Started { total: 1 }));
        assert!(matches!(runner.spawn(SleepJob), Err(JobError::Busy)));
        handle.cancel();
        assert_eq!(handle.done.await.unwrap(), JobOutcome::Cancelled);
        assert_eq!(events.recv().await, Some(JobEvent::Cancelled));
        assert!(!runner.is_active());
        let next = runner.spawn(SleepJob).unwrap();
        next.cancel();
        assert_eq!(next.done.await.unwrap(), JobOutcome::Cancelled);
    }
    struct CompleteJob;
    #[async_trait]
    impl Job for CompleteJob {
        async fn run(self, ctx: JobCtx) -> std::result::Result<JobOutcome, JobError> {
            ctx.events
                .send(JobEvent::Started { total: 0 })
                .await
                .unwrap();
            Ok(JobOutcome::Completed)
        }
    }
    #[tokio::test]
    async fn completion_does_not_wait_for_event_queue_space() {
        let (runner, mut events) = JobRunner::new(1);
        let handle = runner.spawn(CompleteJob).unwrap();
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), handle.done)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result, JobOutcome::Completed);
        assert!(!runner.is_active());
        assert_eq!(events.recv().await, Some(JobEvent::Started { total: 0 }));
        assert_eq!(
            events.recv().await,
            Some(JobEvent::Finished(JobOutcome::Completed))
        );
    }
}
