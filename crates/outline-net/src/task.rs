//! Task lifecycle helpers shared across outline crates.
//!
//! [`AbortOnDrop`] wraps a [`tokio::task::JoinHandle`] so dropping the owning
//! struct aborts the background task instead of detaching it.

use tokio::task::JoinHandle;

/// `JoinHandle` newtype that cancels the task on drop.
///
/// Tokio's bare `JoinHandle` only detaches the task on drop — the task keeps
/// running. For tasks whose lifetime should be bounded by the owning struct
/// (relay readers, NAT entry pumps, per-connection reader loops) that
/// detachment is a leak vector: any early `?`-return or panic in the parent
/// silently orphans the task, which then keeps holding sockets, buffers and
/// `Arc`-shared state for as long as it can find anything to await on.
///
/// Wrapping the handle in `AbortOnDrop` makes cancellation automatic. Stash
/// it in a struct field and the field's natural drop runs `abort()` on every
/// exit path.
///
/// Generic over the task's output type (defaulting to `()`) so it works for
/// both `JoinHandle<()>` reader pumps and `JoinHandle<Result<()>>` relay tasks.
pub struct AbortOnDrop<T = ()>(Option<JoinHandle<T>>);

impl<T> AbortOnDrop<T> {
    pub fn new(handle: JoinHandle<T>) -> Self {
        Self(Some(handle))
    }

    /// Detaches the underlying `JoinHandle` and suppresses the on-drop
    /// abort. The caller takes responsibility for the task's lifecycle —
    /// typically by `.await`ing it and then handing off any output. Used
    /// by the cross-transport resumption path to harvest a relay task's
    /// reader without aborting the task first.
    pub fn into_inner(mut self) -> JoinHandle<T> {
        self.0
            .take()
            .expect("AbortOnDrop::into_inner called on detached handle")
    }
}

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AbortOnDrop;
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn dropping_guard_aborts_the_task() {
        let (started_tx, started_rx) = oneshot::channel();
        let (done_tx, done_rx) = oneshot::channel::<()>();

        let guard = AbortOnDrop::new(tokio::spawn(async move {
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
            let _ = done_tx.send(());
        }));

        started_rx.await.expect("task should start");
        drop(guard);

        // Once the task is aborted, `done_tx` is dropped without sending.
        assert!(done_rx.await.is_err());
    }

    #[tokio::test]
    async fn into_inner_detaches_without_aborting() {
        let guard = AbortOnDrop::new(tokio::spawn(async { 42_u32 }));
        let handle = guard.into_inner();
        assert_eq!(handle.await.expect("task should complete"), 42);
    }
}
