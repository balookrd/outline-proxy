//! `AbortOnDrop`: a `JoinHandle` newtype that cancels the task on drop.
//!
//! Tokio's bare `JoinHandle` only detaches on drop — the task keeps running.
//! For tasks whose lifetime should be bounded by the owning struct (relay
//! readers, NAT entry pumps, per-connection reader loops) that detachment is
//! a leak vector: any early `?`-return or panic in the parent silently
//! orphans the task, which then keeps holding sockets, buffers and
//! `Arc`-shared state for as long as it can find anything to await on.
//!
//! Wrapping the handle in `AbortOnDrop` makes cancellation automatic. Stash
//! it in a struct field and the field's natural drop runs `abort()` on every
//! exit path.
//!
//! Generic over the task's output type so it works for both `JoinHandle<()>`
//! reader pumps and `JoinHandle<Result<()>>` relay tasks.

use tokio::task::JoinHandle;

pub(crate) struct AbortOnDrop<T>(Option<JoinHandle<T>>);

impl<T> AbortOnDrop<T> {
    pub(crate) fn new(handle: JoinHandle<T>) -> Self {
        Self(Some(handle))
    }

    /// Eagerly abort the task. Drop also aborts, so calling this is only
    /// useful when you want to express the intent at a specific code point
    /// (e.g. immediately on cleanup, before later async work).
    #[allow(dead_code)]
    pub(crate) fn abort(&self) {
        if let Some(handle) = &self.0 {
            handle.abort();
        }
    }

    /// Detaches the underlying `JoinHandle` and suppresses the on-drop
    /// abort. The caller takes responsibility for the task's lifecycle —
    /// typically by `.await`ing it and then handing off any output. Used
    /// by the cross-transport resumption path to harvest a relay task's
    /// reader without aborting the task first.
    pub(crate) fn into_inner(mut self) -> JoinHandle<T> {
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
