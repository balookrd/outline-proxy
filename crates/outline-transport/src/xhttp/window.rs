//! Per-session send window for packet-up POSTs on the pipelined (h2/h3)
//! carriers.
//!
//! The server reassembles packet-up by seq: a POST that arrives ahead of the
//! next expected seq is parked in a reorder buffer, and the server tears the
//! session down (HTTP 409) once a POST runs more than 64 seqs ahead; Xray gives
//! up at 30 buffered POSTs (`scMaxBufferedPosts`). A parked POST is answered as
//! soon as it is buffered, so capping the POSTs *in flight* does not bound that
//! gap: with one POST stalled, every later one completes and frees its slot,
//! and the client keeps running ahead. The window is therefore anchored at the
//! lowest seq that has not completed yet, which is never ahead of the seq the
//! server is waiting for. Bytes are not capped here: a full reorder buffer is
//! answered with a retryable 503 (see `post_status`), not a teardown.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use tokio::sync::Notify;

/// Seqs a POST may run ahead of the oldest unfinished one. Xray's default
/// `scMaxBufferedPosts` is 30, and our server allows 64.
pub(super) const UPLINK_WINDOW_POSTS: u64 = 30;

pub(super) struct UplinkWindow {
    /// Admitted POSTs from the oldest unfinished one up: `true` once done.
    /// Finished POSTs above the oldest unfinished one stay, since the server
    /// may still hold their bodies in its reorder buffer.
    posts: Mutex<BTreeMap<u64, bool>>,
    notify: Notify,
    max_posts: u64,
}

impl UplinkWindow {
    pub(super) fn new() -> Arc<Self> {
        Self::with_limit(UPLINK_WINDOW_POSTS)
    }

    pub(super) fn with_limit(max_posts: u64) -> Arc<Self> {
        Arc::new(Self {
            posts: Mutex::new(BTreeMap::new()),
            notify: Notify::new(),
            max_posts,
        })
    }

    /// Waits until POST `seq` fits the window and admits it. Seqs must be
    /// admitted in increasing order. The returned slot marks the POST finished
    /// when dropped, so an aborted POST task releases it as well.
    pub(super) async fn admit(self: &Arc<Self>, seq: u64) -> WindowSlot {
        loop {
            if self.try_admit(seq) {
                return WindowSlot { window: Arc::clone(self), seq };
            }
            self.notify.notified().await;
        }
    }

    fn try_admit(&self, seq: u64) -> bool {
        let mut posts = self.posts.lock().expect("uplink window lock poisoned");
        if let Some((&low, _)) = posts.first_key_value()
            && seq - low >= self.max_posts
        {
            return false;
        }
        posts.insert(seq, false);
        true
    }

    fn complete(&self, seq: u64) {
        let mut posts = self.posts.lock().expect("uplink window lock poisoned");
        if let Some(done) = posts.get_mut(&seq) {
            *done = true;
        }
        while let Some(entry) = posts.first_entry() {
            if !*entry.get() {
                break;
            }
            entry.remove();
        }
        drop(posts);
        // `notify_one` keeps a permit when the driver is not waiting yet, so a
        // completion racing the driver's check is not lost.
        self.notify.notify_one();
    }
}

/// An admitted POST's place in the window; dropping it marks the POST done.
pub(super) struct WindowSlot {
    window: Arc<UplinkWindow>,
    seq: u64,
}

impl Drop for WindowSlot {
    fn drop(&mut self) {
        self.window.complete(self.seq);
    }
}

#[cfg(test)]
#[path = "tests/window.rs"]
mod tests;
