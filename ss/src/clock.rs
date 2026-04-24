//! Cached wall-clock seconds, updated once per second by a background task.
//!
//! On macOS there is no VDSO, so `SystemTime::now()` is a real syscall.
//! Hot paths (NAT touch, replay filter, SS-2022 timestamp validation) read
//! a single `Relaxed` atomic load instead.  One-second granularity is well
//! within the 30-second SS-2022 tolerance and the 5-minute NAT idle window.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static UNIX_SECS: AtomicU64 = AtomicU64::new(0);

/// Returns cached Unix timestamp in whole seconds.
///
/// The value is initialised on first call via a real `SystemTime::now()` and
/// refreshed every second by the background task started with [`tick`].
#[inline]
pub(crate) fn current_unix_secs() -> u64 {
    let cached = UNIX_SECS.load(Ordering::Relaxed);
    if cached != 0 {
        return cached;
    }
    // First call before the periodic task has run — fall back to a real read
    // and seed the cache.
    let now = system_now();
    UNIX_SECS.store(now, Ordering::Relaxed);
    now
}

/// Called once per second by the background maintenance task.
pub(crate) fn tick() {
    UNIX_SECS.store(system_now(), Ordering::Relaxed);
}

fn system_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
