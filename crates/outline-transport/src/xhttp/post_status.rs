//! Non-success answers to a packet-up POST, and the retry of the one answer the
//! server means as "try again".
//!
//! Our server answers 503 when the session's uplink buffers are full — the
//! in-order queue the relay has not drained yet, or the reorder buffer — and
//! leaves the seq unconsumed, so the same POST is expected again once the relay
//! frees room. Treating that 503 as fatal broke every upload that outran the
//! server's upstream. Any other status (409 for a seq gap, 410 for a closed
//! session) still ends the session.

use std::fmt;
use std::time::Duration;

use anyhow::Result;
use http::StatusCode;

/// First pause before re-sending a POST refused with 503.
const RETRY_FIRST_DELAY: Duration = Duration::from_millis(5);
/// Ceiling of the doubling pause.
const RETRY_MAX_DELAY: Duration = Duration::from_millis(200);
/// Wall-clock time since the first attempt after which a still-busy server is
/// given up on: the session ends as it did before retries existed. Counting
/// from the first attempt, not summing the pauses, keeps the bound real when
/// the server holds each POST (up to its uplink-room patience) before it
/// answers 503. Matches the h2/h3 `POST_TIMEOUT`, which also wraps their retry
/// loop; h1 has only this bound.
const RETRY_BUDGET: Duration = Duration::from_secs(30);

/// A POST the server answered with a non-success status.
#[derive(Debug)]
pub(super) struct PostStatusError {
    /// Log prefix of the carrier (`xhttp`, `xhttp/h1`, `xhttp/h3`).
    pub(super) carrier: &'static str,
    pub(super) seq: u64,
    pub(super) status: StatusCode,
}

impl fmt::Display for PostStatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} POST seq={} returned {}", self.carrier, self.seq, self.status)
    }
}

impl std::error::Error for PostStatusError {}

/// Fails with [`PostStatusError`] unless `status` is a success.
pub(super) fn check_post_status(carrier: &'static str, seq: u64, status: StatusCode) -> Result<()> {
    if status.is_success() {
        return Ok(());
    }
    Err(PostStatusError { carrier, seq, status }.into())
}

/// Whether the server asked for this POST again: 503 with the seq unconsumed.
pub(super) fn is_busy(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<PostStatusError>()
        .is_some_and(|e| e.status == StatusCode::SERVICE_UNAVAILABLE)
}

/// Doubling pause between re-sends of a POST the server refused as busy.
pub(super) struct BusyRetry {
    delay: Duration,
    /// When the first attempt started.
    since: tokio::time::Instant,
}

impl BusyRetry {
    pub(super) fn new() -> Self {
        Self {
            delay: RETRY_FIRST_DELAY,
            since: tokio::time::Instant::now(),
        }
    }

    /// After an attempt: `true` (once the pause has passed) when the POST
    /// should be sent again, `false` when `result` is final or the retry
    /// budget is spent.
    pub(super) async fn again(&mut self, result: &Result<()>) -> bool {
        match result {
            Err(error) if is_busy(error) && self.since.elapsed() < RETRY_BUDGET => {
                tokio::time::sleep(self.delay).await;
                self.delay = (self.delay * 2).min(RETRY_MAX_DELAY);
                true
            },
            _ => false,
        }
    }
}

#[cfg(test)]
#[path = "tests/post_status.rs"]
mod tests;
