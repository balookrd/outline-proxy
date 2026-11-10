//! A periodic timer whose every period is shortened by a fresh random share.
//!
//! The relay loops send a WebSocket Ping on a timer. `tokio::time::interval`
//! fires at an exact period, which an on-path observer can pick out of an
//! otherwise idle connection; this ticker draws each gap with
//! [`outline_wire::jitter::jitter_down`] instead. A gap is never longer than
//! the configured period, so the pong deadline and the client's read-idle
//! timeout derived from it keep their margins.

use std::{pin::Pin, time::Duration};

use tokio::time::{Instant, Sleep, sleep};

pub(super) struct JitteredTicker {
    period: Duration,
    sleep: Pin<Box<Sleep>>,
}

impl JitteredTicker {
    /// The first tick fires after one jittered period, not immediately.
    pub(super) fn new(period: Duration) -> Self {
        Self {
            period,
            sleep: Box::pin(sleep(next_gap(period))),
        }
    }

    /// Completes when the current gap elapses, then arms the next one from
    /// that moment (a late poll delays the following ticks rather than
    /// bursting them). Cancel-safe: dropping the future before it completes
    /// leaves the armed deadline untouched.
    pub(super) async fn tick(&mut self) {
        self.sleep.as_mut().await;
        self.sleep.as_mut().reset(Instant::now() + next_gap(self.period));
    }
}

fn next_gap(period: Duration) -> Duration {
    outline_wire::jitter::jitter_down(period, rand::random())
}

#[cfg(test)]
#[path = "tests/jittered_ticker.rs"]
mod tests;
