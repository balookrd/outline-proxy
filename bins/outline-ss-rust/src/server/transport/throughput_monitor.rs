//! Per-carrier downstream-throttle detection.
//!
//! A [`ThroughputMonitor`] lives for one WS carrier (one `run_ws_writer`). The
//! relay tasks feeding that carrier increment `in_bytes` (payload read from the
//! upstream target — i.e. from the internet) and the writer increments
//! `out_bytes` (payload actually handed to the carrier toward the client). A
//! background tick samples both once per window and, when the server keeps
//! pulling from the internet far faster than it can push to the client *while a
//! send backlog is present* (the carrier toward this client is throttled —
//! e.g. a VPS shaping traffic toward Russia), it asks the writer to emit one
//! out-of-band control frame nudging the client to switch uplinks.
//!
//! Detection is pure observation: it never touches the bytes on the wire, only
//! counts them. Disabled by default; enabled per the server `[padding]`
//! `throttle_detect` knobs. The signal only ever reaches a client that decodes
//! padding cover frames, so it is meaningful only on a padded carrier — both
//! VLESS-over-WS/XHTTP and SS-over-WS/XHTTP qualify (their relays share this
//! monitor); unpadded and raw-QUIC carriers are never monitored.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::Notify;

/// Tunables for downstream-throttle detection. `enabled = false` (the default)
/// keeps the whole subsystem inert — no monitor is even allocated.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ThrottleDetectParams {
    pub enabled: bool,
    /// Trigger when `in_rate >= ratio * out_rate` (inbound from the internet
    /// outruns delivery to the client by this factor). Owner's "more than 2×".
    pub ratio: f64,
    /// Sampling window. Rates are computed from per-window byte deltas.
    pub window: Duration,
    /// Consecutive over-threshold windows required before signalling — filters
    /// out brief buffer fills at the start of a transfer.
    pub sustain_windows: u32,
    /// Floor on the inbound rate (bytes/sec) below which a session is too slow
    /// for the "throttled" verdict to be actionable — avoids false positives on
    /// genuinely low-bandwidth flows.
    pub min_in_bytes_per_sec: u64,
    /// Minimum gap between two signals on the same carrier.
    pub signal_cooldown: Duration,
}

impl Default for ThrottleDetectParams {
    fn default() -> Self {
        Self {
            enabled: false,
            ratio: 2.0,
            window: Duration::from_secs(1),
            sustain_windows: 5,
            // ~8 Mbit/s: below this a "throttle" is not worth a carrier switch.
            min_in_bytes_per_sec: 1_000_000,
            signal_cooldown: Duration::from_secs(30),
        }
    }
}

/// Pure verdict for a single sampling window: does it count as a throttled
/// window? The tick layer applies the sustain + cooldown logic on top.
///
/// `out_rate == 0` with inbound flowing and a backlog present is the strongest
/// case (server reading from the internet, nothing reaching the client) and
/// trivially satisfies `in_rate >= ratio * 0`.
pub fn window_is_throttled(
    in_rate: u64,
    out_rate: u64,
    backlog: bool,
    params: &ThrottleDetectParams,
) -> bool {
    if !params.enabled {
        return false;
    }
    // Need a real, actionable amount of inbound traffic and evidence that the
    // server actually has data queued for the client (a send backlog) — without
    // backlog a low out_rate just means there is nothing to send.
    if in_rate < params.min_in_bytes_per_sec || !backlog {
        return false;
    }
    in_rate as f64 >= params.ratio * out_rate as f64
}

/// Per-carrier throughput counters + the writer wake-up channel.
pub struct ThroughputMonitor {
    in_bytes: AtomicU64,
    out_bytes: AtomicU64,
    /// Set whenever the send path observed a backlog (data channel past its
    /// high-water mark) since the last window. The tick consumes (swaps) it.
    backlog_seen: AtomicBool,
    /// Pinged by the tick when a switch should be signalled; awaited by the
    /// writer, which emits one control frame per ping.
    signal_request: Notify,
    params: ThrottleDetectParams,
}

impl ThroughputMonitor {
    pub fn new(params: ThrottleDetectParams) -> Arc<Self> {
        Arc::new(Self {
            in_bytes: AtomicU64::new(0),
            out_bytes: AtomicU64::new(0),
            backlog_seen: AtomicBool::new(false),
            signal_request: Notify::new(),
            params,
        })
    }

    /// Record `n` payload bytes read from the upstream target (inbound).
    #[inline]
    pub fn add_inbound(&self, n: u64) {
        self.in_bytes.fetch_add(n, Ordering::Relaxed);
    }

    /// Record `n` payload bytes handed to the carrier toward the client.
    #[inline]
    pub fn add_outbound(&self, n: u64) {
        self.out_bytes.fetch_add(n, Ordering::Relaxed);
    }

    /// Note that the send path is backlogged (data channel past high-water).
    #[inline]
    pub fn note_backlog(&self) {
        self.backlog_seen.store(true, Ordering::Relaxed);
    }

    /// Feed one downlink datagram (UDP path): count its bytes as inbound and
    /// mark a backlog when the data channel is past its half-full high-water
    /// mark (`used` free-slots depth out of `max`). Convenience for the
    /// datagram response senders, mirroring the streaming TCP relay's two
    /// separate calls.
    #[inline]
    pub fn note_datagram(&self, data_len: usize, used: usize, max: usize) {
        self.add_inbound(data_len as u64);
        if used.saturating_mul(2) >= max {
            self.note_backlog();
        }
    }

    /// The writer awaits this to learn a control frame should be sent.
    pub fn signal(&self) -> &Notify {
        &self.signal_request
    }

    pub fn params(&self) -> &ThrottleDetectParams {
        &self.params
    }
}

/// Drives [`ThroughputMonitor`] detection: samples once per window, applies the
/// sustain + cooldown logic, and pings the writer when a switch should fire.
/// Runs until the carrier tears down (the spawning relay aborts this task).
pub async fn run_throttle_tick(monitor: Arc<ThroughputMonitor>) {
    let params = *monitor.params();
    if !params.enabled {
        return;
    }
    let window_secs = params.window.as_secs_f64().max(0.001);
    let mut prev_in = monitor.in_bytes.load(Ordering::Relaxed);
    let mut prev_out = monitor.out_bytes.load(Ordering::Relaxed);
    let mut sustain: u32 = 0;
    let mut last_signal: Option<tokio::time::Instant> = None;
    let mut ticker = tokio::time::interval(params.window);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    ticker.tick().await; // consume the immediate first tick

    loop {
        ticker.tick().await;
        let in_now = monitor.in_bytes.load(Ordering::Relaxed);
        let out_now = monitor.out_bytes.load(Ordering::Relaxed);
        let backlog = monitor.backlog_seen.swap(false, Ordering::Relaxed);
        let in_rate = ((in_now.saturating_sub(prev_in)) as f64 / window_secs) as u64;
        let out_rate = ((out_now.saturating_sub(prev_out)) as f64 / window_secs) as u64;
        prev_in = in_now;
        prev_out = out_now;

        if window_is_throttled(in_rate, out_rate, backlog, &params) {
            sustain = sustain.saturating_add(1);
        } else {
            sustain = 0;
        }
        if sustain < params.sustain_windows {
            continue;
        }
        let now = tokio::time::Instant::now();
        let cooled = last_signal.is_none_or(|t| now.duration_since(t) >= params.signal_cooldown);
        if cooled {
            monitor.signal().notify_one();
            last_signal = Some(now);
            sustain = 0;
        }
    }
}

#[cfg(test)]
#[path = "tests/throughput_monitor.rs"]
mod tests;
