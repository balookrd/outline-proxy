//! Env-gated per-flow downlink latency diagnostics ("ACK age", Step 1) and
//! egress-stall taxonomy (Step 2), plus the cwnd-inflation experiment (Step 3).
//!
//! Disabled unless `OUTLINE_TUN_DIAG_DST` names the remote endpoint of the flow
//! under test (`"1.2.3.4"` or `"1.2.3.4:443"`; bracketed IPv6 accepted). When
//! armed, fixed-bucket histograms accumulate and are dumped periodically via
//! `tracing` under target `outline_tun::diag`:
//!
//! * `ack_age` — a cleanly-acked segment's `first_sent` → the instant its
//!   cumulative ACK is processed (time-in-pipe).
//! * `read_to_lock` — TUN read → per-flow lock acquired (lock contention /
//!   read-loop head-of-line blocking).
//! * `read_to_apply` — TUN read → `apply_inbound_and_flush`: the full
//!   client-side ingress pipeline for this packet, the "wire → apply" the plan
//!   expects in the tens of ms.
//! * `emit_gap` — interval between consecutive flushes that emitted data.
//! * `stall_<reason>` — send-pause durations, one histogram per dominant cause
//!   (see [`record_flush_outcome`]): what the flush found itself blocked on
//!   while the pause lasted, or `nocall` when nothing invoked the flush at all
//!   (an event/wakeup hole). Each pause above the threshold also logs one
//!   "egress stall ended" line with the per-cause call counts and a state
//!   snapshot taken as the pause broke.
//!
//! Step 3: `OUTLINE_TUN_CWND_MULT` (float > 0) multiplies the BBR in-flight cap
//! in `congestion_window_remaining`, for the armed flow only. A/B lever for
//! "are the pauses created by the cwnd gate?" — peer window and pacing stay
//! untouched.
//!
//! This is throwaway instrumentation gated on a single env switch, so it is
//! effectively zero-cost when unset: [`armed`] is one `is_none` on a
//! `LazyLock<Option<..>>`, and the histograms are only touched for the armed
//! flow. There is no cardinality risk — a filter matches at most one endpoint.
//!
//! The dump is cumulative (never reset): read the *last* line emitted for the
//! run to get the aggregate. Cadence is one dump per `OUTLINE_TUN_DIAG_EVERY`
//! cleanly-acked segments (default 5000).

use std::net::{IpAddr, SocketAddr};
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tracing::info;

use super::state_machine::BbrMode;

/// Which flow the diagnostics are armed on, parsed once from
/// `OUTLINE_TUN_DIAG_DST`. `port == None` matches any port on the IP.
struct DiagFilter {
    ip: IpAddr,
    port: Option<u16>,
}

static FILTER: LazyLock<Option<DiagFilter>> = LazyLock::new(|| {
    let raw = std::env::var("OUTLINE_TUN_DIAG_DST").ok()?;
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    // `ip:port` (incl. bracketed IPv6) first, then a bare `ip`.
    if let Ok(sa) = raw.parse::<SocketAddr>() {
        return Some(DiagFilter { ip: sa.ip(), port: Some(sa.port()) });
    }
    match raw.parse::<IpAddr>() {
        Ok(ip) => Some(DiagFilter { ip, port: None }),
        Err(_) => {
            info!(
                target: "outline_tun::diag",
                value = raw,
                "ignoring unparseable OUTLINE_TUN_DIAG_DST (want ip or ip:port)"
            );
            None
        },
    }
});

static DUMP_EVERY: LazyLock<u64> = LazyLock::new(|| {
    std::env::var("OUTLINE_TUN_DIAG_EVERY")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(5000)
});

/// True when diagnostics are armed for this flow's remote endpoint. Cheap: an
/// `is_none` when unset, else an `IpAddr` compare plus an optional port compare.
#[inline]
pub(in crate::tcp) fn armed(remote_ip: IpAddr, remote_port: u16) -> bool {
    match FILTER.as_ref() {
        None => false,
        Some(f) => f.ip == remote_ip && f.port.is_none_or(|p| p == remote_port),
    }
}

// 2^0 .. 2^27 microseconds: 1 µs .. ~134 s, one bucket per power of two.
const BUCKETS: usize = 28;

struct Histogram {
    buckets: [AtomicU64; BUCKETS],
    count: AtomicU64,
    sum_us: AtomicU64,
}

impl Histogram {
    const fn new() -> Self {
        Histogram {
            buckets: [const { AtomicU64::new(0) }; BUCKETS],
            count: AtomicU64::new(0),
            sum_us: AtomicU64::new(0),
        }
    }

    fn record(&self, d: Duration) {
        let us = d.as_micros().min(u64::MAX as u128) as u64;
        // floor(log2(us)); us==0 lands in bucket 0.
        let idx = if us == 0 {
            0
        } else {
            (63 - us.leading_zeros() as usize).min(BUCKETS - 1)
        };
        self.buckets[idx].fetch_add(1, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_us.fetch_add(us, Ordering::Relaxed);
    }

    /// Upper-bound estimate (µs) of the `q`-quantile: the top edge of the bucket
    /// where the cumulative count crosses `q`. Coarse on purpose — the question
    /// is the order of magnitude (µs vs tens of ms), not a precise percentile.
    fn quantile_us(&self, q: f64, total: u64) -> u64 {
        if total == 0 {
            return 0;
        }
        let target = (q * total as f64).ceil() as u64;
        let mut cum = 0u64;
        for (i, b) in self.buckets.iter().enumerate() {
            cum += b.load(Ordering::Relaxed);
            if cum >= target {
                return 1u64 << (i + 1);
            }
        }
        1u64 << BUCKETS
    }

    fn snapshot(&self, name: &str) {
        let total = self.count.load(Ordering::Relaxed);
        if total == 0 {
            return;
        }
        let sum = self.sum_us.load(Ordering::Relaxed);
        info!(
            target: "outline_tun::diag",
            hist = name,
            count = total,
            mean_us = sum / total,
            p50_us = self.quantile_us(0.50, total),
            p90_us = self.quantile_us(0.90, total),
            p99_us = self.quantile_us(0.99, total),
            "diag histogram"
        );
    }
}

static ACK_AGE: Histogram = Histogram::new();
static READ_TO_LOCK: Histogram = Histogram::new();
static READ_TO_APPLY: Histogram = Histogram::new();
static SAMPLES: AtomicU64 = AtomicU64::new(0);

/// Record a cleanly-acked segment's time-in-pipe and, every `DUMP_EVERY`
/// samples, dump all three histograms. Called only for the armed flow.
pub(in crate::tcp) fn record_ack_age(d: Duration) {
    ACK_AGE.record(d);
    let n = SAMPLES.fetch_add(1, Ordering::Relaxed) + 1;
    if n.is_multiple_of(*DUMP_EVERY) {
        dump();
    }
}

pub(in crate::tcp) fn record_read_to_lock(d: Duration) {
    READ_TO_LOCK.record(d);
}

pub(in crate::tcp) fn record_read_to_apply(d: Duration) {
    READ_TO_APPLY.record(d);
}

fn dump() {
    ACK_AGE.snapshot("ack_age");
    READ_TO_LOCK.snapshot("read_to_lock");
    READ_TO_APPLY.snapshot("read_to_apply");
    EMIT_GAP.snapshot("emit_gap");
    for (i, h) in STALL_HISTS.iter().enumerate() {
        h.snapshot(STALL_NAMES[i]);
    }
}

// ---- Step 2: egress-stall taxonomy -----------------------------------------

/// The four bounds `flush_server_data` can block on, captured by the caller
/// right after a flush together with what the flush emitted. Plain numbers so
/// this module stays decoupled from the state machine internals.
pub(in crate::tcp) struct FlushSnapshot {
    /// Payload bytes the flush just emitted (0 = a blocked flush).
    pub(in crate::tcp) emitted: usize,
    /// `pending_server_data` bytes still queued.
    pub(in crate::tcp) pending: usize,
    /// `congestion_window_remaining` after the flush.
    pub(in crate::tcp) cwnd_remaining: usize,
    /// `send_window_remaining` (peer receive window minus pipe).
    pub(in crate::tcp) send_window: u32,
    /// Whether BBR pacing governs the flush (a BtlBw estimate exists).
    pub(in crate::tcp) pacing: bool,
    /// Pacing token-bucket credit, bytes.
    pub(in crate::tcp) pacing_credit: u64,
    /// Un-SACKed bytes in flight.
    pub(in crate::tcp) pipe: usize,
    /// BBR bottleneck-bandwidth estimate, bytes/s.
    pub(in crate::tcp) btlbw_bps: u64,
    /// BBR windowed-min RTT, µs.
    pub(in crate::tcp) min_rtt_us: u64,
    /// BBRv2 loss ceilings, bytes (`usize::MAX` = unset).
    pub(in crate::tcp) inflight_hi: usize,
    pub(in crate::tcp) inflight_lo: usize,
    pub(in crate::tcp) mode: BbrMode,
}

/// Blocked-flush causes, in classification order. `nocall` is virtual — a pause
/// with zero blocked calls, i.e. nothing invoked the flush while it lasted.
const STALL_NAMES: [&str; 6] = [
    "stall_pending_empty",
    "stall_cwnd",
    "stall_swnd",
    "stall_pacing",
    "stall_other",
    "stall_nocall",
];

fn classify(s: &FlushSnapshot) -> usize {
    if s.pending == 0 {
        0 // carrier/upstream did not feed us
    } else if s.cwnd_remaining == 0 {
        1 // congestion-window gate
    } else if s.send_window == 0 {
        2 // peer receive window
    } else if s.pacing && s.pacing_credit == 0 {
        3 // pacing token bucket
    } else {
        4
    }
}

/// A pause longer than this is an inter-run idle gap, not a stall; keep it out
/// of the histograms and the event log.
const IDLE_CUTOFF_US: u64 = 10_000_000;

static STALL_US: LazyLock<u64> = LazyLock::new(|| {
    std::env::var("OUTLINE_TUN_STALL_MS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(5)
        * 1000
});

static EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);
/// µs since [`EPOCH`] of the last data-emitting flush; 0 = none yet.
static LAST_EMIT_US: AtomicU64 = AtomicU64::new(0);
/// Blocked-flush calls per cause since the last data-emitting flush.
static BLOCKED: [AtomicU64; 5] = [const { AtomicU64::new(0) }; 5];
static EMIT_GAP: Histogram = Histogram::new();
static STALL_HISTS: [Histogram; 6] = [const { Histogram::new() }; 6];

fn kb(bytes: usize) -> usize {
    if bytes == usize::MAX { 0 } else { bytes / 1024 }
}

/// Fold one flush outcome into the stall taxonomy. Called only for the armed
/// flow, under its flow lock (so the statics see a serialized stream). A
/// blocked flush counts its cause; a data-emitting flush closes the interval,
/// and when that interval exceeds the threshold it is scored to the dominant
/// cause and logged with the snapshot taken as the pause broke.
pub(in crate::tcp) fn record_flush_outcome(s: FlushSnapshot) {
    if s.emitted == 0 {
        BLOCKED[classify(&s)].fetch_add(1, Ordering::Relaxed);
        return;
    }
    let now_us = EPOCH.elapsed().as_micros().min(u64::MAX as u128) as u64;
    let prev = LAST_EMIT_US.swap(now_us, Ordering::Relaxed);
    let counts: [u64; 5] = std::array::from_fn(|i| BLOCKED[i].swap(0, Ordering::Relaxed));
    if prev == 0 {
        return;
    }
    let gap_us = now_us.saturating_sub(prev);
    if gap_us >= IDLE_CUTOFF_US {
        return;
    }
    EMIT_GAP.record(Duration::from_micros(gap_us));
    if gap_us < *STALL_US {
        return;
    }
    let total: u64 = counts.iter().sum();
    let reason = if total == 0 {
        5
    } else {
        (0..5).max_by_key(|&i| counts[i]).expect("non-empty range")
    };
    STALL_HISTS[reason].record(Duration::from_micros(gap_us));
    info!(
        target: "outline_tun::diag",
        gap_us,
        reason = STALL_NAMES[reason],
        calls_pending_empty = counts[0],
        calls_cwnd = counts[1],
        calls_swnd = counts[2],
        calls_pacing = counts[3],
        calls_other = counts[4],
        pending_kb = s.pending / 1024,
        cwnd_rem_kb = s.cwnd_remaining / 1024,
        swnd_kb = s.send_window / 1024,
        pipe_kb = s.pipe / 1024,
        credit_kb = s.pacing_credit / 1024,
        btlbw_mbs = s.btlbw_bps / 1_000_000,
        min_rtt_us = s.min_rtt_us,
        inflight_hi_kb = kb(s.inflight_hi),
        inflight_lo_kb = kb(s.inflight_lo),
        mode = ?s.mode,
        "egress stall ended"
    );
}

// ---- Step 3: cwnd-inflation experiment --------------------------------------

static CWND_MULT: LazyLock<Option<f64>> = LazyLock::new(|| {
    let raw = std::env::var("OUTLINE_TUN_CWND_MULT").ok()?;
    match raw.trim().parse::<f64>() {
        Ok(m) if m > 0.0 && m.is_finite() => Some(m),
        _ => {
            info!(
                target: "outline_tun::diag",
                value = raw,
                "ignoring unparseable OUTLINE_TUN_CWND_MULT (want a positive float)"
            );
            None
        },
    }
});

/// The `OUTLINE_TUN_CWND_MULT` factor, if set. Appliers must still gate on
/// [`armed`] — the experiment targets the flow under test only.
#[inline]
pub(in crate::tcp) fn cwnd_mult() -> Option<f64> {
    *CWND_MULT
}
