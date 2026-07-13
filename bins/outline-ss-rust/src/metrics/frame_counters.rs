//! Pre-resolved WebSocket binary-frame counter handles for the relay hot path.
//!
//! [`super::Metrics::record_websocket_binary_frame`] runs on every binary
//! WebSocket frame in both directions across every transport (Shadowsocks /
//! VLESS over WS / XHTTP / H3, TCP and UDP). Resolving the two payload counters
//! via `counter!(...)` there pays a registry lookup — label hashing over four
//! `&'static str` labels plus a sharded `HashMap` probe — on every frame. At
//! 40–60 Mbit that is the dominant data-plane CPU cost.
//!
//! The label set is a bounded enum product (`transport × protocol ×
//! app_protocol × direction` = 2×7×2×2 = 56 rows) and process-global (not
//! per-user), so we cache one [`metrics::Counter`] pair per cell in a
//! lazily-populated static matrix, mirroring
//! [`super::user_counters::PerUserCounters`]. The hot path becomes one array
//! index + `OnceLock::get_or_init` (an acquire load after the first frame) +
//! the final atomic add — no label hashing, no registry lock.
//!
//! Only the two *counters* are cached. The companion `frame_size_bytes`
//! histogram is deliberately left resolving through `histogram!` per call:
//! histograms are the only metric kind under idle-eviction
//! (`MetricKindMask::HISTOGRAM` in [`super::registry`]), so a long-lived cached
//! histogram handle whose series got evicted would keep buffering samples the
//! renderer never drains again — silently losing data. Counters are never
//! idle-evicted, so caching their handles preserves the exported values
//! bit-for-bit. Series still appear on first use (lazy `get_or_init`), so
//! `/metrics` output is identical to the previous per-call `counter!` path.

use std::sync::OnceLock;

use metrics::{Counter, counter, with_local_recorder};
use metrics_exporter_prometheus::PrometheusRecorder;

use super::labels::{AppProtocol, Protocol, Transport};

const TRANSPORT_VARIANTS: usize = Transport::VARIANTS_COUNT;
const PROTOCOL_VARIANTS: usize = Protocol::VARIANTS_COUNT;
const APP_PROTOCOL_VARIANTS: usize = AppProtocol::VARIANTS_COUNT;
const DIRECTION_VARIANTS: usize = 2;

/// Canonical `direction` label values, indexed by [`direction_index`]. Reusing
/// these when building a handle guarantees the emitted label is exactly `up` /
/// `down` regardless of the (already-`&'static`) value the caller passed.
const DIRECTIONS: [&str; DIRECTION_VARIANTS] = ["up", "down"];

#[inline]
fn direction_index(direction: &str) -> usize {
    match direction {
        "up" => 0,
        // Every call-site passes a `"up"`/`"down"` literal; treat anything else
        // as `down` rather than panicking on the hot path.
        _ => 1,
    }
}

/// The two monotonic payload counters emitted per binary frame. Resolved once
/// per `(transport, protocol, app_protocol, direction)` cell, then incremented
/// directly in the relay loop.
pub(super) struct FrameCounters {
    frames: Counter,
    bytes: Counter,
}

impl FrameCounters {
    #[inline]
    pub(super) fn record(&self, bytes: usize) {
        self.frames.increment(1);
        self.bytes.increment(bytes as u64);
    }

    fn build(
        recorder: &PrometheusRecorder,
        transport: Transport,
        protocol: Protocol,
        app_protocol: AppProtocol,
        direction: &'static str,
    ) -> Self {
        with_local_recorder(recorder, || Self {
            frames: counter!(
                "outline_ss_websocket_frames_total",
                "transport"    => transport.as_str(),
                "protocol"     => protocol.as_str(),
                "app_protocol" => app_protocol.as_str(),
                "direction"    => direction
            ),
            bytes: counter!(
                "outline_ss_websocket_bytes_total",
                "transport"    => transport.as_str(),
                "protocol"     => protocol.as_str(),
                "app_protocol" => app_protocol.as_str(),
                "direction"    => direction
            ),
        })
    }
}

/// `[transport][protocol][app_protocol][direction]` lazy matrix of the binary
/// frame counter handles.
pub(super) struct FrameCounterMatrix {
    cells: [[[[OnceLock<FrameCounters>; DIRECTION_VARIANTS]; APP_PROTOCOL_VARIANTS];
        PROTOCOL_VARIANTS]; TRANSPORT_VARIANTS],
}

impl FrameCounterMatrix {
    pub(super) fn new() -> Self {
        Self {
            cells: std::array::from_fn(|_| {
                std::array::from_fn(|_| {
                    std::array::from_fn(|_| std::array::from_fn(|_| OnceLock::new()))
                })
            }),
        }
    }

    /// Returns the cached counter pair for one label combination, resolving and
    /// caching it on first use.
    pub(super) fn get(
        &self,
        recorder: &PrometheusRecorder,
        transport: Transport,
        protocol: Protocol,
        app_protocol: AppProtocol,
        direction: &str,
    ) -> &FrameCounters {
        let dir = direction_index(direction);
        let cell =
            &self.cells[transport.as_index()][protocol.as_index()][app_protocol.as_index()][dir];
        cell.get_or_init(|| {
            FrameCounters::build(recorder, transport, protocol, app_protocol, DIRECTIONS[dir])
        })
    }
}
