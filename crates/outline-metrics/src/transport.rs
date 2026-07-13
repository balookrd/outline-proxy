use super::METRICS;
use prometheus::IntCounter;
use std::sync::LazyLock;
use std::time::Duration;

pub const DIRECT_UPLINK_LABEL: &str = "direct";
/// Group label used for traffic that routes outside all uplinks (direct route).
/// Kept distinct from uplink group names so Grafana can separate direct
/// traffic from tunnelled traffic by the `group` dimension alone.
pub const DIRECT_GROUP_LABEL: &str = "direct";

pub fn record_transport_connect(source: &'static str, mode: &'static str, result: &'static str) {
    METRICS
        .transport_connects_total
        .with_label_values(&[source, mode, result])
        .inc();
}

pub fn add_transport_connects_active(source: &'static str, mode: &'static str, delta: i64) {
    METRICS
        .transport_connects_active
        .with_label_values(&[source, mode])
        .add(delta);
}

pub fn record_upstream_transport(
    source: &'static str,
    protocol: &'static str,
    result: &'static str,
) {
    METRICS
        .upstream_transports_total
        .with_label_values(&[source, protocol, result])
        .inc();
}

pub fn add_upstream_transports_active(source: &'static str, protocol: &'static str, delta: i64) {
    METRICS
        .upstream_transports_active
        .with_label_values(&[source, protocol])
        .add(delta);
}

/// Adjust the per-uplink open-connection gauge. `transport` is the wire-side
/// label (`"tcp"` or `"udp"`); `delta` is `+1` on dial completion and `-1`
/// on close.
///
/// The gauge is the principal observability hook for "stranded sessions on
/// non-active uplinks" in `Global` / `PerUplink` modes — see
/// [`record_uplink_connection_close`] for the matching close-time counter.
pub fn add_uplink_open_connections(group: &str, transport: &str, uplink: &str, delta: i64) {
    METRICS
        .uplink_open_connections
        .with_label_values(&[group, transport, uplink])
        .add(delta);
}

/// Record an upstream-transport close, classified against the currently-active
/// uplink for this group + transport. `classification` should be one of
/// `"active"`, `"inactive"`, or `"unknown"`; passing other strings is allowed
/// but defeats the dashboard panel `Inactive uplink leak rate`.
///
/// Callers that own a binding should consult [`current_active_uplink`] and
/// pass the resolved tag rather than asserting against a stale snapshot.
///
/// [`current_active_uplink`]: crate::current_active_uplink
pub fn record_uplink_connection_close(
    group: &str,
    transport: &str,
    uplink: &str,
    classification: &'static str,
) {
    METRICS
        .uplink_connection_close_total
        .with_label_values(&[group, transport, uplink, classification])
        .inc();
}

pub fn record_request(command: &'static str) {
    METRICS.socks_requests_total.with_label_values(&[command]).inc();
}

pub fn add_bytes(
    protocol: &'static str,
    direction: &'static str,
    group: &str,
    uplink: &str,
    bytes: usize,
) {
    METRICS
        .bytes_total
        .with_label_values(&[protocol, direction, group, uplink])
        .inc_by(u64::try_from(bytes).unwrap_or(u64::MAX));
}

pub fn add_udp_datagram(direction: &'static str, group: &str, uplink: &str) {
    METRICS
        .udp_datagrams_total
        .with_label_values(&[direction, group, uplink])
        .inc();
}

// ── Pre-resolved byte / datagram counter handles ───────────────────────────
//
// `add_bytes` / `add_udp_datagram` hash their label tuple and probe the
// registry on every chunk / datagram. The relay hot paths resolve the concrete
// `IntCounter` once (per flow / per task / per uplink) via the handles below
// and then only touch the atomic, dropping the per-frame label hashing that
// the CPU audit flagged as the top data-plane cost. See
// [`crate::FailoverCounter`] for the mid-flow failover re-resolve invariant and
// the counter-vs-histogram caching caveat.

/// Pre-resolved [`outline_ws_bytes_total`] handle for one
/// `(protocol, direction, group, uplink)` series. Resolve once with
/// [`flow_bytes_counter`] and call [`add`](Self::add) on the hot loop; the
/// exported value is identical to the per-call [`add_bytes`] path.
///
/// [`outline_ws_bytes_total`]: crate
#[derive(Clone)]
pub struct FlowBytesCounter(IntCounter);

impl FlowBytesCounter {
    /// Adds `bytes` to the resolved counter (saturating at `u64::MAX`), exactly
    /// as [`add_bytes`] does.
    #[inline]
    pub fn add(&self, bytes: usize) {
        self.0.inc_by(u64::try_from(bytes).unwrap_or(u64::MAX));
    }
}

/// Resolves the [`FlowBytesCounter`] for one label tuple. The series and value
/// are identical to [`add_bytes`]; this only pre-pays the registry lookup so a
/// hot loop can cache the handle.
pub fn flow_bytes_counter(
    protocol: &str,
    direction: &str,
    group: &str,
    uplink: &str,
) -> FlowBytesCounter {
    FlowBytesCounter(
        METRICS
            .bytes_total
            .with_label_values(&[protocol, direction, group, uplink]),
    )
}

/// Pre-resolved datagram + byte counter pair for one UDP `(direction, group,
/// uplink)`. Every UDP relay site bumps both `outline_ws_udp_datagrams_total`
/// and `outline_ws_bytes_total{protocol="udp"}`, so they are bundled to resolve
/// together and stay in lock-step. Both are `IntCounter`s (cache-safe).
#[derive(Clone)]
pub struct UdpFlowCounters {
    datagrams: IntCounter,
    bytes: IntCounter,
}

impl UdpFlowCounters {
    /// Records one datagram carrying `bytes` payload — mirrors
    /// [`add_udp_datagram`] plus [`add_bytes`]`("udp", …)` in a single call.
    #[inline]
    pub fn record(&self, bytes: usize) {
        self.datagrams.inc();
        self.bytes.inc_by(u64::try_from(bytes).unwrap_or(u64::MAX));
    }
}

/// Resolves the [`UdpFlowCounters`] pair for one UDP label tuple. Equivalent to
/// resolving `udp_datagrams_total{direction,group,uplink}` and
/// `bytes_total{protocol="udp",direction,group,uplink}`.
pub fn udp_flow_counters(direction: &str, group: &str, uplink: &str) -> UdpFlowCounters {
    UdpFlowCounters {
        datagrams: METRICS
            .udp_datagrams_total
            .with_label_values(&[direction, group, uplink]),
        bytes: METRICS
            .bytes_total
            .with_label_values(&["udp", direction, group, uplink]),
    }
}

// Direct-route traffic carries the constant `(group, uplink) = (direct,
// direct)` labels, so its handles are process-global. Back each of the four
// cells with a `LazyLock` so a per-datagram direct read-loop (which has no
// per-task local to cache in) resolves the handle exactly once.
static DIRECT_TCP_UP: LazyLock<FlowBytesCounter> =
    LazyLock::new(|| flow_bytes_counter("tcp", "up", DIRECT_GROUP_LABEL, DIRECT_UPLINK_LABEL));
static DIRECT_TCP_DOWN: LazyLock<FlowBytesCounter> =
    LazyLock::new(|| flow_bytes_counter("tcp", "down", DIRECT_GROUP_LABEL, DIRECT_UPLINK_LABEL));
static DIRECT_UDP_UP: LazyLock<UdpFlowCounters> =
    LazyLock::new(|| udp_flow_counters("up", DIRECT_GROUP_LABEL, DIRECT_UPLINK_LABEL));
static DIRECT_UDP_DOWN: LazyLock<UdpFlowCounters> =
    LazyLock::new(|| udp_flow_counters("down", DIRECT_GROUP_LABEL, DIRECT_UPLINK_LABEL));

/// Cached [`FlowBytesCounter`] for direct-route TCP traffic. `direction` is
/// `"up"` (client→target) or `"down"` (target→client); any other value maps to
/// `"down"`.
pub fn direct_tcp_bytes(direction: &str) -> &'static FlowBytesCounter {
    match direction {
        "up" => &DIRECT_TCP_UP,
        _ => &DIRECT_TCP_DOWN,
    }
}

/// Cached [`UdpFlowCounters`] for direct-route UDP traffic. `direction` is
/// `"up"` / `"down"` as in [`direct_tcp_bytes`].
pub fn direct_udp_counters(direction: &str) -> &'static UdpFlowCounters {
    match direction {
        "up" => &DIRECT_UDP_UP,
        _ => &DIRECT_UDP_DOWN,
    }
}

pub fn record_dropped_oversized_udp_packet(direction: &'static str, cause: &'static str) {
    METRICS
        .udp_oversized_dropped_total
        .with_label_values(&[direction, cause])
        .inc();
}

pub fn record_uplink_selected(transport: &'static str, group: &str, uplink: &str) {
    METRICS
        .uplink_selected_total
        .with_label_values(&[transport, group, uplink])
        .inc();
}

pub fn record_runtime_failure(transport: &'static str, group: &str, uplink: &str) {
    METRICS
        .uplink_runtime_failures_total
        .with_label_values(&[transport, group, uplink])
        .inc();
}

pub fn record_runtime_failure_cause(
    transport: &'static str,
    group: &str,
    uplink: &str,
    cause: &'static str,
) {
    METRICS
        .uplink_runtime_failure_causes_total
        .with_label_values(&[transport, group, uplink, cause])
        .inc();
}

pub fn record_runtime_failure_signature(
    transport: &'static str,
    group: &str,
    uplink: &str,
    signature: &'static str,
) {
    METRICS
        .uplink_runtime_failure_signatures_total
        .with_label_values(&[transport, group, uplink, signature])
        .inc();
}

pub fn record_runtime_failure_other_detail(
    transport: &'static str,
    group: &str,
    uplink: &str,
    detail: &str,
) {
    METRICS
        .uplink_runtime_failure_other_details_total
        .with_label_values(&[transport, group, uplink, detail])
        .inc();
}

pub fn record_runtime_failure_suppressed(transport: &'static str, group: &str, uplink: &str) {
    METRICS
        .uplink_runtime_failures_suppressed_total
        .with_label_values(&[transport, group, uplink])
        .inc();
}

pub fn record_failover(transport: &'static str, group: &str, from_uplink: &str, to_uplink: &str) {
    METRICS
        .uplink_failovers_total
        .with_label_values(&[transport, group, from_uplink, to_uplink])
        .inc();
}

/// Counts SOCKS5 TCP sessions that were forcibly aborted because the active
/// uplink changed away from the one the session was pinned to (strict
/// `active_passive` mode). The session is closed with TCP RST so the client
/// reconnects through the new active uplink — see
/// `outline_ws_socks_tcp_strict_aborts_total`.
pub fn record_socks_tcp_strict_abort(group: &str, uplink: &str, reason: &'static str) {
    METRICS
        .socks_tcp_strict_aborts_total
        .with_label_values(&[group, uplink, reason])
        .inc();
}

/// Records the outcome of one mid-session retry attempt on the
/// pinned-relay path. `outcome` should be one of the canonical values
/// described on the `outline_ws_uplink_mid_session_retries_total`
/// metric registration:
/// - `success` — retry replayed the v1 uplink suffix and (when v2 was
///   engaged) the v2 downlink suffix without truncation;
/// - `failed_redial` — the redial itself or the v1/v2 control-frame
///   consume timed out / errored;
/// - `failed_replay` — the v1 uplink replay write failed mid-suffix;
/// - `buffer_overflow` — the v1 client-side ring buffer overflowed
///   under `tcp_mid_session_retry_overflow_policy = "soft"`;
/// - `downlink_truncated` — v2 was engaged and the server's `ORDR`
///   frame carried `REPLAY_TRUNCATED`; honoured under the same
///   overflow policy.
///
/// Passing other values is technically allowed (Prometheus does not
/// validate label cardinality at insert time) but defeats the
/// dashboard's pre-built panels.
pub fn record_mid_session_retry(
    transport: &'static str,
    group: &str,
    uplink: &str,
    outcome: &'static str,
) {
    METRICS
        .uplink_mid_session_retries_total
        .with_label_values(&[transport, group, uplink, outcome])
        .inc();
}

/// Counts one operator cluster soft-switch migration attempt for `group`, by
/// `outcome` (`migrated` / `redial_failed` / `not_ws_family` / `no_candidate` /
/// `same_uplink`). See `outline_ws_soft_switch_total`.
pub fn record_soft_switch(group: &str, outcome: &'static str) {
    METRICS.soft_switch_total.with_label_values(&[group, outcome]).inc();
}

/// Counts one resume-cache lookup at an uplink dial, by `transport`
/// (`tcp`/`udp`), `scope` (`group` for cluster `shared_resume`, else `uplink`)
/// and `result` (`hit`/`miss`). See `outline_ws_resume_lookup_total`.
pub fn record_resume_lookup(transport: &'static str, scope: &'static str, result: &'static str) {
    METRICS
        .resume_lookup_total
        .with_label_values(&[transport, scope, result])
        .inc();
}

pub fn record_probe(
    group: &str,
    uplink: &str,
    transport: &'static str,
    probe: &'static str,
    success: bool,
    duration: Duration,
) {
    METRICS
        .probe_runs_total
        .with_label_values(&[
            group,
            uplink,
            transport,
            probe,
            if success { "success" } else { "error" },
        ])
        .inc();
    METRICS
        .probe_duration_seconds
        .with_label_values(&[group, uplink, transport, probe])
        .observe(duration.as_secs_f64());
}

pub fn add_probe_bytes(
    group: &str,
    uplink: &str,
    transport: &'static str,
    probe: &'static str,
    direction: &'static str,
    bytes: usize,
) {
    METRICS
        .probe_bytes_total
        .with_label_values(&[group, uplink, transport, probe, direction])
        .inc_by(u64::try_from(bytes).unwrap_or(u64::MAX));
}

pub fn record_probe_wakeup(
    group: &str,
    uplink: &str,
    transport: &'static str,
    reason: &'static str,
    result: &'static str,
) {
    METRICS
        .probe_wakeups_total
        .with_label_values(&[group, uplink, transport, reason, result])
        .inc();
}

pub fn record_warm_standby_acquire(
    transport: &'static str,
    group: &str,
    uplink: &str,
    outcome: &'static str,
) {
    METRICS
        .warm_standby_acquire_total
        .with_label_values(&[transport, group, uplink, outcome])
        .inc();
}

pub fn record_warm_standby_refill(
    transport: &'static str,
    group: &str,
    uplink: &str,
    success: bool,
) {
    METRICS
        .warm_standby_refill_total
        .with_label_values(&[transport, group, uplink, if success { "success" } else { "error" }])
        .inc();
}

/// Record an HTTP request served by the control or metrics listener.
///
/// `path` must be a low-cardinality label — a known route like `"/metrics"` or
/// `"/switch"`, or `"other"` for unmatched paths. Never pass a raw request URI
/// here: it would let an external caller inflate the label set.
pub fn record_metrics_http_request(path: &'static str, status: u16) {
    METRICS
        .metrics_http_requests_total
        .with_label_values(&[path, status.to_string().as_str()])
        .inc();
}
