//! Plain-data snapshot types that cross the boundary between the main
//! binary (producer of probe / uplink / process state) and the metrics
//! rendering code in this crate (consumer).
//!
//! Kept outside any feature gate so the producers in the main binary can
//! build these values regardless of whether the `prometheus` feature is
//! enabled — they just happen to be handed to a no-op renderer in that
//! case.

use serde::Serialize;

// ── Uplink snapshots ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct UplinkManagerSnapshot {
    /// Group this snapshot was generated for. Surfaced as the `group`
    /// Prometheus label on snapshot-rendered metrics.
    pub group: String,
    pub generated_at_unix_ms: u128,
    pub load_balancing_mode: String,
    pub routing_scope: String,
    pub auto_failback: bool,
    pub global_active_uplink: Option<String>,
    pub global_active_reason: Option<String>,
    /// Active uplink for TCP in per_uplink routing scope.
    pub tcp_active_uplink: Option<String>,
    pub tcp_active_reason: Option<String>,
    /// Active uplink for UDP in per_uplink routing scope.
    pub udp_active_uplink: Option<String>,
    pub udp_active_reason: Option<String>,
    pub uplinks: Vec<UplinkSnapshot>,
    pub sticky_routes: Vec<StickyRouteSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UplinkSnapshot {
    pub index: usize,
    pub name: String,
    /// Name of the uplink group this entry belongs to. Emitted as the
    /// `group` Prometheus label alongside `uplink`.
    pub group: String,
    /// Inner protocol / encapsulation (`ws`, `shadowsocks`, `vless`) — what
    /// payload format the uplink speaks. Surfaced on dashboards as the
    /// "encapsulation" layer.
    pub transport: String,
    /// Outer transport mode for TCP-style sessions (`ws_h1`, `ws_h2`,
    /// `ws_h3`, `quic`, `xhttp_h1`, `xhttp_h2`, `xhttp_h3`). `Some`
    /// whenever the uplink has a dial URL on TCP — i.e. for `ws` and
    /// `vless`. `None` for plain `shadowsocks`.
    pub tcp_mode: Option<String>,
    /// Outer transport mode for UDP-style sessions. Same semantics as
    /// `tcp_mode`. `Some` only when the uplink supports UDP via WS/QUIC.
    pub udp_mode: Option<String>,
    pub weight: f64,
    pub tcp_healthy: Option<bool>,
    pub udp_healthy: Option<bool>,
    /// Effective health on this transport — `tcp_healthy` (probe-only) OR
    /// "any wire recently dialed successfully" for uplinks with at least
    /// one fallback configured. Single-wire uplinks have this equal to
    /// `tcp_healthy`. The point is "visualization truth": an uplink whose
    /// primary wire is down but whose fallback is doing the actual work
    /// shows `Some(true)` here even though `tcp_healthy` is `Some(false)`.
    /// Dashboards that just want "is this uplink delivering traffic?"
    /// should read this field; dashboards that specifically care about
    /// the primary wire's probe verdict should keep reading `tcp_healthy`.
    /// `None` when neither signal has produced a verdict yet (e.g. a
    /// just-started instance whose first probe cycle hasn't completed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_health_effective: Option<bool>,
    /// UDP counterpart to [`Self::tcp_health_effective`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_health_effective: Option<bool>,
    pub tcp_latency_ms: Option<u128>,
    pub udp_latency_ms: Option<u128>,
    pub tcp_rtt_ewma_ms: Option<u128>,
    pub udp_rtt_ewma_ms: Option<u128>,
    /// RTT EWMA for the wire that **new TCP sessions** currently land on
    /// (i.e. `tcp_active_wire`). Equals `tcp_rtt_ewma_ms` when the active
    /// wire is primary; reads the corresponding per-fallback-wire slot
    /// when the dial loop / probe walk has flipped onto a fallback. The
    /// legacy `tcp_rtt_ewma_ms` field stays primary-only for the
    /// Prometheus consumers that already rely on its semantics; the
    /// dashboard prefers this field so the operator sees the latency of
    /// the wire actually carrying traffic.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_active_wire_rtt_ewma_ms: Option<u128>,
    /// UDP counterpart to [`Self::tcp_active_wire_rtt_ewma_ms`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_active_wire_rtt_ewma_ms: Option<u128>,
    pub tcp_penalty_ms: Option<u128>,
    pub udp_penalty_ms: Option<u128>,
    pub tcp_effective_latency_ms: Option<u128>,
    pub udp_effective_latency_ms: Option<u128>,
    pub tcp_score_ms: Option<u128>,
    pub udp_score_ms: Option<u128>,
    pub cooldown_tcp_ms: Option<u128>,
    pub cooldown_udp_ms: Option<u128>,
    pub last_checked_ago_ms: Option<u128>,
    pub last_error: Option<String>,
    pub standby_tcp_ready: usize,
    pub standby_udp_ready: usize,
    pub tcp_consecutive_failures: u32,
    pub udp_consecutive_failures: u32,
    pub h3_tcp_downgrade_until_ms: Option<u128>,
    pub h3_udp_downgrade_until_ms: Option<u128>,
    /// Family-aware ceiling carrier the dispatcher returns from
    /// `effective_tcp_mode` while the per-uplink downgrade window is
    /// active (see `h3_tcp_downgrade_until_ms`). `Some` only when the
    /// window is set; `None` clears to whatever `tcp_mode` carries.
    /// Stringified `TransportMode` (`ws_h2`, `xhttp_h2`, `xhttp_h1`).
    pub tcp_mode_capped_to: Option<String>,
    /// UDP counterpart to [`Self::tcp_mode_capped_to`].
    pub udp_mode_capped_to: Option<String>,
    /// XHTTP submode the TCP dial URL configures (`packet-up` or
    /// `stream-one`, parsed from the `?mode=` query). `None` for
    /// non-XHTTP transports — the concept does not apply outside the
    /// XHTTP family.
    pub tcp_xhttp_submode: Option<String>,
    /// UDP counterpart to [`Self::tcp_xhttp_submode`].
    pub udp_xhttp_submode: Option<String>,
    /// Milliseconds remaining on the per-host stream-one block in the
    /// XHTTP submode cache for the TCP dial URL. `Some(_)` when a
    /// recent stream-one failure has clamped subsequent dials to
    /// packet-up; `None` when stream-one is currently allowed (or the
    /// uplink is not XHTTP, or the URL is not configured for
    /// stream-one in the first place).
    pub tcp_xhttp_submode_block_remaining_ms: Option<u128>,
    /// UDP counterpart to [`Self::tcp_xhttp_submode_block_remaining_ms`].
    pub udp_xhttp_submode_block_remaining_ms: Option<u128>,
    pub last_active_tcp_ago_ms: Option<u128>,
    pub last_active_udp_ago_ms: Option<u128>,
    /// Ordered list of fallback transport names configured under
    /// `[[outline.uplinks.fallbacks]]` for this uplink. Empty when no
    /// fallbacks are configured. Surfaced on the dashboard as a chip chain
    /// next to the uplink name (e.g. `vless → ws → ss`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub configured_fallbacks: Vec<String>,
    /// Ordered, fully-resolved view of every wire on this uplink — primary
    /// at index 0 followed by `fallbacks[0..]`. Each entry exposes the
    /// transport family and the configured TCP / UDP mode for that wire,
    /// so the dashboard's top pill can render the **active wire**'s mode
    /// (e.g. `VLESS/WS/H2` when `tcp_active_wire == 1` and the first
    /// fallback is `vless` over `ws_h2`) rather than primary's mode.
    /// Without this, the snapshot only carried per-fallback transport
    /// strings, forcing the dashboard to fall back to the bare transport
    /// label and lose the carrier shape that the chain visualisation
    /// otherwise depends on.
    ///
    /// Always exactly `1 + configured_fallbacks.len()` entries when
    /// fallbacks are configured; empty (skipped on the wire) when no
    /// fallbacks exist — single-wire uplinks already carry their primary
    /// mode in the existing `tcp_mode` / `udp_mode` fields.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub configured_wire_chain: Vec<WireSnapshot>,
    /// Index into `[primary, fallbacks[0], ..., fallbacks[N-1]]` of the
    /// wire that **new TCP sessions** start with. `0` is primary; non-zero
    /// means a sticky-fallback is in effect after consecutive primary
    /// failures. Always `0` for uplinks without fallbacks.
    #[serde(default, skip_serializing_if = "is_zero_u8")]
    pub tcp_active_wire: u8,
    /// UDP counterpart to [`Self::tcp_active_wire`].
    #[serde(default, skip_serializing_if = "is_zero_u8")]
    pub udp_active_wire: u8,
    /// Milliseconds remaining on the TCP active-wire pin: time until the
    /// active wire snaps back to primary. `Some(_)` only while a non-primary
    /// wire is sticky; `None` when active is on primary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_active_wire_pin_remaining_ms: Option<u128>,
    /// UDP counterpart to [`Self::tcp_active_wire_pin_remaining_ms`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_active_wire_pin_remaining_ms: Option<u128>,
}

#[doc(hidden)]
fn is_zero_u8(v: &u8) -> bool {
    *v == 0
}

/// One entry in [`UplinkSnapshot::configured_wire_chain`]. Represents a
/// single wire (primary OR a fallback) with the transport family,
/// configured TCP / UDP mode strings, the **effective** modes after the
/// per-wire mode-downgrade window is applied (so a fallback wire that
/// has been capped from `xhttp_h3` to `xhttp_h2` shows the cap here),
/// and per-wire XHTTP submode state (configured submode + remaining
/// block on stream-one).
///
/// `*_mode` / `*_mode_effective` are `None` for Shadowsocks wires —
/// those don't carry a TransportMode enum (their TCP/UDP shape is fixed
/// by the address fields). `*_xhttp_submode*` are `None` for non-VLESS
/// wires (only XHTTP carriers under VLESS have a submode axis).
#[derive(Debug, Clone, Serialize)]
pub struct WireSnapshot {
    pub transport: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_mode: Option<String>,
    /// Effective TCP mode after the per-wire mode-downgrade slot is
    /// applied. Equals `tcp_mode` when no downgrade is active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_mode_effective: Option<String>,
    /// `true` when this wire is currently serving a downgraded TCP
    /// carrier (`tcp_mode_effective` ranks below `tcp_mode`). Skipped
    /// from the wire when `false` to keep the JSON small.
    #[serde(default, skip_serializing_if = "is_false")]
    pub tcp_downgrade_active: bool,
    /// Configured XHTTP submode on this wire's TCP dial URL — `(S)` for
    /// stream-one, `(P)` for packet-up, `None` for non-XHTTP wires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_xhttp_submode: Option<String>,
    /// Remaining time on this wire's per-host stream-one block. `Some`
    /// means a recent stream-one failure has the next dial silently
    /// served by packet-up; `None` means stream-one is dial-able.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_xhttp_submode_block_remaining_ms: Option<u128>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_mode_effective: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub udp_downgrade_active: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_xhttp_submode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_xhttp_submode_block_remaining_ms: Option<u128>,
}

#[doc(hidden)]
fn is_false(v: &bool) -> bool {
    !*v
}

#[derive(Debug, Clone, Serialize)]
pub struct StickyRouteSnapshot {
    pub key: String,
    pub uplink_index: usize,
    pub uplink_name: String,
    pub expires_in_ms: u128,
}

// ── Process-memory snapshots ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ProcessMemorySnapshot {
    pub rss_bytes: Option<u64>,
    pub virtual_bytes: Option<u64>,
    pub heap_bytes: Option<u64>,
    pub heap_allocated_bytes: Option<u64>,
    pub heap_free_bytes: Option<u64>,
    pub heap_mode: &'static str,
    pub open_fds: Option<u64>,
    pub thread_count: Option<u64>,
    pub fd_snapshot: Option<ProcessFdSnapshot>,
}

impl Default for ProcessMemorySnapshot {
    fn default() -> Self {
        Self {
            rss_bytes: None,
            virtual_bytes: None,
            heap_bytes: None,
            heap_allocated_bytes: None,
            heap_free_bytes: None,
            heap_mode: "unavailable",
            open_fds: None,
            thread_count: None,
            fd_snapshot: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ProcessFdSnapshot {
    pub total: u64,
    pub sockets: u64,
    pub pipes: u64,
    pub anon_inodes: u64,
    pub regular_files: u64,
    pub other: u64,
    /// Per-(protocol, family, state) counts of TCP/UDP sockets currently
    /// owned by this process. See the producer in the main binary for the
    /// precise Linux-specific sampling rules.
    pub socket_states: Option<Vec<SocketStateCount>>,
}

#[derive(Debug, Clone)]
pub struct SocketStateCount {
    pub protocol: &'static str,
    pub family: &'static str,
    pub state: &'static str,
    pub count: u64,
}
