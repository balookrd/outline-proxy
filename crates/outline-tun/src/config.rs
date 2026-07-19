use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct TunConfig {
    pub path: PathBuf,
    pub name: Option<String>,
    pub mtu: usize,
    pub max_flows: usize,
    pub idle_timeout: Duration,
    /// Process-wide cap on concurrent upstream dials, shared by the TCP and
    /// UDP engines. Every new tunnelled flow dials its upstream on its own
    /// task, so a flow burst used to launch one carrier handshake
    /// (TLS/WS/QUIC) per flow *simultaneously* — the super-linear term in the
    /// 2026-07-18 1 GiB-host livelock (~141 concurrent dials). With the cap,
    /// excess connect tasks queue for a permit (held only for the dial, never
    /// the flow's lifetime) and a burst handshakes in small waves; aggregate
    /// throughput is unchanged, only burst concurrency is smoothed. The
    /// client-side cost is microseconds per wave on loopback-scale dials.
    /// `0` disables the gate.
    pub max_concurrent_upstream_dials: usize,
    pub tcp: TunTcpConfig,
    /// Max concurrent IP fragment reassembly sets.
    pub defrag_max_fragment_sets: usize,
    /// Max fragment chunks per reassembly set before the set is dropped.
    pub defrag_max_fragments_per_set: usize,
    /// Max bytes buffered across all in-progress IP fragment reassembly sets.
    pub defrag_max_total_bytes: usize,
    /// Max bytes buffered per individual fragment set.
    pub defrag_max_bytes_per_set: usize,
    /// Hard-coded fast-path for IKE/IPsec NAT-T: when `true`, UDP flows whose
    /// destination port is 500 or 4500 bypass policy routing and resolve to
    /// `TunRoute::Direct` (same path as `via = "direct"`). VoWiFi and other
    /// IKEv2/IPsec clients rely on ESP datagrams that cannot be tunnelled
    /// through Outline transports — ESP-in-UDP packets are forwarded
    /// transparently by the direct socket; raw ESP (proto 50) is still
    /// dropped by the TUN classifier regardless. The direct path uses
    /// `direct_fwmark` to escape the TUN routing loop, so this option only
    /// works out-of-the-box in split-tunnel setups; with TUN catching the
    /// default route, set `direct_fwmark` and configure a corresponding
    /// `ip rule fwmark X lookup Y` table (Linux only).
    pub ipsec_bypass: bool,
    /// Whether the TUN UDP path is allowed to emit ICMP "Fragmentation
    /// Needed" / "Packet Too Big" replies that advertise a path MTU
    /// below QUIC v1's Initial-datagram minimum (1200 bytes IPv4 /
    /// 1280 bytes IPv6, RFC 9000 §14.1).
    ///
    /// Default `false`: such a PTB would tell compliant QUIC stacks
    /// that the destination cannot carry QUIC, evicting real QUIC
    /// traffic (YouTube, Google services, …) onto TCP. Sub-minimum
    /// oversize drops are silently absorbed instead, and the sender's
    /// own retransmit / timeout logic eventually adjusts.
    ///
    /// Set to `true` to restore unconditional PTB emission for
    /// deployments that prefer explicit PMTUD signalling on every
    /// sub-minimum drop — pure VoWiFi / IKEv2 concentrators with no
    /// QUIC clients to protect are the canonical case. The full
    /// trade-off is documented in `docs/TUN-PMTUD.md`.
    pub pmtud_emit_below_quic_initial: bool,
    /// QUIC connection sniffing (Xray-style destOverride for the UDP path).
    /// When `true` (default) the first datagram of a new tunnelled UDP flow is
    /// inspected: if it is a QUIC Initial, its (publicly decryptable)
    /// ClientHello SNI is recovered and the per-flow destination is rewritten
    /// from the literal IP into a `TargetAddr::Domain`, so subsequent datagrams
    /// of the flow leave over the tunnel carrying the *domain* and the exit
    /// node resolves it. Direct flows are never affected. Mirrors the TCP-path
    /// `[tun.tcp] sniffing` for QUIC.
    pub sniff_quic: bool,
    /// Domain suffixes excluded from sniff destination-override (Xray
    /// `domainsExcluded`). A sniffed host matching any suffix keeps the literal
    /// IP the client dialled instead of being rewritten to a domain — for sites
    /// where the client's own resolution is better than the exit's (the exit
    /// re-resolving lands on a geo-wrong / broken CDN edge). Suffix match:
    /// `strava.com` excludes `graphql.strava.com` and `cdn-1.strava.com`.
    /// Applies to both the TCP and QUIC sniff paths. Entries are pre-normalized
    /// (lowercased, leading dots stripped) at config load.
    pub sniff_override_exclude: Arc<[Box<str>]>,
    /// Open the TUN device with `IFF_VNET_HDR` so every `read(2)` / `write(2)`
    /// carries a 10-byte `virtio_net_hdr` prefix (Linux only). Default `true`.
    ///
    /// Phase 0 of TUN GSO: the header is present but always `GSO_NONE` (no
    /// checksum/segmentation offload), so on-wire behaviour is unchanged — this
    /// only validates the vnet plumbing on the running kernel + WireGuard path
    /// before TSO (writing MSS super-segments) is layered on. Ignored on
    /// non-Linux targets.
    pub gso: bool,
    /// Enable RX GRO for the uplink (`TUNSETOFFLOAD` with
    /// `TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6`, Linux only). Requires `gso`.
    /// With it the kernel coalesces inbound TCP into >MSS super-packets on
    /// read, which the TCP engine accepts whole — the read-path mirror of the
    /// downlink `gso` TSO win. `TUN_F_USO*` is deliberately NOT requested, so
    /// UDP stays per-datagram (the kernel re-segments it before we read); a UDP
    /// super-packet that does arrive is still handled (re-segmented) by the read
    /// loop. Defaults to the value of `gso`; the write-side TSO (`gso`) is
    /// unaffected when off, so GRO rolls back on its own. Ignored on non-Linux
    /// targets.
    pub gro: bool,
    /// Enable UDP USO on write (`TUNSETOFFLOAD` adds `TUN_F_USO4 | TUN_F_USO6`,
    /// Linux only). Requires `gso`. Coalesces equal-sized downlink UDP datagrams
    /// of one flow into a `GSO_UDP_L4` super-segment the kernel splits per
    /// datagram — the UDP mirror of the downlink TCP TSO win, aimed at bulk QUIC
    /// video. `TUN_F_USO` also lets the kernel hand us UDP GRO super-packets on
    /// read, which the read loop re-segments (`resegment_udp_gso`). Defaults to
    /// the value of `gso`; independent of `gro`. Ignored on non-Linux targets or kernels
    /// without USO (< 6.2) — the client logs and keeps TCP offload.
    pub uso: bool,
}

#[derive(Debug, Clone)]
pub struct TunTcpConfig {
    pub connect_timeout: Duration,
    pub handshake_timeout: Duration,
    pub half_close_timeout: Duration,
    pub max_pending_server_bytes: usize,
    /// Engine-wide ceiling on the *sum* of every flow's pending downlink
    /// bytes. `max_pending_server_bytes` bounds one flow, but N concurrent
    /// bulk downloads legally hold `N ×` that — enough to run a low-RAM host
    /// out of memory during a flow burst. While the sum is over this budget,
    /// all upstream readers park (same downlink-backpressure gate as the
    /// per-flow limit) until client ACKs drain the queues; nothing is
    /// aborted. `0` disables the global budget.
    pub pending_server_budget_bytes: usize,
    pub backlog_abort_grace: Duration,
    pub backlog_hard_limit_multiplier: usize,
    pub backlog_no_progress_abort: Duration,
    pub max_buffered_client_segments: usize,
    pub max_buffered_client_bytes: usize,
    /// Initial per-flow uplink receive window. A new flow advertises this much
    /// from the SYN-ACK and the pump grows the window toward
    /// `max_buffered_client_bytes` as bytes actually drain into the upstream —
    /// so a flow whose upstream is still dialling (or whose carrier is
    /// congested) can only buffer this much, not the full window. A burst of
    /// new flows therefore holds `N × this` instead of `N × 2 MiB`, which is
    /// what ran a 1 GiB host out of memory during the 2026-07-18 flow-burst
    /// livelock. The client terminates ~0 RTT away, so the ramp-up costs
    /// microseconds, not round trips. `0` disables auto-tuning: flows start at
    /// the full `max_buffered_client_bytes` as they always did.
    pub initial_receive_window_bytes: usize,
    pub max_retransmits: u32,
    /// Hard ceiling on the per-flow downlink send rate, in bytes/sec. Caps the
    /// BBR pacing rate (STARTUP overshoot included) so the stack never offers
    /// the last hop more than it can drain. `0` disables the cap.
    pub downlink_max_rate_bps: u64,
    /// Idle duration after which the stack emits a TCP keepalive probe
    /// (ACK with seq = SND.NXT−1, no payload). `None` disables keepalives.
    pub keepalive_idle: Option<Duration>,
    /// Spacing between subsequent keepalive probes once armed.
    pub keepalive_interval: Duration,
    /// Max unanswered keepalive probes before the flow is aborted with
    /// `keepalive_timeout`. Only consulted when `keepalive_idle` is `Some`.
    pub keepalive_max_probes: u32,
    /// Connection sniffing (Xray-style). When `true` (default) the TCP engine
    /// peeks the first client bytes of a tunnelled flow, extracts the
    /// destination host from the TLS ClientHello SNI or the HTTP `Host`
    /// header, and rewrites the dialled destination from the literal IP into a
    /// `TargetAddr::Domain` — so the request leaves over VLESS/Shadowsocks
    /// carrying the *domain* and the exit node resolves it. Direct flows are
    /// never affected (they need a literal IP). UDP/QUIC sniffing is not yet
    /// implemented.
    pub sniffing: bool,
    /// How long to wait for the first parseable client chunk before giving up
    /// and dialling by IP. Sniffable flows (TLS/HTTP) complete almost
    /// instantly because the TUN stack terminates the handshake locally; this
    /// timeout only bounds the wait for server-speaks-first protocols that
    /// never send a sniffable preface.
    pub sniff_timeout: Duration,
    /// Domain suffixes excluded from sniff destination-override. Shared with the
    /// QUIC path; see [`TunConfig::sniff_override_exclude`].
    pub sniff_override_exclude: Arc<[Box<str>]>,
    /// SNI bypass for the *direct* (`via = "direct"`) path. When `true` and a
    /// direct flow's first bytes carry a TLS SNI / HTTP Host, the host is
    /// re-resolved through this node's own (local) resolver and the connection
    /// is made to *that* IP instead of the literal IP the client dialled. Fixes
    /// the case where the client resolved a bypassed domain (via a tunnelled /
    /// foreign resolver) to an IP that is dead or unreachable from this node,
    /// while the node's local resolver returns a healthy one. `sniffing` must
    /// also be on. `sniff_override_exclude` still applies (excluded hosts keep
    /// the client's IP). Default `false` — direct keeps dialling the literal IP.
    pub sniff_direct_reresolve: bool,
    /// Carrier migration: when a tunnelled flow's shared carrier (one H3/H2/H1
    /// connection multiplexing many flows) dies, re-dial a fresh carrier, have
    /// the server re-attach the upstream it parked, replay the byte gap in both
    /// directions, and keep the flow running — instead of turning the dead
    /// carrier into a FIN/RST the application sees. Default `true`.
    ///
    /// It only ever engages on a **confirmed server-side resume hit** (the
    /// server emits the v1 Ack-Prefix control frame, which it does only when it
    /// really re-attached the parked upstream). A server with resumption
    /// disabled never mints a Session ID, so its flows are never even eligible
    /// — the knob is inert there, not merely harmless. Anything short of a
    /// confirmed hit (miss, expired park, replay gap, timeout) falls through to
    /// the unchanged teardown: a spliced byte stream is far worse than an honest
    /// disconnect. Set `false` to keep the pre-migration behaviour.
    pub carrier_migration: bool,
}

impl TunTcpConfig {
    /// The uplink receive window a brand-new flow starts with: the configured
    /// initial window clamped to the full buffer cap, or the full cap when
    /// auto-tuning is disabled (`initial_receive_window_bytes == 0`).
    pub fn initial_receive_window(&self) -> usize {
        if self.initial_receive_window_bytes == 0 {
            self.max_buffered_client_bytes
        } else {
            self.initial_receive_window_bytes.min(self.max_buffered_client_bytes)
        }
    }
}
