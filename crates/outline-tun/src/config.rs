use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct TunConfig {
    pub path: PathBuf,
    pub name: Option<String>,
    pub mtu: usize,
    pub max_flows: usize,
    pub idle_timeout: Duration,
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
}

#[derive(Debug, Clone)]
pub struct TunTcpConfig {
    pub connect_timeout: Duration,
    pub handshake_timeout: Duration,
    pub half_close_timeout: Duration,
    pub max_pending_server_bytes: usize,
    pub backlog_abort_grace: Duration,
    pub backlog_hard_limit_multiplier: usize,
    pub backlog_no_progress_abort: Duration,
    pub max_buffered_client_segments: usize,
    pub max_buffered_client_bytes: usize,
    pub max_retransmits: u32,
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
}
