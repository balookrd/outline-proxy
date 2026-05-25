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
}
