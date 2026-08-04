//! Loss counters read off a live carrier connection.
//!
//! Both carrier families already count what a lossy path costs — QUIC in
//! `PathStats`, TCP in `TCP_INFO` — so this module only reads and normalises
//! them. It answers exactly one question per carrier: how many packets have
//! been sent, how many were lost, and is the carrier still up. Differencing,
//! smoothing and attribution to an uplink all live in `outline-uplink`.
//!
//! Values are cumulative per connection, never deltas: a missed sampling tick
//! then costs resolution, not correctness.

#[cfg(target_os = "linux")]
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
#[cfg(feature = "h3")]
use std::sync::Weak;

/// One reading of a carrier's cumulative loss counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CarrierLossSample {
    /// Packets (QUIC) or segments (TCP) sent since the carrier was created.
    pub sent: u64,
    /// Packets declared lost (QUIC) or segments retransmitted (TCP) since the
    /// carrier was created. TCP retransmits include spurious ones; the quantity
    /// being compared is relative pressure between candidate paths, and for
    /// that they are the right measure.
    pub lost: u64,
    /// Whether the carrier is still established. A `false` here is what evicts
    /// the probe from the registry that holds it.
    pub alive: bool,
}

/// A carrier that can report its own loss counters. Implemented by the
/// connection wrappers themselves (`SharedH3Connection`, the XHTTP-over-H3
/// carrier), so a probe can read a carrier without keeping it alive: the
/// probe holds a `Weak<dyn CarrierLossCounters>`, and when the transport
/// drops its last strong reference the carrier closes normally — quinn's
/// implicit close-on-drop, the endpoint's UDP socket teardown, all of it —
/// and the probe starts reporting itself dead instead of pinning any of that
/// open.
pub trait CarrierLossCounters: Send + Sync {
    /// Read this carrier's current counters. `None` means the carrier is
    /// still alive but its counters could not be read right now (mirrors
    /// `CarrierLossProbe::sample`'s "no sample this tick" contract). A
    /// carrier that has actually gone away is not represented here at all —
    /// that case is handled one layer up, by the `Weak`'s `upgrade()` failing
    /// before this method is ever called.
    fn loss_counters(&self) -> Option<CarrierLossSample>;
}

/// A handle that can read [`CarrierLossSample`] from a carrier.
///
/// The TCP variant retains a handle (a duplicated fd) to the carrier for as
/// long as this probe is registered, which is exactly what lets a
/// registration outlive the code that originally dialed the carrier — but it
/// also means an abandoned probe (a retired wire, or a standby that stopped
/// being dialed) keeps that carrier from tearing down on its own. The
/// registry that holds these probes is responsible for evicting one once it
/// goes stale — see `outline_uplink::loss::MAX_IDLE_TICKS` — which is what
/// actually lets a TCP carrier close.
///
/// The QUIC variant does not have this problem: it observes through a `Weak`
/// (see [`CarrierLossCounters`]), so it never extends the carrier's life in
/// the first place — staleness eviction still applies to it (belt and
/// braces), but nothing here depends on it for QUIC to close on its own.
#[derive(Debug)]
pub enum CarrierLossProbe {
    /// QUIC carrier (`ws_h3`, `xhttp_h3`). `counters` is a `Weak` handle onto
    /// the connection wrapper that owns the real `quinn::Connection` (see
    /// [`CarrierLossCounters`]) — upgrading it fails, rather than reading
    /// stale data, once the transport has dropped its last strong reference.
    /// `identity` is captured once at construction, independent of
    /// `counters`, so it stays answerable even after the carrier is gone: the
    /// registry needs to recognise (and evict) a probe whose `counters` no
    /// longer upgrade.
    #[cfg(feature = "h3")]
    Quic {
        counters: Weak<dyn CarrierLossCounters>,
        identity: u64,
    },
    /// TCP carrier (`ws`, `h2`, `xhttp` over TLS/TCP). Holds a **duplicate** of
    /// the carrier's descriptor: without the `dup`, once the carrier closes the
    /// fd number is recycled by an unrelated socket and this probe would report
    /// that stranger's statistics as the uplink's. `identity` is computed once
    /// at capture time (see [`tcp_identity`]) and copied by `try_clone`, rather
    /// than recomputed from the fd, so `identity()` stays infallible.
    ///
    /// A milder version of the QUIC problem above applies here too: as long
    /// as this duplicate is outstanding, the transport's own close of its fd
    /// does not send a FIN (the duplicate keeps the underlying open file
    /// description referenced), so the connection lingers half-closed until
    /// eviction drops this handle. Unlike QUIC this self-heals even without
    /// eviction — TCP carries no client-driven keepalive once the transport
    /// layer above has abandoned it, so the peer's own read-idle watchdog
    /// eventually closes its side and the OS reclaims the rest.
    #[cfg(target_os = "linux")]
    Tcp { fd: OwnedFd, identity: u64 },
}

impl CarrierLossProbe {
    /// Duplicate `stream`'s descriptor into a probe. `None` when the duplicate
    /// cannot be made (fd limit), the socket's addresses cannot be read, or on
    /// a platform without `TCP_INFO` — loss measurement is best-effort and must
    /// never fail a dial.
    #[cfg(target_os = "linux")]
    pub fn from_tcp_stream(stream: &tokio::net::TcpStream) -> Option<Self> {
        let identity = tcp_identity(stream)?;
        let fd = stream.as_fd().try_clone_to_owned().ok()?;
        Some(Self::Tcp { fd, identity })
    }

    /// Non-Linux builds (developer machines) have no `TCP_INFO`; the client
    /// only ships on Linux, so the signal is simply absent there.
    #[cfg(not(target_os = "linux"))]
    pub fn from_tcp_stream(_stream: &tokio::net::TcpStream) -> Option<Self> {
        None
    }

    /// A second handle onto the same carrier. Used where one shared connection
    /// backs many streams and each dial wants its own registration. Cloning
    /// the QUIC variant only clones the `Weak` (and the `Copy` identity), so
    /// it never adds a strong reference to the carrier.
    pub fn try_clone(&self) -> Option<Self> {
        match self {
            #[cfg(feature = "h3")]
            Self::Quic { counters, identity } => Some(Self::Quic {
                counters: counters.clone(),
                identity: *identity,
            }),
            #[cfg(target_os = "linux")]
            Self::Tcp { fd, identity } => {
                fd.try_clone().ok().map(|fd| Self::Tcp { fd, identity: *identity })
            },
            // See the matching wildcard arm in `sample` above: only reached on
            // a build with neither variant, where `CarrierLossProbe` is empty.
            #[cfg(not(any(feature = "h3", target_os = "linux")))]
            _ => None,
        }
    }

    /// A number that identifies the underlying carrier, equal for any two
    /// handles on the same connection (including a `try_clone` of each
    /// other) and (with overwhelming probability) different across distinct
    /// carriers. This is what lets a registry recognise a shared H2/H3
    /// connection arriving a second time — via another session's probe — as
    /// the same carrier rather than counting its traffic twice. Infallible
    /// and syscall-free: it never queries the socket, only what was captured
    /// or handed to it at construction time.
    pub fn identity(&self) -> u64 {
        match self {
            // Captured once at construction (quinn's `stable_id()` for the
            // QUIC variant) and copied by `try_clone`, never re-derived
            // through `counters` — the registry must still recognise this
            // probe by identity after the carrier, and therefore the `Weak`,
            // is dead.
            #[cfg(feature = "h3")]
            Self::Quic { identity, .. } => *identity,
            #[cfg(target_os = "linux")]
            Self::Tcp { identity, .. } => *identity,
            // Neither variant exists on this build: see the wildcard arm in
            // `sample` below for why this is unreachable rather than absent,
            // and why it still needs an arm.
            #[cfg(not(any(feature = "h3", target_os = "linux")))]
            _ => unreachable!("CarrierLossProbe is uninhabited on this build"),
        }
    }

    /// Read the carrier's current counters. `None` when the carrier is alive
    /// but cannot be queried right now (kernel too old to report
    /// `tcpi_segs_out`, `getsockopt` failure) — a transient gap that may well
    /// clear on the next tick. A carrier that has actually gone away is a
    /// *different* fact, not a queryable-but-empty one, so it is reported as
    /// `Some(sample)` with `alive: false` — never as `None` — with `sent` and
    /// `lost` left at `0` rather than guessed at: the registry differences
    /// this reading against the last real one it saw
    /// (`current.saturating_sub(previous)`), and `0` is the one value that
    /// can never read as genuine traffic, so the final tick before eviction
    /// never fabricates a delta out of a carrier nobody can query anymore.
    pub fn sample(&self) -> Option<CarrierLossSample> {
        match self {
            #[cfg(feature = "h3")]
            Self::Quic { counters, .. } => match counters.upgrade() {
                Some(counters) => counters.loss_counters(),
                // The transport dropped its last strong reference: the
                // carrier is definitively gone, which is a different fact
                // from "could not read it this tick" — see the doc comment
                // above for why that is reported as a dead sample rather
                // than as `None`.
                None => Some(CarrierLossSample { sent: 0, lost: 0, alive: false }),
            },
            #[cfg(target_os = "linux")]
            Self::Tcp { fd, .. } => sample_tcp_info(fd),
            // Neither variant exists on this build (non-Linux without the
            // `h3` feature, e.g. a plain `cargo check -p outline-transport`
            // on a developer macOS machine): `CarrierLossProbe` is an empty
            // type, but a `match` on a *reference* to an empty type still
            // needs an arm to be considered exhaustive. `#[cfg]`-gating this
            // wildcard keeps it from ever shadowing a real variant on builds
            // where one exists (which would trip `unreachable_patterns`).
            #[cfg(not(any(feature = "h3", target_os = "linux")))]
            _ => None,
        }
    }
}

/// Derive a stable identity for a TCP carrier from its 4-tuple (local and
/// peer addresses), computed once while the live socket is still reachable
/// at capture time. Deliberately not derived from the fd number: `try_clone`
/// hands out a different fd for the same carrier, which is exactly the case
/// this identity must recognise as equal. `None` when the socket cannot
/// report its own addresses — best-effort, must never fail a dial.
#[cfg(target_os = "linux")]
fn tcp_identity(stream: &tokio::net::TcpStream) -> Option<u64> {
    use std::hash::{Hash, Hasher};

    let local = stream.local_addr().ok()?;
    let peer = stream.peer_addr().ok()?;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    local.hash(&mut hasher);
    peer.hash(&mut hasher);
    Some(hasher.finish())
}

/// Kernel `struct tcp_info`, truncated at the fields we read.
///
/// Declared here rather than taken from `libc` on purpose: under `linux-gnu`
/// `libc::tcp_info` stops at `tcpi_total_retrans` and has no `tcpi_segs_out`,
/// while under musl it has both. The fleet builds musl and CI builds gnu, so
/// `libc::tcp_info` would compile in one and break the other. The kernel only
/// ever appends to this struct and reports how many bytes it wrote, so reading
/// a prefix is the documented, forward-compatible contract.
#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct KernelTcpInfo {
    tcpi_state: u8,
    tcpi_ca_state: u8,
    tcpi_retransmits: u8,
    tcpi_probes: u8,
    tcpi_backoff: u8,
    tcpi_options: u8,
    tcpi_snd_rcv_wscale: u8,
    tcpi_delivery_fastopen_bitfields: u8,
    tcpi_rto: u32,
    tcpi_ato: u32,
    tcpi_snd_mss: u32,
    tcpi_rcv_mss: u32,
    tcpi_unacked: u32,
    tcpi_sacked: u32,
    tcpi_lost: u32,
    tcpi_retrans: u32,
    tcpi_fackets: u32,
    tcpi_last_data_sent: u32,
    tcpi_last_ack_sent: u32,
    tcpi_last_data_recv: u32,
    tcpi_last_ack_recv: u32,
    tcpi_pmtu: u32,
    tcpi_rcv_ssthresh: u32,
    tcpi_rtt: u32,
    tcpi_rttvar: u32,
    tcpi_snd_ssthresh: u32,
    tcpi_snd_cwnd: u32,
    tcpi_advmss: u32,
    tcpi_reordering: u32,
    tcpi_rcv_rtt: u32,
    tcpi_rcv_space: u32,
    tcpi_total_retrans: u32,
    tcpi_pacing_rate: u64,
    tcpi_max_pacing_rate: u64,
    tcpi_bytes_acked: u64,
    tcpi_bytes_received: u64,
    tcpi_segs_out: u32,
    tcpi_segs_in: u32,
}

/// `tcpi_state` value for an established connection (kernel `TCP_ESTABLISHED`).
/// `libc` only defines this constant for hurd, so it is spelled out here.
#[cfg(target_os = "linux")]
const TCP_STATE_ESTABLISHED: u8 = 1;

/// Byte offset one past `tcpi_segs_out`. A kernel that returned fewer bytes
/// than this did not report the send count, and without a denominator there is
/// no loss ratio to compute (`tcpi_segs_out` landed in Linux 4.2; the fleet
/// runs 6.1 and 6.8).
#[cfg(target_os = "linux")]
const TCP_INFO_MIN_LEN: libc::socklen_t = 140;

#[cfg(target_os = "linux")]
fn sample_tcp_info(fd: &OwnedFd) -> Option<CarrierLossSample> {
    let mut info = KernelTcpInfo::default();
    let mut len = std::mem::size_of::<KernelTcpInfo>() as libc::socklen_t;
    // SAFETY: `fd` is an owned, open descriptor borrowed for the duration of
    // this call. `info` is a live, correctly aligned `KernelTcpInfo` and `len`
    // is initialised to its exact size, so the kernel writes at most
    // `size_of::<KernelTcpInfo>()` bytes into it and updates `len` with how
    // many it actually wrote.
    let rc = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            std::ptr::from_mut(&mut info).cast(),
            &mut len,
        )
    };
    if rc != 0 || len < TCP_INFO_MIN_LEN {
        return None;
    }
    Some(CarrierLossSample {
        sent: u64::from(info.tcpi_segs_out),
        lost: u64::from(info.tcpi_total_retrans),
        alive: info.tcpi_state == TCP_STATE_ESTABLISHED,
    })
}

#[cfg(test)]
#[path = "tests/carrier_loss.rs"]
mod tests;
