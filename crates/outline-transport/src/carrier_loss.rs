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

/// A handle that can read [`CarrierLossSample`] from a live carrier.
#[derive(Debug)]
pub enum CarrierLossProbe {
    /// QUIC carrier (`ws_h3`, `xhttp_h3`). The clone is cheap — a
    /// `quinn::Connection` is `Arc`-backed.
    #[cfg(feature = "h3")]
    Quic(quinn::Connection),
    /// TCP carrier (`ws`, `h2`, `xhttp` over TLS/TCP). Holds a **duplicate** of
    /// the carrier's descriptor: without the `dup`, once the carrier closes the
    /// fd number is recycled by an unrelated socket and this probe would report
    /// that stranger's statistics as the uplink's.
    #[cfg(target_os = "linux")]
    Tcp(OwnedFd),
}

impl CarrierLossProbe {
    /// Duplicate `stream`'s descriptor into a probe. `None` when the duplicate
    /// cannot be made (fd limit) or on a platform without `TCP_INFO` — loss
    /// measurement is best-effort and must never fail a dial.
    #[cfg(target_os = "linux")]
    pub fn from_tcp_stream(stream: &tokio::net::TcpStream) -> Option<Self> {
        stream.as_fd().try_clone_to_owned().ok().map(Self::Tcp)
    }

    /// Non-Linux builds (developer machines) have no `TCP_INFO`; the client
    /// only ships on Linux, so the signal is simply absent there.
    #[cfg(not(target_os = "linux"))]
    pub fn from_tcp_stream(_stream: &tokio::net::TcpStream) -> Option<Self> {
        None
    }

    /// A second handle onto the same carrier. Used where one shared connection
    /// backs many streams and each dial wants its own registration.
    pub fn try_clone(&self) -> Option<Self> {
        match self {
            #[cfg(feature = "h3")]
            Self::Quic(connection) => Some(Self::Quic(connection.clone())),
            #[cfg(target_os = "linux")]
            Self::Tcp(fd) => fd.try_clone().ok().map(Self::Tcp),
            // See the matching wildcard arm in `sample` above: only reached on
            // a build with neither variant, where `CarrierLossProbe` is empty.
            #[cfg(not(any(feature = "h3", target_os = "linux")))]
            _ => None,
        }
    }

    /// Read the carrier's current counters. `None` when the carrier cannot be
    /// queried at all (kernel too old to report `tcpi_segs_out`, `getsockopt`
    /// failure); the caller treats that as "no sample this tick".
    pub fn sample(&self) -> Option<CarrierLossSample> {
        match self {
            #[cfg(feature = "h3")]
            Self::Quic(connection) => {
                let path = connection.stats().path;
                Some(CarrierLossSample {
                    sent: path.sent_packets,
                    lost: path.lost_packets,
                    alive: connection.close_reason().is_none(),
                })
            },
            #[cfg(target_os = "linux")]
            Self::Tcp(fd) => sample_tcp_info(fd),
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
