# Carrier Loss As An Uplink-Selection Input — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Measure packet loss on the carrier socket itself, accumulate it as per-uplink/per-wire state visible in metrics and the control snapshot, and let it inflate the latency selection ranks by — disabled by default until field numbers justify a coefficient.

**Architecture:** `outline-transport` gains a `CarrierLossProbe` that reads cumulative loss counters from a live carrier (quinn `PathStats` for QUIC, `TCP_INFO` for TCP) and a `TransportStream::loss_probe()` accessor. `outline-uplink` registers a probe on every successful dial, differences the counters on a timer into a per-wire EWMA held in `PerTransportStatus`, publishes it, and multiplies `base_latency()` by `1 + k · loss_ratio`.

**Tech Stack:** Rust 2024, tokio, quinn 0.11 / quinn-proto 0.11.14, libc, prometheus.

Spec: [`docs/superpowers/specs/2026-08-03-uplink-loss-signal-design.md`](../specs/2026-08-03-uplink-loss-signal-design.md).

## Global Constraints

- CI gate, run locally before every commit, in this exact order:
  `cargo fmt --check -p outline-ss-rust -p outline-ws-rust -p outline-metrics -p outline-net -p outline-routing -p outline-transport -p outline-tun -p outline-uplink -p outline-wire -p shadowsocks-crypto -p socks5-proto`,
  then `cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings`,
  then `cargo test --workspace --exclude sockudo-ws`.
- Tests live in `tests/` subdirectories next to the module (`<dir>/tests/<basename>.rs`), wired with `#[cfg(test)] #[path = "tests/<basename>.rs"] mod tests;`. No inline `#[cfg(test)] mod tests {}`.
- Every `unsafe` block carries a `// SAFETY:` comment naming the concrete invariant — `undocumented_unsafe_blocks` is a workspace lint plus `-D warnings`.
- Commit messages, code comments and test names in English. Never add `Co-Authored-By: Claude` or any "Generated with Claude Code" attribution.
- User-facing docs are bilingual: `*.md` and `*.ru.md` change together.
- Default behaviour must not change: `loss_latency_penalty_k` defaults to `0.0`, and with it selection output is bit-for-bit what it is today.
- Nothing is deployed to the fleet as part of this plan.
- `quinn` lives behind the `h3` feature of `outline-transport`; every QUIC-touching item is `#[cfg(feature = "h3")]`.

---

### Task 1: Carrier loss probe (`outline-transport`)

The probe reads cumulative counters off a live carrier. Two facts drive the
implementation and are not negotiable:

1. **`libc`'s `tcp_info` is truncated on gnu.** Under `linux-gnu` the struct
   ends at `tcpi_total_retrans` — `tcpi_segs_out` does not exist there, while
   under musl it does. The fleet builds musl and CI builds gnu, so using
   `libc::tcp_info` compiles in one and fails in the other. Declare our own
   `#[repr(C)]` mirror of the kernel struct instead, and validate the length the
   kernel actually returned.
2. **The fd must be duplicated.** Borrowing the carrier's fd number means that
   once the carrier closes, the number is recycled by an unrelated socket and
   the sampler silently reports a stranger's statistics.

**Files:**
- Create: `crates/outline-transport/src/carrier_loss.rs`
- Create: `crates/outline-transport/src/tests/carrier_loss.rs`
- Modify: `crates/outline-transport/src/lib.rs` (add `mod carrier_loss;` next to the other `mod` declarations and re-export the public types in the "Entry points" block)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `pub enum CarrierLossProbe { #[cfg(feature = "h3")] Quic(quinn::Connection), #[cfg(target_os = "linux")] Tcp(OwnedFd) }`
  - `pub struct CarrierLossSample { pub sent: u64, pub lost: u64, pub alive: bool }` (`Clone, Copy, Debug, PartialEq, Eq`)
  - `impl CarrierLossProbe { pub fn from_tcp_stream(stream: &tokio::net::TcpStream) -> Option<Self>; pub fn sample(&self) -> Option<CarrierLossSample>; }`

- [ ] **Step 1: Write the failing test**

Create `crates/outline-transport/src/tests/carrier_loss.rs`:

```rust
use crate::carrier_loss::CarrierLossProbe;

/// A freshly connected socket has already sent at least the SYN, so the
/// sampler must report a non-zero send count and a live carrier.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn tcp_probe_reports_progress_on_a_live_socket() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = tokio::net::TcpStream::connect(addr).await.unwrap();
    let _server = listener.accept().await.unwrap();

    let probe = CarrierLossProbe::from_tcp_stream(&client).expect("probe from a live socket");
    let sample = probe.sample().expect("TCP_INFO on a live socket");

    assert!(sample.sent > 0, "a connected socket has sent at least a SYN");
    assert_eq!(sample.lost, 0, "a loopback handshake retransmits nothing");
    assert!(sample.alive, "an established socket is alive");
}

/// The probe outlives the carrier: after the peer goes away the socket leaves
/// ESTABLISHED, and the sampler must say so instead of reporting stale numbers
/// (this is what evicts the entry from the registry).
#[cfg(target_os = "linux")]
#[tokio::test]
async fn tcp_probe_reports_a_dead_carrier_after_the_peer_closes() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = tokio::net::TcpStream::connect(addr).await.unwrap();
    let server = listener.accept().await.unwrap();

    let probe = CarrierLossProbe::from_tcp_stream(&client).expect("probe from a live socket");
    drop(server);
    drop(client);
    // The FIN exchange is asynchronous; poll briefly rather than sleeping blind.
    let mut alive = true;
    for _ in 0..50 {
        alive = probe.sample().map(|s| s.alive).unwrap_or(false);
        if !alive {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(!alive, "a closed carrier must not report itself alive");
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p outline-transport carrier_loss -- --nocapture`
Expected: FAIL — compilation error, `unresolved module carrier_loss` / `use of undeclared crate or module`.

- [ ] **Step 3: Write the implementation**

Create `crates/outline-transport/src/carrier_loss.rs`:

```rust
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
```

In `crates/outline-transport/src/lib.rs`, declare the module alongside the
other `mod` statements:

```rust
mod carrier_loss;
```

and re-export next to the other entry points:

```rust
pub use carrier_loss::{CarrierLossProbe, CarrierLossSample};
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p outline-transport carrier_loss`
Expected: PASS — 2 passed on Linux; both are `#[cfg(target_os = "linux")]` and are simply absent on macOS.

- [ ] **Step 5: Run the CI gate**

Run the three gate commands from Global Constraints.
Expected: fmt clean, clippy clean (the single `unsafe` block has its `// SAFETY:`), tests green.

- [ ] **Step 6: Commit**

```bash
git add crates/outline-transport/src/carrier_loss.rs crates/outline-transport/src/tests/carrier_loss.rs crates/outline-transport/src/lib.rs
git commit -m "feat(transport): read carrier loss counters from QUIC and TCP_INFO"
```

---

### Task 2: Expose the probe on HTTP/1 and H3 carriers

**Files:**
- Modify: `crates/outline-transport/src/ws_stream.rs` (add `loss_probe()` to `TransportStream`; extend the `SharedConnectionHealth` trait)
- Modify: `crates/outline-transport/src/h3/mod.rs` (`H3WsStream::loss_probe`)
- Modify: `crates/outline-transport/src/h3/shared.rs` (`SharedH3Connection` accessor + trait impl)

**Interfaces:**
- Consumes: `CarrierLossProbe` from Task 1.
- Produces: `TransportStream::loss_probe(&self) -> Option<CarrierLossProbe>`, returning `Some` for `Http1` and `H3` after this task and for every variant after Task 3. Also `SharedConnectionHealth::loss_probe(&self) -> Option<CarrierLossProbe>` with a `None` default body.

- [ ] **Step 1: Write the failing test**

Add to `crates/outline-transport/src/tests/carrier_loss.rs`:

```rust
/// An HTTP/1 carrier hands out a probe on its underlying TCP socket, so a
/// plain `ws://` uplink is measurable without any shared-connection plumbing.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn http1_transport_stream_yields_a_tcp_probe() {
    use crate::ws_stream::TransportStream;
    use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
    use tokio_tungstenite::tungstenite::protocol::Role;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = tokio::net::TcpStream::connect(addr).await.unwrap();
    let _server = listener.accept().await.unwrap();

    let ws = WebSocketStream::from_raw_socket(MaybeTlsStream::Plain(client), Role::Client, None)
        .await;
    let stream = TransportStream::new_http1(ws);

    let probe = stream.loss_probe().expect("http1 carrier exposes a probe");
    let sample = probe.sample().expect("probe reads the live socket");
    assert!(sample.alive);
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p outline-transport http1_transport_stream_yields_a_tcp_probe`
Expected: FAIL — `no method named 'loss_probe' found for enum 'TransportStream'`.

- [ ] **Step 3: Write the implementation**

In `crates/outline-transport/src/ws_stream.rs`, extend the shared-connection
trait so both multiplexed families can surrender a probe (`H2WsStream` holds
`Arc<dyn SharedConnectionHealth>`, so the trait is the only route to it):

```rust
pub(crate) trait SharedConnectionHealth: Send + Sync {
    fn is_open(&self) -> bool;
    fn conn_id(&self) -> u64;
    fn mode(&self) -> &'static str;
    /// Loss counters for the connection underneath, when the family can
    /// surrender them. Defaults to `None` so an implementation that predates
    /// loss measurement keeps compiling and simply contributes no signal.
    fn loss_probe(&self) -> Option<crate::CarrierLossProbe> {
        None
    }
}
```

and add the accessor on `TransportStream` next to `issued_session_id()`:

```rust
    /// A handle to this carrier's loss counters, when the carrier family can
    /// surrender one. Read once at dial time and held by the uplink manager;
    /// the stream itself neither samples nor stores anything.
    ///
    /// `None` means "no signal from this carrier", never "no loss": a
    /// non-Linux build, or a carrier family whose socket is not reachable from
    /// here, both land on `None`.
    pub fn loss_probe(&self) -> Option<crate::CarrierLossProbe> {
        match self {
            TransportStream::Http1 { inner, .. } => match inner.get_ref() {
                tokio_tungstenite::MaybeTlsStream::Plain(tcp) => {
                    crate::CarrierLossProbe::from_tcp_stream(tcp)
                },
                tokio_tungstenite::MaybeTlsStream::Rustls(tls) => {
                    crate::CarrierLossProbe::from_tcp_stream(tls.get_ref().0)
                },
                _ => None,
            },
            #[cfg(feature = "h3")]
            TransportStream::H3 { inner, .. } => inner.loss_probe(),
            #[cfg(not(feature = "h3"))]
            TransportStream::H3 { .. } => None,
            TransportStream::H2 { .. } | TransportStream::Xhttp { .. } => None,
        }
    }
```

In `crates/outline-transport/src/h3/shared.rs`, add an accessor on
`SharedH3Connection` (the field is private) and the trait impl:

```rust
impl SharedH3Connection {
    /// Clone of the underlying QUIC connection for loss sampling. Cheap — a
    /// `quinn::Connection` is `Arc`-backed — and read-only: the sampler never
    /// opens streams or closes the connection.
    pub(crate) fn loss_probe(&self) -> crate::CarrierLossProbe {
        crate::CarrierLossProbe::Quic(self.connection.clone())
    }
}
```

Locate the existing `impl SharedConnectionHealth for SharedH3Connection` and
add:

```rust
    fn loss_probe(&self) -> Option<crate::CarrierLossProbe> {
        Some(SharedH3Connection::loss_probe(self))
    }
```

In `crates/outline-transport/src/h3/mod.rs`, on `H3WsStream` next to
`is_connection_alive`:

```rust
    pub(crate) fn loss_probe(&self) -> Option<crate::CarrierLossProbe> {
        Some(self._shared_connection.loss_probe())
    }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p outline-transport carrier_loss`
Expected: PASS — 3 passed.

- [ ] **Step 5: Run the CI gate, then commit**

```bash
git add crates/outline-transport/src
git commit -m "feat(transport): expose carrier loss probes on http1 and h3 streams"
```

---

### Task 3: Expose the probe on H2 and XHTTP carriers

`SharedH2Connection` owns the TCP socket but hands the stream to h2, and
`XhttpStream` holds only channels and a driver task — neither can reach a
socket after the fact. Both therefore capture the probe at dial time and store
it.

**Files:**
- Modify: `crates/outline-transport/src/h2/shared.rs` (capture the probe where `connect_tcp_socket` is called around line 80 and around line 502; store it on `SharedH2Connection`; implement the trait method)
- Modify: `crates/outline-transport/src/xhttp/stream.rs` (`loss_probe: Option<CarrierLossProbe>` field + accessor)
- Modify: `crates/outline-transport/src/xhttp/h2.rs` (capture from the TCP socket dialed around line 476)
- Modify: `crates/outline-transport/src/xhttp/h3.rs` (capture the `quinn::Connection` established in `connect_h3`)
- Modify: `crates/outline-transport/src/xhttp/mod.rs` (thread the captured probe into the `XhttpStream` constructor)
- Modify: `crates/outline-transport/src/ws_stream.rs` (replace the `H2 | Xhttp => None` arm)

**Interfaces:**
- Consumes: `SharedConnectionHealth::loss_probe` from Task 2.
- Produces: `XhttpStream::loss_probe(&self) -> Option<CarrierLossProbe>`; `TransportStream::loss_probe` returning `Some` for all four variants on Linux.

- [ ] **Step 1: Write the failing test**

Add to `crates/outline-transport/src/tests/carrier_loss.rs`:

```rust
/// A probe captured at dial time survives being handed through the carrier
/// constructor — the XHTTP stream keeps only channels, so if the field were
/// dropped the signal would silently vanish for every xhttp uplink.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn xhttp_stream_keeps_the_probe_captured_at_dial_time() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = tokio::net::TcpStream::connect(addr).await.unwrap();
    let _server = listener.accept().await.unwrap();

    let probe = crate::CarrierLossProbe::from_tcp_stream(&client).unwrap();
    let stream = crate::xhttp::XhttpStream::for_loss_probe_test(Some(probe));

    let sample = stream.loss_probe().expect("captured probe").sample().unwrap();
    assert!(sample.alive);
}
```

Add the test-only constructor in `crates/outline-transport/src/xhttp/stream.rs`
(the real constructor takes a driver task and channels this test has no use
for):

```rust
    /// Test-only: an otherwise inert stream carrying just the loss probe, so
    /// the probe's survival through the struct can be asserted without
    /// standing up an h2 connection.
    #[cfg(test)]
    pub(crate) fn for_loss_probe_test(loss_probe: Option<crate::CarrierLossProbe>) -> Self {
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        Self {
            incoming: rx,
            outgoing: crate::carrier_queue::BudgetedSink::for_test(),
            closed: false,
            active_submode: super::XhttpSubmode::PacketUp,
            carrier_is_h3: false,
            udp_records: false,
            recv_records: None,
            pending_in: Default::default(),
            loss_probe,
            _driver: crate::guards::AbortOnDrop::noop(),
        }
    }
```

If `BudgetedSink::for_test` / `AbortOnDrop::noop` do not exist, add them as
`#[cfg(test)]` helpers in their own modules rather than reshaping production
constructors.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p outline-transport xhttp_stream_keeps_the_probe`
Expected: FAIL — `no field 'loss_probe' on type 'XhttpStream'`.

- [ ] **Step 3: Write the implementation**

`crates/outline-transport/src/xhttp/stream.rs` — add the field to the struct
and an accessor:

```rust
    /// Loss counters for the carrier underneath, captured at dial time. The
    /// stream owns only channels and a driver task, so the socket (h1/h2) or
    /// the QUIC connection (h3) is unreachable from here afterwards — the
    /// probe has to be taken while the dialer still holds it.
    pub(super) loss_probe: Option<crate::CarrierLossProbe>,
```

```rust
    pub(crate) fn loss_probe(&self) -> Option<&crate::CarrierLossProbe> {
        self.loss_probe.as_ref()
    }
```

`crates/outline-transport/src/xhttp/h2.rs` — where the socket is dialed
(around line 476, `let tcp = connect_tcp_socket(addr, fwmark).await?;`),
capture before the stream is consumed by the TLS/h2 handshake:

```rust
    let loss_probe = crate::CarrierLossProbe::from_tcp_stream(&tcp);
```

and thread `loss_probe` through to the `XhttpStream` construction.

`crates/outline-transport/src/xhttp/h3.rs` — after the QUIC connection is
established in `connect_h3`:

```rust
    #[cfg(feature = "h3")]
    let loss_probe = Some(crate::CarrierLossProbe::Quic(connection.clone()));
```

and thread it through the same way.

`crates/outline-transport/src/h2/shared.rs` — capture at both dial sites
(around lines 80 and 502) with `CarrierLossProbe::from_tcp_stream(&tcp)`,
store the result on `SharedH2Connection` as
`loss_probe: Option<crate::CarrierLossProbe>`, and implement:

```rust
    fn loss_probe(&self) -> Option<crate::CarrierLossProbe> {
        // The shared connection outlives every stream on it, so handing out a
        // second probe would duplicate one carrier's counters across sessions.
        // Sampling is idempotent, so the manager de-duplicates by probe id at
        // registration instead of cloning the fd here.
        self.loss_probe.as_ref().and_then(|probe| probe.try_clone())
    }
```

Add `CarrierLossProbe::try_clone(&self) -> Option<Self>` in
`carrier_loss.rs` — `Quic` clones the connection, `Tcp` clones the descriptor
with `try_clone_to_owned()`:

```rust
    /// A second handle onto the same carrier. Used where one shared connection
    /// backs many streams and each dial wants its own registration.
    pub fn try_clone(&self) -> Option<Self> {
        match self {
            #[cfg(feature = "h3")]
            Self::Quic(connection) => Some(Self::Quic(connection.clone())),
            #[cfg(target_os = "linux")]
            Self::Tcp(fd) => fd.try_clone().ok().map(Self::Tcp),
        }
    }
```

Finally, in `ws_stream.rs`, replace the `H2 | Xhttp => None` arm:

```rust
            TransportStream::H2 { inner, .. } => inner.loss_probe(),
            TransportStream::Xhttp { inner, .. } => {
                inner.loss_probe().and_then(|probe| probe.try_clone())
            },
```

and add the forwarding accessor on `H2WsStream` in
`crates/outline-transport/src/h2/mod.rs`:

```rust
    pub(super) fn loss_probe(&self) -> Option<crate::CarrierLossProbe> {
        self._shared_connection.loss_probe()
    }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p outline-transport carrier_loss`
Expected: PASS — 4 passed.

- [ ] **Step 5: Run the CI gate, then commit**

```bash
git add crates/outline-transport/src
git commit -m "feat(transport): expose carrier loss probes on h2 and xhttp streams"
```

---

### Task 3a: Carrier identity (fix, found in Task 3's review)

A shared H2/H3 connection is handed to many sessions, and every session
registers its own probe. Summed, one socket's traffic is then counted once per
session. The ratio survives (numerator and denominator scale together) but the
observed volume does not — a wire would clear `loss_sample_min_packets` on a
fraction of the traffic that threshold names, which is exactly the silent
distortion the threshold exists to prevent.

Give a probe a stable identity so the registry can recognise the same carrier
arriving twice, and correct the `SharedH2Connection::loss_probe` comment, which
currently claims a de-duplication mechanism that did not exist.

**Files:**
- Modify: `crates/outline-transport/src/carrier_loss.rs` (`identity()`; the `Tcp` variant carries its identity)
- Modify: `crates/outline-transport/src/tests/carrier_loss.rs`
- Modify: `crates/outline-transport/src/h2/shared.rs` (the comment)

**Interfaces:**
- Produces: `CarrierLossProbe::identity(&self) -> u64` — equal for two handles on the same carrier (including one obtained via `try_clone`), different for distinct carriers.

- [ ] **Step 1: Write the failing tests**

```rust
/// Two handles on one carrier must be recognisable as the same carrier —
/// this is what stops a shared H2/H3 connection from being counted once per
/// session that rides it.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_cloned_probe_keeps_the_carrier_identity() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = tokio::net::TcpStream::connect(addr).await.unwrap();
    let _server = listener.accept().await.unwrap();

    let probe = CarrierLossProbe::from_tcp_stream(&client).unwrap();
    let clone = probe.try_clone().unwrap();
    assert_eq!(probe.identity(), clone.identity());
}

/// Distinct carriers must not collide, or the registry would drop a real
/// second carrier as a duplicate and undercount the wire.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn distinct_carriers_have_distinct_identities() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let first = tokio::net::TcpStream::connect(addr).await.unwrap();
    let _first_server = listener.accept().await.unwrap();
    let second = tokio::net::TcpStream::connect(addr).await.unwrap();
    let _second_server = listener.accept().await.unwrap();

    let a = CarrierLossProbe::from_tcp_stream(&first).unwrap();
    let b = CarrierLossProbe::from_tcp_stream(&second).unwrap();
    assert_ne!(a.identity(), b.identity());
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p outline-transport carrier_identity`
Expected: FAIL — `no method named 'identity'`.

- [ ] **Step 3: Implement**

For QUIC the identity is `connection.stable_id() as u64` — quinn's own
per-connection handle, stable for the connection's life and unaffected by
cloning the `Connection`.

For TCP it is derived once at capture from the socket's local and peer
addresses (the connection's 4-tuple), stored alongside the descriptor, and
copied by `try_clone`. Deriving it from the *duplicated* descriptor rather
than storing it would be equally correct, but storing it keeps `identity()`
infallible and syscall-free. Do not use the raw fd number: `try_clone` gives
a different number for the same carrier, which is precisely the case this
must recognise.

- [ ] **Step 4: Run the tests to verify they pass, then the CI gate**

- [ ] **Step 5: Commit**

```bash
git commit -m "fix(transport): give carrier loss probes a stable identity"
```

---

### Task 4: Loss accumulator and probe registry (`outline-uplink`)

Two structures, split by what they may hold. `LossEwma` is pure numbers and
lives inside `UplinkStatus`, which is `Clone`. `CarrierLossRegistry` holds
`OwnedFd`s, which are not `Clone`, so it lives beside the statuses in
`UplinkManagerInner` and never enters a status clone.

**Files:**
- Create: `crates/outline-uplink/src/loss.rs`
- Create: `crates/outline-uplink/src/tests/loss.rs`
- Modify: `crates/outline-uplink/src/lib.rs` (`mod loss;`)

**Interfaces:**
- Consumes: `CarrierLossProbe`, `CarrierLossSample`, `CarrierLossProbe::identity() -> u64` (Task 1, extended by the Task 3a fix).
- Produces:
  - `pub(crate) struct LossEwma` (`Clone, Copy, Debug, Default`) with `ratio(&self) -> Option<f64>`, `observed_packets(&self) -> u64`, `record_window(&mut self, sent: u64, lost: u64, min_packets: u64, alpha: f64)`, `inflation(&self, k: f64, cap: f64) -> f64`.
  - `pub(crate) struct CarrierLossRegistry` with `register(&mut self, transport: TransportKind, wire: u8, probe: CarrierLossProbe)` (a carrier already registered under the same transport and wire is ignored — see the de-duplication note below), `collect_windows(&mut self) -> Vec<LossWindow>`.
  - `pub(crate) struct LossWindow { pub transport: TransportKind, pub wire: u8, pub sent: u64, pub lost: u64 }`.
  - `pub(crate) const MAX_PROBES_PER_WIRE: usize = 8;`

- [ ] **Step 1: Write the failing test**

Create `crates/outline-uplink/src/tests/loss.rs`:

```rust
use super::{CarrierLossRegistry, LossEwma, MAX_PROBES_PER_WIRE};

/// A window that saw too little traffic proves nothing: one lost packet out of
/// ten is not "10% loss", it is no measurement. The EWMA must not move.
#[test]
fn a_window_below_the_minimum_volume_does_not_move_the_ewma() {
    let mut ewma = LossEwma::default();
    ewma.record_window(10, 1, 200, 0.2);
    assert_eq!(ewma.ratio(), None, "a sub-threshold window yields no verdict");
    assert_eq!(ewma.observed_packets(), 0, "and contributes no observed volume");
}

/// A window with enough volume produces the ratio itself on first sight —
/// there is no prior value to blend with, and starting from an implicit zero
/// would understate a path that was already lossy when sampling began.
#[test]
fn the_first_qualifying_window_seeds_the_ewma_with_its_own_ratio() {
    let mut ewma = LossEwma::default();
    ewma.record_window(1_000, 20, 200, 0.2);
    assert_eq!(ewma.ratio(), Some(0.02));
    assert_eq!(ewma.observed_packets(), 1_000);
}

/// Subsequent windows blend, so a single clean or single terrible window
/// cannot swing selection on its own.
#[test]
fn later_windows_blend_into_the_ewma() {
    let mut ewma = LossEwma::default();
    ewma.record_window(1_000, 20, 200, 0.5);
    ewma.record_window(1_000, 0, 200, 0.5);
    assert_eq!(ewma.ratio(), Some(0.01));
}

/// Inflation is capped: a burst of loss must degrade an uplink's rank, not
/// remove it from ranking altogether.
#[test]
fn inflation_is_clamped_at_the_cap() {
    let mut ewma = LossEwma::default();
    ewma.record_window(1_000, 500, 200, 1.0);
    assert_eq!(ewma.inflation(20.0, 4.0), 4.0);
}

/// With the feature off the multiplier is exactly 1.0, so `base_latency` is
/// bit-for-bit what it is today.
#[test]
fn zero_k_yields_an_identity_multiplier() {
    let mut ewma = LossEwma::default();
    ewma.record_window(1_000, 100, 200, 0.2);
    assert_eq!(ewma.inflation(0.0, 4.0), 1.0);
}

/// A carrier that vanishes between ticks must not produce a delta at all —
/// neither negative (counters reset with the connection) nor inflated.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_vanished_carrier_contributes_no_window() {
    let mut registry = CarrierLossRegistry::default();
    let probe = crate::loss::tests_support::dead_probe().await;
    registry.register(crate::types::TransportKind::Tcp, 0, probe);
    let windows = registry.collect_windows();
    assert!(windows.is_empty(), "a dead carrier yields no window");
    assert_eq!(registry.len(), 0, "and is evicted from the registry");
}

/// One shared H2/H3 connection is handed to many sessions and every one of
/// them registers. Counting it once per session would let a wire clear the
/// minimum-volume threshold on a fraction of the traffic the threshold names.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn the_same_carrier_registered_twice_is_counted_once() {
    let mut registry = CarrierLossRegistry::default();
    let (probe, _client, _server) = crate::loss::tests_support::live_pair().await;
    let twin = probe.try_clone().expect("a second handle on the same carrier");

    registry.register(crate::types::TransportKind::Tcp, 0, probe);
    registry.register(crate::types::TransportKind::Tcp, 0, twin);

    assert_eq!(registry.len(), 1, "one carrier occupies one registry slot");
}

/// The registry is bounded: a busy uplink dials constantly, and every dial
/// registers a distinct carrier. Oldest entries are dropped, newest kept.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn the_registry_is_bounded_per_wire() {
    let mut registry = CarrierLossRegistry::default();
    let mut sockets = Vec::new();
    for _ in 0..(MAX_PROBES_PER_WIRE + 4) {
        let (probe, client, server) = crate::loss::tests_support::live_pair().await;
        sockets.push((client, server));
        registry.register(crate::types::TransportKind::Tcp, 0, probe);
    }
    assert_eq!(registry.len(), MAX_PROBES_PER_WIRE);
}
```

The two registry tests need probes over real sockets. The helpers below go in
`crates/outline-uplink/src/loss.rs` (they are shared by Task 6's tests, which
is why they live in the module rather than in the test file):

```rust
#[cfg(test)]
pub(crate) mod tests_support {
    use outline_transport::CarrierLossProbe;

    /// A probe over an established loopback pair. The returned listener and
    /// streams must be kept alive by the caller — dropping them closes the
    /// carrier and the probe starts reporting `alive = false`.
    pub(crate) async fn live_pair() -> (CarrierLossProbe, tokio::net::TcpStream, tokio::net::TcpStream)
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let probe = CarrierLossProbe::from_tcp_stream(&client).expect("probe over loopback");
        (probe, client, server)
    }

    /// A probe whose carrier is already gone. The FIN exchange is
    /// asynchronous, so poll until the socket leaves ESTABLISHED rather than
    /// sleeping a guessed interval.
    pub(crate) async fn dead_probe() -> CarrierLossProbe {
        let (probe, client, server) = live_pair().await;
        drop(server);
        drop(client);
        for _ in 0..50 {
            if !probe.sample().map(|s| s.alive).unwrap_or(false) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        probe
    }

    /// A live probe plus enough traffic pushed through the pair that
    /// `tcpi_segs_out` has certainly advanced, for tests that assert on
    /// observed volume. Both sockets come back with it: the caller must keep
    /// them bound for as long as the probe is expected to read a live carrier.
    pub(crate) async fn live_probe_with_traffic()
    -> (CarrierLossProbe, tokio::net::TcpStream, tokio::net::TcpStream) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (probe, mut client, mut server) = live_pair().await;
        for _ in 0..16 {
            client.write_all(&[0u8; 1024]).await.unwrap();
        }
        let mut sink = vec![0u8; 16 * 1024];
        server.read_exact(&mut sink).await.unwrap();
        (probe, client, server)
    }
}
```

No helper may `std::mem::forget` a socket to keep a carrier alive — that
leaks the descriptor for the rest of the test binary. Helpers hand the
sockets back and the test binds them (`let _guards = ...`) for as long as the
carrier must stay up.

The two registry tests are `async` because the helpers are; mark them
`#[tokio::test]` and `await` the helper calls.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p outline-uplink loss`
Expected: FAIL — `unresolved import crate::loss`.

- [ ] **Step 3: Write the implementation**

Create `crates/outline-uplink/src/loss.rs`:

```rust
//! Per-wire carrier-loss accounting.
//!
//! Split in two because of what each half may hold. [`LossEwma`] is numbers
//! only and lives inside `UplinkStatus`, which is cloned on every snapshot.
//! [`CarrierLossRegistry`] holds live descriptors (`OwnedFd` is not `Clone`)
//! and therefore lives beside the statuses, sampled by the loss loop.

use outline_transport::CarrierLossProbe;

use crate::types::TransportKind;

/// Maximum live probes retained per (transport, wire). A busy uplink dials
/// constantly and every dial registers; without a bound the registry would
/// grow with the dial rate. Newest win — they are the carriers actually
/// carrying traffic.
pub(crate) const MAX_PROBES_PER_WIRE: usize = 8;

/// Smoothed loss ratio for one wire, plus the volume it was derived from.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct LossEwma {
    ratio: Option<f64>,
    observed_packets: u64,
}

impl LossEwma {
    pub(crate) fn ratio(&self) -> Option<f64> {
        self.ratio
    }

    /// Cumulative packets this verdict is based on. Published so a dashboard
    /// can tell "no loss" apart from "no data".
    pub(crate) fn observed_packets(&self) -> u64 {
        self.observed_packets
    }

    /// Fold one sampling window into the EWMA. A window carrying fewer than
    /// `min_packets` sends is discarded outright: on a near-idle carrier the
    /// ratio is dominated by rounding, and feeding it would let an idle uplink
    /// look catastrophically lossy.
    pub(crate) fn record_window(&mut self, sent: u64, lost: u64, min_packets: u64, alpha: f64) {
        if sent < min_packets.max(1) {
            return;
        }
        let ratio = (lost as f64 / sent as f64).clamp(0.0, 1.0);
        self.observed_packets = self.observed_packets.saturating_add(sent);
        self.ratio = Some(match self.ratio {
            // First qualifying window seeds the estimate with itself: blending
            // against an implicit zero would understate a path that was
            // already lossy before sampling started.
            None => ratio,
            Some(current) => current + alpha * (ratio - current),
        });
    }

    /// Latency multiplier for scoring: `1 + k · loss`, clamped to `cap`.
    /// `k = 0` yields exactly `1.0`, which is what keeps the default build's
    /// selection identical to today's.
    pub(crate) fn inflation(&self, k: f64, cap: f64) -> f64 {
        if k <= 0.0 {
            return 1.0;
        }
        let loss = self.ratio.unwrap_or(0.0);
        (1.0 + k * loss).clamp(1.0, cap.max(1.0))
    }
}

/// One wire's traffic during a single sampling window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LossWindow {
    pub(crate) transport: TransportKind,
    pub(crate) wire: u8,
    pub(crate) sent: u64,
    pub(crate) lost: u64,
}

struct ProbeEntry {
    transport: TransportKind,
    wire: u8,
    /// Identity of the carrier underneath, from `CarrierLossProbe::identity()`.
    /// A shared H2/H3 connection backs many sessions and each of them
    /// registers, so without this the same socket's traffic would be counted
    /// once per session: the ratio would survive (numerator and denominator
    /// scale together) but the observed volume would not, and
    /// `loss_sample_min_packets` would be cleared N times too easily.
    identity: u64,
    probe: CarrierLossProbe,
    /// Previous reading, so the next tick can difference against it. `None`
    /// until the first successful sample.
    last: Option<(u64, u64)>,
}

/// Live probes for one uplink, keyed by (transport, wire).
#[derive(Default)]
pub(crate) struct CarrierLossRegistry {
    entries: Vec<ProbeEntry>,
}

impl CarrierLossRegistry {
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// File a probe under the wire that dialed it, evicting the oldest entry
    /// for that wire once the bound is reached.
    ///
    /// A carrier already registered under this (transport, wire) is dropped on
    /// the floor: one shared H2/H3 connection is handed to many sessions, and
    /// counting its counters once per session would inflate the observed
    /// volume the minimum-volume threshold is measured against.
    pub(crate) fn register(&mut self, transport: TransportKind, wire: u8, probe: CarrierLossProbe) {
        let identity = probe.identity();
        if self
            .entries
            .iter()
            .any(|e| e.transport == transport && e.wire == wire && e.identity == identity)
        {
            return;
        }
        let count = self
            .entries
            .iter()
            .filter(|e| e.transport == transport && e.wire == wire)
            .count();
        if count >= MAX_PROBES_PER_WIRE
            && let Some(pos) = self
                .entries
                .iter()
                .position(|e| e.transport == transport && e.wire == wire)
        {
            self.entries.remove(pos);
        }
        self.entries.push(ProbeEntry {
            transport,
            wire,
            identity,
            probe,
            last: None,
        });
    }

    /// Sample every live probe, difference against the previous reading, and
    /// return one aggregated window per (transport, wire). Dead or
    /// unreadable carriers are evicted here — that eviction is what closes
    /// their duplicated descriptors.
    pub(crate) fn collect_windows(&mut self) -> Vec<LossWindow> {
        let mut windows: Vec<LossWindow> = Vec::new();
        self.entries.retain_mut(|entry| {
            let Some(sample) = entry.probe.sample() else {
                return false;
            };
            if let Some((prev_sent, prev_lost)) = entry.last {
                // Counters are cumulative and monotonic within one connection;
                // `saturating_sub` is belt-and-braces against a kernel that
                // reports a narrower field after a wrap.
                let sent = sample.sent.saturating_sub(prev_sent);
                let lost = sample.lost.saturating_sub(prev_lost);
                if sent > 0 {
                    match windows
                        .iter_mut()
                        .find(|w| w.transport == entry.transport && w.wire == entry.wire)
                    {
                        Some(window) => {
                            window.sent += sent;
                            window.lost += lost;
                        },
                        None => windows.push(LossWindow {
                            transport: entry.transport,
                            wire: entry.wire,
                            sent,
                            lost,
                        }),
                    }
                }
            }
            entry.last = Some((sample.sent, sample.lost));
            sample.alive
        });
        windows
    }
}

// The `tests_support` module goes here verbatim as written in Step 1 — it is
// shared with Task 6's sampler tests, which is why it lives in the module
// rather than in the test file.

#[cfg(test)]
#[path = "tests/loss.rs"]
mod tests;
```

Declare `mod loss;` in `crates/outline-uplink/src/lib.rs`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p outline-uplink loss`
Expected: PASS — 7 passed.

- [ ] **Step 5: Run the CI gate, then commit**

```bash
git add crates/outline-uplink/src/loss.rs crates/outline-uplink/src/tests/loss.rs crates/outline-uplink/src/lib.rs
git commit -m "feat(uplink): add per-wire carrier loss accumulator and probe registry"
```

---

### Task 5: Configuration knobs

**Files:**
- Modify: `crates/outline-uplink/src/config.rs` (`LoadBalancingConfig` fields)
- Modify: `bins/outline-ws-rust/src/config/schema.rs` (both `load_balancing` sections — around line 555 and around line 814)
- Modify: `bins/outline-ws-rust/src/config/load/balancing.rs` (parsing, defaults, validation)
- Modify: `bins/outline-uplink/src/tests/mod.rs` and `crates/outline-uplink/src/tests/registry.rs` (existing `LoadBalancingConfig` literals — there are many; the compiler lists every one)
- Modify: `bins/outline-ws-rust/src/config/tests/mod.rs` (parse test)

**Interfaces:**
- Consumes: nothing.
- Produces: `LoadBalancingConfig::{loss_latency_penalty_k: f64, loss_latency_inflation_max: f64, loss_sample_interval: Duration, loss_sample_min_packets: u64, loss_ewma_alpha: f64}`.

- [ ] **Step 1: Write the failing test**

Add to `bins/outline-ws-rust/src/config/tests/mod.rs`, alongside the existing
`rtt_ewma_alpha` parse test:

```rust
#[test]
fn load_balancing_parses_loss_signal_knobs() {
    let cfg = parse_config(
        r#"
        [outline.load_balancing]
        loss_latency_penalty_k = 12.0
        loss_latency_inflation_max = 6.0
        loss_sample_interval_secs = 15
        loss_sample_min_packets = 500
        loss_ewma_alpha = 0.4
        "#,
    )
    .unwrap();
    let lb = load_balancing(&cfg);
    assert_eq!(lb.loss_latency_penalty_k, 12.0);
    assert_eq!(lb.loss_latency_inflation_max, 6.0);
    assert_eq!(lb.loss_sample_interval, std::time::Duration::from_secs(15));
    assert_eq!(lb.loss_sample_min_packets, 500);
    assert_eq!(lb.loss_ewma_alpha, 0.4);
}

/// The shipped default observes without acting.
#[test]
fn loss_signal_defaults_to_observation_only() {
    let lb = load_balancing(&parse_config("[outline]").unwrap());
    assert_eq!(lb.loss_latency_penalty_k, 0.0);
    assert_eq!(lb.loss_sample_interval, std::time::Duration::from_secs(10));
    assert_eq!(lb.loss_sample_min_packets, 200);
}

/// A negative coefficient would reward loss; reject it at load time rather
/// than discovering it as an inverted ranking in production.
#[test]
fn negative_loss_penalty_is_rejected() {
    let err = load_balancing_result(
        &parse_config("[outline.load_balancing]\nloss_latency_penalty_k = -1.0").unwrap(),
    )
    .unwrap_err();
    assert!(err.to_string().contains("loss_latency_penalty_k"));
}
```

Match the helper names already used in that test module (`parse_config`,
and whichever accessor the neighbouring `rtt_ewma_alpha` test uses); add
`load_balancing_result` if only an unwrapping helper exists.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p outline-ws-rust loss_signal`
Expected: FAIL — unknown field `loss_latency_penalty_k` / no field on `LoadBalancingConfig`.

- [ ] **Step 3: Write the implementation**

In `crates/outline-uplink/src/config.rs`, add to `LoadBalancingConfig` after
`rtt_ewma_alpha`:

```rust
    /// Strength of the carrier-loss latency inflation: the wire's smoothed
    /// loss ratio multiplies scoring latency by `1 + k · loss`. `0.0` (the
    /// default) observes without acting — the loss ratio is measured and
    /// published, but selection is unchanged. There is no principled value to
    /// derive `k` from a priori; it is meant to be set once the field spread
    /// between uplinks is visible in the metrics.
    pub loss_latency_penalty_k: f64,
    /// Ceiling on that multiplier. Bounds how far one bad measurement window
    /// can push an uplink down the ranking: a lossy path must lose rank, not
    /// drop out of ranking altogether — it may still be the only live one.
    pub loss_latency_inflation_max: f64,
    /// Sampling grid for carrier loss counters. Deliberately independent of
    /// the probe cycle, which runs far coarser and skips cycles for uplinks
    /// carrying traffic — differencing cumulative counters needs an even grid.
    pub loss_sample_interval: Duration,
    /// Minimum packets a wire must send within one window for that window to
    /// count. Below this the ratio is rounding noise: one lost packet out of
    /// ten is not "10% loss".
    pub loss_sample_min_packets: u64,
    /// Smoothing factor for the per-wire loss EWMA.
    pub loss_ewma_alpha: f64,
```

In `bins/outline-ws-rust/src/config/schema.rs`, add to **both**
`load_balancing` sections:

```rust
    pub(super) loss_latency_penalty_k: Option<f64>,
    pub(super) loss_latency_inflation_max: Option<f64>,
    pub(super) loss_sample_interval_secs: Option<u64>,
    pub(super) loss_sample_min_packets: Option<u64>,
    pub(super) loss_ewma_alpha: Option<f64>,
```

In `bins/outline-ws-rust/src/config/load/balancing.rs`, mirroring the existing
`rtt_ewma_alpha` handling:

```rust
    let loss_latency_penalty_k = lb.and_then(|l| l.loss_latency_penalty_k).unwrap_or(0.0);
    if !(loss_latency_penalty_k.is_finite() && loss_latency_penalty_k >= 0.0) {
        bail!("load_balancing.loss_latency_penalty_k must be a finite value >= 0");
    }
    let loss_latency_inflation_max = lb.and_then(|l| l.loss_latency_inflation_max).unwrap_or(4.0);
    if !(loss_latency_inflation_max.is_finite() && loss_latency_inflation_max >= 1.0) {
        bail!("load_balancing.loss_latency_inflation_max must be a finite value >= 1");
    }
    let loss_ewma_alpha = lb.and_then(|l| l.loss_ewma_alpha).unwrap_or(0.2);
    if !(loss_ewma_alpha.is_finite() && 0.0 < loss_ewma_alpha && loss_ewma_alpha <= 1.0) {
        bail!("load_balancing.loss_ewma_alpha must be in the range (0, 1]");
    }
```

and in the struct literal:

```rust
        loss_latency_penalty_k,
        loss_latency_inflation_max,
        loss_sample_interval: Duration::from_secs(
            lb.and_then(|l| l.loss_sample_interval_secs).unwrap_or(10),
        ),
        loss_sample_min_packets: lb.and_then(|l| l.loss_sample_min_packets).unwrap_or(200),
        loss_ewma_alpha,
```

Then fix every existing `LoadBalancingConfig { .. }` literal the compiler
flags (test fixtures in `crates/outline-uplink/src/tests/`) by adding the five
fields with the defaults above.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p outline-ws-rust loss_signal && cargo test -p outline-uplink`
Expected: PASS.

- [ ] **Step 5: Run the CI gate, then commit**

```bash
git add crates/outline-uplink/src/config.rs crates/outline-uplink/src/tests bins/outline-ws-rust/src/config
git commit -m "feat(uplink): add carrier-loss configuration knobs, defaulting to observe-only"
```

---

### Task 6: State, registration and the sampling loop

**Files:**
- Modify: `crates/outline-uplink/src/manager/status.rs` (`carrier_loss` / `fallback_carrier_loss` on `PerTransportStatus`, plus `active_wire_loss()` and `record_wire_loss_window()`)
- Modify: `crates/outline-uplink/src/manager/state.rs` (`carrier_loss: Vec<Mutex<CarrierLossRegistry>>` on the inner state, sized like `statuses`, plus an accessor)
- Create: `crates/outline-uplink/src/manager/loss_sampler.rs` (registration entry point + `spawn_loss_sampler_loop`)
- Create: `crates/outline-uplink/src/manager/tests/loss_sampler.rs`
- Modify: `crates/outline-uplink/src/manager/mod.rs` (`mod loss_sampler;`)
- Modify: `crates/outline-uplink/src/registry.rs` (spawn per group, next to `spawn_shuffle_timer_loops` at lines 205 and 404)
- Modify: `bins/outline-ws-rust/src/bootstrap/mod.rs:143` (call the registry spawner)
- Modify: `bins/outline-ws-rust/src/proxy/tcp/failover.rs:809`, `bins/outline-ws-rust/src/proxy/udp/transport.rs:208` and `:269`, `crates/outline-uplink/src/manager/standby/mod.rs:420` and `:615` (register the probe where the dial latency is already reported)

**Interfaces:**
- Consumes: `CarrierLossRegistry`, `LossEwma`, `LossWindow` (Task 4); config knobs (Task 5); `TransportStream::loss_probe` (Tasks 2–3).
- Produces:
  - `UplinkManager::register_carrier_loss_probe(&self, index: usize, wire: u8, transport: TransportKind, probe: Option<CarrierLossProbe>)` — takes an `Option` so every dial site can hand over `stream.loss_probe()` directly, without each one repeating the "no signal on this carrier" branch
  - `UplinkManager::spawn_loss_sampler_loop(&self)`
  - `PerTransportStatus::active_wire_loss(&self) -> LossEwma`
  - `PerTransportStatus::record_wire_loss_window(&mut self, wire: u8, sent: u64, lost: u64, min_packets: u64, alpha: f64)`

- [ ] **Step 1: Write the failing test**

Create `crates/outline-uplink/src/manager/tests/loss_sampler.rs`:

```rust
use crate::types::TransportKind;

/// A window recorded against the wire that is currently active must be the one
/// `active_wire_loss` returns — the same active-wire rule the RTT already uses.
#[test]
fn loss_is_read_from_the_active_wire() {
    let mut status = crate::manager::status::PerTransportStatus::default();
    status.record_wire_loss_window(0, 1_000, 10, 200, 1.0);
    status.record_wire_loss_window(1, 1_000, 200, 200, 1.0);

    status.active_wire = 0;
    assert_eq!(status.active_wire_loss().ratio(), Some(0.01));

    status.active_wire = 1;
    assert_eq!(
        status.active_wire_loss().ratio(),
        Some(0.2),
        "after a wire flip, scoring must read the wire actually carrying traffic"
    );
}

/// Sampling one tick over a registered live carrier writes a verdict into the
/// status, so the metric has something to publish without any user traffic
/// bookkeeping in between.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_sampling_tick_writes_the_wire_verdict_into_status() {
    let mut config = crate::tests::lb();
    // One packet is enough to qualify here: the assertion is that a window
    // reaches the status at all, not how fast loopback moves segments.
    config.loss_sample_min_packets = 1;
    let manager = crate::types::UplinkManager::new_for_test(
        "test",
        vec![crate::tests::make_uplink("primary", "wss://primary.example.com/tcp")],
        crate::tests::probe_disabled(),
        config,
    )
    .unwrap();

    let (probe, _client, _server) = crate::loss::tests_support::live_probe_with_traffic().await;
    manager.register_carrier_loss_probe(0, 0, TransportKind::Tcp, Some(probe));

    // First tick establishes the baseline, second produces the delta.
    manager.sample_carrier_loss_once().await;
    manager.sample_carrier_loss_once().await;

    let status = manager.inner.read_status(0);
    assert!(
        status.tcp.carrier_loss.observed_packets() > 0,
        "a live carrier under traffic must produce observed volume"
    );
}
```

The fixtures are the existing ones in `crates/outline-uplink/src/tests/mod.rs`:
`lb()` (line 25), `make_uplink(name, url)` (line 129), `probe_disabled()`
(line 88), and `UplinkManager::new_for_test(group, uplinks, probe, config)`.
`_client` and `_server` must stay bound: dropping either closes the carrier and
the second tick would evict the probe before it produced a window. The first test in this file
is synchronous and needs no fixtures.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p outline-uplink loss_sampler`
Expected: FAIL — `no method named 'record_wire_loss_window'`.

- [ ] **Step 3: Write the implementation**

`status.rs` — add the fields to `PerTransportStatus`, next to
`fallback_rtt_ewma`:

```rust
    /// Smoothed carrier loss for the primary wire. The live probes it is
    /// derived from live in the manager's registry, not here: they own
    /// duplicated descriptors, and `UplinkStatus` is cloned on every snapshot.
    pub(crate) carrier_loss: crate::loss::LossEwma,
    /// Per-fallback-wire loss slots, indexed by `wire_index - 1` exactly like
    /// [`Self::fallback_rtt_ewma`]. Lazily extended on first write.
    pub(crate) fallback_carrier_loss: Vec<crate::loss::LossEwma>,
```

and the two accessors, mirroring `active_wire_rtt_ewma` /
`record_fallback_wire_latency`:

```rust
    /// Loss for the wire new sessions currently land on. Same active-wire rule
    /// as [`Self::active_wire_rtt_ewma`], so scoring never mixes one wire's
    /// latency with another's loss.
    pub(crate) fn active_wire_loss(&self) -> crate::loss::LossEwma {
        if self.active_wire == 0 {
            return self.carrier_loss;
        }
        let slot_idx = (self.active_wire - 1) as usize;
        self.fallback_carrier_loss.get(slot_idx).copied().unwrap_or_default()
    }

    /// Fold one sampling window into the slot for `wire`.
    pub(crate) fn record_wire_loss_window(
        &mut self,
        wire: u8,
        sent: u64,
        lost: u64,
        min_packets: u64,
        alpha: f64,
    ) {
        if wire == 0 {
            self.carrier_loss.record_window(sent, lost, min_packets, alpha);
            return;
        }
        let slot_idx = (wire - 1) as usize;
        while self.fallback_carrier_loss.len() <= slot_idx {
            self.fallback_carrier_loss.push(crate::loss::LossEwma::default());
        }
        self.fallback_carrier_loss[slot_idx].record_window(sent, lost, min_packets, alpha);
    }
```

`state.rs` — add the registry vector beside `statuses`, built with the same
length, and an accessor:

```rust
    /// Live loss probes per uplink. Kept out of `statuses` because it owns
    /// `OwnedFd`s, which are not `Clone`, while `UplinkStatus` is cloned for
    /// every snapshot.
    pub(crate) carrier_loss: Vec<Mutex<crate::loss::CarrierLossRegistry>>,
```

Create `crates/outline-uplink/src/manager/loss_sampler.rs`:

```rust
//! Carrier-loss sampling: registration at dial time, and the timer that turns
//! cumulative carrier counters into a per-wire verdict on the status.

use tokio::time::sleep;
use tracing::{debug, info};

use outline_transport::CarrierLossProbe;

use crate::types::{TransportKind, UplinkManager};

impl UplinkManager {
    /// File a freshly dialed carrier's loss probe under the uplink and wire
    /// that dialed it. Called from the dial paths that already report the dial
    /// latency, so the two signals always describe the same carrier.
    ///
    /// Best-effort by construction: a `None` probe (non-Linux build, carrier
    /// family without a reachable socket) simply contributes no signal, and no
    /// dial ever fails because loss could not be measured.
    pub fn register_carrier_loss_probe(
        &self,
        index: usize,
        wire: u8,
        transport: TransportKind,
        probe: Option<CarrierLossProbe>,
    ) {
        let Some(probe) = probe else { return };
        let Some(slot) = self.inner.carrier_loss.get(index) else {
            return;
        };
        slot.lock().register(transport, wire, probe);
    }

    /// One sampling pass over every uplink: difference each live carrier's
    /// counters and fold the per-wire totals into the status.
    pub(crate) async fn sample_carrier_loss_once(&self) {
        let min_packets = self.inner.load_balancing.loss_sample_min_packets;
        let alpha = self.inner.load_balancing.loss_ewma_alpha;
        for index in 0..self.inner.uplinks.len() {
            let Some(slot) = self.inner.carrier_loss.get(index) else {
                continue;
            };
            let windows = slot.lock().collect_windows();
            if windows.is_empty() {
                continue;
            }
            self.inner.with_status_mut(index, |status| {
                for window in &windows {
                    let per = match window.transport {
                        TransportKind::Tcp => &mut status.tcp,
                        TransportKind::Udp => &mut status.udp,
                    };
                    per.record_wire_loss_window(
                        window.wire,
                        window.sent,
                        window.lost,
                        min_packets,
                        alpha,
                    );
                }
            });
            debug!(
                uplink = %self.inner.uplinks[index].name,
                windows = windows.len(),
                "carrier loss sampled"
            );
        }
    }

    /// Spawn the sampling timer for this group. One task per group, dying on
    /// the group's shutdown channel exactly like the shuffle timer, so a
    /// `/control/apply` hot-swap does not leave an orphan sampling a config
    /// that no longer exists.
    pub fn spawn_loss_sampler_loop(&self) {
        let interval = self.inner.load_balancing.loss_sample_interval;
        if interval.is_zero() {
            return;
        }
        let manager = self.clone();
        let mut shutdown = self.shutdown_rx();
        info!(
            group = %self.inner.group_name,
            interval_secs = interval.as_secs(),
            "carrier loss sampling loop spawned",
        );
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = shutdown.changed() => break,
                    _ = sleep(interval) => {}
                }
                manager.sample_carrier_loss_once().await;
            }
        });
    }
}

#[cfg(test)]
#[path = "tests/loss_sampler.rs"]
mod tests;
```

Wire the spawner in `crates/outline-uplink/src/registry.rs` beside both
`spawn_shuffle_timer_loops` call sites (lines 205 and 404):

```rust
            group.manager.spawn_loss_sampler_loop();
```

and add the registry-level spawner call in
`bins/outline-ws-rust/src/bootstrap/mod.rs`, next to line 143:

```rust
    registry.spawn_loss_sampler_loops();
```

Register at each dial site. In
`bins/outline-ws-rust/src/proxy/tcp/failover.rs`, immediately before the
existing `report_connection_latency` call at line 809 — while `ws` is still in
scope, i.e. before `do_tcp_ss_setup` consumes it, so capture the probe right
after the `connect_transport` await at line 772:

```rust
    let loss_probe = ws.loss_probe();
```

and after the dial succeeds:

```rust
    uplinks.register_carrier_loss_probe(parent.index, wire_index, TransportKind::Tcp, loss_probe);
```

Do the same at `bins/outline-ws-rust/src/proxy/udp/transport.rs:208` and
`:269` with `TransportKind::Udp` and that path's `wire_index`, and at
`crates/outline-uplink/src/manager/standby/mod.rs:420` / `:615` with
`wire = 0` (the pool dials the primary wire) and the matching transport.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p outline-uplink loss_sampler`
Expected: PASS — 2 passed.

- [ ] **Step 5: Run the CI gate, then commit**

```bash
git add crates/outline-uplink/src bins/outline-ws-rust/src
git commit -m "feat(uplink): sample carrier loss per wire and hold the verdict on status"
```

---

### Task 7: Inflate the scoring latency

**Files:**
- Modify: `crates/outline-uplink/src/manager/status.rs` (`base_latency`, and the `PerTransportStatus::selection_view` that resolves it)
- Modify: `crates/outline-uplink/src/manager/tests/status.rs` (ranking tests)

`base_latency()` is a trait method with no access to the config, and the
inflation needs `k` and the cap. Resolve it where the config is already in
hand: `PerTransportStatus::selection_view(&self, config: &LoadBalancingConfig)`
takes the config and applies the multiplier, and `UplinkStatus::selection_view`
forwards it. Every caller of `selection_view` already holds the manager's
`load_balancing`. The `TransportStatusView::base_latency` impl on
`PerTransportStatus` (used by the paths that read the status directly) applies
it through a new `base_latency_with(&self, config)`, keeping one formula.

**Interfaces:**
- Consumes: `active_wire_loss()` (Task 6), config knobs (Task 5).
- Produces: `PerTransportStatus::base_latency_with(&self, config: &LoadBalancingConfig) -> Option<Duration>`; `selection_view` gains a `&LoadBalancingConfig` parameter.

- [ ] **Step 1: Write the failing test**

Add to `crates/outline-uplink/src/manager/tests/status.rs`:

```rust
/// The field case: a 0.21 s path losing 2 % must rank behind a clean 0.30 s
/// path once the operator has set a coefficient — this is the ordering that
/// failed to happen on 2026-08-02.
#[test]
fn a_lossy_fast_path_ranks_behind_a_clean_slower_one() {
    let mut config = crate::tests::lb();
    config.loss_latency_penalty_k = 20.0;
    config.loss_latency_inflation_max = 4.0;

    let mut lossy = PerTransportStatus {
        rtt_ewma: Some(Duration::from_millis(210)),
        ..Default::default()
    };
    lossy.record_wire_loss_window(0, 10_000, 200, 200, 1.0);

    let clean = PerTransportStatus {
        rtt_ewma: Some(Duration::from_millis(300)),
        ..Default::default()
    };

    assert!(
        lossy.base_latency_with(&config) > clean.base_latency_with(&config),
        "2% loss at k=20 inflates 210ms past a clean 300ms path"
    );
}

/// With the shipped default the inflation is inert, so today's ranking is
/// preserved exactly.
#[test]
fn the_default_coefficient_leaves_base_latency_untouched() {
    let config = crate::tests::lb();
    assert_eq!(config.loss_latency_penalty_k, 0.0);

    let mut status = PerTransportStatus {
        rtt_ewma: Some(Duration::from_millis(210)),
        ..Default::default()
    };
    status.record_wire_loss_window(0, 10_000, 5_000, 200, 1.0);

    assert_eq!(status.base_latency_with(&config), Some(Duration::from_millis(210)));
}

/// Loss without a latency sample must not invent one: an uplink that has never
/// been measured stays unranked rather than being handed a fabricated score.
#[test]
fn loss_alone_does_not_synthesise_a_latency() {
    let mut config = crate::tests::lb();
    config.loss_latency_penalty_k = 20.0;

    let mut status = PerTransportStatus::default();
    status.record_wire_loss_window(0, 10_000, 500, 200, 1.0);

    assert_eq!(status.base_latency_with(&config), None);
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p outline-uplink base_latency`
Expected: FAIL — `no method named 'base_latency_with'`.

- [ ] **Step 3: Write the implementation**

In `status.rs`:

```rust
impl PerTransportStatus {
    /// Penalty-free latency this transport is ranked by, with carrier loss on
    /// the active wire folded in.
    ///
    /// Loss is applied as a multiplier on latency rather than as a separate
    /// term because that is what it physically is: every retransmit costs the
    /// affected bytes another round trip, so a lossy path delivers later at
    /// the same RTT. Applying it here — the shared input of every routing
    /// scope — is also what makes it visible to Global scope under
    /// `auto_failback`, which discards `penalty` entirely and would otherwise
    /// stay blind exactly where the field incident happened.
    ///
    /// Loss never synthesises a latency: with no RTT sample the result stays
    /// `None`, because an uplink that has never been measured must not be
    /// ranked on a fabricated number.
    pub(crate) fn base_latency_with(
        &self,
        config: &crate::config::LoadBalancingConfig,
    ) -> Option<Duration> {
        let base = self.active_wire_rtt_ewma().or(self.rtt_ewma).or(self.latency)?;
        let multiplier = self
            .active_wire_loss()
            .inflation(config.loss_latency_penalty_k, config.loss_latency_inflation_max);
        if multiplier <= 1.0 {
            return Some(base);
        }
        Some(Duration::from_secs_f64(base.as_secs_f64() * multiplier))
    }
}
```

Change `PerTransportStatus::selection_view` to take
`config: &crate::config::LoadBalancingConfig` and resolve
`base_latency: self.base_latency_with(config)`; change
`UplinkStatus::selection_view` the same way and pass the config through. Update
every call site the compiler flags — each one already holds
`self.inner.load_balancing`.

Keep the existing `TransportStatusView::base_latency` impl for
`PerTransportStatus` delegating to the uninflated path (it is the trait's
config-free contract, used by paths that rank a single status against itself);
add a doc line stating that scoring goes through `base_latency_with` and the
trait impl is the raw value.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p outline-uplink`
Expected: PASS — the whole crate, including the pre-existing selection tests, which must be unaffected because `k` defaults to `0.0`.

- [ ] **Step 5: Run the CI gate, then commit**

```bash
git add crates/outline-uplink/src
git commit -m "feat(uplink): fold carrier loss into the latency selection ranks by"
```

---

### Task 8: Metrics and control snapshot

**Files:**
- Modify: `crates/outline-metrics/src/snapshot_types.rs` (four fields on `UplinkSnapshot`)
- Modify: `crates/outline-metrics/src/registration/uplink.rs` (register two gauges and one counter-shaped gauge)
- Modify: `crates/outline-metrics/src/registration/mod.rs` (map the new handles)
- Modify: `crates/outline-metrics/src/lib.rs` (fields on `Metrics`)
- Modify: `crates/outline-metrics/src/snapshot.rs` (reset + publish)
- Modify: `crates/outline-uplink/src/manager/snapshot.rs` (fill the fields around line 380)
- Modify: `crates/outline-metrics/src/tests/mod.rs` (rendering test)

**Interfaces:**
- Consumes: `active_wire_loss()` and `base_latency_with()` (Tasks 6–7).
- Produces: snapshot fields `tcp_carrier_loss_ratio`, `udp_carrier_loss_ratio`, `tcp_carrier_loss_packets`, `udp_carrier_loss_packets`; metrics `outline_ws_uplink_carrier_loss_ratio`, `outline_ws_uplink_carrier_loss_observed_packets`, `outline_ws_uplink_latency_inflated_seconds`.

- [ ] **Step 1: Write the failing test**

Add to `crates/outline-metrics/src/tests/mod.rs`, following the shape of the
existing snapshot-rendering tests:

```rust
#[test]
fn carrier_loss_is_rendered_per_uplink_and_transport() {
    let snapshot = uplink_manager_snapshot_fixture(|uplink| {
        uplink.tcp_carrier_loss_ratio = Some(0.02);
        uplink.tcp_carrier_loss_packets = Some(10_000);
    });
    let rendered = render_snapshot_metrics(&[snapshot]);

    assert!(rendered.contains(
        "outline_ws_uplink_carrier_loss_ratio{group=\"main\",transport=\"tcp\",uplink=\"primary\"} 0.02"
    ));
    assert!(rendered.contains(
        "outline_ws_uplink_carrier_loss_observed_packets{group=\"main\",transport=\"tcp\",uplink=\"primary\"} 10000"
    ));
}

/// "No data" must not render as "no loss": an uplink with no qualifying window
/// publishes no series at all, so a dashboard cannot mistake silence for a
/// clean path.
#[test]
fn an_unmeasured_uplink_publishes_no_loss_series() {
    let snapshot = uplink_manager_snapshot_fixture(|uplink| {
        uplink.tcp_carrier_loss_ratio = None;
        uplink.tcp_carrier_loss_packets = None;
    });
    let rendered = render_snapshot_metrics(&[snapshot]);
    assert!(!rendered.contains("outline_ws_uplink_carrier_loss_ratio"));
}
```

Use whatever fixture/render helpers that module already provides; if there is
no `uplink_manager_snapshot_fixture`, build the `UplinkManagerSnapshot` inline
the way the neighbouring tests do.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p outline-metrics carrier_loss`
Expected: FAIL — `no field 'tcp_carrier_loss_ratio' on type 'UplinkSnapshot'`.

- [ ] **Step 3: Write the implementation**

`snapshot_types.rs` — add next to `tcp_active_wire_rtt_ewma_ms`:

```rust
    /// Smoothed carrier loss ratio on the wire currently carrying TCP traffic,
    /// in `[0, 1]`. `None` until a sampling window clears the volume
    /// threshold — absence means "not measured", never "no loss".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_carrier_loss_ratio: Option<f64>,
    /// UDP counterpart to [`Self::tcp_carrier_loss_ratio`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_carrier_loss_ratio: Option<f64>,
    /// Packets the TCP loss verdict is based on. Published so a dashboard can
    /// tell a confident verdict from one drawn on a handful of packets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_carrier_loss_packets: Option<u64>,
    /// UDP counterpart to [`Self::tcp_carrier_loss_packets`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_carrier_loss_packets: Option<u64>,
```

`registration/uplink.rs` — register alongside `uplink_rtt_ewma_seconds`:

```rust
    let uplink_carrier_loss_ratio = register_labeled!(
        registry,
        GaugeVec,
        "outline_ws_uplink_carrier_loss_ratio",
        "Smoothed packet-loss ratio measured on the carrier of the wire currently \
         carrying traffic (QUIC lost/sent, TCP retransmits/segments out). Absent \
         when no sampling window has cleared the minimum-volume threshold.",
        &["group", "transport", "uplink"],
    );
    let uplink_carrier_loss_observed_packets = register_labeled!(
        registry,
        GaugeVec,
        "outline_ws_uplink_carrier_loss_observed_packets",
        "Packets observed behind outline_ws_uplink_carrier_loss_ratio — how much \
         traffic the loss verdict is based on.",
        &["group", "transport", "uplink"],
    );
    let uplink_latency_inflated_seconds = register_labeled!(
        registry,
        GaugeVec,
        "outline_ws_uplink_latency_inflated_seconds",
        "Latency selection actually ranks by: the active wire's RTT EWMA after \
         carrier-loss inflation. Equals outline_ws_uplink_active_wire_rtt_ewma_seconds \
         while loss_latency_penalty_k is 0.",
        &["group", "transport", "uplink"],
    );
```

Return them from the registration function, add the three fields to the
`Metrics` struct in `lib.rs`, map them in `registration/mod.rs`, then in
`snapshot.rs` add the three `.reset()` calls in `update_snapshot_metrics` and
publish inside the per-uplink loop:

```rust
            if let Some(ratio) = uplink.tcp_carrier_loss_ratio {
                self.uplink_carrier_loss_ratio
                    .with_label_values(&[group, "tcp", &uplink.name])
                    .set(ratio);
            }
            if let Some(ratio) = uplink.udp_carrier_loss_ratio {
                self.uplink_carrier_loss_ratio
                    .with_label_values(&[group, "udp", &uplink.name])
                    .set(ratio);
            }
            if let Some(packets) = uplink.tcp_carrier_loss_packets {
                self.uplink_carrier_loss_observed_packets
                    .with_label_values(&[group, "tcp", &uplink.name])
                    .set(packets as f64);
            }
            if let Some(packets) = uplink.udp_carrier_loss_packets {
                self.uplink_carrier_loss_observed_packets
                    .with_label_values(&[group, "udp", &uplink.name])
                    .set(packets as f64);
            }
            if let Some(latency_ms) = uplink.tcp_inflated_latency_ms {
                self.uplink_latency_inflated_seconds
                    .with_label_values(&[group, "tcp", &uplink.name])
                    .set(latency_ms as f64 / 1000.0);
            }
            if let Some(latency_ms) = uplink.udp_inflated_latency_ms {
                self.uplink_latency_inflated_seconds
                    .with_label_values(&[group, "udp", &uplink.name])
                    .set(latency_ms as f64 / 1000.0);
            }
```

Add `tcp_inflated_latency_ms` / `udp_inflated_latency_ms` to `UplinkSnapshot`
alongside the loss fields, with the same `Option<u128>` shape and
`skip_serializing_if` treatment as `tcp_effective_latency_ms`.

`crates/outline-uplink/src/manager/snapshot.rs` — fill all six around the
existing `tcp_score_ms` assignment, reading `status.tcp.active_wire_loss()` /
`status.udp.active_wire_loss()` and `base_latency_with(&self.inner.load_balancing)`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p outline-metrics carrier_loss && cargo test -p outline-uplink`
Expected: PASS.

- [ ] **Step 5: Run the CI gate, then commit**

```bash
git add crates/outline-metrics/src crates/outline-uplink/src/manager/snapshot.rs
git commit -m "feat(metrics): publish carrier loss ratio, observed volume and inflated latency"
```

---

### Task 9: Documentation (EN + RU)

**Files:**
- Modify: `bins/outline-ws-rust/docs/UPLINK-CONFIGURATIONS.md`
- Modify: `bins/outline-ws-rust/docs/UPLINK-CONFIGURATIONS.ru.md`

- [ ] **Step 1: Write the English section**

Add a `### Carrier loss in uplink selection` subsection to the
`load_balancing` documentation covering, in this order:

1. What is measured and where — QUIC `PathStats`, TCP `TCP_INFO`, on the
   carrier of the wire currently carrying traffic; not on the LAN leg, and not
   on the probe slot.
2. The five knobs, with the defaults from Task 5, and the plain statement that
   the shipped default measures without changing selection.
3. How to read the metrics: `outline_ws_uplink_carrier_loss_ratio` next to
   `outline_ws_uplink_carrier_loss_observed_packets`, and that an absent series
   means "not measured", not "no loss".
4. How to pick `k`: compare the loss spread between the group's uplinks over a
   week, then choose `k` so that the worst-performing path's inflated latency
   crosses the best clean candidate's — worked with an example from the
   metrics.
5. That `loss_latency_inflation_max` bounds the damage of a single bad window,
   and that a lossy uplink is never removed from candidacy — only ranked lower.

- [ ] **Step 2: Write the Russian section**

Mirror it in `UPLINK-CONFIGURATIONS.ru.md`, same position, same content.
Terminology: «носитель» for carrier (never «карьер»), «гейт» for gate; keep
`loss_latency_penalty_k` and the other keys in Latin.

- [ ] **Step 3: Verify both sides carry the same knobs**

Run: `grep -c "loss_latency_penalty_k\|loss_latency_inflation_max\|loss_sample_interval\|loss_sample_min_packets\|loss_ewma_alpha" bins/outline-ws-rust/docs/UPLINK-CONFIGURATIONS.md bins/outline-ws-rust/docs/UPLINK-CONFIGURATIONS.ru.md`
Expected: both files report the same non-zero count.

- [ ] **Step 4: Run the CI gate, then commit**

```bash
git add bins/outline-ws-rust/docs
git commit -m "docs(uplink): document carrier-loss measurement and its selection knobs"
```

---

## After the plan

The feature ships measuring and not acting. To finish the job the owner
collects a week of `outline_ws_uplink_carrier_loss_ratio` across the four
client nodes, compares the spread between the group's uplinks, sets
`loss_latency_penalty_k` in `config.toml`, and applies it — no new binary, as
the knob is read per selection.

Rollout, when instructed: `ops/deploy/deploy-binary.sh`, one node at a time,
all four clients moved off unconditionally via `POST :9191/control/activate`,
`.102` last.
