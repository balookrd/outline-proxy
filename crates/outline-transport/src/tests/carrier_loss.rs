// The TCP tests below are Linux-only (`TCP_INFO` sampling is gated to
// Linux); the QUIC tests are gated to the `h3` feature instead. Import once,
// under whichever cfg combination is active, so a build with both active
// (an ordinary Linux `--features h3` run) does not import `CarrierLossProbe`
// twice.
#[cfg(any(target_os = "linux", feature = "h3"))]
use crate::carrier_loss::CarrierLossProbe;
#[cfg(feature = "h3")]
use crate::carrier_loss::{CarrierLossCounters, CarrierLossSample};
#[cfg(feature = "h3")]
use std::sync::Arc;

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

/// An HTTP/1 carrier hands out a probe on its underlying TCP socket, so a
/// plain `ws://` uplink is measurable without any shared-connection plumbing.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn http1_transport_stream_yields_a_tcp_probe() {
    use crate::ws_stream::TransportStream;
    use tokio_tungstenite::tungstenite::protocol::Role;
    use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = tokio::net::TcpStream::connect(addr).await.unwrap();
    let _server = listener.accept().await.unwrap();

    let ws =
        WebSocketStream::from_raw_socket(MaybeTlsStream::Plain(client), Role::Client, None).await;
    let stream = TransportStream::new_http1(ws);

    let probe = stream.loss_probe().expect("http1 carrier exposes a probe");
    let sample = probe.sample().expect("probe reads the live socket");
    assert!(sample.alive);
}

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

// ── QUIC: `CarrierLossProbe::Quic` observes through a `Weak`, not a clone ──
//
// A minimal, real implementer of `CarrierLossCounters`: it reports a fixed
// sample, but the `Arc`/`Weak` pair wrapped around it, and the drop that
// invalidates the `Weak`, are exactly the mechanics `SharedH3Connection`
// (`h3/shared.rs`) and the XHTTP-over-H3 carrier (`xhttp/h3.rs`) wire up in
// production. These tests exercise `CarrierLossProbe`'s real `sample()` /
// `identity()` through a real `Weak` that a real `Arc` drop invalidates —
// nothing about the probe's own logic is stubbed out, only the specific
// counters a production carrier would report.

#[cfg(feature = "h3")]
struct StubCarrier(CarrierLossSample);

#[cfg(feature = "h3")]
impl CarrierLossCounters for StubCarrier {
    fn loss_counters(&self) -> Option<CarrierLossSample> {
        Some(self.0)
    }
}

#[cfg(feature = "h3")]
fn quic_probe_over(carrier: &Arc<StubCarrier>, identity: u64) -> CarrierLossProbe {
    // Unsize to `Arc<dyn CarrierLossCounters>` first: `Arc::downgrade` is
    // generic in `T`, and handing it a concrete `&Arc<StubCarrier>` directly
    // while the target type says `Weak<dyn CarrierLossCounters>` fails to
    // unify. Downgrading an already-unsized `Arc` needs no such dance.
    let dyn_carrier: Arc<dyn CarrierLossCounters> = carrier.clone();
    let counters = Arc::downgrade(&dyn_carrier);
    CarrierLossProbe::Quic { counters, identity }
}

/// A live carrier's probe reports exactly the counters the carrier itself
/// reports — the `Weak` indirection must not perturb an ordinary reading.
#[cfg(feature = "h3")]
#[test]
fn quic_probe_reports_live_counters_unchanged() {
    let sample = CarrierLossSample { sent: 42, lost: 3, alive: true };
    let carrier = Arc::new(StubCarrier(sample));
    let probe = quic_probe_over(&carrier, 7);

    assert_eq!(probe.sample(), Some(sample));
}

/// This is the regression that matters: the old `CarrierLossProbe::Quic`
/// held a `quinn::Connection` clone directly, which kept the real connection
/// alive, so `close_reason().is_none()` never turned false and the carrier
/// never aged out of the registry. Here the probe holds only a `Weak`;
/// dropping the carrier's last strong reference must make `sample()` report
/// the carrier dead so the registry's dead-carrier eviction path actually
/// fires on it.
#[cfg(feature = "h3")]
#[test]
fn quic_probe_reports_dead_once_the_last_strong_reference_drops() {
    let carrier = Arc::new(StubCarrier(CarrierLossSample { sent: 42, lost: 3, alive: true }));
    let probe = quic_probe_over(&carrier, 7);

    drop(carrier);

    let sample = probe
        .sample()
        .expect("a dead carrier is still `Some` — see `CarrierLossProbe::sample`'s doc comment");
    assert!(!sample.alive, "dropping the last strong reference must report the carrier dead");
}

/// The registry recognises (and evicts) probes by identity, including a probe
/// whose carrier is already gone — so identity must stay answerable without
/// going through the (by-then-dead) `Weak`.
#[cfg(feature = "h3")]
#[test]
fn quic_probe_identity_survives_the_carrier_dying() {
    let carrier = Arc::new(StubCarrier(CarrierLossSample { sent: 0, lost: 0, alive: true }));
    let probe = quic_probe_over(&carrier, 99);

    drop(carrier);

    assert_eq!(probe.identity(), 99, "identity must stay readable after the carrier is gone");
}
