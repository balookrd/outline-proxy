// Both tests below are Linux-only (`TCP_INFO` sampling is gated to Linux); on
// other platforms this import would otherwise be unused.
#[cfg(target_os = "linux")]
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
