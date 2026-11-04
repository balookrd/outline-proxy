use super::{H2ConnectionKey, H2Dialer};
use crate::dial_plan::{DialNetworkOptions, DialResumeOptions};
use crate::fingerprint_profile::{TlsFingerprint, with_dial_fingerprint};
use crate::shared_cache::should_reuse_connection;
use crate::shared_dial::WsDialer;

const CHROMIUM: TlsFingerprint = TlsFingerprint::Chromium;

#[test]
fn h2_shared_connection_key_distinguishes_scheme_server_name_port_fwmark_and_family() {
    let base = H2ConnectionKey::new("one.example", 443, true, None, CHROMIUM);

    assert_ne!(base, H2ConnectionKey::new("two.example", 443, true, None, CHROMIUM));
    assert_ne!(base, H2ConnectionKey::new("one.example", 443, false, None, CHROMIUM));
    assert_ne!(base, H2ConnectionKey::new("one.example", 443, true, Some(42), CHROMIUM));
    assert_ne!(base, H2ConnectionKey::new("one.example", 8443, true, None, CHROMIUM));
    assert_ne!(
        base,
        H2ConnectionKey::new("one.example", 443, true, None, TlsFingerprint::Firefox)
    );
    assert_eq!(base, H2ConnectionKey::new("one.example", 443, true, None, CHROMIUM));
}

/// The dialer reads the dial-scoped family, so two dials to the same server
/// as different browsers key two shared connections, while a dial without a
/// profile shares the Chromium one (it sends the Chromium hello and shape).
#[tokio::test]
async fn h2_dialer_keys_connections_by_dial_scoped_family() {
    async fn key_under(fp: Option<TlsFingerprint>) -> H2ConnectionKey {
        with_dial_fingerprint(fp, async {
            H2Dialer::new(true, DialResumeOptions::default(), None).make_key(
                "one.example",
                443,
                DialNetworkOptions::default(),
            )
        })
        .await
    }
    let chromium = key_under(Some(TlsFingerprint::Chromium)).await;
    let firefox = key_under(Some(TlsFingerprint::Firefox)).await;
    let safari = key_under(Some(TlsFingerprint::Safari)).await;
    let unscoped = H2Dialer::new(true, DialResumeOptions::default(), None).make_key(
        "one.example",
        443,
        DialNetworkOptions::default(),
    );
    assert_ne!(chromium, firefox);
    assert_ne!(chromium, safari);
    assert_ne!(firefox, safari);
    assert_eq!(chromium, key_under(None).await);
    assert_eq!(chromium, unscoped);
}

#[test]
fn probe_sources_do_not_reuse_shared_h2_connections() {
    assert!(should_reuse_connection("direct"));
    assert!(should_reuse_connection("standby_tcp"));
    assert!(!should_reuse_connection("probe_ws"));
    assert!(!should_reuse_connection("probe_http"));
}

/// `H2Io` must forward vectored writes: otherwise h2 writes the frame header and
/// payload separately and rustls emits a TLS record for each.
#[tokio::test]
async fn h2_io_forwards_vectored_writes() {
    use std::io::IoSlice;
    use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (client, server) = tokio::join!(TcpStream::connect(addr), listener.accept());
    let mut io = super::H2Io::Plain { inner: client.unwrap() };
    let mut server = server.unwrap().0;
    assert!(AsyncWrite::is_write_vectored(&io));

    let header = [1u8; 9];
    let payload = vec![7u8; 1572];
    let n = io
        .write_vectored(&[IoSlice::new(&header), IoSlice::new(&payload)])
        .await
        .unwrap();
    assert_eq!(n, 9 + 1572, "loopback accepts the whole gather");
    io.shutdown().await.unwrap();
    let mut got = Vec::new();
    server.read_to_end(&mut got).await.unwrap();
    assert_eq!(got.len(), 9 + 1572);
    assert_eq!(&got[..9], &header);
}

/// `disable_udp_gso` only changes how QUIC sockets send; an h2 carrier rides
/// TCP, so dials that differ only in it must keep sharing one connection.
#[test]
fn h2_dialer_key_ignores_disable_udp_gso() {
    let dialer = H2Dialer::new(true, DialResumeOptions::default(), None);
    let plain = dialer.make_key("one.example", 443, DialNetworkOptions::default());
    let no_gso = dialer.make_key(
        "one.example",
        443,
        DialNetworkOptions {
            disable_udp_gso: true,
            ..DialNetworkOptions::default()
        },
    );
    assert_eq!(plain, no_gso);
}
