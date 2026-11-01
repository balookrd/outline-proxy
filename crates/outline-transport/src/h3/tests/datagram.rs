use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use outline_wire::h3_datagram::{DatagramDemux, DropReason, decode_datagram, encode_datagram};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use quinn::rustls::{self, RootCertStore};

use super::*;
use crate::udp_transport::tests::MockChannel;

const ID: u64 = 7;

fn transport() -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    t.datagram_receive_buffer_size(Some(1 << 20));
    t.datagram_send_buffer_size(1 << 20);
    Arc::new(t)
}

async fn pair() -> (quinn::Connection, quinn::Connection, quinn::Endpoint, quinn::Endpoint) {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));

    let mut server_tls = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key)
        .unwrap();
    server_tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut server_cfg =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_tls).unwrap()));
    server_cfg.transport_config(transport());
    let server_ep = quinn::Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = server_ep.local_addr().unwrap();

    let mut roots = RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let mut client_tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut client_cfg =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_tls).unwrap()));
    client_cfg.transport_config(transport());
    let mut client_ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_ep.set_default_client_config(client_cfg);

    let connecting = client_ep.connect(addr, "localhost").unwrap();
    let (client, server) =
        tokio::join!(connecting, async { server_ep.accept().await.unwrap().await });
    (client.unwrap(), server.unwrap(), client_ep, server_ep)
}

struct Fixture {
    channel: H3DatagramChannel,
    mock: Arc<MockChannel>,
    server: quinn::Connection,
    demux: Arc<DatagramDemux>,
    unknown_drops: Arc<AtomicUsize>,
    _endpoints: (quinn::Endpoint, quinn::Endpoint),
}

async fn fixture() -> Fixture {
    fixture_with(None).await
}

/// `gate`: the VLESS-UDP channel, which keeps the stream until the gate opens.
async fn fixture_with(gate: Option<Arc<DatagramGate>>) -> Fixture {
    let (client, server, client_ep, server_ep) = pair().await;
    let unknown_drops = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&unknown_drops);
    let demux = DatagramDemux::spawn(
        client.clone(),
        Arc::new(move |reason| {
            if reason == DropReason::UnknownStream {
                counter.fetch_add(1, Ordering::SeqCst);
            }
        }),
    );
    let binding = H3DatagramBinding {
        connection: client,
        quarter_stream_id: ID,
        registration: demux.register(ID),
    };
    let mock = Arc::new(MockChannel::waiting());
    let fallback: Arc<dyn DatagramChannel> = mock.clone();
    let channel = H3DatagramChannel::new(binding, fallback, "ws_h3", "ss");
    let channel = match gate {
        Some(gate) => channel.with_gate(gate),
        None => channel,
    };
    Fixture {
        channel,
        mock,
        server,
        demux,
        unknown_drops,
        _endpoints: (client_ep, server_ep),
    }
}

/// Echoes every datagram the server receives back to the client unchanged.
fn spawn_echo(server: quinn::Connection) {
    tokio::spawn(async move {
        while let Ok(datagram) = server.read_datagram().await {
            if server.send_datagram(datagram).is_err() {
                return;
            }
        }
    });
}

async fn recv(channel: &H3DatagramChannel) -> Option<Bytes> {
    tokio::time::timeout(Duration::from_secs(5), channel.recv_datagram())
        .await
        .expect("recv timed out")
        .expect("recv failed")
}

#[tokio::test]
async fn small_packet_goes_as_a_datagram_and_comes_back() {
    let f = fixture().await;
    spawn_echo(f.server.clone());

    let packet = Bytes::from(vec![0xab; 100]);
    f.channel.send_datagram(packet.clone()).await.unwrap();

    assert_eq!(recv(&f.channel).await, Some(packet));
    assert!(f.mock.sent.lock().is_empty(), "a fitting packet must not touch the stream");
}

#[tokio::test]
async fn oversized_packet_rides_the_stream() {
    let f = fixture().await;
    let room = f.channel.connection.max_datagram_size().expect("datagrams enabled");
    let packet = Bytes::from(vec![0xcd; room + 1]);
    f.channel.send_datagram(packet.clone()).await.unwrap();
    assert_eq!(*f.mock.sent.lock(), vec![packet]);

    // Exactly at the limit (prefix included) still fits a datagram.
    let fits = Bytes::from(vec![0xef; room - outline_wire::h3_datagram::datagram_overhead(ID)]);
    f.channel.send_datagram(fits.clone()).await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(5), f.server.read_datagram())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(decode_datagram(got), Some((ID, fits)));
    assert_eq!(f.mock.sent.lock().len(), 1);
}

#[tokio::test]
async fn receives_from_both_the_demux_and_the_stream() {
    let f = fixture().await;
    f.server.send_datagram(encode_datagram(ID, b"datagram")).unwrap();
    f.mock.push(b"stream".to_vec());

    let mut got = vec![recv(&f.channel).await.unwrap(), recv(&f.channel).await.unwrap()];
    got.sort();
    assert_eq!(got, vec![Bytes::from_static(b"datagram"), Bytes::from_static(b"stream")]);
}

#[tokio::test]
async fn ended_registration_is_not_eof() {
    let f = fixture().await;
    // A second registration of the same id ends the channel's queue.
    let _newer = f.demux.register(ID);
    f.mock.push(b"after".to_vec());
    assert_eq!(recv(&f.channel).await, Some(Bytes::from_static(b"after")));

    // The stream's own end still ends the channel.
    f.mock.close().await;
    assert_eq!(recv(&f.channel).await, None);
}

#[tokio::test]
async fn close_closes_the_stream_and_unregisters() {
    let f = fixture().await;
    f.channel.close().await;
    assert!(f.mock.closed.load(Ordering::SeqCst));
    assert_eq!(recv(&f.channel).await, None);
    assert!(f.channel.send_datagram(Bytes::from_static(b"late")).await.is_err());

    // The id is gone from the demux: its datagrams now count as unknown.
    f.server.send_datagram(encode_datagram(ID, b"orphan")).unwrap();
    for _ in 0..200 {
        if f.unknown_drops.load(Ordering::SeqCst) >= 1 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("datagram for a closed channel was not dropped as unknown");
}

#[tokio::test]
async fn close_wakes_a_parked_receiver() {
    let f = Arc::new(fixture().await);
    let receiver = {
        let f = Arc::clone(&f);
        tokio::spawn(async move { f.channel.recv_datagram().await.unwrap() })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    tokio::time::timeout(Duration::from_secs(5), f.channel.close())
        .await
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), receiver)
            .await
            .unwrap()
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn gated_channel_keeps_the_stream_until_the_gate_opens() {
    let gate = Arc::new(DatagramGate::default());
    let f = fixture_with(Some(Arc::clone(&gate))).await;
    let first = Bytes::from_static(b"request header and first record");
    f.channel.send_datagram(first.clone()).await.unwrap();

    // Inbound packets, from either source, do not open it: only the protocol
    // above knows when the response header has been read.
    f.mock.push(b"cover".to_vec());
    let reply = tokio::time::timeout(Duration::from_secs(5), f.channel.recv_datagram_with_source())
        .await
        .expect("recv timed out")
        .expect("recv failed");
    assert_eq!(reply, Some((PacketSource::Stream, Bytes::from_static(b"cover"))));
    let reply = Bytes::from_static(b"reply over a datagram");
    f.server.send_datagram(encode_datagram(ID, &reply)).unwrap();
    let got = tokio::time::timeout(Duration::from_secs(5), f.channel.recv_datagram_with_source())
        .await
        .expect("recv timed out")
        .expect("recv failed");
    assert_eq!(got, Some((PacketSource::Datagram, reply)));
    let second = Bytes::from_static(b"still before the gate");
    f.channel.send_datagram(second.clone()).await.unwrap();
    assert_eq!(*f.mock.sent.lock(), vec![first.clone(), second.clone()]);

    gate.open();
    let third = Bytes::from_static(b"after the gate");
    f.channel.send_datagram(third.clone()).await.unwrap();
    let datagram = tokio::time::timeout(Duration::from_secs(5), f.server.read_datagram())
        .await
        .expect("datagram timed out")
        .expect("datagram read");
    assert_eq!(decode_datagram(datagram), Some((ID, third)));
    assert_eq!(*f.mock.sent.lock(), vec![first, second], "an open gate stays open");
}
