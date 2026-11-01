use bytes::Bytes;

use super::*;

#[test]
fn round_trips_across_varint_widths() {
    for id in [0u64, 63, 64, 16_383, 16_384, (1 << 30) - 1, 1 << 30, (1 << 62) - 1] {
        let d = encode_datagram(id, b"payload");
        assert_eq!(d.len(), datagram_overhead(id) + 7, "id {id}");
        let (got, payload) = decode_datagram(d).expect("decodes");
        assert_eq!(got, id);
        assert_eq!(&payload[..], b"payload");
    }
}

#[test]
fn overhead_matches_rfc9000_varint() {
    assert_eq!(datagram_overhead(0), 1);
    assert_eq!(datagram_overhead(63), 1);
    assert_eq!(datagram_overhead(64), 2);
    assert_eq!(datagram_overhead(16_383), 2);
    assert_eq!(datagram_overhead(16_384), 4);
    assert_eq!(datagram_overhead(1 << 30), 8);
}

#[test]
fn rejects_truncated_or_empty() {
    assert!(decode_datagram(Bytes::new()).is_none());
    // 2-byte varint prefix (0b01) with only one byte present.
    assert!(decode_datagram(Bytes::from_static(&[0x40])).is_none());
}

#[test]
fn empty_payload_is_valid() {
    let (id, p) = decode_datagram(encode_datagram(5, b"")).unwrap();
    assert_eq!((id, p.len()), (5, 0));
}

#[cfg(feature = "h3-datagram")]
mod demux {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
    use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use quinn::rustls::{self, RootCertStore};

    use super::*;

    #[derive(Default)]
    struct Counts {
        unknown: AtomicUsize,
        malformed: AtomicUsize,
        queue_full: AtomicUsize,
    }

    fn counting() -> (Arc<Counts>, Arc<dyn Fn(DropReason) + Send + Sync>) {
        let counts = Arc::new(Counts::default());
        let c = Arc::clone(&counts);
        let f = move |reason| {
            match reason {
                DropReason::UnknownStream => c.unknown.fetch_add(1, Ordering::SeqCst),
                DropReason::Malformed => c.malformed.fetch_add(1, Ordering::SeqCst),
                DropReason::QueueFull => c.queue_full.fetch_add(1, Ordering::SeqCst),
            };
        };
        (counts, Arc::new(f))
    }

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
        let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(server_tls).unwrap(),
        ));
        server_cfg.transport_config(transport());
        let server_ep =
            quinn::Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
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

    async fn recv(rx: &mut tokio::sync::mpsc::Receiver<Bytes>) -> Option<Bytes> {
        tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap()
    }

    async fn wait_for(counter: &AtomicUsize, at_least: usize) {
        for _ in 0..200 {
            if counter.load(Ordering::SeqCst) >= at_least {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("counter never reached {at_least}");
    }

    #[tokio::test]
    async fn routes_by_stream_and_counts_drops() {
        let (client, server, _cep, _sep) = pair().await;
        let (counts, on_drop) = counting();
        let demux = DatagramDemux::spawn(client, on_drop);
        let mut reg1 = demux.register(1);
        let mut reg2 = demux.register(2);

        server.send_datagram(encode_datagram(1, b"a")).unwrap();
        server.send_datagram(encode_datagram(2, b"b")).unwrap();
        server.send_datagram(encode_datagram(9, b"x")).unwrap();
        server.send_datagram(Bytes::from_static(&[0x40])).unwrap();

        assert_eq!(&recv(&mut reg1.rx).await.unwrap()[..], b"a");
        assert_eq!(&recv(&mut reg2.rx).await.unwrap()[..], b"b");
        wait_for(&counts.unknown, 1).await;
        wait_for(&counts.malformed, 1).await;
        assert_eq!(counts.unknown.load(Ordering::SeqCst), 1);
        assert_eq!(counts.malformed.load(Ordering::SeqCst), 1);

        drop(reg1);
        server.send_datagram(encode_datagram(1, b"late")).unwrap();
        wait_for(&counts.unknown, 2).await;
        assert_eq!(counts.unknown.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn stale_registration_drop_keeps_newer_route() {
        let (client, server, _cep, _sep) = pair().await;
        let (_counts, on_drop) = counting();
        let demux = DatagramDemux::spawn(client, on_drop);
        let a = demux.register(1);
        let mut b = demux.register(1);
        drop(a);
        server.send_datagram(encode_datagram(1, b"to-b")).unwrap();
        assert_eq!(&recv(&mut b.rx).await.unwrap()[..], b"to-b");
    }

    #[tokio::test]
    async fn dropping_demux_stops_reader() {
        let (client, _server, _cep, _sep) = pair().await;
        let (_counts, on_drop) = counting();
        // The reader task owns one clone of `on_drop`.
        let probe = Arc::clone(&on_drop);
        let demux = DatagramDemux::spawn(client, on_drop);
        assert_eq!(Arc::strong_count(&probe), 2);
        drop(demux);
        for _ in 0..200 {
            if Arc::strong_count(&probe) == 1 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("reader task still alive after the demux was dropped");
    }

    #[tokio::test]
    async fn connection_close_ends_registrations() {
        let (client, server, _cep, _sep) = pair().await;
        let (_counts, on_drop) = counting();
        let demux = DatagramDemux::spawn(client, on_drop);
        let mut reg = demux.register(1);
        server.close(0u32.into(), b"bye");
        assert!(recv(&mut reg.rx).await.is_none());
        // Registering after the close also yields an ended receiver.
        let mut late = demux.register(2);
        assert!(recv(&mut late.rx).await.is_none());
    }

    #[tokio::test]
    async fn full_queue_drops_without_stopping_reader() {
        let (client, server, _cep, _sep) = pair().await;
        let (counts, on_drop) = counting();
        let demux = DatagramDemux::spawn(client, on_drop);
        let mut reg = demux.register(1);
        for i in 0..400u32 {
            server.send_datagram(encode_datagram(1, &i.to_be_bytes())).unwrap();
            if i % 50 == 49 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        let mut drained = 0;
        while reg.rx.try_recv().is_ok() {
            drained += 1;
        }
        assert!(drained <= DATAGRAM_QUEUE, "drained {drained}");
        assert!(drained > 0);
        assert!(counts.queue_full.load(Ordering::SeqCst) >= 1, "queue_full not counted");
        server.send_datagram(encode_datagram(1, b"after")).unwrap();
        assert_eq!(&recv(&mut reg.rx).await.unwrap()[..], b"after");
    }
}
