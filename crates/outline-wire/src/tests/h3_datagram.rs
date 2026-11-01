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
        closed: AtomicUsize,
        malformed: AtomicUsize,
        queue_full: AtomicUsize,
        stalled: AtomicUsize,
    }

    fn counting() -> (Arc<Counts>, Arc<dyn Fn(DropReason) + Send + Sync>) {
        let counts = Arc::new(Counts::default());
        let c = Arc::clone(&counts);
        let f = move |reason| {
            match reason {
                DropReason::UnknownStream => c.unknown.fetch_add(1, Ordering::SeqCst),
                DropReason::ClosedStream => c.closed.fetch_add(1, Ordering::SeqCst),
                DropReason::Malformed => c.malformed.fetch_add(1, Ordering::SeqCst),
                DropReason::QueueFull => c.queue_full.fetch_add(1, Ordering::SeqCst),
                DropReason::QueueStalled => c.stalled.fetch_add(1, Ordering::SeqCst),
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

    async fn recv(reg: &mut DatagramRegistration) -> Option<Bytes> {
        tokio::time::timeout(Duration::from_secs(5), reg.recv())
            .await
            .unwrap()
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

        assert_eq!(&recv(&mut reg1).await.unwrap()[..], b"a");
        assert_eq!(&recv(&mut reg2).await.unwrap()[..], b"b");
        wait_for(&counts.unknown, 1).await;
        wait_for(&counts.malformed, 1).await;
        assert_eq!(counts.unknown.load(Ordering::SeqCst), 1);
        assert_eq!(counts.malformed.load(Ordering::SeqCst), 1);

        drop(reg1);
        server.send_datagram(encode_datagram(1, b"late")).unwrap();
        // The tail of a stream that just unregistered is expected, not a
        // routing error.
        wait_for(&counts.closed, 1).await;
        assert_eq!(counts.unknown.load(Ordering::SeqCst), 1);
    }

    /// A tombstone outlives its TTL only until the next datagram for the id,
    /// which then counts as unknown again.
    #[tokio::test]
    async fn tombstone_expires_into_unknown_stream() {
        let (client, server, _cep, _sep) = pair().await;
        let (counts, on_drop) = counting();
        let demux = DatagramDemux::spawn_with_ttl(client, on_drop, Duration::from_millis(100));
        drop(demux.register(1));
        server.send_datagram(encode_datagram(1, b"tail")).unwrap();
        wait_for(&counts.closed, 1).await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        server.send_datagram(encode_datagram(1, b"stray")).unwrap();
        wait_for(&counts.unknown, 1).await;
        assert_eq!(counts.closed.load(Ordering::SeqCst), 1);
    }

    /// Registering an id again replaces its tombstone.
    #[tokio::test]
    async fn register_over_a_tombstone_routes_again() {
        let (client, server, _cep, _sep) = pair().await;
        let (_counts, on_drop) = counting();
        let demux = DatagramDemux::spawn(client, on_drop);
        drop(demux.register(1));
        let mut again = demux.register(1);
        server.send_datagram(encode_datagram(1, b"back")).unwrap();
        assert_eq!(&recv(&mut again).await.unwrap()[..], b"back");
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
        assert_eq!(&recv(&mut b).await.unwrap()[..], b"to-b");
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
        assert!(recv(&mut reg).await.is_none());
        // Registering after the close also yields an ended receiver.
        let mut late = demux.register(2);
        assert!(recv(&mut late).await.is_none());
    }

    #[tokio::test]
    async fn full_queue_drops_without_stopping_reader() {
        let (client, server, _cep, _sep) = pair().await;
        let (counts, on_drop) = counting();
        let demux = DatagramDemux::spawn(client, on_drop);
        let mut reg = demux.register(1);
        // Tiny datagrams: only the packet-count ceiling can overflow.
        for i in 0..(DATAGRAM_QUEUE as u32 + 400) {
            server.send_datagram(encode_datagram(1, &i.to_be_bytes())).unwrap();
            if i % 50 == 49 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        let mut drained = 0;
        while reg.try_recv().is_some() {
            drained += 1;
        }
        assert!(drained <= DATAGRAM_QUEUE, "drained {drained}");
        assert!(drained > 0);
        assert!(
            counts.queue_full.load(Ordering::SeqCst) + counts.stalled.load(Ordering::SeqCst) >= 1,
            "overflow not counted"
        );
        server.send_datagram(encode_datagram(1, b"after")).unwrap();
        assert_eq!(&recv(&mut reg).await.unwrap()[..], b"after");
    }

    async fn wait_total(counts: &Counts, queued: impl Fn() -> usize, total: usize) {
        for _ in 0..300 {
            let dropped =
                counts.queue_full.load(Ordering::SeqCst) + counts.stalled.load(Ordering::SeqCst);
            if dropped + queued() >= total {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("datagrams never settled");
    }

    /// A registration nobody reads holds at most its byte budget; the rest drop
    /// as `queue_stalled` once the consumer has left its queue unread for
    /// `QUEUE_STALL`.
    #[tokio::test]
    async fn registration_queue_is_bounded_in_bytes() {
        let (client, server, _cep, _sep) = pair().await;
        let (counts, on_drop) = counting();
        let demux = DatagramDemux::spawn_with_limits(client, on_drop, 10_000, 1 << 20, QUEUE_STALL);
        let mut reg = demux.register(1);
        for _ in 0..10 {
            server.send_datagram(encode_datagram(1, &[0u8; 1000])).unwrap();
        }
        wait_total(&counts, || demux.queued_bytes() / 1000, 10).await;
        tokio::time::sleep(QUEUE_STALL * 2).await;
        for _ in 0..20 {
            server.send_datagram(encode_datagram(1, &[0u8; 1000])).unwrap();
        }
        wait_total(&counts, || demux.queued_bytes() / 1000, 30).await;
        assert_eq!(demux.queued_bytes(), 10_000);
        assert_eq!(counts.stalled.load(Ordering::SeqCst), 20);
        assert_eq!(counts.queue_full.load(Ordering::SeqCst), 0);
        let mut read = 0;
        while reg.try_recv().is_some() {
            read += 1;
        }
        assert_eq!(read, 10);
        assert_eq!(demux.queued_bytes(), 0);
    }

    /// The connection budget caps the sum over registrations.
    #[tokio::test]
    async fn connection_budget_caps_all_registrations() {
        let (client, server, _cep, _sep) = pair().await;
        let (counts, on_drop) = counting();
        let demux = DatagramDemux::spawn_with_limits(client, on_drop, 10_000, 15_000, QUEUE_STALL);
        let mut a = demux.register(1);
        let mut b = demux.register(2);
        for id in [1, 2] {
            for _ in 0..10 {
                server.send_datagram(encode_datagram(id, &[0u8; 1000])).unwrap();
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        wait_total(&counts, || demux.queued_bytes() / 1000, 20).await;
        assert_eq!(demux.queued_bytes(), 15_000);
        let drain = |reg: &mut DatagramRegistration| std::iter::from_fn(|| reg.try_recv()).count();
        assert_eq!(drain(&mut a), 10);
        assert_eq!(drain(&mut b), 5);
    }

    /// Dropping a registration with queued datagrams returns their bytes.
    #[tokio::test]
    async fn dropped_registration_releases_its_bytes() {
        let (client, server, _cep, _sep) = pair().await;
        let (counts, on_drop) = counting();
        let demux = DatagramDemux::spawn_with_limits(client, on_drop, 10_000, 1 << 20, QUEUE_STALL);
        let reg = demux.register(1);
        for _ in 0..5 {
            server.send_datagram(encode_datagram(1, &[0u8; 1000])).unwrap();
        }
        wait_total(&counts, || demux.queued_bytes() / 1000, 5).await;
        drop(reg);
        assert_eq!(demux.queued_bytes(), 0);
    }

    /// A burst overflowing the queue of a consumer that has long waited on an
    /// empty queue is `queue_full`: the idle clock starts when the queue turns
    /// non-empty, not at the last read. A generous stall keeps the burst
    /// itself well inside it.
    #[tokio::test]
    async fn burst_into_a_waiting_consumer_is_queue_full() {
        let (client, server, _cep, _sep) = pair().await;
        let (counts, on_drop) = counting();
        let stall = Duration::from_millis(500);
        let demux = DatagramDemux::spawn_with_limits(client, on_drop, 10_000, 1 << 20, stall);
        let mut reg = demux.register(1);
        // Waits on the empty queue for longer than the stall.
        assert!(tokio::time::timeout(stall + stall / 2, reg.recv()).await.is_err());
        for _ in 0..30 {
            server.send_datagram(encode_datagram(1, &[0u8; 1000])).unwrap();
        }
        wait_total(&counts, || demux.queued_bytes() / 1000, 30).await;
        assert_eq!(counts.queue_full.load(Ordering::SeqCst), 20);
        assert_eq!(counts.stalled.load(Ordering::SeqCst), 0);
        assert_eq!(std::iter::from_fn(|| reg.try_recv()).count(), 10);
        assert_eq!(demux.queued_bytes(), 0);
    }

    /// A registration replaced by a newer one of the same id keeps what it had
    /// queued until it reads or drops it, and then returns those bytes.
    #[tokio::test]
    async fn replaced_registration_returns_its_bytes() {
        let (client, server, _cep, _sep) = pair().await;
        let (counts, on_drop) = counting();
        let demux = DatagramDemux::spawn_with_limits(client, on_drop, 10_000, 1 << 20, QUEUE_STALL);
        let mut old = demux.register(1);
        let dropped_old = demux.register(2);
        for id in [1, 2] {
            for _ in 0..4 {
                server.send_datagram(encode_datagram(id, &[0u8; 1000])).unwrap();
            }
        }
        wait_total(&counts, || demux.queued_bytes() / 1000, 8).await;
        let mut new = demux.register(1);
        let _new2 = demux.register(2);
        for _ in 0..3 {
            server.send_datagram(encode_datagram(1, &[0u8; 1000])).unwrap();
        }
        wait_total(&counts, || demux.queued_bytes() / 1000, 11).await;
        assert_eq!(demux.queued_bytes(), 11_000);
        // The replaced one drains what it had, then ends.
        for _ in 0..4 {
            assert!(old.try_recv().is_some());
        }
        assert!(recv(&mut old).await.is_none());
        assert_eq!(demux.queued_bytes(), 7_000);
        // Dropping a replaced one returns its queue as well.
        drop(dropped_old);
        assert_eq!(demux.queued_bytes(), 3_000);
        assert_eq!(std::iter::from_fn(|| new.try_recv()).count(), 3);
        assert_eq!(demux.queued_bytes(), 0);
    }

    /// Datagrams queued when the connection closes stay counted until read or
    /// dropped with their registration.
    #[tokio::test]
    async fn connection_close_returns_queued_bytes() {
        let (client, server, _cep, _sep) = pair().await;
        let (counts, on_drop) = counting();
        let watch = client.clone();
        let demux = DatagramDemux::spawn_with_limits(client, on_drop, 10_000, 1 << 20, QUEUE_STALL);
        let mut read = demux.register(1);
        let dropped = demux.register(2);
        for id in [1, 2] {
            for _ in 0..3 {
                server.send_datagram(encode_datagram(id, &[0u8; 1000])).unwrap();
            }
        }
        wait_total(&counts, || demux.queued_bytes() / 1000, 6).await;
        server.close(0u32.into(), b"bye");
        tokio::time::timeout(Duration::from_secs(5), watch.closed())
            .await
            .unwrap();
        assert_eq!(demux.queued_bytes(), 6_000);
        drop(dropped);
        assert_eq!(demux.queued_bytes(), 3_000);
        for _ in 0..3 {
            assert!(recv(&mut read).await.is_some());
        }
        assert!(recv(&mut read).await.is_none());
        assert_eq!(demux.queued_bytes(), 0);
    }

    /// Registrations dropped on one worker while the reader routes datagrams
    /// to them on another must return every byte: dropping a registration
    /// can land between the reader's permit and its write into the channel.
    /// The outcome does not depend on hitting that window.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn churn_under_load_returns_every_byte() {
        let (client, server, _cep, _sep) = pair().await;
        let (_counts, on_drop) = counting();
        let demux = DatagramDemux::spawn(client, on_drop);
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        const IDS: u64 = 8;
        let sender = {
            let stop = Arc::clone(&stop);
            tokio::spawn(async move {
                let mut n = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    let _ = server.send_datagram(encode_datagram(n % IDS, &[0u8; 1000]));
                    n += 1;
                    if n.is_multiple_of(32) {
                        tokio::task::yield_now().await;
                    }
                }
                server
            })
        };
        let churners: Vec<_> = (0..IDS)
            .map(|id| {
                let demux = Arc::clone(&demux);
                tokio::spawn(async move {
                    for round in 0..400u64 {
                        let mut reg = demux.register(id);
                        for _ in 0..(round % 4) {
                            tokio::task::yield_now().await;
                            let _ = reg.try_recv();
                        }
                        tokio::task::yield_now().await;
                        drop(reg);
                    }
                })
            })
            .collect();
        for churner in churners {
            churner.await.unwrap();
        }
        stop.store(true, Ordering::Relaxed);
        let server = sender.await.unwrap();
        // Datagrams the reader is still routing release their bytes once it
        // lets go of the channels; a leak never would.
        for _ in 0..500 {
            if demux.queued_bytes() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(demux.queued_bytes(), 0);
        drop(server);
    }

    /// A watched demux reports the path every interval, with black holes and
    /// lost probes as deltas since the previous sample, and once more when the
    /// connection closes.
    #[tokio::test]
    async fn watched_demux_samples_the_path() {
        let (client, server, _cep, _sep) = pair().await;
        let (_counts, on_drop) = counting();
        let samples = Arc::new(std::sync::Mutex::new(Vec::<PathSample>::new()));
        let sink = Arc::clone(&samples);
        let demux = DatagramDemux::spawn_watched_every(
            client,
            on_drop,
            Arc::new(move |s| sink.lock().unwrap().push(s)),
            Duration::from_millis(50),
        );
        tokio::time::sleep(Duration::from_millis(180)).await;
        let seen = samples.lock().unwrap().len();
        assert!(seen >= 2, "only {seen} samples");
        for s in samples.lock().unwrap().iter() {
            assert!(s.current_mtu.is_some_and(|m| m >= 1200), "{s:?}");
            assert_eq!((s.black_holes, s.lost_probes), (0, 0), "{s:?}");
        }
        server.close(0u32.into(), b"bye");
        for _ in 0..200 {
            if samples.lock().unwrap().len() > seen {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(samples.lock().unwrap().len() > seen, "no final sample on close");
        assert_eq!(samples.lock().unwrap().last().unwrap().current_mtu, None);
        drop(demux);
    }

    /// Cumulative counters come out as deltas, and the close-time sample
    /// carries the counters but no MTU.
    #[test]
    fn next_sample_reports_deltas_and_no_mtu_at_close() {
        let mut base = (0, 0);
        let first = next_sample(&mut base, 1200, 3, 5, false);
        assert_eq!(
            first,
            PathSample {
                current_mtu: Some(1200),
                black_holes: 3,
                lost_probes: 5
            }
        );
        let second = next_sample(&mut base, 1400, 5, 5, false);
        assert_eq!(
            second,
            PathSample {
                current_mtu: Some(1400),
                black_holes: 2,
                lost_probes: 0
            }
        );
        let last = next_sample(&mut base, 1400, 6, 9, true);
        assert_eq!(
            last,
            PathSample {
                current_mtu: None,
                black_holes: 1,
                lost_probes: 4
            }
        );
        assert_eq!(base, (6, 9));
    }
}
