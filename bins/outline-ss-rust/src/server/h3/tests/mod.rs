//! The public HTTP/3 listener's QUIC transport parameters, connection ID
//! length and HTTP/3 SETTINGS, read off a real loopback handshake with the
//! production endpoint and server configs and compared with a quic-go (Caddy)
//! server.

use std::{
    any::Any,
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use quinn::crypto::{
    ExportKeyingMaterialError, HeaderKey, KeyPair, Keys, PacketKey, Session,
    rustls::QuicClientConfig,
};
use rustls::pki_types::CertificateDer;

use super::vendored::{
    QUIC_GO_ACTIVE_CONNECTION_ID_LIMIT, QUIC_GO_MAX_ACK_DELAY_MS, QUIC_GO_MAX_DATAGRAM_FRAME_SIZE,
    QUIC_GO_TP_ORDER, h3_ws_server_from_endpoint,
};
use super::{H3ServeCtx, build_h3_endpoint_config, build_h3_quinn_server_config, serve_h3_server};
use crate::metrics::Metrics;
use crate::server::constants::{H3_MAX_UDP_PAYLOAD_SIZE, H3_SERVER_CID_LEN};
use crate::server::nat::NatTable;
use crate::server::shutdown::ShutdownSignal;
use crate::server::tests::{build_test_state, sample_config, test_h3_server_tls};
use crate::server::{DnsCache, ensure_rustls_provider_installed};

const TP_MAX_UDP_PAYLOAD_SIZE: u64 = 0x03;
const TP_MAX_ACK_DELAY: u64 = 0x0b;
const TP_ACTIVE_CONNECTION_ID_LIMIT: u64 = 0x0e;
const TP_INITIAL_SOURCE_CONNECTION_ID: u64 = 0x0f;
const TP_MAX_DATAGRAM_FRAME_SIZE: u64 = 0x20;
const TP_GREASE_QUIC_BIT: u64 = 0x2ab2;
const TP_MIN_ACK_DELAY_DRAFT07: u64 = 0xff04_de1b;
const SETTINGS_H3_DATAGRAM: u64 = 0x33;
const SETTINGS_ENABLE_CONNECT_PROTOCOL: u64 = 0x08;

/// Client crypto config that records every byte of the server's CRYPTO
/// stream (Initial, Handshake and 1-RTT), so the test can read the server's
/// raw transport parameters out of EncryptedExtensions. quinn hands a client
/// only the parsed parameters, without their order or the GREASE entry.
struct RecordingClientConfig {
    inner: Arc<QuicClientConfig>,
    received: Arc<Mutex<Vec<u8>>>,
}

impl quinn::crypto::ClientConfig for RecordingClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &quinn_proto::transport_parameters::TransportParameters,
    ) -> Result<Box<dyn Session>, quinn::ConnectError> {
        let inner = Arc::clone(&self.inner).start_session(version, server_name, params)?;
        Ok(Box::new(RecordingSession {
            inner,
            received: Arc::clone(&self.received),
        }))
    }
}

struct RecordingSession {
    inner: Box<dyn Session>,
    received: Arc<Mutex<Vec<u8>>>,
}

impl Session for RecordingSession {
    fn initial_keys(&self, dst_cid: &quinn::ConnectionId, side: quinn::Side) -> Keys {
        self.inner.initial_keys(dst_cid, side)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        self.inner.handshake_data()
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.inner.peer_identity()
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
        self.inner.early_crypto()
    }

    fn early_data_accepted(&self) -> Option<bool> {
        self.inner.early_data_accepted()
    }

    fn is_handshaking(&self) -> bool {
        self.inner.is_handshaking()
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, quinn_proto::TransportError> {
        self.received.lock().expect("recording lock").extend_from_slice(buf);
        self.inner.read_handshake(buf)
    }

    fn transport_parameters(
        &self,
    ) -> Result<
        Option<quinn_proto::transport_parameters::TransportParameters>,
        quinn_proto::TransportError,
    > {
        self.inner.transport_parameters()
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        self.inner.write_handshake(buf)
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        self.inner.next_1rtt_keys()
    }

    fn is_valid_retry(
        &self,
        orig_dst_cid: &quinn::ConnectionId,
        header: &[u8],
        payload: &[u8],
    ) -> bool {
        self.inner.is_valid_retry(orig_dst_cid, header, payload)
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        self.inner.export_keying_material(output, label, context)
    }
}

/// A running listener built from the production endpoint and server configs.
struct TestListener {
    addr: SocketAddr,
    cert_der: CertificateDer<'static>,
    task: tokio::task::JoinHandle<Result<()>>,
}

impl Drop for TestListener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn start_listener(udp_datagrams: bool) -> Result<TestListener> {
    let (tls_config, cert_der) = test_h3_server_tls()?;
    let probe_config = sample_config(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));
    let server_config =
        build_h3_quinn_server_config(tls_config, &probe_config.tuning, None, None, udp_datagrams)?;
    let socket = std::net::UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let endpoint = quinn::Endpoint::new(
        build_h3_endpoint_config()?,
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;
    let addr = endpoint.local_addr()?;
    let server =
        h3_ws_server_from_endpoint(endpoint, super::build_h3_ws_config(&probe_config.tuning));

    let config = sample_config(addr);
    let metrics = Metrics::new(&config);
    let nat_table = NatTable::new(std::time::Duration::from_secs(300));
    let dns_cache = DnsCache::new(std::time::Duration::from_secs(30));
    let (routes, services, auth) = build_test_state(
        &config,
        metrics,
        nat_table,
        dns_cache,
        false,
        config.http_root_realm.clone(),
    );
    let task = tokio::spawn(async move {
        serve_h3_server(
            server,
            H3ServeCtx {
                routes,
                services,
                auth,
                alpn: Arc::from(vec![crate::config::H3Alpn::H3].into_boxed_slice()),
                http_fallback: None,
                cluster: None,
                udp_datagrams,
            },
            ShutdownSignal::never(),
        )
        .await
    });
    Ok(TestListener { addr, cert_der, task })
}

/// What a client sees of the listener: its raw transport parameters in wire
/// order, its HTTP/3 SETTINGS in wire order, and the connection.
struct Observed {
    transport_parameters: Vec<(u64, Vec<u8>)>,
    settings: Vec<(u64, u64)>,
    connection: quinn::Connection,
    _endpoint: quinn::Endpoint,
}

async fn observe(listener: &TestListener) -> Result<Observed> {
    ensure_rustls_provider_installed();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(listener.cert_der.clone())?;
    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(Arc::new(roots))
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"h3".to_vec()];
    let received = Arc::new(Mutex::new(Vec::new()));
    let crypto = RecordingClientConfig {
        inner: Arc::new(QuicClientConfig::try_from(tls_config).map_err(|e| anyhow!(e))?),
        received: Arc::clone(&received),
    };
    let mut endpoint = quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    let connection = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        endpoint.connect(listener.addr, "localhost")?,
    )
    .await
    .context("handshake timed out")??;

    let crypto_stream = received.lock().expect("recording lock").clone();
    let transport_parameters = parse_transport_parameters(&server_tp_extension(&crypto_stream)?)?;
    let settings =
        tokio::time::timeout(std::time::Duration::from_secs(5), read_settings(&connection))
            .await
            .context("server SETTINGS timed out")??;
    Ok(Observed {
        transport_parameters,
        settings,
        connection,
        _endpoint: endpoint,
    })
}

/// The `quic_transport_parameters` (0x39) extension of the server's
/// EncryptedExtensions, found in the server's TLS handshake messages.
fn server_tp_extension(mut messages: &[u8]) -> Result<Vec<u8>> {
    const ENCRYPTED_EXTENSIONS: u8 = 8;
    const QUIC_TRANSPORT_PARAMETERS: u16 = 0x39;
    while messages.len() >= 4 {
        let kind = messages[0];
        let len = usize::from(messages[1]) << 16
            | usize::from(messages[2]) << 8
            | usize::from(messages[3]);
        ensure!(messages.len() >= 4 + len, "truncated TLS handshake message");
        let body = &messages[4..4 + len];
        messages = &messages[4 + len..];
        if kind != ENCRYPTED_EXTENSIONS {
            continue;
        }
        let total = usize::from(u16::from_be_bytes([body[0], body[1]]));
        let mut extensions = &body[2..2 + total];
        while extensions.len() >= 4 {
            let ext = u16::from_be_bytes([extensions[0], extensions[1]]);
            let ext_len = usize::from(u16::from_be_bytes([extensions[2], extensions[3]]));
            let data = &extensions[4..4 + ext_len];
            if ext == QUIC_TRANSPORT_PARAMETERS {
                return Ok(data.to_vec());
            }
            extensions = &extensions[4 + ext_len..];
        }
        bail!("EncryptedExtensions without quic_transport_parameters");
    }
    bail!("no EncryptedExtensions in the server's handshake")
}

fn read_varint(buf: &mut &[u8]) -> Result<u64> {
    let first = *buf.first().context("varint: empty buffer")?;
    let len = 1usize << (first >> 6);
    ensure!(buf.len() >= len, "varint: truncated");
    let mut value = u64::from(first & 0x3f);
    for byte in &buf[1..len] {
        value = value << 8 | u64::from(*byte);
    }
    *buf = &buf[len..];
    Ok(value)
}

fn parse_transport_parameters(mut raw: &[u8]) -> Result<Vec<(u64, Vec<u8>)>> {
    let mut params = Vec::new();
    while !raw.is_empty() {
        let id = read_varint(&mut raw)?;
        let len = usize::try_from(read_varint(&mut raw)?)?;
        ensure!(raw.len() >= len, "transport parameter {id:#x} truncated");
        params.push((id, raw[..len].to_vec()));
        raw = &raw[len..];
    }
    Ok(params)
}

/// The server's SETTINGS: the first frame of its control stream (uni stream
/// type 0x00), read off the raw QUIC connection.
async fn read_settings(connection: &quinn::Connection) -> Result<Vec<(u64, u64)>> {
    const CONTROL_STREAM: u64 = 0x00;
    const SETTINGS_FRAME: u64 = 0x04;
    loop {
        let mut recv = connection.accept_uni().await?;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 256];
        loop {
            if let Some(settings) = try_parse_control_stream(&buf)? {
                match settings {
                    None => break,
                    Some(settings) => return Ok(settings),
                }
            }
            let n = recv.read(&mut chunk).await?.context("stream ended early")?;
            buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// `Ok(None)`: need more bytes. `Ok(Some(None))`: not the control stream.
    fn try_parse_control_stream(buf: &[u8]) -> Result<Option<Option<Vec<(u64, u64)>>>> {
        let mut rest = buf;
        let Ok(stream_type) = read_varint(&mut rest) else {
            return Ok(None);
        };
        if stream_type != CONTROL_STREAM {
            return Ok(Some(None));
        }
        let (Ok(frame_type), Ok(len)) = (read_varint(&mut rest), read_varint(&mut rest)) else {
            return Ok(None);
        };
        ensure!(frame_type == SETTINGS_FRAME, "control stream starts with frame {frame_type:#x}");
        let len = usize::try_from(len)?;
        if rest.len() < len {
            return Ok(None);
        }
        let mut payload = &rest[..len];
        let mut settings = Vec::new();
        while !payload.is_empty() {
            settings.push((read_varint(&mut payload)?, read_varint(&mut payload)?));
        }
        Ok(Some(Some(settings)))
    }
}

fn varint_value(raw: &[u8]) -> Result<u64> {
    let mut rest = raw;
    let value = read_varint(&mut rest)?;
    ensure!(rest.is_empty(), "trailing bytes after varint");
    Ok(value)
}

fn param(observed: &Observed, id: u64) -> Option<&[u8]> {
    observed
        .transport_parameters
        .iter()
        .find(|(pid, _)| *pid == id)
        .map(|(_, value)| value.as_slice())
}

fn is_grease_id(id: u64) -> bool {
    id >= 27 && (id - 27).is_multiple_of(31)
}

#[tokio::test]
async fn transport_parameters_follow_the_quic_go_order() -> Result<()> {
    let listener = start_listener(true).await?;
    let observed = observe(&listener).await?;
    let ids: Vec<u64> = observed.transport_parameters.iter().map(|(id, _)| *id).collect();

    assert!(is_grease_id(ids[0]), "first parameter {:#x} is not GREASE: {ids:x?}", ids[0]);
    // What a quic-go server writes for this config: `ack_delay_exponent` (3)
    // is the default, migration is allowed and Retry is off, so 0x0a, 0x0c
    // and 0x10 stay out.
    assert_eq!(
        ids[1..],
        [0x05, 0x06, 0x07, 0x04, 0x08, 0x09, 0x01, 0x03, 0x0b, 0x02, 0x00, 0x0e, 0x0f, 0x20],
        "{ids:x?}"
    );
    let listed: Vec<u64> = QUIC_GO_TP_ORDER
        .iter()
        .copied()
        .filter(|id| ids[1..].contains(id))
        .collect();
    assert_eq!(ids[1..], listed[..], "order differs from QUIC_GO_TP_ORDER");
    Ok(())
}

#[tokio::test]
async fn transport_parameters_omit_min_ack_delay_and_grease_quic_bit() -> Result<()> {
    let listener = start_listener(true).await?;
    let observed = observe(&listener).await?;
    assert!(param(&observed, TP_MIN_ACK_DELAY_DRAFT07).is_none());
    assert!(param(&observed, TP_GREASE_QUIC_BIT).is_none());
    Ok(())
}

#[tokio::test]
async fn transport_parameters_carry_quic_go_values() -> Result<()> {
    let listener = start_listener(true).await?;
    let observed = observe(&listener).await?;
    let value = |id| -> Result<u64> {
        varint_value(param(&observed, id).with_context(|| format!("parameter {id:#x} missing"))?)
    };
    assert_eq!(value(TP_MAX_ACK_DELAY)?, u64::from(QUIC_GO_MAX_ACK_DELAY_MS));
    assert_eq!(QUIC_GO_MAX_ACK_DELAY_MS, 26);
    assert_eq!(
        value(TP_ACTIVE_CONNECTION_ID_LIMIT)?,
        u64::from(QUIC_GO_ACTIVE_CONNECTION_ID_LIMIT)
    );
    assert_eq!(QUIC_GO_ACTIVE_CONNECTION_ID_LIMIT, 4);
    assert_eq!(value(TP_MAX_UDP_PAYLOAD_SIZE)?, u64::from(H3_MAX_UDP_PAYLOAD_SIZE));
    Ok(())
}

/// `initial_source_connection_id` is the SCID of the server's long headers
/// (quinn rejects a handshake where they differ, RFC 9000 §7.3).
#[tokio::test]
async fn server_connection_id_is_four_bytes() -> Result<()> {
    let listener = start_listener(true).await?;
    let observed = observe(&listener).await?;
    let scid = param(&observed, TP_INITIAL_SOURCE_CONNECTION_ID)
        .context("initial_source_connection_id missing")?;
    assert_eq!(scid.len(), H3_SERVER_CID_LEN);
    assert_eq!(H3_SERVER_CID_LEN, 4);
    Ok(())
}

#[tokio::test]
async fn datagrams_are_announced_with_udp_datagrams() -> Result<()> {
    let listener = start_listener(true).await?;
    let observed = observe(&listener).await?;
    let size = param(&observed, TP_MAX_DATAGRAM_FRAME_SIZE).context("0x20 missing")?;
    assert_eq!(varint_value(size)?, u64::from(QUIC_GO_MAX_DATAGRAM_FRAME_SIZE));
    assert_eq!(QUIC_GO_MAX_DATAGRAM_FRAME_SIZE, 16_383);
    assert!(
        observed.settings.contains(&(SETTINGS_H3_DATAGRAM, 1)),
        "{:x?}",
        observed.settings
    );
    assert!(
        observed.settings.contains(&(SETTINGS_ENABLE_CONNECT_PROTOCOL, 1)),
        "{:x?}",
        observed.settings
    );
    assert!(observed.connection.max_datagram_size().is_some());
    Ok(())
}

#[tokio::test]
async fn datagrams_are_not_announced_without_udp_datagrams() -> Result<()> {
    let listener = start_listener(false).await?;
    let observed = observe(&listener).await?;
    assert!(param(&observed, TP_MAX_DATAGRAM_FRAME_SIZE).is_none());
    // The h3 crate writes `H3_DATAGRAM = 0` when datagrams are off instead of
    // leaving the setting out (quic-go leaves it out); dropping it needs a
    // patch to the vendored h3, like the other SETTINGS differences.
    assert!(
        observed
            .settings
            .iter()
            .all(|(id, value)| *id != SETTINGS_H3_DATAGRAM || *value == 0),
        "{:x?}",
        observed.settings
    );
    assert!(
        observed.settings.contains(&(SETTINGS_ENABLE_CONNECT_PROTOCOL, 1)),
        "{:x?}",
        observed.settings
    );
    assert!(observed.connection.max_datagram_size().is_none());
    Ok(())
}

#[tokio::test]
async fn version_negotiation_greases_reserved_version_and_randomizes_position() -> Result<()> {
    let listener = start_listener(false).await?;
    let client_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;

    let mut saw_grease_at_index_0 = false;
    let mut saw_grease_at_index_1 = false;
    let mut observed_greases = std::collections::HashSet::new();

    // Send several probes with unsupported versions
    for i in 0..20 {
        let mut req = vec![0u8; 1200];
        req[0] = 0xc0; // Long header (Initial)
        let unsupp_ver = 0x1a2b_3c00u32 + i as u32;
        req[1..5].copy_from_slice(&unsupp_ver.to_be_bytes());
        req[5] = 8; // DCID len
        req[6..14].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        req[14] = 8; // SCID len
        req[15..23].copy_from_slice(&[8, 7, 6, 5, 4, 3, 2, 1]);

        client_sock.send_to(&req, listener.addr).await?;

        let mut resp = [0u8; 1500];
        let n =
            tokio::time::timeout(std::time::Duration::from_secs(2), client_sock.recv(&mut resp))
                .await??;

        assert!(resp[0] & 0x80 != 0, "must be long header");
        assert_eq!(&resp[1..5], &[0, 0, 0, 0], "version must be 0 for Version Negotiation");
        let dcid_len = resp[5] as usize;
        let scid_len = resp[6 + dcid_len] as usize;
        let versions_bytes = &resp[6 + dcid_len + 1 + scid_len..n];
        assert_eq!(versions_bytes.len() % 4, 0, "versions payload must be multiple of 4 bytes");
        let versions: Vec<u32> = versions_bytes
            .as_chunks::<4>()
            .0
            .iter()
            .map(|chunk| u32::from_be_bytes(*chunk))
            .collect();

        // Must contain QUIC v1 and a GREASE version
        assert_eq!(versions.len(), 2, "must contain exactly 2 versions: v1 and GREASE");
        assert!(versions.contains(&0x0000_0001), "must contain QUIC v1");

        let grease_pos = versions
            .iter()
            .position(|&v| v != 0x0000_0001)
            .expect("must contain a GREASE version");
        let grease_ver = versions[grease_pos];

        // RFC 9000 §15: 0x?a?a?a?a
        for (byte_idx, &b) in grease_ver.to_be_bytes().iter().enumerate() {
            assert_eq!(
                b & 0x0f,
                0x0a,
                "byte {byte_idx} of grease version {grease_ver:#010x} must end with 0xa"
            );
        }

        if grease_pos == 0 {
            saw_grease_at_index_0 = true;
        } else {
            saw_grease_at_index_1 = true;
        }
        observed_greases.insert(grease_ver);
    }

    // Over 20 iterations, both positions and multiple distinct grease values should be observed
    assert!(
        saw_grease_at_index_0 && saw_grease_at_index_1,
        "GREASE version must be randomized in position (saw index 0: {saw_grease_at_index_0}, index 1: {saw_grease_at_index_1})"
    );
    assert!(
        observed_greases.len() > 1,
        "GREASE version must not be static (observed: {observed_greases:?})"
    );

    Ok(())
}
