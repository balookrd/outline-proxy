//! Raw-QUIC VLESS resumption: TCP path through a manual QUIC server
//! instead of the WebSocket harness used by [`super::ss`] /
//! [`super::vless`].

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use anyhow::{Result, bail};
use arc_swap::ArcSwap;
use bytes::Bytes;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sockudo_ws::{
    Config as H3WsConfig, Http3 as H3Transport, WebSocketServer as H3WebSocketServer,
};
use tokio::task::JoinHandle;

use super::super::super::resumption::{OrphanRegistry, ResumptionConfig, SessionId};
use super::super::super::shutdown::ShutdownSignal;
use super::super::super::state::UserKeySlice;
use super::super::super::{AuthPolicy, DnsCache, RouteRegistry, Services, UdpServices};
use super::spawn_echo_target;
use crate::config::H3Alpn;
use crate::crypto::UserKey;
use crate::metrics::Metrics;
use crate::protocol::vless::{
    ADDON_TAG_RESUME_CAPABLE, ADDON_TAG_RESUME_ID, ADDON_TAG_RESUME_RESULT, ADDON_TAG_SESSION_ID,
    COMMAND_TCP, VERSION as VLESS_VERSION, VlessUser, parse_uuid,
};

// ── TLS / QUIC plumbing ──────────────────────────────────────────────────────

fn raw_quic_test_tls() -> Result<(rustls::ServerConfig, CertificateDer<'static>)> {
    super::super::super::ensure_rustls_provider_installed();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key)?;
    tls_config.alpn_protocols = vec![b"vless".to_vec()];
    Ok((tls_config, cert_der))
}

async fn bind_raw_quic_test_server(
    addr: SocketAddr,
    tls_config: rustls::ServerConfig,
) -> Result<H3WebSocketServer<H3Transport>> {
    let quic_config = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
        .map_err(|_| anyhow::anyhow!("invalid raw-quic test TLS config"))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_config));
    let mut transport = quinn::TransportConfig::default();
    transport
        .datagram_receive_buffer_size(Some(1 << 20))
        .datagram_send_buffer_size(1 << 20);
    server_config.transport_config(Arc::new(transport));
    let endpoint = quinn::Endpoint::server(server_config, addr)?;
    Ok(H3WebSocketServer::<H3Transport>::from_endpoint(
        endpoint,
        H3WsConfig::default(),
    ))
}

fn raw_quic_client_config(cert_der: CertificateDer<'static>) -> Result<quinn::ClientConfig> {
    super::super::super::ensure_rustls_provider_installed();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der)?;
    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(Arc::new(roots))
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"vless".to_vec()];
    let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
        .map_err(|error| anyhow::anyhow!(error))?;
    Ok(quinn::ClientConfig::new(Arc::new(quic_config)))
}

/// Builds a VLESS TCP request whose Addons section carries a single
/// resumption opcode pair: `RESUME_CAPABLE=0x01` and (optionally)
/// `RESUME_ID=<bytes>`. Returns the raw bytes ready to be written
/// into a QUIC bidi stream.
fn vless_raw_quic_tcp_request_with_resume(
    uuid: &str,
    target: SocketAddr,
    payload: &[u8],
    requested_resume: Option<&SessionId>,
) -> Result<Bytes> {
    let mut addons = Vec::new();
    addons.push(ADDON_TAG_RESUME_CAPABLE);
    addons.push(1);
    addons.push(0x01);
    if let Some(id) = requested_resume {
        addons.push(ADDON_TAG_RESUME_ID);
        addons.push(16);
        addons.extend_from_slice(id.as_bytes());
    }
    if addons.len() > u8::MAX as usize {
        bail!("test addons block too large: {} bytes", addons.len());
    }

    let mut request = Vec::new();
    request.push(VLESS_VERSION);
    request.extend_from_slice(&parse_uuid(uuid)?);
    request.push(addons.len() as u8);
    request.extend_from_slice(&addons);
    request.push(COMMAND_TCP);
    request.extend_from_slice(&target.port().to_be_bytes());
    request.push(0x01); // IPv4
    let std::net::IpAddr::V4(ipv4) = target.ip() else {
        bail!("raw-quic test target must be IPv4");
    };
    request.extend_from_slice(&ipv4.octets());
    request.extend_from_slice(payload);
    Ok(Bytes::from(request))
}

#[derive(Debug, Default)]
struct ParsedVlessResponse {
    session_id: Option<SessionId>,
    resume_result: Option<u8>,
}

/// Parses the VLESS raw-QUIC TCP response header out of a slice. The
/// wire shape is `[VERSION, addons_len, addons...]`. `addons_len` may
/// be `0` for legacy clients; this test always negotiates resumption,
/// so we expect non-zero on every successful handshake.
fn parse_vless_raw_quic_tcp_response(buf: &[u8]) -> Result<(ParsedVlessResponse, usize)> {
    if buf.len() < 2 {
        bail!("response truncated: only {} bytes", buf.len());
    }
    if buf[0] != VLESS_VERSION {
        bail!("unexpected VLESS response version: {:#x}", buf[0]);
    }
    let addons_len = buf[1] as usize;
    let addons_start = 2;
    let addons_end = addons_start + addons_len;
    if buf.len() < addons_end {
        bail!(
            "response truncated: declared {} addon bytes but only {} available",
            addons_len,
            buf.len() - addons_start
        );
    }
    let mut response = ParsedVlessResponse::default();
    let block = &buf[addons_start..addons_end];
    let mut i = 0;
    while i + 2 <= block.len() {
        let tag = block[i];
        let len = block[i + 1] as usize;
        let value_start = i + 2;
        let value_end = value_start + len;
        if value_end > block.len() {
            break;
        }
        let value = &block[value_start..value_end];
        match tag {
            ADDON_TAG_SESSION_ID => {
                if let Ok(arr) = <[u8; 16]>::try_from(value) {
                    response.session_id = Some(SessionId::from_bytes(arr));
                }
            },
            ADDON_TAG_RESUME_RESULT => {
                if value.len() == 1 {
                    response.resume_result = Some(value[0]);
                }
            },
            _ => {},
        }
        i = value_end;
    }
    Ok((response, addons_end))
}

/// Stand-up of a raw-QUIC VLESS server with `[session_resumption]`
/// enabled. Returns the listen address, the lone `VlessUser`, the
/// CA cert needed by the client, and a JoinHandle that aborts the
/// background `serve_h3_server` task on drop.
async fn spawn_raw_quic_vless_resumption_server() -> Result<(
    SocketAddr,
    VlessUser,
    CertificateDer<'static>,
    JoinHandle<Result<()>>,
)> {
    use super::super::sample_config;

    let server_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let (tls_config, cert_der) = raw_quic_test_tls()?;
    let server = bind_raw_quic_test_server(server_addr, tls_config).await?;
    let listen_addr = server.local_addr()?;

    let dummy_listen: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let mut config = sample_config(dummy_listen);
    config.session_resumption.enabled = true;

    let metrics = Metrics::new(&config);
    let orphan_registry = Arc::new(OrphanRegistry::new(
        ResumptionConfig::from(&config.session_resumption),
        Arc::clone(&metrics),
    ));

    let vless_user = VlessUser::new("550e8400-e29b-41d4-a716-446655440000".into(), std::sync::Arc::from("test"), None)?;
    let raw_vless_users: Arc<[VlessUser]> = Arc::from(vec![vless_user.clone()].into_boxed_slice());
    let raw_vless_candidates: Arc<[Arc<str>]> =
        Arc::from(vec![vless_user.label_arc()].into_boxed_slice());

    let routes = Arc::new(ArcSwap::from_pointee(RouteRegistry {
        tcp: Arc::new(std::collections::BTreeMap::new()),
        udp: Arc::new(std::collections::BTreeMap::new()),
        vless: Arc::new(std::collections::BTreeMap::new()),
    }));
    let services = Arc::new(Services::new(
        Arc::clone(&metrics),
        DnsCache::new(Duration::from_secs(30)),
        false,
        None,
        UdpServices {
            nat_table: super::super::super::nat::NatTable::new(Duration::from_secs(300)),
            replay_store: super::super::super::replay::ReplayStore::new(
                Duration::from_secs(300),
                0,
            ),
            relay_semaphore: None,
        },
        Some(orphan_registry),
        16,
    ));
    let auth = Arc::new(AuthPolicy {
        users: Arc::new(ArcSwap::from_pointee(UserKeySlice(Arc::from(
            Vec::<UserKey>::new().into_boxed_slice(),
        )))),
        http_root_auth: false,
        http_root_realm: Arc::from("Authorization required"),
    });

    let task = tokio::spawn(async move {
        super::super::super::serve_h3_server(
            server,
            routes,
            services,
            auth,
            Arc::from(vec![H3Alpn::Vless].into_boxed_slice()),
            raw_vless_users,
            raw_vless_candidates,
            Arc::from(Vec::<UserKey>::new().into_boxed_slice()),
            ShutdownSignal::never(),
        )
        .await
    });

    Ok((listen_addr, vless_user, cert_der, task))
}

// ── Test ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn vless_raw_quic_resume_hit_skips_fresh_upstream() -> Result<()> {
    // Park a VLESS-TCP-over-raw-QUIC session, then resume it through
    // a fresh raw-QUIC connection. The mock TCP echo target's accept
    // counter must stay at 1 across both QUIC sessions — proof that
    // `try_park_raw_quic_tcp` and `try_attach_parked_tcp` line up.
    let (target_addr, target_accepts) = spawn_echo_target().await?;
    let (listen_addr, vless_user, cert_der, server_task) =
        spawn_raw_quic_vless_resumption_server().await?;
    let uuid = "550e8400-e29b-41d4-a716-446655440000";
    let _ = vless_user; // silence unused: identity is encoded in the request UUID

    // ── Session #1: fresh raw-QUIC dial with `RESUME_CAPABLE` ─────────
    let mut endpoint_1 =
        quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    endpoint_1.set_default_client_config(raw_quic_client_config(cert_der.clone())?);
    let connection_1 = endpoint_1.connect(listen_addr, "localhost")?.await?;
    let (mut send_1, mut recv_1) = connection_1.open_bi().await?;

    let request = vless_raw_quic_tcp_request_with_resume(uuid, target_addr, b"ping1", None)?;
    send_1.write_all(&request).await?;

    // Read enough bytes for the response header. Addons block carrying
    // SESSION_ID (16 + 2) plus the leading two-byte preamble = 20 bytes
    // is the upper bound for the resume-capable handshake.
    let mut header_buf = vec![0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(2), recv_1.read(&mut header_buf))
        .await?
        .map_err(|e| anyhow::anyhow!("read VLESS response on first session: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("VLESS response: stream closed before header"))?;
    let (response, header_len) = parse_vless_raw_quic_tcp_response(&header_buf[..n])?;
    let session_id = response
        .session_id
        .ok_or_else(|| anyhow::anyhow!("server didn't issue SESSION_ID despite RESUME_CAPABLE"))?;
    assert!(
        response.resume_result.is_none(),
        "fresh handshake should not carry RESUME_RESULT"
    );

    // The same chunk may already carry the echoed payload after the
    // header. If not, read more.
    let mut echoed = Vec::new();
    if header_len < n {
        echoed.extend_from_slice(&header_buf[header_len..n]);
    }
    while echoed.len() < 5 {
        let mut more = [0u8; 64];
        let read = recv_1
            .read(&mut more)
            .await
            .map_err(|e| anyhow::anyhow!("read echoed payload: {e}"))?
            .ok_or_else(|| anyhow::anyhow!("echo: stream closed early"))?;
        echoed.extend_from_slice(&more[..read]);
    }
    assert_eq!(&echoed[..5], b"ping1");
    assert_eq!(target_accepts.load(Ordering::SeqCst), 1);

    // Close the QUIC stream gracefully. `send.finish()` flushes a
    // FIN; once the server-side upload task observes `recv == None`
    // it fires the cancel notify so the download task hands its
    // reader back for parking. We must give the server enough time
    // to run that whole sequence *before* tearing the QUIC connection
    // down — otherwise the connection abort wins the race and the
    // park-on-drop path is skipped (download returns `Drained` on a
    // ResetStream error).
    let _ = send_1.finish();
    drop(recv_1);
    drop(send_1);
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(connection_1);
    endpoint_1.close(0u32.into(), b"resume");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // ── Session #2: fresh raw-QUIC dial with `RESUME_ID` ──────────────
    let mut endpoint_2 =
        quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    endpoint_2.set_default_client_config(raw_quic_client_config(cert_der)?);
    let connection_2 = endpoint_2.connect(listen_addr, "localhost")?.await?;
    let (mut send_2, mut recv_2) = connection_2.open_bi().await?;

    let request =
        vless_raw_quic_tcp_request_with_resume(uuid, target_addr, b"ping2", Some(&session_id))?;
    send_2.write_all(&request).await?;

    let mut header_buf = vec![0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(2), recv_2.read(&mut header_buf))
        .await?
        .map_err(|e| anyhow::anyhow!("read VLESS response on resumed session: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("VLESS resume response: stream closed early"))?;
    let (response, header_len) = parse_vless_raw_quic_tcp_response(&header_buf[..n])?;
    assert_eq!(
        response.resume_result, Some(0x00),
        "expected RESUME_RESULT=Hit (0x00) in raw-QUIC resume response"
    );
    assert!(
        response.session_id.is_some(),
        "resume hit must still echo a SESSION_ID"
    );

    let mut echoed = Vec::new();
    if header_len < n {
        echoed.extend_from_slice(&header_buf[header_len..n]);
    }
    while echoed.len() < 5 {
        let mut more = [0u8; 64];
        let read = recv_2
            .read(&mut more)
            .await
            .map_err(|e| anyhow::anyhow!("read echoed payload (resumed): {e}"))?
            .ok_or_else(|| anyhow::anyhow!("echo on resumed session: stream closed early"))?;
        echoed.extend_from_slice(&more[..read]);
    }
    assert_eq!(&echoed[..5], b"ping2");
    assert_eq!(
        target_accepts.load(Ordering::SeqCst),
        1,
        "resume hit must reuse parked raw-QUIC TCP upstream"
    );

    let _ = send_2.finish();
    drop(connection_2);
    endpoint_2.close(0u32.into(), b"done");
    server_task.abort();
    let _ = server_task.await;
    Ok(())
}
