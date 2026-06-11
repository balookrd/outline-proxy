//! End-to-end reverse-tunnel (topology A) runtime test.
//!
//! Proves the carrier inversion actually carries bytes: the `ss` server is
//! the QUIC **client** (dials out) yet still `accept_bi`-loops the carrier
//! via the production `handle_raw_ss_connection`, while the `ws` role is the
//! QUIC **server** (accepts) and opens a per-session stream through the same
//! `ss_tcp_over_connection` pipeline the listener uses. mTLS with pinned
//! self-signed certs gates both directions.
//!
//! The `ws`-side relay/registry are thin bin wrappers over the same
//! `outline-transport` primitives exercised directly here, so this covers
//! the full wire path (open_bi → accept_bi → upstream connect → round-trip)
//! without standing up the SOCKS5 ingress.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, oneshot};

use outline_transport::tls_reverse::{build_reverse_server_quic_config, cert_fingerprint};
use outline_transport::{
    CipherKind, UpstreamTransportGuard, quic::shared_connection_from_accepted,
    ss_tcp_over_connection,
};

use super::super::bootstrap::build_reverse_client_quic_config;
use super::super::h3::handle_raw_ss_connection;
use super::super::nat::NatTable;
use super::super::replay::ReplayStore;
use super::super::shutdown::ShutdownSignal;
use super::super::transport::{RawQuicSsCtx, RawSsConnectionCtx};
use super::super::{DnsCache, Services, UdpServices, build_users};
use super::sample_config;
use crate::metrics::Metrics;
use crate::protocol::TargetAddr;

const SS_PASSWORD: &str = "secret-b";

/// Generate a self-signed leaf cert valid for `localhost`. Returns the DER
/// chain, the private key, and the SHA-256 pin the peer trusts.
fn gen_cert(cn: &str) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>, [u8; 32]) {
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, cn);
    params.subject_alt_names = vec![SanType::DnsName("localhost".try_into().unwrap())];
    let key_pair = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let pin = cert_fingerprint(&cert_der);
    let key_der = PrivateKeyDer::try_from(key_pair.serialize_der()).unwrap();
    (vec![cert_der], key_der, pin)
}

/// Build the raw-SS accept context (user keys + services) the dialer hands to
/// `handle_raw_ss_connection`, mirroring the forward H3 server's wiring.
fn raw_ss_ctx() -> Result<Arc<RawSsConnectionCtx>> {
    // The listen addr is unused — only the user keys / cipher matter here.
    let config = sample_config(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));
    let users = build_users(&config)?;
    let services = Arc::new(Services::new(
        Metrics::new(&config),
        DnsCache::new(Duration::from_secs(30)),
        false,
        None,
        UdpServices {
            nat_table: NatTable::new(Duration::from_secs(300)),
            replay_store: ReplayStore::new(Duration::from_secs(300), 0),
            relay_semaphore: None,
        },
        None,
        16,
    ));
    Ok(Arc::new(RawSsConnectionCtx {
        raw_ss_ctx: Arc::new(RawQuicSsCtx { users, services }),
        stream_semaphore: Arc::new(Semaphore::new(64)),
    }))
}

#[tokio::test]
async fn reverse_tunnel_ss_tcp_round_trip() -> Result<()> {
    // Upstream echo standing in for the real internet egress the ss server
    // reaches: read "ping", reply "pong".
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut got = [0_u8; 4];
        stream.read_exact(&mut got).await?;
        stream.write_all(b"pong").await?;
        Result::<_, anyhow::Error>::Ok(got)
    });

    let (ws_chain, ws_key, ws_pin) = gen_cert("ws-reverse");
    let (ss_chain, ss_key, ss_pin) = gen_cert("ss-reverse");
    let alpn: &[&[u8]] = &[b"ss-mtu", b"ss"];

    // ── ws role: QUIC server endpoint (accepts the carrier) ──────────────
    let server_config = build_reverse_server_quic_config(ws_chain, ws_key, vec![ss_pin], alpn)?;
    let ws_endpoint =
        quinn::Endpoint::server(server_config, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let ws_addr = ws_endpoint.local_addr()?;
    let (peer_tx, peer_rx) = oneshot::channel();
    let ws_accept_endpoint = ws_endpoint.clone();
    tokio::spawn(async move {
        let incoming = ws_endpoint.accept().await.expect("ws accept");
        let connection = incoming.await.expect("ws handshake");
        let shared = shared_connection_from_accepted(ws_accept_endpoint, connection);
        let _ = peer_tx.send(shared);
    });

    // ── ss role: QUIC client endpoint (dials out), then accept_bi loop ───
    let ctx = raw_ss_ctx()?;
    let client_config = build_reverse_client_quic_config(ss_chain, ss_key, ws_pin, alpn)?;
    let ss_endpoint = quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?;
    let ss_conn = ss_endpoint.connect_with(client_config, ws_addr, "localhost")?.await?;
    let ss_handler = tokio::spawn(handle_raw_ss_connection(ss_conn, ctx));

    // ── drive: open a session stream from the ws side (server-initiated
    //    bidi) → ss accept_bi → ss connects to the echo → round-trip ──────
    let shared = peer_rx.await.expect("ws received reverse peer");
    let cipher = CipherKind::Chacha20IetfPoly1305;
    let master_key = cipher.derive_master_key(SS_PASSWORD).expect("derive master key");
    let lifetime = UpstreamTransportGuard::new("reverse-e2e", "ss-tcp");
    let (mut writer, reader) =
        ss_tcp_over_connection(&shared, cipher, &master_key, lifetime).await?;
    let request_salt = writer.request_salt();
    let mut reader = reader.with_request_salt(request_salt);

    writer
        .send_chunk(&TargetAddr::from(upstream_addr).to_wire_bytes()?)
        .await?;
    writer.send_chunk(b"ping").await?;

    let reply = tokio::time::timeout(Duration::from_secs(5), reader.read_chunk()).await??;
    assert_eq!(&reply, b"pong", "reverse SS-TCP echo round-trips");

    let upstream_bytes = tokio::time::timeout(Duration::from_secs(5), upstream_task).await???;
    assert_eq!(&upstream_bytes, b"ping", "echo upstream saw the payload");

    drop(reader);
    drop(writer);
    ss_handler.abort();
    let _ = ss_endpoint; // keep the client endpoint alive until here
    Ok(())
}

#[tokio::test]
async fn reverse_tunnel_rejects_wrong_client_pin() -> Result<()> {
    let (ws_chain, ws_key, ws_pin) = gen_cert("ws-reverse");
    let (ss_chain, ss_key, _ss_pin) = gen_cert("ss-reverse");
    // ws trusts a DIFFERENT pin than the ss client presents.
    let (_other_chain, _other_key, wrong_pin) = gen_cert("other-ss");
    let alpn: &[&[u8]] = &[b"ss-mtu", b"ss"];

    let server_config = build_reverse_server_quic_config(ws_chain, ws_key, vec![wrong_pin], alpn)?;
    let ws_endpoint =
        quinn::Endpoint::server(server_config, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let ws_addr = ws_endpoint.local_addr()?;
    tokio::spawn(async move {
        // The handshake must fail mTLS, so accept either yields nothing
        // usable or errors — either way no peer is produced.
        if let Some(incoming) = ws_endpoint.accept().await {
            let _ = incoming.await;
        }
    });

    let client_config = build_reverse_client_quic_config(ss_chain, ss_key, ws_pin, alpn)?;
    let ss_endpoint = quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?;
    let dial = ss_endpoint.connect_with(client_config, ws_addr, "localhost")?.await;

    // In QUIC/TLS 1.3 the client may consider the handshake complete before
    // the server's mTLS rejection (sent after the client Finished) arrives,
    // so `connect_with` can return `Ok`. Either way the carrier must not be
    // usable: a rejected client cert makes the connection close promptly.
    let rejected = match dial {
        Err(_) => true,
        Ok(connection) => tokio::time::timeout(Duration::from_secs(3), connection.closed())
            .await
            .is_ok(),
    };
    assert!(rejected, "untrusted client cert must not yield a usable reverse carrier");
    Ok(())
}
