//! Reverse-tunnel QUIC server endpoint: accepts carriers dialed by `ss`
//! peers behind NAT, authenticates them by pinned client-cert fingerprint
//! (mTLS), and registers each into the [`ReversePeerRegistry`].

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tracing::{debug, info, warn};

use outline_transport::quic::shared_connection_from_accepted;
use outline_transport::tls_reverse::{
    build_reverse_server_quic_config, cert_fingerprint, parse_cert_pin,
};
use shadowsocks_crypto::CipherKind;

use crate::config::ReverseListenerConfig;
use crate::reverse::peer_registry::{ReversePeer, ReversePeerRegistry};

/// Per-peer SS credentials resolved from config, keyed by the peer's pinned
/// client-cert SHA-256 fingerprint.
struct PeerCreds {
    cipher: CipherKind,
    master_key: Vec<u8>,
    label: Arc<str>,
}

/// Build the QUIC server endpoint and run the accept loop until shutdown.
/// Returns `Err` only on bind/setup failure (logged by the caller); accept
/// errors per-connection are logged and skipped.
pub(crate) async fn run_reverse_listener(
    cfg: ReverseListenerConfig,
    registry: Arc<ReversePeerRegistry>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    // Resolve pins + per-peer SS credentials. A bad pin / cipher / password
    // here fails the whole listener (operator config error), not a single
    // connection.
    let mut allowed_pins = Vec::with_capacity(cfg.peers.len());
    let mut creds: HashMap<[u8; 32], PeerCreds> = HashMap::with_capacity(cfg.peers.len());
    for (idx, peer) in cfg.peers.iter().enumerate() {
        let pin = parse_cert_pin(&peer.client_cert_pin)
            .with_context(|| format!("[reverse_listener].peers[{idx}].client_cert_pin"))?;
        let master_key = peer
            .method
            .derive_master_key(&peer.password)
            .with_context(|| format!("[reverse_listener].peers[{idx}].password"))?;
        allowed_pins.push(pin);
        creds.insert(
            pin,
            PeerCreds {
                cipher: peer.method,
                master_key,
                label: Arc::from(format!("reverse-{idx}").as_str()),
            },
        );
    }

    let cert_chain =
        load_cert_chain(&cfg.server_cert_path).context("[reverse_listener].server_cert_path")?;
    let key =
        load_private_key(&cfg.server_key_path).context("[reverse_listener].server_key_path")?;
    let alpn: &[&[u8]] = if cfg.mtu { &[b"ss-mtu", b"ss"] } else { &[b"ss"] };
    let server_config = build_reverse_server_quic_config(cert_chain, key, allowed_pins, alpn)?;

    let endpoint = quinn::Endpoint::server(server_config, cfg.listen)
        .with_context(|| format!("failed to bind reverse listener on {}", cfg.listen))?;
    info!(listen = %cfg.listen, group = %registry.group(), "reverse-tunnel listener bound");

    loop {
        let incoming = tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    endpoint.close(0u32.into(), b"server shutting down");
                    return Ok(());
                }
                continue;
            }
            incoming = endpoint.accept() => match incoming {
                Some(incoming) => incoming,
                None => return Ok(()),
            },
        };

        let registry = Arc::clone(&registry);
        let endpoint = endpoint.clone();
        // Resolve creds once the handshake completes (the client cert is
        // available only then). Clone the small creds map per accept task.
        let creds: HashMap<[u8; 32], (CipherKind, Vec<u8>, Arc<str>)> = creds
            .iter()
            .map(|(k, v)| (*k, (v.cipher, v.master_key.clone(), Arc::clone(&v.label))))
            .collect();
        tokio::spawn(async move {
            if let Err(error) = accept_peer(incoming, endpoint, &registry, &creds).await {
                debug!(?error, "reverse-tunnel peer rejected");
            }
        });
    }
}

async fn accept_peer(
    incoming: quinn::Incoming,
    endpoint: quinn::Endpoint,
    registry: &Arc<ReversePeerRegistry>,
    creds: &HashMap<[u8; 32], (CipherKind, Vec<u8>, Arc<str>)>,
) -> Result<()> {
    let connection = incoming.await.context("reverse: QUIC handshake failed")?;

    // mTLS already gated the carrier to the allowed pin set; now resolve
    // *which* peer connected to pick its SS credentials. The client cert is
    // in the rustls peer identity.
    let fingerprint = client_cert_fingerprint(&connection)
        .ok_or_else(|| anyhow!("reverse: accepted carrier has no client certificate"))?;
    let (cipher, master_key, label) = creds
        .get(&fingerprint)
        .ok_or_else(|| anyhow!("reverse: client cert not in configured peer set"))?;

    let shared = shared_connection_from_accepted(endpoint, connection);
    let peer = Arc::new(ReversePeer {
        conn: shared,
        cipher: *cipher,
        master_key: master_key.clone(),
        label: Arc::clone(label),
    });
    if registry.try_insert(Arc::clone(&peer)) {
        info!(peer = %label, live = registry.live_count(), "reverse-tunnel peer registered");
    } else {
        // Dropping `peer` here drops the SharedQuicConnection, whose Drop
        // sends CONNECTION_CLOSE — the rejected carrier is torn down cleanly.
        warn!(peer = %label, "reverse-tunnel pool at capacity; dropping peer");
    }
    Ok(())
}

/// SHA-256 fingerprint of the peer's leaf client certificate, from the
/// rustls handshake identity. `None` if the peer presented no cert.
fn client_cert_fingerprint(connection: &quinn::Connection) -> Option<[u8; 32]> {
    let identity = connection.peer_identity()?;
    let certs = identity.downcast::<Vec<CertificateDer<'static>>>().ok()?;
    let leaf = certs.first()?;
    Some(cert_fingerprint(leaf))
}

fn load_cert_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let pem = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    if path.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("der")) {
        return Ok(vec![CertificateDer::from(pem)]);
    }
    let chain: Vec<_> = CertificateDer::pem_slice_iter(&pem)
        .collect::<std::result::Result<_, _>>()
        .with_context(|| format!("failed to parse certificate chain {}", path.display()))?;
    if chain.is_empty() {
        bail!("no certificates found in {}", path.display());
    }
    Ok(chain)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let key = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    if path.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("der")) {
        return PrivateKeyDer::try_from(key)
            .map_err(|error| anyhow!(error))
            .with_context(|| format!("failed to parse private key {}", path.display()));
    }
    PrivateKeyDer::from_pem_slice(&key)
        .map_err(|error| anyhow!("{error}"))
        .with_context(|| format!("failed to parse private key {}", path.display()))
}
