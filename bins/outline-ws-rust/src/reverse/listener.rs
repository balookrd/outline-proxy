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

use crate::config::{ReverseListenerConfig, ReversePeerKind};
use crate::reverse::peer_registry::{ReversePeer, ReversePeerCreds, ReverseRegistry};

/// Per-peer framing credentials resolved from config, keyed by the peer's
/// pinned client-cert SHA-256 fingerprint. `group` is the resolved egress
/// group the peer is pooled under.
#[derive(Clone)]
struct PeerCreds {
    framing: ReversePeerCreds,
    label: Arc<str>,
    group: Arc<str>,
}

/// Wire protocol a reverse carrier negotiated, derived from its ALPN. Used to
/// reject a peer whose carrier protocol disagrees with its configured creds.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CarrierProtocol {
    Ss,
    Vless,
}

/// Build the QUIC server endpoint and run the accept loop until shutdown.
/// Returns `Err` only on bind/setup failure (logged by the caller); accept
/// errors per-connection are logged and skipped.
pub(crate) async fn run_reverse_listener(
    cfg: ReverseListenerConfig,
    registry: Arc<ReverseRegistry>,
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
        let framing = match &peer.kind {
            ReversePeerKind::Ss { method, password } => {
                let master_key = method
                    .derive_master_key(password)
                    .with_context(|| format!("[reverse_listener].peers[{idx}].password"))?;
                ReversePeerCreds::Ss {
                    cipher: *method,
                    master_key,
                    password: Arc::from(password.as_str()),
                }
            },
            ReversePeerKind::Vless { uuid } => ReversePeerCreds::Vless { uuid: *uuid },
        };
        allowed_pins.push(pin);
        creds.insert(
            pin,
            PeerCreds {
                framing,
                label: Arc::from(format!("reverse-{idx}").as_str()),
                group: Arc::clone(&peer.group),
            },
        );
    }

    let cert_chain =
        load_cert_chain(&cfg.server_cert_path).context("[reverse_listener].server_cert_path")?;
    let key =
        load_private_key(&cfg.server_key_path).context("[reverse_listener].server_key_path")?;
    // Advertise the ALPN superset across the peers' protocols (MTU-aware
    // sibling first when enabled): a single listener carries both SS and VLESS
    // peers, each dialing in with its own protocol's ALPN.
    let has_vless = cfg
        .peers
        .iter()
        .any(|p| matches!(p.kind, ReversePeerKind::Vless { .. }));
    let has_ss = cfg.peers.iter().any(|p| matches!(p.kind, ReversePeerKind::Ss { .. }));
    let mut alpn: Vec<&[u8]> = Vec::new();
    if has_vless {
        if cfg.mtu {
            alpn.push(b"vless-mtu");
        }
        alpn.push(b"vless");
    }
    if has_ss {
        if cfg.mtu {
            alpn.push(b"ss-mtu");
        }
        alpn.push(b"ss");
    }
    let server_config = build_reverse_server_quic_config(cert_chain, key, allowed_pins, &alpn)?;

    let endpoint = quinn::Endpoint::server(server_config, cfg.listen)
        .with_context(|| format!("failed to bind reverse listener on {}", cfg.listen))?;
    info!(listen = %cfg.listen, peers = cfg.peers.len(), "reverse-tunnel listener bound");

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
        // Clone the small creds map per accept task (the client cert — and
        // thus the peer identity — is available only after the handshake).
        let creds = creds.clone();
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
    registry: &Arc<ReverseRegistry>,
    creds: &HashMap<[u8; 32], PeerCreds>,
) -> Result<()> {
    let connection = incoming.await.context("reverse: QUIC handshake failed")?;

    // mTLS already gated the carrier to the allowed pin set; now resolve
    // *which* peer connected to pick its framing credentials and egress group.
    // The client cert is in the rustls peer identity.
    let fingerprint = client_cert_fingerprint(&connection)
        .ok_or_else(|| anyhow!("reverse: accepted carrier has no client certificate"))?;
    let creds = creds
        .get(&fingerprint)
        .ok_or_else(|| anyhow!("reverse: client cert not in configured peer set"))?;

    // The carrier ALPN (chosen by the dialing ss) must match the peer's
    // configured protocol, otherwise the framing this listener applies would
    // not parse on the peer side.
    let configured = match &creds.framing {
        ReversePeerCreds::Ss { .. } => CarrierProtocol::Ss,
        ReversePeerCreds::Vless { .. } => CarrierProtocol::Vless,
    };
    if carrier_protocol(&connection) != Some(configured) {
        bail!(
            "reverse: peer {} carrier ALPN does not match its configured protocol",
            creds.label
        );
    }

    // Every peer's group has a pool (built from this same peer list), so a
    // miss is a logic error — drop the carrier rather than panic.
    let pool = registry
        .pool(&creds.group)
        .ok_or_else(|| anyhow!("reverse: no pool for peer group {}", creds.group))?;

    let shared = shared_connection_from_accepted(endpoint, connection);
    let peer = Arc::new(ReversePeer {
        conn: shared,
        creds: creds.framing.clone(),
        label: Arc::clone(&creds.label),
    });
    if pool.try_insert(Arc::clone(&peer)) {
        info!(peer = %creds.label, group = %creds.group, live = pool.live_count(),
            "reverse-tunnel peer registered");
    } else {
        // Dropping `peer` here drops the SharedQuicConnection, whose Drop
        // sends CONNECTION_CLOSE — the rejected carrier is torn down cleanly.
        warn!(peer = %creds.label, group = %creds.group,
            "reverse-tunnel pool at capacity; dropping peer");
    }
    Ok(())
}

/// The carrier's negotiated wire protocol, derived from its ALPN. `None` for
/// an unrecognised ALPN (rejected by the caller).
fn carrier_protocol(connection: &quinn::Connection) -> Option<CarrierProtocol> {
    let proto = connection
        .handshake_data()?
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .ok()?
        .protocol?;
    match proto.as_slice() {
        b"ss" | b"ss-mtu" => Some(CarrierProtocol::Ss),
        b"vless" | b"vless-mtu" => Some(CarrierProtocol::Vless),
        _ => None,
    }
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
