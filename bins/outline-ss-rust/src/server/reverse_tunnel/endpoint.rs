//! Outbound QUIC client endpoint for the reverse-tunnel dialer.
//!
//! Resolves the public `ws` address, binds an ephemeral client endpoint
//! (matching the target address family) and dials with the pinned-mTLS
//! client config. The resulting [`quinn::Connection`] is handed to the
//! shared raw-SS accept loop exactly as the forward H3 path would.

use std::net::SocketAddr;

use anyhow::{Context, Result, anyhow};
use tokio::net::lookup_host;

use crate::config::ReverseTunnelEndpoint;
use crate::server::bootstrap::{
    build_reverse_client_quic_config, load_cert_chain, load_private_key, parse_cert_pin,
};

/// Immutable per-endpoint dialing material, built once at dial-loop
/// startup so a malformed pin / unreadable cert fails fast (and only this
/// endpoint) instead of re-parsing on every reconnect.
pub(super) struct ReverseDialer {
    addr: String,
    server_name: String,
    client_config: quinn::ClientConfig,
}

/// Why a dial attempt ended, so the reconnect loop can back off accordingly.
pub(super) enum DialError {
    /// TLS/mTLS/pin failure at the handshake — a retry with the same config
    /// cannot fix it (persistent). Drives the long auth backoff.
    Auth(anyhow::Error),
    /// Resolve/bind/network/timeout/capability failure — retry with the
    /// normal exponential backoff.
    Transient(anyhow::Error),
}

/// QUIC carries TLS alerts as transport error codes in `0x0100..0x0200`
/// (RFC 9001 §4.8). A connection that closed with a code in that range — be
/// it generated locally (we rejected the `ws` server cert) or sent by the
/// peer (`ws` rejected our client cert) — is a pin/cert authentication
/// failure. Pure, so it is unit-tested directly.
pub(super) fn is_crypto_code(code: u64) -> bool {
    (0x0100..0x0200).contains(&code)
}

/// Classify a [`quinn::ConnectionError`] as an authentication failure (a
/// crypto-range close) versus a transient transport/network condition.
pub(in crate::server) fn is_auth_failure(err: &quinn::ConnectionError) -> bool {
    match err {
        quinn::ConnectionError::TransportError(te) => is_crypto_code(u64::from(te.code)),
        quinn::ConnectionError::ConnectionClosed(cc) => is_crypto_code(u64::from(cc.error_code)),
        _ => false,
    }
}

impl ReverseDialer {
    /// Parse the pin, load the client cert/key and build the QUIC client
    /// config. Errors here are terminal for this endpoint's dial loop.
    pub(super) fn new(ep: &ReverseTunnelEndpoint) -> Result<Self> {
        let pin = parse_cert_pin(&ep.server_cert_pin)
            .with_context(|| format!("reverse endpoint {}: invalid server_cert_pin", ep.addr))?;
        let cert_chain = load_cert_chain(&ep.client_cert_path)
            .with_context(|| format!("reverse endpoint {}: failed to load client cert", ep.addr))?;
        let key = load_private_key(&ep.client_key_path)
            .with_context(|| format!("reverse endpoint {}: failed to load client key", ep.addr))?;
        let client_config =
            build_reverse_client_quic_config(cert_chain, key, pin, ep.advertised_alpns())?;
        Ok(Self {
            addr: ep.addr.clone(),
            server_name: ep.server_name.clone(),
            client_config,
        })
    }

    pub(super) fn addr(&self) -> &str {
        &self.addr
    }

    /// Resolve, bind a fresh client endpoint and complete the QUIC
    /// handshake. A fresh endpoint per attempt keeps the socket lifetime
    /// tied to the connection (dropped on return), avoiding a leaked
    /// half-open endpoint after a failed dial. The error variant tells the
    /// reconnect loop whether to retry soon (transient) or back off long
    /// (auth/pin failure).
    pub(super) async fn dial(&self) -> std::result::Result<quinn::Connection, DialError> {
        let server_addr = self.resolve().await.map_err(DialError::Transient)?;
        let bind_addr: SocketAddr = if server_addr.is_ipv6() {
            "[::]:0".parse().expect("valid v6 wildcard")
        } else {
            "0.0.0.0:0".parse().expect("valid v4 wildcard")
        };
        let endpoint = quinn::Endpoint::client(bind_addr)
            .with_context(|| format!("failed to bind reverse client endpoint on {bind_addr}"))
            .map_err(DialError::Transient)?;
        let connection = endpoint
            .connect_with(self.client_config.clone(), server_addr, &self.server_name)
            .with_context(|| format!("failed to initiate reverse QUIC dial to {server_addr}"))
            .map_err(DialError::Transient)?
            .await
            .map_err(|error| {
                let auth = is_auth_failure(&error);
                let error = anyhow::Error::new(error)
                    .context(format!("reverse QUIC handshake failed for {server_addr}"));
                if auth {
                    DialError::Auth(error)
                } else {
                    DialError::Transient(error)
                }
            })?;
        // Datagram support is required for SS-UDP over the reverse carrier.
        if connection.max_datagram_size().is_none() {
            connection.close(0u32.into(), b"datagrams unsupported");
            return Err(DialError::Transient(anyhow!(
                "reverse peer {server_addr} did not negotiate QUIC datagram support"
            )));
        }
        Ok(connection)
    }

    async fn resolve(&self) -> Result<SocketAddr> {
        lookup_host(&self.addr)
            .await
            .with_context(|| format!("failed to resolve reverse endpoint {}", self.addr))?
            .next()
            .ok_or_else(|| anyhow!("no addresses resolved for reverse endpoint {}", self.addr))
    }
}

#[cfg(test)]
#[path = "tests/endpoint.rs"]
mod tests;
