//! Server-side TLS for the reverse-tunnel listener (topology A).
//!
//! In reverse mode `outline-ws-rust` is the QUIC **server**: it accepts
//! carriers dialed by `outline-ss-rust` peers behind NAT. The TLS roles are
//! inverted relative to the forward client transport — here `ws` presents a
//! server certificate and requires client certificates (mTLS), trusting only
//! the pinned SHA-256 fingerprints of the configured `ss` peers.
//!
//! The pinned client-cert verifier mirrors `cert_check::AcceptAnyServerCert`:
//! signature verification stays delegated to the crypto provider, only the
//! trust decision is replaced with a constant-time fingerprint membership
//! test. Peer *identity* (which `ss` connected) is recovered separately by
//! the listener via `connection.peer_identity()`.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use ring::digest::{SHA256, digest};
use rustls::DigitallySignedStruct;
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DistinguishedName, SignatureScheme};
use subtle::ConstantTimeEq;

/// SHA-256 fingerprint length in bytes.
pub const CERT_PIN_LEN: usize = 32;

/// Parses a pinned certificate fingerprint: 64 hex chars (optionally
/// colon-separated) or standard base64 of 32 bytes. Pure; never logs input.
pub fn parse_cert_pin(s: &str) -> Result<[u8; CERT_PIN_LEN]> {
    let trimmed = s.trim();
    let hex: String = trimmed.chars().filter(|c| *c != ':').collect();
    if hex.len() == CERT_PIN_LEN * 2 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        let mut out = [0u8; CERT_PIN_LEN];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|_| anyhow!("invalid hex in cert pin"))?;
        }
        return Ok(out);
    }
    use base64::Engine;
    for engine in [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::STANDARD_NO_PAD,
    ] {
        if let Ok(bytes) = engine.decode(trimmed)
            && bytes.len() == CERT_PIN_LEN
        {
            let mut out = [0u8; CERT_PIN_LEN];
            out.copy_from_slice(&bytes);
            return Ok(out);
        }
    }
    Err(anyhow!("cert pin must be 32-byte SHA-256 as hex (64 chars) or base64"))
}

/// SHA-256 over a DER-encoded certificate — the pinned fingerprint.
pub fn cert_fingerprint(der: &CertificateDer<'_>) -> [u8; CERT_PIN_LEN] {
    let mut out = [0u8; CERT_PIN_LEN];
    out.copy_from_slice(digest(&SHA256, der.as_ref()).as_ref());
    out
}

/// A [`ClientCertVerifier`] that accepts a client certificate iff its
/// SHA-256 fingerprint is in the configured allow-set (the pinned `ss`
/// peers). mTLS is mandatory: a connection without a client cert is
/// rejected. Signature verification stays delegated to the provider.
#[derive(Debug)]
struct PinnedClientCertVerifier {
    provider: Arc<CryptoProvider>,
    allowed: Vec<[u8; CERT_PIN_LEN]>,
}

impl ClientCertVerifier for PinnedClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // Pinned mTLS: we do not advertise CA subjects; the peer presents
        // its known self-signed cert regardless.
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let actual = cert_fingerprint(end_entity);
        let trusted = self.allowed.iter().any(|pin| actual.ct_eq(pin).into());
        if trusted {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(rustls::Error::General("reverse peer client cert pin mismatch".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// Builds the QUIC server config the reverse listener uses: presents
/// `server_cert_chain` + `server_key`, requires a client cert whose
/// fingerprint is in `allowed_client_pins` (mTLS), and advertises
/// `alpn` (e.g. `[ss-mtu, ss]`). Transport tuning mirrors the forward H3
/// server (keep-alive, idle timeout, datagrams) so SS-UDP and oversize
/// paths behave identically.
pub fn build_reverse_server_quic_config(
    server_cert_chain: Vec<CertificateDer<'static>>,
    server_key: PrivateKeyDer<'static>,
    allowed_client_pins: Vec<[u8; CERT_PIN_LEN]>,
    alpn: &[&[u8]],
) -> Result<quinn::ServerConfig> {
    if allowed_client_pins.is_empty() {
        return Err(anyhow!("reverse listener requires at least one allowed client cert pin"));
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(PinnedClientCertVerifier {
        provider: Arc::clone(&provider),
        allowed: allowed_client_pins,
    });
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("ring provider supports the default protocol versions")?
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_cert_chain, server_key)
        .context("failed to install reverse-tunnel server certificate")?;
    tls.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();

    let quic_tls = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|_| anyhow!("invalid reverse-tunnel server TLS config"))?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(quic_tls));
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    transport.max_idle_timeout(Some(
        Duration::from_secs(30)
            .try_into()
            .expect("valid reverse server idle timeout"),
    ));
    transport.datagram_receive_buffer_size(Some(64 * 1024));
    transport.datagram_send_buffer_size(64 * 1024);
    transport.initial_mtu(1400);
    let mut mtu = quinn::MtuDiscoveryConfig::default();
    mtu.upper_bound(1452);
    transport.mtu_discovery_config(Some(mtu));
    config.transport_config(Arc::new(transport));
    Ok(config)
}

#[cfg(test)]
#[path = "tests/tls_reverse.rs"]
mod tests;
