//! Client-side TLS for the reverse-tunnel dialer (topology A).
//!
//! In reverse mode `outline-ss-rust` is the QUIC **client**: it dials the
//! public `outline-ws-rust` listener. The TLS roles are inverted relative to
//! the forward H3 server — here `ss` presents a client certificate (mTLS) and
//! pins the `ws` server certificate by SHA-256 fingerprint instead of going
//! through webpki (CDN fronting is not applicable to the reverse carrier).
//!
//! The pinned verifier mirrors the shape of `outline-transport`'s
//! `AcceptAnyServerCert`: signature verification is still delegated to the
//! crypto provider so the handshake stays well-formed; only the trust
//! decision is replaced with a constant-time fingerprint comparison.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use ring::digest::{SHA256, digest};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use subtle::ConstantTimeEq;

/// SHA-256 fingerprint length in bytes.
pub(in crate::server) const CERT_PIN_LEN: usize = 32;

/// Parses a pinned certificate fingerprint from config: 64 hex chars
/// (optionally colon-separated) or standard base64 of 32 bytes. Pure, so it
/// is unit-tested. Never logs the input.
pub(in crate::server) fn parse_cert_pin(s: &str) -> Result<[u8; CERT_PIN_LEN]> {
    let trimmed = s.trim();
    // Hex (allow `aa:bb:..` or `aabb..`).
    let hex: String = trimmed.chars().filter(|c| *c != ':').collect();
    if hex.len() == CERT_PIN_LEN * 2 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        let mut out = [0u8; CERT_PIN_LEN];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|_| anyhow!("invalid hex in cert pin"))?;
        }
        return Ok(out);
    }
    // Base64 (standard, with or without padding).
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
pub(in crate::server) fn cert_fingerprint(der: &CertificateDer<'_>) -> [u8; CERT_PIN_LEN] {
    let mut out = [0u8; CERT_PIN_LEN];
    out.copy_from_slice(digest(&SHA256, der.as_ref()).as_ref());
    out
}

/// A [`ServerCertVerifier`] that trusts exactly one server certificate,
/// identified by its SHA-256 fingerprint. Replaces webpki path validation
/// with a constant-time pin comparison; signature verification is still
/// delegated to the provider so the handshake remains cryptographically
/// sound.
#[derive(Debug)]
struct PinnedServerCertVerifier {
    provider: Arc<CryptoProvider>,
    pin: [u8; CERT_PIN_LEN],
}

impl ServerCertVerifier for PinnedServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let actual = cert_fingerprint(end_entity);
        if actual.ct_eq(&self.pin).into() {
            Ok(ServerCertVerified::assertion())
        } else {
            // Never log either fingerprint — a mismatch is a generic trust
            // failure to the operator.
            Err(rustls::Error::General("reverse peer server cert pin mismatch".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// Builds the QUIC client config the reverse dialer uses: pins the `ws`
/// server cert by `ws_pin`, presents `client_cert_chain` + `client_key`
/// for mTLS, and offers `alpn_offered` (e.g. `[ss-mtu, ss]`). Transport
/// tuning mirrors the forward QUIC client (keep-alive 10s, idle 30s,
/// datagrams enabled, MTU floor 1400 → target 1452) so the SS-UDP and
/// oversize-record paths behave identically on the reverse carrier.
pub(in crate::server) fn build_reverse_client_quic_config(
    client_cert_chain: Vec<CertificateDer<'static>>,
    client_key: PrivateKeyDer<'static>,
    ws_pin: [u8; CERT_PIN_LEN],
    alpn_offered: &[&[u8]],
) -> Result<quinn::ClientConfig> {
    super::ensure_rustls_provider_installed();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut tls = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .context("aws-lc-rs provider supports the default protocol versions")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedServerCertVerifier {
            provider,
            pin: ws_pin,
        }))
        .with_client_auth_cert(client_cert_chain, client_key)
        .context("failed to install reverse-tunnel client certificate")?;
    tls.alpn_protocols = alpn_offered.iter().map(|a| a.to_vec()).collect();

    let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|_| anyhow!("invalid reverse-tunnel client TLS config"))?;
    let mut config = quinn::ClientConfig::new(Arc::new(quic_tls));
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    transport.max_idle_timeout(Some(
        Duration::from_secs(30)
            .try_into()
            .expect("valid reverse client idle timeout"),
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
#[path = "tests/reverse_tls.rs"]
mod tests;
