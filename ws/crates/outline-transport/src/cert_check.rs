//! Direct TLS certificate-expiry check for uplink endpoints.
//!
//! Opens a direct (non-tunnel) TLS connection to an uplink's own endpoint
//! (e.g. `senko.beerloga.su:443`), accepts the presented certificate
//! *regardless of validity* — so an already-expired cert still completes the
//! handshake — and reads the leaf certificate's `notAfter`.
//!
//! This is deliberately different from the TLS data-path probe in
//! `outline-uplink` (`probe/tls.rs`), which validates the *inner* certificate
//! of an external SNI reached *through* the tunnel. Here we inspect the
//! *outer* certificate the uplink server itself presents — the one whose
//! expiry silently breaks every wire of the uplink at once.
//!
//! The connection carries no application data and is dropped immediately, so
//! accepting an untrusted/expired cert is safe: the only thing extracted is
//! the `notAfter` timestamp.
//!
//! Gated behind the `cert-check` feature so router builds pull neither this
//! code nor the X.509 parser.

use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::debug;
use x509_cert::der::Decode;

use crate::DnsCache;
use crate::connect_tcp_socket;
use crate::dns::resolve_host_with_preference;

/// Total budget for resolve + connect + TLS handshake of a single endpoint.
/// Mirrors the data-path probe's lack of an inner deadline: a silent endpoint
/// surfaces as a single bounded timeout rather than hanging the check loop.
const CERT_CHECK_TIMEOUT: Duration = Duration::from_secs(10);

/// A [`ServerCertVerifier`] that accepts ANY server certificate — valid,
/// expired, self-signed, wrong-name — so the handshake always completes and
/// the presented leaf certificate can be read. Signature verification is
/// still delegated to the crypto provider so the handshake stays well-formed;
/// only the trust/validity *decision* is bypassed. Safe because the
/// connection is used solely to read the certificate and is then dropped — no
/// application bytes are ever exchanged.
#[derive(Debug)]
struct AcceptAnyServerCert {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
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

/// Process-wide accept-any client config, built once. Cheap to share across
/// the few endpoints checked per (infrequent) cycle.
static ACCEPT_ANY_TLS_CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();

fn accept_any_client_config() -> Arc<ClientConfig> {
    Arc::clone(ACCEPT_ANY_TLS_CONFIG.get_or_init(|| {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .expect("ring provider supports the default protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert { provider }))
            .with_no_client_auth();
        Arc::new(config)
    }))
}

/// Parse the `notAfter` of a DER-encoded X.509 certificate as Unix
/// milliseconds. Pure, so it is unit-tested against a fixture certificate.
pub fn leaf_not_after_unix_ms(leaf_der: &[u8]) -> Result<u64> {
    let cert = x509_cert::Certificate::from_der(leaf_der)
        .map_err(|e| anyhow!("failed to parse leaf certificate: {e}"))?;
    let ms = cert.tbs_certificate.validity.not_after.to_unix_duration().as_millis();
    Ok(ms as u64)
}

/// Open a direct TLS connection to `host:port` — bypassing the tunnel but
/// honouring the uplink's `fwmark`/`ipv6_first` so it follows the same egress
/// routing — and return the leaf certificate's `notAfter` as Unix
/// milliseconds. Accepts expired / untrusted certs on purpose: reading the
/// expiry is the entire point.
///
/// Network or handshake failures are `Err`; a completed handshake with no
/// peer certificate (should not happen for a TLS server) is also `Err`.
pub async fn fetch_leaf_cert_not_after_unix_ms(
    cache: &DnsCache,
    host: &str,
    port: u16,
    fwmark: Option<u32>,
    ipv6_first: bool,
) -> Result<u64> {
    timeout(CERT_CHECK_TIMEOUT, async move {
        let addrs = resolve_host_with_preference(
            cache,
            host,
            port,
            &format!("cert check: failed to resolve {host}:{port}"),
            ipv6_first,
        )
        .await?;
        let addr = addrs
            .first()
            .copied()
            .ok_or_else(|| anyhow!("cert check: no addresses for {host}:{port}"))?;
        let tcp = connect_tcp_socket(addr, fwmark).await?;
        let server_name = if let Ok(ip) = host.parse::<IpAddr>() {
            ServerName::IpAddress(ip.into())
        } else {
            ServerName::try_from(host.to_string())
                .map_err(|_| anyhow!("cert check: invalid TLS server name {host}"))?
        };
        let tls = TlsConnector::from(accept_any_client_config())
            .connect(server_name, tcp)
            .await
            .context("cert check: TLS handshake failed")?;
        let leaf = {
            let (_io, conn) = tls.get_ref();
            conn.peer_certificates()
                .and_then(|chain| chain.first())
                .map(|der| der.as_ref().to_vec())
                .ok_or_else(|| anyhow!("cert check: server presented no certificate"))?
        };
        let not_after = leaf_not_after_unix_ms(&leaf)?;
        debug!(host, port, not_after_unix_ms = not_after, "fetched uplink endpoint cert expiry");
        Ok(not_after)
    })
    .await
    .map_err(|_| anyhow!("cert check: timed out after {:?}", CERT_CHECK_TIMEOUT))?
}

#[cfg(test)]
#[path = "cert_check/tests/cert_check.rs"]
mod tests;
