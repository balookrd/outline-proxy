//! PSK-derived mutual TLS for the mesh interconnect.
//!
//! The mesh is a QUIC link between cluster members. QUIC mandates a TLS 1.3
//! handshake, which already gives us ephemeral ECDHE session keys (forward
//! secrecy) plus AES-GCM. We keep that and drop the X.509 PKI: instead of a CA
//! and per-node certificates, every node derives one keypair deterministically
//! from the shared `cluster_psk` (`derive_mesh_auth_seed` → ed25519), builds a
//! fixed self-signed certificate from it, and pins peers by that certificate's
//! SHA-256 fingerprint. Because the derivation is deterministic every member
//! arrives at the *same* certificate, so the pin needs no distribution — the
//! only shared secret is the PSK already in the config.
//!
//! Authentication is mutual: the listener installs a client-cert verifier and
//! the dialer a server-cert verifier, both doing a constant-time fingerprint
//! compare and delegating signature verification to the crypto provider (so
//! the handshake stays cryptographically sound; only path validation is
//! replaced). A peer that does not know the PSK cannot produce a certificate
//! with the pinned fingerprint. See `docs/CLUSTER.md`.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use outline_wire::cluster::derive_mesh_auth_seed;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ED25519, SanType};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName as RustlsDn, ServerConfig,
    SignatureScheme,
};
use subtle::ConstantTimeEq;

use crate::server::bootstrap::{CERT_PIN_LEN, cert_fingerprint, ensure_rustls_provider_installed};

/// ALPN protocol id for the mesh interconnect. Distinct from the carrier
/// protocols so a stray client can never negotiate onto the mesh.
const MESH_ALPN: &[u8] = b"outline-mesh/1";

/// SAN in the mesh certificate; the dialer passes it as the QUIC server name.
/// The pin verifier ignores the name, but quinn still requires a valid one.
pub(super) const MESH_SERVER_NAME: &str = "mesh.cluster.internal";

/// Keep-alive / idle tuning, mirroring the reverse carrier so the mesh link
/// stays warm across the long inter-country hop without hanging forever.
const MESH_KEEP_ALIVE_SECS: u64 = 10;
const MESH_IDLE_TIMEOUT_SECS: u64 = 30;

/// Buffers for QUIC datagrams carrying out-of-band control signals
/// (`THROTTLE_HINT`). A control datagram is tiny (17 bytes) and low-rate
/// (cooldown-gated), so small buffers are ample and bound the memory a peer can
/// make us queue. Enabling the receive buffer also advertises datagram support
/// to peers, which the send side requires.
const MESH_DATAGRAM_RECV_BUFFER: usize = 64 * 1024;
const MESH_DATAGRAM_SEND_BUFFER: usize = 64 * 1024;

/// PKCS#8 v1 wrapper for a raw 32-byte Ed25519 seed: a fixed 16-byte ASN.1
/// prefix followed by the seed. Lets us hand a deterministic seed to rcgen.
fn ed25519_pkcs8_from_seed(seed: &[u8; 32]) -> Vec<u8> {
    const PREFIX: [u8; 16] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    let mut out = Vec::with_capacity(PREFIX.len() + seed.len());
    out.extend_from_slice(&PREFIX);
    out.extend_from_slice(seed);
    out
}

/// This node's mesh identity: the deterministic self-signed certificate and
/// key it presents, plus its own SHA-256 fingerprint (the shared pin every
/// member computes identically).
pub(in crate::server) struct MeshIdentity {
    cert_der: CertificateDer<'static>,
    key_der: PrivateKeyDer<'static>,
    pin: [u8; CERT_PIN_LEN],
}

impl MeshIdentity {
    /// Derives the mesh identity from the shared cluster PSK. Deterministic:
    /// the same PSK always yields the same certificate and pin, so peers agree
    /// without any exchange.
    pub(in crate::server) fn derive(psk: &[u8]) -> Result<Self> {
        ensure_rustls_provider_installed();
        let seed = derive_mesh_auth_seed(psk);
        let pkcs8 = ed25519_pkcs8_from_seed(&seed);
        let key_pair = KeyPair::from_pkcs8_der_and_sign_algo(
            &PrivatePkcs8KeyDer::from(pkcs8.as_slice()),
            &PKCS_ED25519,
        )
        .context("building mesh keypair from PSK-derived seed")?;

        let mut params = CertificateParams::default();
        // Everything fixed so the DER is deterministic across nodes.
        params.serial_number = Some(1u64.into());
        params.not_before = rcgen::date_time_ymd(2000, 1, 1);
        params.not_after = rcgen::date_time_ymd(9999, 1, 1);
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "outline-cluster-mesh");
        params.subject_alt_names =
            vec![SanType::DnsName(MESH_SERVER_NAME.try_into().expect("valid SAN"))];
        let cert = params
            .self_signed(&key_pair)
            .context("self-signing mesh certificate")?;

        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::try_from(key_pair.serialize_der())
            .map_err(|e| anyhow!("serializing mesh key: {e}"))?;
        let pin = cert_fingerprint(&cert_der);
        Ok(Self { cert_der, key_der, pin })
    }

    fn cert_chain(&self) -> Vec<CertificateDer<'static>> {
        vec![self.cert_der.clone()]
    }

    fn key(&self) -> PrivateKeyDer<'static> {
        self.key_der.clone_key()
    }
}

/// Constant-time fingerprint match shared by both verifier directions.
fn pin_matches(presented: &CertificateDer<'_>, pin: &[u8; CERT_PIN_LEN]) -> bool {
    cert_fingerprint(presented).ct_eq(pin).into()
}

/// Verifies the peer *server* certificate (dialer side) by pinned fingerprint.
#[derive(Debug)]
struct MeshServerVerifier {
    provider: Arc<CryptoProvider>,
    pin: [u8; CERT_PIN_LEN],
}

impl ServerCertVerifier for MeshServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if pin_matches(end_entity, &self.pin) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("mesh peer server cert pin mismatch".into()))
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

/// Verifies the peer *client* certificate (listener side) by pinned fingerprint.
#[derive(Debug)]
struct MeshClientVerifier {
    provider: Arc<CryptoProvider>,
    pin: [u8; CERT_PIN_LEN],
}

impl ClientCertVerifier for MeshClientVerifier {
    fn root_hint_subjects(&self) -> &[RustlsDn] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        if pin_matches(end_entity, &self.pin) {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(rustls::Error::General("mesh peer client cert pin mismatch".into()))
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

fn mesh_transport_config() -> Result<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(MESH_KEEP_ALIVE_SECS)));
    transport.max_idle_timeout(Some(
        Duration::from_secs(MESH_IDLE_TIMEOUT_SECS)
            .try_into()
            .context("invalid mesh idle timeout")?,
    ));
    // Out-of-band control signals (THROTTLE_HINT) ride QUIC datagrams.
    transport.datagram_receive_buffer_size(Some(MESH_DATAGRAM_RECV_BUFFER));
    transport.datagram_send_buffer_size(MESH_DATAGRAM_SEND_BUFFER);
    Ok(transport)
}

/// Builds the QUIC server config for the mesh listener: presents this node's
/// PSK-derived certificate and requires the peer to present one pinned to the
/// same fingerprint (mutual auth).
pub(in crate::server) fn build_mesh_server_quic_config(
    identity: &MeshIdentity,
) -> Result<quinn::ServerConfig> {
    ensure_rustls_provider_installed();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = Arc::new(MeshClientVerifier {
        provider: Arc::clone(&provider),
        pin: identity.pin,
    });
    let mut tls = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("aws-lc-rs provider supports the default protocol versions")?
        .with_client_cert_verifier(verifier)
        .with_single_cert(identity.cert_chain(), identity.key())
        .context("installing mesh server certificate")?;
    tls.alpn_protocols = vec![MESH_ALPN.to_vec()];

    let quic_tls = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|_| anyhow!("invalid mesh server TLS config"))?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(quic_tls));
    config.transport_config(Arc::new(mesh_transport_config()?));
    Ok(config)
}

/// Builds the QUIC client config for dialing a peer over the mesh: presents
/// this node's certificate (mTLS) and pins the peer's server certificate.
pub(in crate::server) fn build_mesh_client_quic_config(
    identity: &MeshIdentity,
) -> Result<quinn::ClientConfig> {
    ensure_rustls_provider_installed();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = Arc::new(MeshServerVerifier {
        provider: Arc::clone(&provider),
        pin: identity.pin,
    });
    let mut tls = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("aws-lc-rs provider supports the default protocol versions")?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(identity.cert_chain(), identity.key())
        .context("installing mesh client certificate")?;
    tls.alpn_protocols = vec![MESH_ALPN.to_vec()];

    let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|_| anyhow!("invalid mesh client TLS config"))?;
    let mut config = quinn::ClientConfig::new(Arc::new(quic_tls));
    config.transport_config(Arc::new(mesh_transport_config()?));
    Ok(config)
}

#[cfg(test)]
#[path = "tests/tls.rs"]
mod tests;
