//! SHA-256 certificate-fingerprint pinning helpers.
//!
//! Shared by the mesh-cluster QUIC TLS (`server::cluster::mesh::tls`), which
//! pins peer certificates by fingerprint rather than going through webpki
//! (there is no CA to distribute across cluster members).

use ring::digest::{SHA256, digest};
use rustls::pki_types::CertificateDer;

/// SHA-256 fingerprint length in bytes.
pub(in crate::server) const CERT_PIN_LEN: usize = 32;

/// SHA-256 over a DER-encoded certificate — the pinned fingerprint.
pub(in crate::server) fn cert_fingerprint(der: &CertificateDer<'_>) -> [u8; CERT_PIN_LEN] {
    let mut out = [0u8; CERT_PIN_LEN];
    out.copy_from_slice(digest(&SHA256, der.as_ref()).as_ref());
    out
}
