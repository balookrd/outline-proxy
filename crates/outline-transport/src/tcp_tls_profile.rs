//! Browser-shaped TLS ClientHello for the TCP dials (HTTP/1.1 and HTTP/2 carriers).
//!
//! Each profile mirrors a capture of the real browser's TCP ClientHello (Chrome 156,
//! Apple's URLSession on macOS 27 and Firefox 159, 2026-10-30) and reproduces its JA4
//! for the ALPN list the carrier offers (`h2, http/1.1` or `http/1.1`):
//!
//! * the browser's full `cipher_suites` list goes on the wire, TLS 1.2 suites (CBC,
//!   RSA key exchange, Apple's 3DES) included, while only the TLS 1.3 suites in
//!   `cipher_suites` can be negotiated;
//! * `supported_versions` offers TLS 1.2 after 1.3, and the TLS 1.2-era extensions the
//!   browsers send (`ec_point_formats`, `extended_master_secret`, `session_ticket`,
//!   `renegotiation_info`) are present, but the config negotiates TLS 1.3 only: a
//!   server that selects TLS 1.2 fails the handshake with an error;
//! * supported groups, key shares, signature algorithms (Chrome's ML-DSA and GREASE
//!   value included), certificate compression, GREASE, GREASE ECH and the extension
//!   order follow the browser; Chrome's ALPS for `h2` is sent only when `h2` is offered,
//!   and a server's ALPS answer gets the client's settings back.
//!
//! The Firefox profile on an `http/1.1`-only carrier differs from Firefox only in the
//! ALPN list (Firefox offers `h2, http/1.1` for WebSocket too). Not aligned here:
//! resumed / 0-RTT hellos and the HTTP/2 SETTINGS layer.

use rustls::{CertificateCompressionAlgorithm, CipherSuite, NamedGroup, SignatureScheme};

use crate::fingerprint_profile::TlsFingerprint;
use crate::tls_hello::{CHROME_TRUST_ANCHORS, EchAead, HelloProfile, ShapeOrder};

/// Client ALPS settings for `h2`: empty, so the server keeps the HTTP/2 defaults until
/// the connection preface's SETTINGS (Chrome sends its HTTP/2 SETTINGS here; Google's
/// front ends accept the empty body as well). Not aligned: with Chrome's body the
/// encrypted second-flight record is a few bytes longer than ours.
pub(crate) const ALPS_H2_SETTINGS: &[u8] = &[];

/// Chrome 156 over TCP (Edge and other Blink clients share the stack).
pub(crate) const CHROMIUM: HelloProfile = HelloProfile {
    name: "chromium",
    cipher_suites: &[
        CipherSuite::TLS13_AES_128_GCM_SHA256,
        CipherSuite::TLS13_AES_256_GCM_SHA384,
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
    ],
    wire_cipher_suites: &[
        CipherSuite::TLS13_AES_128_GCM_SHA256,
        CipherSuite::TLS13_AES_256_GCM_SHA384,
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
    ],
    kx_groups: &[
        NamedGroup::X25519MLKEM768,
        NamedGroup::X25519,
        NamedGroup::secp256r1,
        NamedGroup::secp384r1,
    ],
    sig_schemes: &[
        SignatureScheme::ML_DSA_44,
        SignatureScheme::ML_DSA_65,
        SignatureScheme::ML_DSA_87,
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::RSA_PSS_SHA256,
        SignatureScheme::RSA_PKCS1_SHA256,
        SignatureScheme::ECDSA_NISTP384_SHA384,
        SignatureScheme::RSA_PSS_SHA384,
        SignatureScheme::RSA_PKCS1_SHA384,
        SignatureScheme::RSA_PSS_SHA512,
        SignatureScheme::RSA_PKCS1_SHA512,
    ],
    cert_compression: &[CertificateCompressionAlgorithm::Brotli],
    ech_grease: true,
    ech_grease_aead: EchAead::Aes128Gcm,
    // rustls builds 23 (empty) and 11 (`0100`) even TLS 1.3-only.
    omit_extended_master_secret: false,
    // 5 = 0100000000, as Chrome.
    omit_status_request: false,
    extra_extensions: &[
        // session_ticket, empty (no ticket).
        (35, &[]),
        // signed_certificate_timestamp, empty.
        (18, &[]),
        // renegotiation_info, empty.
        (65281, &[0x00]),
        // Chrome 156 trust-anchor ids, constant across captures.
        (51764, &CHROME_TRUST_ANCHORS),
    ],
    alps: &[(b"h2", ALPS_H2_SETTINGS)],
    grease: true,
    grease_signature_algorithms: true,
    advertise_tls12: true,
    order: ShapeOrder::ShuffledWithEch,
    extra_key_shares: &[],
    // GREASE ECH payload lengths observed in Chrome 156 TCP captures (its buckets).
    ech_grease_payload_lengths: &[144, 176, 208, 240],
};

/// Apple URLSession / Network.framework (Safari) over TCP.
pub(crate) const SAFARI: HelloProfile = HelloProfile {
    name: "safari",
    cipher_suites: &[
        CipherSuite::TLS13_AES_256_GCM_SHA384,
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        CipherSuite::TLS13_AES_128_GCM_SHA256,
    ],
    wire_cipher_suites: &[
        CipherSuite::TLS13_AES_256_GCM_SHA384,
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        CipherSuite::TLS13_AES_128_GCM_SHA256,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
        CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
        CipherSuite::TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
        CipherSuite::TLS_RSA_WITH_3DES_EDE_CBC_SHA,
    ],
    kx_groups: &[
        NamedGroup::X25519MLKEM768,
        NamedGroup::X25519,
        NamedGroup::secp256r1,
        NamedGroup::secp384r1,
        NamedGroup::secp521r1,
    ],
    // As over QUIC.
    sig_schemes: &[
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::RSA_PSS_SHA256,
        SignatureScheme::RSA_PKCS1_SHA256,
        SignatureScheme::ECDSA_NISTP384_SHA384,
        // Apple offers rsa_pss_rsae_sha384 twice.
        SignatureScheme::RSA_PSS_SHA384,
        SignatureScheme::RSA_PSS_SHA384,
        SignatureScheme::RSA_PKCS1_SHA384,
        SignatureScheme::RSA_PSS_SHA512,
        SignatureScheme::RSA_PKCS1_SHA512,
        SignatureScheme::RSA_PKCS1_SHA1,
    ],
    cert_compression: &[CertificateCompressionAlgorithm::Zlib],
    ech_grease: false,
    ech_grease_aead: EchAead::Aes128Gcm,
    omit_extended_master_secret: false,
    omit_status_request: false,
    extra_extensions: &[
        // renegotiation_info, empty.
        (65281, &[0x00]),
        // signed_certificate_timestamp, empty.
        (18, &[]),
    ],
    alps: &[],
    grease: true,
    grease_signature_algorithms: false,
    advertise_tls12: true,
    order: ShapeOrder::Fixed(&[0, 23, 65281, 10, 11, 16, 5, 13, 18, 51, 45, 43, 27]),
    extra_key_shares: &[],
    ech_grease_payload_lengths: &[],
};

/// Firefox 159 (NSS) over TCP.
pub(crate) const FIREFOX: HelloProfile = HelloProfile {
    name: "firefox",
    cipher_suites: &[
        CipherSuite::TLS13_AES_128_GCM_SHA256,
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        CipherSuite::TLS13_AES_256_GCM_SHA384,
    ],
    wire_cipher_suites: &[
        CipherSuite::TLS13_AES_128_GCM_SHA256,
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        CipherSuite::TLS13_AES_256_GCM_SHA384,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
    ],
    kx_groups: &[
        NamedGroup::X25519MLKEM768,
        NamedGroup::X25519,
        NamedGroup::secp256r1,
        NamedGroup::secp384r1,
        NamedGroup::secp521r1,
    ],
    sig_schemes: &[
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::ECDSA_NISTP384_SHA384,
        SignatureScheme::ECDSA_NISTP521_SHA512,
        SignatureScheme::RSA_PSS_SHA256,
        SignatureScheme::RSA_PSS_SHA384,
        SignatureScheme::RSA_PSS_SHA512,
        SignatureScheme::RSA_PKCS1_SHA256,
        SignatureScheme::RSA_PKCS1_SHA384,
        SignatureScheme::RSA_PKCS1_SHA512,
        SignatureScheme::ECDSA_SHA1_Legacy,
        SignatureScheme::RSA_PKCS1_SHA1,
    ],
    // TCP order differs from QUIC (zlib, zstd, brotli).
    cert_compression: &[
        CertificateCompressionAlgorithm::Zlib,
        CertificateCompressionAlgorithm::Brotli,
        CertificateCompressionAlgorithm::Zstd,
    ],
    ech_grease: true,
    // Firefox 159 over TCP names ChaCha20-Poly1305 in its GREASE ECH (QUIC: AES-128-GCM).
    ech_grease_aead: EchAead::ChaCha20Poly1305,
    omit_extended_master_secret: false,
    omit_status_request: false,
    extra_extensions: &[
        // renegotiation_info, empty.
        (65281, &[0x00]),
        // session_ticket, empty (no ticket).
        (35, &[]),
        // delegated_credentials: ecdsa p256/p384/p521, ecdsa_sha1.
        (34, &[0x00, 0x08, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03]),
        // signed_certificate_timestamp, empty.
        (18, &[]),
        // record_size_limit = 16385.
        (28, &[0x40, 0x01]),
    ],
    alps: &[],
    grease: false,
    grease_signature_algorithms: false,
    advertise_tls12: true,
    order: ShapeOrder::Fixed(&[
        0, 23, 65281, 10, 11, 35, 16, 5, 34, 18, 51, 43, 13, 45, 28, 27, 65037,
    ]),
    extra_key_shares: &[NamedGroup::secp256r1],
    // Firefox 159 always sends a 240-byte GREASE ECH payload.
    ech_grease_payload_lengths: &[240],
};

/// The TCP profile of a dial fingerprint; with none the client still looks like the
/// most common browser (as the QUIC profiles).
pub(crate) fn for_fingerprint(fp: Option<TlsFingerprint>) -> &'static HelloProfile {
    match fp {
        Some(TlsFingerprint::Safari) => &SAFARI,
        Some(TlsFingerprint::Firefox) => &FIREFOX,
        Some(TlsFingerprint::Chromium) | None => &CHROMIUM,
    }
}

#[cfg(test)]
#[path = "tests/tcp_tls_profile.rs"]
mod tests;
