//! Browser-shaped TLS ClientHello for the H3 (QUIC) carrier: the QUIC profiles. The
//! machinery (profile type, config builder, verifier, decompressors) is shared with the
//! TCP dials in [`crate::tls_hello`].
//!
//! The ClientHello rides the client's Initial packets, which any passive observer
//! decrypts (the Initial keys derive from the public destination CID), so the TLS
//! fingerprint of an H3 dial is as visible as its transport parameters. Each profile
//! mirrors a capture of the real browser's QUIC ClientHello (Chrome 156, Apple's
//! URLSession on macOS 27 and Firefox 159, 2026-10-29) and reproduces its JA4:
//!
//! * cipher suites, supported groups and signature algorithms in the browser's offer
//!   order (signature algorithms verbatim, duplicates included, via
//!   [`crate::tls_hello::BrowserVerifier`]);
//! * the extension set: `ec_point_formats` is never sent, `extended_master_secret` and
//!   `status_request` follow the browser, `compress_certificate` lists the browser's
//!   algorithms, the browser's extra extensions (Chrome's trust-anchor ids, SCT,
//!   `record_size_limit`, `delegated_credentials`, `renegotiation_info`) are written
//!   verbatim, and Chrome's ALPS for `h3` is built by rustls (`HelloProfile::alps`);
//! * extension order: Chrome shuffles everything including GREASE ECH, Firefox
//!   shuffles with ECH last, Apple uses a fixed order framed by GREASE extensions;
//! * GREASE (Apple only) in ciphers, groups, key shares and versions; GREASE ECH
//!   (Chrome, Firefox) with the browser's payload lengths; Firefox's extra `secp256r1`
//!   key share.
//!
//! Not aligned here: how the ClientHello is split into CRYPTO frames across Initials
//! (Chrome's "chaos protection", neqo's split) and the size of the Initial datagrams
//! (all stay at quinn's default 1200 bytes; over IPv4 the measured browsers send 1250
//! (Chrome) / 1252 (Firefox), deliberately not matched because such sizes exceed the
//! 1280-byte IPv6 minimum MTU once the IPv6 and UDP headers are added; the browsers'
//! IPv6 Initial sizes were not measured) - both are tracked with the separate
//! CRYPTO-fragmentation work - and resumption: a resumed hello keeps the shape and adds
//! `pre_shared_key`, but the browsers' resumed / 0-RTT hellos (with `early_data`) are not
//! aligned.
//!
//! ALPS is answered: when a server (Google's front ends, BoringSSL) returns
//! `application_settings` for h3, rustls sends the client's settings
//! ([`ALPS_H3_SETTINGS`]) in its own EncryptedExtensions before Finished, as Chrome
//! does. Advertised extensions the client does not implement (trust-anchor ids,
//! delegated credentials, SCT, record size limit) work only against servers that do
//! not answer them: answers in EncryptedExtensions are accepted, but rustls rejects
//! delegated credentials, SCT or trust-anchor answers inside a CertificateEntry.
//! `outline-ss-rust` (rustls) answers none of them; a third-party front or CDN might.

use rustls::{CertificateCompressionAlgorithm, CipherSuite, NamedGroup, SignatureScheme};

use crate::fingerprint_profile::TlsFingerprint;
use crate::tls_hello::{CHROME_TRUST_ANCHORS, EchAead, HelloProfile, ShapeOrder};

/// Client ALPS settings for `h3`: empty, as QUICHE (Chrome's QUIC stack) sends them; the
/// HTTP/3 SETTINGS travel on the control stream.
pub(crate) const ALPS_H3_SETTINGS: &[u8] = &[];

/// Chrome 156 (Edge and other Blink clients share the stack).
pub(crate) const CHROMIUM: HelloProfile = HelloProfile {
    name: "chromium",
    cipher_suites: &[
        CipherSuite::TLS13_AES_128_GCM_SHA256,
        CipherSuite::TLS13_AES_256_GCM_SHA384,
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
    ],
    // TCP-only knobs stay neutral: the QUIC hello is unchanged.
    wire_cipher_suites: &[],
    kx_groups: &[
        NamedGroup::X25519MLKEM768,
        NamedGroup::X25519,
        NamedGroup::secp256r1,
        NamedGroup::secp384r1,
    ],
    sig_schemes: &[
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::RSA_PSS_SHA256,
        SignatureScheme::RSA_PKCS1_SHA256,
        SignatureScheme::ECDSA_NISTP384_SHA384,
        SignatureScheme::RSA_PSS_SHA384,
        SignatureScheme::RSA_PKCS1_SHA384,
        SignatureScheme::RSA_PSS_SHA512,
        SignatureScheme::RSA_PKCS1_SHA512,
        SignatureScheme::RSA_PKCS1_SHA1,
    ],
    cert_compression: &[CertificateCompressionAlgorithm::Brotli],
    ech_grease: true,
    ech_grease_aead: EchAead::Aes128Gcm,
    omit_extended_master_secret: true,
    omit_status_request: true,
    extra_extensions: &[
        // Chrome 156 trust-anchor ids, constant across captures.
        (51764, &CHROME_TRUST_ANCHORS),
    ],
    // application_settings (ALPS, new codepoint) for "h3".
    alps: &[(b"h3", ALPS_H3_SETTINGS)],
    grease: false,
    grease_signature_algorithms: false,
    advertise_tls12: false,
    order: ShapeOrder::ShuffledWithEch,
    extra_key_shares: &[],
    // GREASE ECH payload lengths observed in Chrome 156 captures (its buckets).
    ech_grease_payload_lengths: &[176, 208, 240],
};

/// Apple URLSession / Network.framework (Safari).
pub(crate) const SAFARI: HelloProfile = HelloProfile {
    name: "safari",
    cipher_suites: &[
        CipherSuite::TLS13_AES_256_GCM_SHA384,
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        CipherSuite::TLS13_AES_128_GCM_SHA256,
    ],
    // TCP-only knobs stay neutral: the QUIC hello is unchanged.
    wire_cipher_suites: &[],
    kx_groups: &[
        NamedGroup::X25519MLKEM768,
        NamedGroup::X25519,
        NamedGroup::secp256r1,
        NamedGroup::secp384r1,
        NamedGroup::secp521r1,
    ],
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
    omit_extended_master_secret: true,
    omit_status_request: false,
    // signed_certificate_timestamp, empty.
    extra_extensions: &[(18, &[])],
    alps: &[],
    grease: true,
    grease_signature_algorithms: false,
    advertise_tls12: false,
    order: ShapeOrder::Fixed(&[0, 10, 16, 5, 13, 18, 51, 45, 43, 57, 27]),
    extra_key_shares: &[],
    ech_grease_payload_lengths: &[],
};

/// Firefox 159 (NSS).
pub(crate) const FIREFOX: HelloProfile = HelloProfile {
    name: "firefox",
    cipher_suites: &[
        CipherSuite::TLS13_AES_128_GCM_SHA256,
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        CipherSuite::TLS13_AES_256_GCM_SHA384,
    ],
    // TCP-only knobs stay neutral: the QUIC hello is unchanged.
    wire_cipher_suites: &[],
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
        SignatureScheme::ECDSA_SHA1_Legacy,
        SignatureScheme::RSA_PSS_SHA256,
        SignatureScheme::RSA_PSS_SHA384,
        SignatureScheme::RSA_PSS_SHA512,
        SignatureScheme::RSA_PKCS1_SHA256,
        SignatureScheme::RSA_PKCS1_SHA384,
        SignatureScheme::RSA_PKCS1_SHA512,
        SignatureScheme::RSA_PKCS1_SHA1,
    ],
    cert_compression: &[
        CertificateCompressionAlgorithm::Zlib,
        CertificateCompressionAlgorithm::Zstd,
        CertificateCompressionAlgorithm::Brotli,
    ],
    ech_grease: true,
    ech_grease_aead: EchAead::Aes128Gcm,
    omit_extended_master_secret: false,
    omit_status_request: false,
    extra_extensions: &[
        // record_size_limit = 16385.
        (28, &[0x40, 0x01]),
        // delegated_credentials: ecdsa p256/p384/p521, ecdsa_sha1.
        (34, &[0x00, 0x08, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03]),
        // renegotiation_info, empty.
        (65281, &[0x00]),
    ],
    alps: &[],
    grease: false,
    grease_signature_algorithms: false,
    advertise_tls12: false,
    order: ShapeOrder::Shuffled,
    extra_key_shares: &[NamedGroup::secp256r1],
    // Firefox 159 always sends a 240-byte GREASE ECH payload.
    ech_grease_payload_lengths: &[240],
};

/// With no dial fingerprint the client still looks like the most common browser
/// (as [`super::tp_profile::for_fingerprint`]).
pub(crate) fn for_fingerprint(fp: Option<TlsFingerprint>) -> &'static HelloProfile {
    match fp {
        Some(TlsFingerprint::Safari) => &SAFARI,
        Some(TlsFingerprint::Firefox) => &FIREFOX,
        Some(TlsFingerprint::Chromium) | None => &CHROMIUM,
    }
}

#[cfg(test)]
#[path = "tests/tls_profile.rs"]
mod tests;
