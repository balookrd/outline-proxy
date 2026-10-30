//! Browser-shaped TLS ClientHello for the H3 (QUIC) carrier.
//!
//! The ClientHello rides the client's Initial packets, which any passive observer
//! decrypts (the Initial keys derive from the public destination CID), so the TLS
//! fingerprint of an H3 dial is as visible as its transport parameters. Each profile
//! mirrors a capture of the real browser's QUIC ClientHello (Chrome 156, Apple's
//! URLSession on macOS 27 and Firefox 159, 2026-10-29) and reproduces its JA4:
//!
//! * cipher suites, supported groups and signature algorithms in the browser's offer
//!   order (signature algorithms verbatim, duplicates included, via [`BrowserVerifier`]);
//! * the extension set: `ec_point_formats` is never sent, `extended_master_secret` and
//!   `status_request` follow the browser, `compress_certificate` lists the browser's
//!   algorithms, and the browser's extra extensions (ALPS, Chrome's trust-anchor ids,
//!   SCT, `record_size_limit`, `delegated_credentials`, `renegotiation_info`) are
//!   written verbatim;
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
//! Advertised extensions the client does not implement (ALPS, trust-anchor ids,
//! delegated credentials, SCT, record size limit) work only against servers that do not
//! answer them: answers in EncryptedExtensions are accepted, but rustls rejects
//! delegated credentials, SCT or trust-anchor answers inside a CertificateEntry, and a
//! BoringSSL server with ALPS enabled for h3 expects the client's own ALPS settings.
//! `outline-ss-rust` (rustls) answers none of them; a third-party front or CDN might.

use std::io::Read;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{
    ClientSessionMemoryCache, ClientSessionStore, Tls12ClientSessionValue, Tls13ClientSessionValue,
    WebPkiServerVerifier,
};
use rustls::compress::{CertDecompressor, DecompressionFailed};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertificateCompressionAlgorithm, CipherSuite, DigitallySignedStruct, DistinguishedName,
    NamedGroup, SignatureScheme,
};

use crate::fingerprint_profile::TlsFingerprint;

/// Extension order of a profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShapeOrder {
    /// Random per connection, ECH (and PSK) last - upstream rustls.
    Shuffled,
    /// Random per connection, ECH shuffled too (PSK last).
    ShuffledWithEch,
    /// Exactly this order, framed by the GREASE extensions when `grease` is set.
    Fixed(&'static [u16]),
}

/// The QUIC TLS ClientHello of one browser family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QuicTlsProfile {
    pub(crate) name: &'static str,
    /// TLS 1.3 cipher suites, offer order.
    pub(crate) cipher_suites: &'static [CipherSuite],
    /// `supported_groups`, offer order, real groups only (GREASE comes from `grease`);
    /// the first two get key shares.
    pub(crate) kx_groups: &'static [NamedGroup],
    /// `signature_algorithms`, verbatim (duplicates kept).
    pub(crate) sig_schemes: &'static [SignatureScheme],
    /// `compress_certificate` algorithms, offer order; empty omits the extension.
    pub(crate) cert_compression: &'static [CertificateCompressionAlgorithm],
    /// GREASE `encrypted_client_hello` (X25519 / HKDF-SHA256 / AES-128-GCM).
    pub(crate) ech_grease: bool,
    pub(crate) omit_extended_master_secret: bool,
    pub(crate) omit_status_request: bool,
    /// Extensions written as-is: `(type, body)`.
    pub(crate) extra_extensions: &'static [(u16, &'static [u8])],
    /// BoringSSL-style GREASE (RFC 8701).
    pub(crate) grease: bool,
    pub(crate) order: ShapeOrder,
    /// Key shares sent after the first two groups' shares.
    pub(crate) extra_key_shares: &'static [NamedGroup],
    /// GREASE ECH `payload` lengths (tag included), one drawn per connection; empty
    /// keeps rustls' inner-hello-derived size.
    pub(crate) ech_grease_payload_lengths: &'static [u16],
}

/// Chrome 156 `trust_anchors` (0xca34) body: identical in every capture (186 bytes).
const CHROME_TRUST_ANCHORS: [u8; 186] = [
    0x00, 0xb8, 0x05, 0x82, 0xdf, 0x13, 0x02, 0x01, 0x05, 0x82, 0xdf, 0x13, 0x02, 0x06, 0x05, 0x82,
    0xdf, 0x13, 0x02, 0x0d, 0x05, 0x82, 0xdf, 0x13, 0x02, 0x0e, 0x05, 0x82, 0xdf, 0x13, 0x02, 0x0f,
    0x05, 0x82, 0xdf, 0x13, 0x02, 0x12, 0x05, 0x82, 0xdf, 0x13, 0x02, 0x13, 0x05, 0x82, 0xdf, 0x13,
    0x02, 0x14, 0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x07, 0x08, 0x83, 0x9a, 0x64, 0x8c,
    0x9b, 0x2d, 0x01, 0x08, 0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x09, 0x08, 0x83, 0x9a,
    0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0a, 0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0b, 0x08,
    0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0c, 0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01,
    0x0d, 0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x12, 0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b,
    0x2d, 0x01, 0x13, 0x04, 0xd6, 0x79, 0x09, 0x01, 0x04, 0xd6, 0x79, 0x09, 0x04, 0x04, 0xd6, 0x79,
    0x09, 0x05, 0x04, 0xd6, 0x79, 0x09, 0x06, 0x04, 0xd6, 0x79, 0x09, 0x07, 0x04, 0xd6, 0x79, 0x09,
    0x08, 0x04, 0xd6, 0x79, 0x09, 0x0a, 0x04, 0xd6, 0x79, 0x09, 0x0b, 0x04, 0xd6, 0x79, 0x09, 0x0c,
    0x04, 0xd6, 0x79, 0x09, 0x0d, 0x04, 0xd6, 0x79, 0x09, 0x0f,
];

/// Chrome 156 (Edge and other Blink clients share the stack).
pub(crate) const CHROMIUM: QuicTlsProfile = QuicTlsProfile {
    name: "chromium",
    cipher_suites: &[
        CipherSuite::TLS13_AES_128_GCM_SHA256,
        CipherSuite::TLS13_AES_256_GCM_SHA384,
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
    ],
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
    omit_extended_master_secret: true,
    omit_status_request: true,
    extra_extensions: &[
        // application_settings (ALPS, new codepoint) for "h3".
        (17613, &[0x00, 0x03, 0x02, b'h', b'3']),
        // Chrome 156 trust-anchor ids, constant across captures.
        (51764, &CHROME_TRUST_ANCHORS),
    ],
    grease: false,
    order: ShapeOrder::ShuffledWithEch,
    extra_key_shares: &[],
    // GREASE ECH payload lengths observed in Chrome 156 captures (its buckets).
    ech_grease_payload_lengths: &[176, 208, 240],
};

/// Apple URLSession / Network.framework (Safari).
pub(crate) const SAFARI: QuicTlsProfile = QuicTlsProfile {
    name: "safari",
    cipher_suites: &[
        CipherSuite::TLS13_AES_256_GCM_SHA384,
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        CipherSuite::TLS13_AES_128_GCM_SHA256,
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
    omit_extended_master_secret: true,
    omit_status_request: false,
    // signed_certificate_timestamp, empty.
    extra_extensions: &[(18, &[])],
    grease: true,
    order: ShapeOrder::Fixed(&[0, 10, 16, 5, 13, 18, 51, 45, 43, 57, 27]),
    extra_key_shares: &[],
    ech_grease_payload_lengths: &[],
};

/// Firefox 159 (NSS).
pub(crate) const FIREFOX: QuicTlsProfile = QuicTlsProfile {
    name: "firefox",
    cipher_suites: &[
        CipherSuite::TLS13_AES_128_GCM_SHA256,
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        CipherSuite::TLS13_AES_256_GCM_SHA384,
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
    grease: false,
    order: ShapeOrder::Shuffled,
    extra_key_shares: &[NamedGroup::secp256r1],
    // Firefox 159 always sends a 240-byte GREASE ECH payload.
    ech_grease_payload_lengths: &[240],
};

/// With no dial fingerprint the client still looks like the most common browser
/// (as [`super::tp_profile::for_fingerprint`]).
pub(crate) fn for_fingerprint(fp: Option<TlsFingerprint>) -> &'static QuicTlsProfile {
    match fp {
        Some(TlsFingerprint::Safari) => &SAFARI,
        Some(TlsFingerprint::Firefox) => &FIREFOX,
        Some(TlsFingerprint::Chromium) | None => &CHROMIUM,
    }
}

impl QuicTlsProfile {
    /// aws-lc-rs provider offering exactly this profile's cipher suites and groups.
    pub(crate) fn provider(&self) -> rustls::crypto::CryptoProvider {
        use rustls::crypto::aws_lc_rs;
        let cipher_suites = self
            .cipher_suites
            .iter()
            .map(|want| {
                *aws_lc_rs::ALL_CIPHER_SUITES
                    .iter()
                    .find(|s| s.suite() == *want)
                    .unwrap_or_else(|| panic!("{}: no aws-lc-rs suite {want:?}", self.name))
            })
            .collect();
        let kx_groups = self
            .kx_groups
            .iter()
            .map(|want| {
                aws_lc_rs::ALL_KX_GROUPS
                    .iter()
                    .copied()
                    .chain([crate::tls_vendored::secp521r1()])
                    .find(|g| g.name() == *want)
                    .unwrap_or_else(|| panic!("{}: no aws-lc-rs group {want:?}", self.name))
            })
            .collect();
        rustls::crypto::CryptoProvider {
            cipher_suites,
            kx_groups,
            ..aws_lc_rs::default_provider()
        }
    }

    /// Certificate decompressors in `compress_certificate` offer order.
    pub(crate) fn cert_decompressors(&self) -> Vec<&'static dyn CertDecompressor> {
        self.cert_compression
            .iter()
            .map(|alg| -> &'static dyn CertDecompressor {
                match alg {
                    CertificateCompressionAlgorithm::Zlib => &ZLIB,
                    CertificateCompressionAlgorithm::Brotli => &BROTLI,
                    CertificateCompressionAlgorithm::Zstd => &ZSTD,
                    other => panic!("{}: no decompressor for {other:?}", self.name),
                }
            })
            .collect()
    }
}

// ── Certificate decompressors (RFC 8879) ────────────────────────────────────
//
// Our own decoders rather than rustls's `zlib` / `brotli` features: those would also
// give a server built in the same graph compressors, and it would start compressing
// its certificate.

/// Reads exactly `output.len()` bytes from `decoder`, failing on any shortfall, excess
/// or decode error.
fn decompress_exact(mut decoder: impl Read, output: &mut [u8]) -> Result<(), DecompressionFailed> {
    decoder.read_exact(output).map_err(|_| DecompressionFailed)?;
    let mut extra = [0u8; 1];
    match decoder.read(&mut extra) {
        Ok(0) => Ok(()),
        _ => Err(DecompressionFailed),
    }
}

#[derive(Debug)]
pub(crate) struct ZlibDecompressor;

impl CertDecompressor for ZlibDecompressor {
    fn decompress(&self, input: &[u8], output: &mut [u8]) -> Result<(), DecompressionFailed> {
        decompress_exact(flate2::read::ZlibDecoder::new(input), output)
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::Zlib
    }
}

#[derive(Debug)]
pub(crate) struct BrotliDecompressor;

impl CertDecompressor for BrotliDecompressor {
    fn decompress(&self, input: &[u8], output: &mut [u8]) -> Result<(), DecompressionFailed> {
        decompress_exact(brotli_decompressor::Decompressor::new(input, 4096), output)
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::Brotli
    }
}

#[derive(Debug)]
pub(crate) struct ZstdDecompressor;

impl CertDecompressor for ZstdDecompressor {
    fn decompress(&self, input: &[u8], output: &mut [u8]) -> Result<(), DecompressionFailed> {
        let decoder =
            ruzstd::decoding::StreamingDecoder::new(input).map_err(|_| DecompressionFailed)?;
        decompress_exact(decoder, output)
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::Zstd
    }
}

pub(crate) static ZLIB: ZlibDecompressor = ZlibDecompressor;
pub(crate) static BROTLI: BrotliDecompressor = BrotliDecompressor;
pub(crate) static ZSTD: ZstdDecompressor = ZstdDecompressor;

// ── Signature algorithms ────────────────────────────────────────────────────

/// WebPKI verification that advertises the browser's `signature_algorithms` list
/// verbatim. Schemes webpki cannot verify (SHA-1, duplicates) are only advertised: a
/// TLS 1.3 server never picks a SHA-1 scheme for CertificateVerify, and webpki rejects
/// SHA-1 certificate signatures anyway.
#[derive(Debug)]
pub(crate) struct BrowserVerifier {
    inner: Arc<WebPkiServerVerifier>,
    schemes: &'static [SignatureScheme],
}

impl BrowserVerifier {
    pub(crate) fn new(
        inner: Arc<WebPkiServerVerifier>,
        schemes: &'static [SignatureScheme],
    ) -> Self {
        Self { inner, schemes }
    }
}

impl ServerCertVerifier for BrowserVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.to_vec()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.inner.requires_raw_public_keys()
    }

    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        self.inner.root_hint_subjects()
    }
}

// ── Session store ───────────────────────────────────────────────────────────

/// rustls's in-memory session store without the key-exchange hint. Upstream remembers
/// the group each server chose and leads the next ClientHello's `key_share` with it, so
/// one handshake with a server that picked plain `x25519` would drop the 1216-byte
/// `X25519MLKEM768` share from every later dial to that server - a hello no browser
/// sends. Without the hint every ClientHello offers the profile's key shares.
#[derive(Debug)]
pub(crate) struct NoKxHintStore {
    inner: ClientSessionMemoryCache,
}

impl NoKxHintStore {
    /// Same capacity as rustls's default `Resumption` (256 server names).
    pub(crate) fn new() -> Self {
        Self {
            inner: ClientSessionMemoryCache::new(256),
        }
    }
}

impl ClientSessionStore for NoKxHintStore {
    fn set_kx_hint(&self, _server_name: ServerName<'static>, _group: NamedGroup) {}

    fn kx_hint(&self, _server_name: &ServerName<'_>) -> Option<NamedGroup> {
        None
    }

    fn set_tls12_session(&self, server_name: ServerName<'static>, value: Tls12ClientSessionValue) {
        self.inner.set_tls12_session(server_name, value)
    }

    fn tls12_session(&self, server_name: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
        self.inner.tls12_session(server_name)
    }

    fn remove_tls12_session(&self, server_name: &ServerName<'static>) {
        self.inner.remove_tls12_session(server_name)
    }

    fn insert_tls13_ticket(
        &self,
        server_name: ServerName<'static>,
        value: Tls13ClientSessionValue,
    ) {
        self.inner.insert_tls13_ticket(server_name, value)
    }

    fn take_tls13_ticket(
        &self,
        server_name: &ServerName<'static>,
    ) -> Option<Tls13ClientSessionValue> {
        self.inner.take_tls13_ticket(server_name)
    }
}

#[cfg(test)]
#[path = "tests/tls_profile.rs"]
mod tests;
