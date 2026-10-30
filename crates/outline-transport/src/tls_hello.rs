//! Browser-shaped TLS ClientHello machinery shared by the TCP (h1/h2) dials
//! (`crate::tcp_tls_profile`) and the H3 (QUIC) carrier (`crate::quic::tls_profile`).
//!
//! A [`HelloProfile`] describes one browser's ClientHello: offered cipher suites,
//! groups, signature algorithms, certificate compression, GREASE, GREASE ECH, raw
//! extensions and their order. [`build_shaped_client_config`] turns it into a rustls
//! `ClientConfig` (TLS 1.3 only) whose hello carries that shape through the patched
//! rustls API (`crate::tls_vendored`). The browsers' TCP and QUIC hellos differ, so each
//! transport keeps its own profile constants.

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
    CertificateCompressionAlgorithm, CipherSuite, ClientConfig, DigitallySignedStruct,
    DistinguishedName, NamedGroup, SignatureScheme,
};

/// Extension order of a profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShapeOrder {
    /// Random per connection, ECH (and PSK) last - upstream rustls.
    // Only the QUIC Firefox profile uses it.
    #[cfg_attr(not(feature = "quic"), allow(dead_code))]
    Shuffled,
    /// Random per connection, ECH shuffled too (PSK last).
    ShuffledWithEch,
    /// Exactly this order, framed by the GREASE extensions when `grease` is set.
    Fixed(&'static [u16]),
}

/// HPKE AEAD of a GREASE ECH cipher suite (KEM X25519, KDF HKDF-SHA256).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EchAead {
    /// AEAD id 1.
    Aes128Gcm,
    /// AEAD id 3 (Firefox over TCP).
    ChaCha20Poly1305,
}

/// The TLS ClientHello of one browser family on one transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HelloProfile {
    pub(crate) name: &'static str,
    /// TLS 1.3 cipher suites the client implements, offer order (the provider's list).
    pub(crate) cipher_suites: &'static [CipherSuite],
    /// Exactly the `cipher_suites` sent on the wire (after GREASE), including suites the
    /// client does not implement; empty sends [`HelloProfile::cipher_suites`]. A
    /// non-empty list must contain every entry of `cipher_suites`.
    pub(crate) wire_cipher_suites: &'static [CipherSuite],
    /// `supported_groups`, offer order, real groups only (GREASE comes from `grease`);
    /// the first two get key shares.
    pub(crate) kx_groups: &'static [NamedGroup],
    /// `signature_algorithms`, verbatim (duplicates kept).
    pub(crate) sig_schemes: &'static [SignatureScheme],
    /// `compress_certificate` algorithms, offer order; empty omits the extension.
    pub(crate) cert_compression: &'static [CertificateCompressionAlgorithm],
    /// GREASE `encrypted_client_hello` (X25519 / HKDF-SHA256 / `ech_grease_aead`).
    pub(crate) ech_grease: bool,
    /// AEAD named in the GREASE ECH cipher suite (ignored without `ech_grease`).
    pub(crate) ech_grease_aead: EchAead,
    pub(crate) omit_extended_master_secret: bool,
    pub(crate) omit_status_request: bool,
    /// Extensions written as-is: `(type, body)`.
    pub(crate) extra_extensions: &'static [(u16, &'static [u8])],
    /// ALPS (`application_settings`, new codepoint 17613): `(ALPN protocol, client
    /// settings)`. The hello lists the offered ALPN protocols that have an entry; when
    /// the server answers for the negotiated one, rustls sends these settings in the
    /// client's EncryptedExtensions. Empty: no ALPS.
    pub(crate) alps: &'static [(&'static [u8], &'static [u8])],
    /// BoringSSL-style GREASE (RFC 8701).
    pub(crate) grease: bool,
    /// With `grease`, a GREASE value first in `signature_algorithms`.
    pub(crate) grease_signature_algorithms: bool,
    /// Offer TLS 1.2 (`0303`) in `supported_versions` and send the TLS 1.2-era
    /// `ec_point_formats`, while the config itself negotiates TLS 1.3 only.
    pub(crate) advertise_tls12: bool,
    pub(crate) order: ShapeOrder,
    /// Key shares sent after the first two groups' shares.
    pub(crate) extra_key_shares: &'static [NamedGroup],
    /// GREASE ECH `payload` lengths (tag included), one drawn per connection; empty
    /// keeps rustls' inner-hello-derived size.
    pub(crate) ech_grease_payload_lengths: &'static [u16],
}

/// Chrome 156 `trust_anchors` (0xca34) body: identical in every capture, TCP and QUIC
/// (186 bytes).
pub(crate) const CHROME_TRUST_ANCHORS: [u8; 186] = [
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

impl HelloProfile {
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

    /// `Err(suite)` when a non-empty [`HelloProfile::wire_cipher_suites`] leaves out an
    /// implemented suite, which the client could then never negotiate.
    pub(crate) fn check_wire_cipher_suites(&self) -> Result<(), CipherSuite> {
        if self.wire_cipher_suites.is_empty() {
            return Ok(());
        }
        match self
            .cipher_suites
            .iter()
            .find(|s| !self.wire_cipher_suites.contains(s))
        {
            Some(missing) => Err(*missing),
            None => Ok(()),
        }
    }
}

/// WebPKI verification over the dial roots (the test override when installed, else
/// webpki-roots) that advertises `profile`'s `signature_algorithms`.
pub(crate) fn webpki_verifier(profile: &HelloProfile) -> Arc<dyn ServerCertVerifier> {
    let provider = Arc::new(profile.provider());
    let inner =
        WebPkiServerVerifier::builder_with_provider(Arc::new(crate::tls::roots()), provider)
            .build()
            .expect("webpki verifier over a non-empty root store");
    Arc::new(BrowserVerifier::new(inner, profile.sig_schemes))
}

/// TLS 1.3 `ClientConfig` whose ClientHello is shaped like `profile`, offering `alpn`
/// and verifying the server with `verifier`. With GREASE ECH the config goes through
/// rustls' ECH builder (TLS 1.3 only by construction); without it TLS 1.3 is selected
/// explicitly. TLS 1.2 may still be advertised ([`HelloProfile::advertise_tls12`]); a
/// server that selects it fails the handshake with an error.
pub(crate) fn build_shaped_client_config(
    profile: &HelloProfile,
    alpn: &[&[u8]],
    verifier: Arc<dyn ServerCertVerifier>,
) -> Arc<ClientConfig> {
    use rustls::client::{EchGreaseConfig, EchMode};
    use rustls::crypto::aws_lc_rs::hpke::{
        DH_KEM_X25519_HKDF_SHA256_AES_128, DH_KEM_X25519_HKDF_SHA256_CHACHA20_POLY1305,
    };
    use rustls::crypto::hpke::Hpke;

    debug_assert!(
        profile.check_wire_cipher_suites().is_ok(),
        "{}: wire_cipher_suites must list every implemented suite",
        profile.name
    );
    let builder = ClientConfig::builder_with_provider(Arc::new(profile.provider()));
    let builder = if profile.ech_grease {
        // A fresh X25519 point per build stands in for the (absent) server ECH key.
        let suite: &'static dyn Hpke = match profile.ech_grease_aead {
            EchAead::Aes128Gcm => DH_KEM_X25519_HKDF_SHA256_AES_128,
            EchAead::ChaCha20Poly1305 => DH_KEM_X25519_HKDF_SHA256_CHACHA20_POLY1305,
        };
        let (placeholder, _) = suite.generate_key_pair().expect("aws-lc-rs X25519 key generation");
        builder
            .with_ech(EchMode::Grease(EchGreaseConfig::new(suite, placeholder)))
            .expect("aws-lc-rs provider supports TLS 1.3 and ECH")
    } else {
        builder
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("aws-lc-rs provider supports TLS 1.3")
    };
    let mut config = builder
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config.cert_decompressors = profile.cert_decompressors();
    // TLS 1.3 tickets only (the config is TLS 1.3); no kx hint, so every hello keeps the
    // profile's key shares.
    config.resumption = rustls::client::Resumption::store(Arc::new(NoKxHintStore::new()));
    crate::tls_vendored::apply_tls_hello_profile(&mut config, profile);
    Arc::new(config)
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

/// Wraps any verifier (WebPKI, or accept-any for the cert-expiry check) and advertises
/// the browser's `signature_algorithms` list verbatim. Schemes webpki cannot verify (SHA-1, ML-DSA, duplicates) are only
/// advertised: a TLS 1.3 server never picks a SHA-1 scheme for CertificateVerify,
/// webpki rejects SHA-1 certificate signatures anyway, and a server choosing ML-DSA
/// fails the handshake with a verifier error.
#[derive(Debug)]
pub(crate) struct BrowserVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    schemes: &'static [SignatureScheme],
}

impl BrowserVerifier {
    pub(crate) fn new(
        inner: Arc<dyn ServerCertVerifier>,
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
#[path = "tests/tls_hello.rs"]
mod tests;
