use std::io::Write;
use std::sync::{Arc, OnceLock};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use super::*;
use crate::quic::loopback;

#[test]
fn chromium_and_none_get_chromium_profile() {
    for fp in [Some(TlsFingerprint::Chromium), None] {
        assert_eq!(for_fingerprint(fp), &CHROMIUM, "{fp:?}");
    }
    assert_eq!(for_fingerprint(Some(TlsFingerprint::Safari)), &SAFARI);
    assert_eq!(for_fingerprint(Some(TlsFingerprint::Firefox)), &FIREFOX);
}

#[test]
fn providers_offer_profile_suites_and_groups_in_order() {
    for p in [&CHROMIUM, &SAFARI, &FIREFOX] {
        let provider = p.provider();
        let suites: Vec<_> = provider.cipher_suites.iter().map(|s| s.suite()).collect();
        assert_eq!(suites, p.cipher_suites, "{}", p.name);
        let groups: Vec<_> = provider.kx_groups.iter().map(|g| g.name()).collect();
        assert_eq!(groups, p.kx_groups, "{}", p.name);
        let algs: Vec<_> = p.cert_decompressors().iter().map(|d| d.algorithm()).collect();
        assert_eq!(algs, p.cert_compression, "{}", p.name);
    }
}

// ── Decompressors ───────────────────────────────────────────────────────────

const SAMPLE: &[u8] = b"certificate chain bytes, certificate chain bytes";

/// `SAMPLE` compressed with `brotli -q 11` (brotli-decompressor has no encoder).
const SAMPLE_BROTLI: [u8; 32] = [
    0x1f, 0x2f, 0x00, 0xf8, 0x8d, 0x94, 0xa9, 0xe3, 0x5b, 0x83, 0x88, 0x8d, 0xcd, 0x69, 0x96, 0x32,
    0xba, 0x3c, 0x39, 0x08, 0x30, 0xfc, 0x24, 0x0a, 0xae, 0xbc, 0xd3, 0xe8, 0xd2, 0xe0, 0x39, 0x04,
];

fn sample_zlib() -> Vec<u8> {
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(SAMPLE).unwrap();
    enc.finish().unwrap()
}

fn sample_zstd() -> Vec<u8> {
    ruzstd::encoding::compress_to_vec(SAMPLE, ruzstd::encoding::CompressionLevel::Fastest)
}

fn check_decompressor(d: &dyn rustls::compress::CertDecompressor, compressed: &[u8]) {
    let mut out = vec![0u8; SAMPLE.len()];
    d.decompress(compressed, &mut out).unwrap();
    assert_eq!(out, SAMPLE, "{:?}", d.algorithm());

    // The declared length must match exactly.
    let mut short = vec![0u8; SAMPLE.len() - 1];
    assert!(d.decompress(compressed, &mut short).is_err(), "{:?}: excess", d.algorithm());
    let mut long = vec![0u8; SAMPLE.len() + 1];
    assert!(d.decompress(compressed, &mut long).is_err(), "{:?}: shortfall", d.algorithm());
    // Garbage input fails instead of panicking.
    let mut out = vec![0u8; SAMPLE.len()];
    assert!(d.decompress(&[0xff; 16], &mut out).is_err(), "{:?}: garbage", d.algorithm());
}

#[test]
fn decompressors_round_trip_exact_length() {
    check_decompressor(&ZLIB, &sample_zlib());
    check_decompressor(&BROTLI, &SAMPLE_BROTLI);
    check_decompressor(&ZSTD, &sample_zstd());
    assert_eq!(ZLIB.algorithm(), CertificateCompressionAlgorithm::Zlib);
    assert_eq!(BROTLI.algorithm(), CertificateCompressionAlgorithm::Brotli);
    assert_eq!(ZSTD.algorithm(), CertificateCompressionAlgorithm::Zstd);
}

// ── Loopback handshakes through the production builder ──────────────────────

/// One self-signed `localhost` identity for every loopback test in this process: the
/// builder trusts it through the process-global test-root override
/// (`crate::tls::install_test_tls_root`), so all installs write the same root and
/// concurrent tests cannot replace each other's.
fn shared_identity() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    static IDENTITY: OnceLock<(CertificateDer<'static>, Vec<u8>)> = OnceLock::new();
    let (cert, key) = IDENTITY.get_or_init(|| {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        (CertificateDer::from(cert.cert.der().to_vec()), cert.signing_key.serialize_der())
    });
    crate::tls::install_test_tls_root(cert.clone());
    (cert.clone(), PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.clone())))
}

/// Handshakes the production QUIC TLS config of `fp` (roots from the test override)
/// with our quinn/rustls server, using the profile's transport and endpoint config,
/// and echoes one message over a bidi stream.
async fn handshake_and_echo(fp: TlsFingerprint) {
    let (cert, key) = shared_identity();
    let lb = loopback::Loopback::with_identity(rustls::ServerConfig::builder(), cert, key);
    let server = lb.server.clone();
    let echo = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        let msg = recv.read_to_end(64).await.unwrap();
        send.write_all(&msg).await.unwrap();
        send.finish().unwrap();
        conn.closed().await
    });

    // Uncached: another test may have cached a config built before the override.
    let tls = crate::tls::build_quic_client_config_uncached(Some(fp), &[b"h3"]);
    let quic = Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from((*tls).clone()).unwrap());
    let tp = super::super::tp_profile::for_fingerprint(Some(fp));
    let transport = super::super::tls_config::build_h3_transport(
        tp,
        super::super::tls_config::RuntimeWindows::current(tp),
    );
    let (_ep, conn) = lb.connect_with_tls(quic, tp.endpoint_config(), transport).await;

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(b"ping").await.unwrap();
    send.finish().unwrap();
    assert_eq!(recv.read_to_end(64).await.unwrap(), b"ping", "{fp:?}");
    assert_eq!(conn.close_reason(), None, "{fp:?}");
    let alpn = conn
        .handshake_data()
        .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|d| d.protocol);
    assert_eq!(alpn.as_deref(), Some(&b"h3"[..]), "{fp:?}");
    conn.close(0u32.into(), b"done");
    echo.abort();
}

#[tokio::test]
async fn chromium_profile_handshakes_with_our_server() {
    handshake_and_echo(TlsFingerprint::Chromium).await;
}

#[tokio::test]
async fn safari_profile_handshakes_with_our_server() {
    handshake_and_echo(TlsFingerprint::Safari).await;
}

#[tokio::test]
async fn firefox_profile_handshakes_with_our_server() {
    handshake_and_echo(TlsFingerprint::Firefox).await;
}
