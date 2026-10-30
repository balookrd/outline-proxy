//! Shared ClientHello machinery: certificate decompressors and the wire-cipher check.

use std::io::Write;

use rustls::CertificateCompressionAlgorithm;
use rustls::compress::CertDecompressor;

use super::*;

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

#[test]
fn wire_cipher_suites_must_cover_the_provider() {
    let base = crate::tcp_tls_profile::CHROMIUM;
    assert_eq!(base.check_wire_cipher_suites(), Ok(()));
    let neutral = HelloProfile { wire_cipher_suites: &[], ..base };
    assert_eq!(neutral.check_wire_cipher_suites(), Ok(()));
    let missing = HelloProfile {
        wire_cipher_suites: &[CipherSuite::TLS13_AES_128_GCM_SHA256],
        ..base
    };
    assert_eq!(missing.check_wire_cipher_suites(), Err(CipherSuite::TLS13_AES_256_GCM_SHA384));
}
