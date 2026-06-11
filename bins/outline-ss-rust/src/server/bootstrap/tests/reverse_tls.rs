use super::{CERT_PIN_LEN, cert_fingerprint, parse_cert_pin};

use base64::Engine;
use rustls::pki_types::CertificateDer;

const PIN: [u8; CERT_PIN_LEN] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
];

#[test]
fn parses_plain_hex() {
    let hex: String = PIN.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(parse_cert_pin(&hex).unwrap(), PIN);
}

#[test]
fn parses_uppercase_and_colon_hex() {
    let hex: String = PIN.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":");
    assert_eq!(parse_cert_pin(&hex).unwrap(), PIN);
}

#[test]
fn parses_base64_padded_and_unpadded() {
    let padded = base64::engine::general_purpose::STANDARD.encode(PIN);
    let unpadded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(PIN);
    assert_eq!(parse_cert_pin(&padded).unwrap(), PIN);
    assert_eq!(parse_cert_pin(&unpadded).unwrap(), PIN);
}

#[test]
fn rejects_wrong_length_and_garbage() {
    assert!(parse_cert_pin("deadbeef").is_err());
    assert!(parse_cert_pin("not a pin at all").is_err());
    // 31 bytes of base64 — wrong decoded length.
    let short = base64::engine::general_purpose::STANDARD.encode([0u8; 31]);
    assert!(parse_cert_pin(&short).is_err());
}

#[test]
fn fingerprint_is_deterministic_sha256() {
    let der = CertificateDer::from(b"fake-cert-bytes".to_vec());
    let fp = cert_fingerprint(&der);
    assert_eq!(fp, cert_fingerprint(&der));
    // Known SHA-256 of "fake-cert-bytes" can round-trip through the pin parser.
    let hex: String = fp.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(parse_cert_pin(&hex).unwrap(), fp);
}
