use super::{CERT_PIN_LEN, cert_fingerprint, parse_cert_pin};

use base64::Engine;
use rustls::pki_types::CertificateDer;

const PIN: [u8; CERT_PIN_LEN] = [
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
];

#[test]
fn parses_hex_colon_and_base64() {
    let hex: String = PIN.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(parse_cert_pin(&hex).unwrap(), PIN);
    let colon: String = PIN.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":");
    assert_eq!(parse_cert_pin(&colon).unwrap(), PIN);
    let b64 = base64::engine::general_purpose::STANDARD.encode(PIN);
    assert_eq!(parse_cert_pin(&b64).unwrap(), PIN);
}

#[test]
fn rejects_garbage_and_wrong_length() {
    assert!(parse_cert_pin("deadbeef").is_err());
    assert!(parse_cert_pin("zzzz").is_err());
    let short = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
    assert!(parse_cert_pin(&short).is_err());
}

#[test]
fn fingerprint_round_trips_through_pin_parser() {
    let der = CertificateDer::from(b"another-fake-cert".to_vec());
    let fp = cert_fingerprint(&der);
    assert_eq!(fp, cert_fingerprint(&der));
    let hex: String = fp.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(parse_cert_pin(&hex).unwrap(), fp);
}
