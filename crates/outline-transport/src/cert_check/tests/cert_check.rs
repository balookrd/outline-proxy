//! Unit tests for the cert-expiry parser and accept-any TLS config.

use super::{accept_any_client_config, leaf_not_after_unix_ms};

/// DER of a self-signed P-256 certificate (`CN=cert-check-fixture.test`)
/// generated with a fixed validity window:
///
/// ```text
/// openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
///   -nodes -days 36500 -subj "/CN=cert-check-fixture.test" | \
/// openssl x509 -outform DER -out fixture_cert.der
/// ```
///
/// notAfter = 2126-05-09 15:45:52 UTC = 4_934_015_152 s.
const FIXTURE_DER: &[u8] = include_bytes!("fixture_cert.der");
const FIXTURE_NOT_AFTER_MS: u64 = 4_934_015_152_000;

#[test]
fn parses_not_after_from_fixture() {
    let ms = leaf_not_after_unix_ms(FIXTURE_DER).expect("fixture must parse");
    assert_eq!(ms, FIXTURE_NOT_AFTER_MS);
}

#[test]
fn rejects_non_certificate_bytes() {
    assert!(leaf_not_after_unix_ms(b"not a certificate at all").is_err());
    assert!(leaf_not_after_unix_ms(&[]).is_err());
}

#[test]
fn accept_any_config_builds() {
    // Building the accept-any client config must not panic: ring provider,
    // safe default protocol versions, and the custom verifier wired in.
    let cfg = accept_any_client_config();
    assert!(!cfg.alpn_protocols.iter().any(|p| p.is_empty()));
}
