#![allow(dead_code)]
//! Self-signed CA + leaf generation for the TLS / H3 / raw-QUIC e2e tests.
//! Compiled only under the `test-tls` feature (the client binary's matching
//! hook trusts the CA via `OUTLINE_WS_TEST_TLS_CA_DER`).
//!
//! Follows the proven pattern in `bins/outline-ss-rust/src/server/tests/mod.rs`
//! (`cross_repo_shared_test_cert`): a real CA (so webpki accepts it as a trust
//! root) signs a leaf whose SANs include both `localhost` and the `127.0.0.1`
//! IP — letting cleartext and TLS dials share the `127.0.0.1` host.

use std::fs;
use std::path::{Path, PathBuf};

type BoxError = Box<dyn std::error::Error>;

/// Paths to the generated PEM/DER files. `leaf_pem`/`key_pem` go to the
/// server's `[server].cert_path`/`key_path`; `ca_der` is handed to the client
/// via the `OUTLINE_WS_TEST_TLS_CA_DER` env var.
pub struct TlsFixture {
    pub leaf_pem: PathBuf,
    pub key_pem: PathBuf,
    pub ca_der: PathBuf,
}

impl TlsFixture {
    pub fn generate_into(dir: &Path) -> Result<Self, BoxError> {
        // CA: self-signed, marked as a real CA so webpki accepts it as a root.
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new())?;
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "outline-e2e-test-ca");
        let ca_key = rcgen::KeyPair::generate()?;
        let ca_cert = ca_params.self_signed(&ca_key)?;

        // Leaf: SAN = localhost + 127.0.0.1 (IP SAN), signed by the CA above.
        let leaf_params =
            rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])?;
        let leaf_key = rcgen::KeyPair::generate()?;
        let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
        let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer)?;

        let leaf_pem = dir.join("leaf.pem");
        let key_pem = dir.join("key.pem");
        let ca_der = dir.join("ca.der");
        fs::write(&leaf_pem, leaf_cert.pem())?;
        fs::write(&key_pem, leaf_key.serialize_pem())?;
        fs::write(&ca_der, ca_cert.der().as_ref())?;

        Ok(Self { leaf_pem, key_pem, ca_der })
    }
}
