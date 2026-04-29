//! Shared rustls `ClientConfig` builder used by HTTP/2 and HTTP/3 transports.
//!
//! Both transports want the same webpki root store and no client auth; they
//! only differ in the ALPN protocol they advertise. Centralising the builder
//! avoids drift if we ever need to, e.g., add a custom certificate verifier
//! or tweak crypto settings — it only has to happen in one place.
//!
//! A test-only override slot lives below: cross-repo integration tests
//! (`outline-ss-rust/tests`) generate a self-signed cert for an in-process
//! server, install it via [`install_test_tls_root`], and the XHTTP h2 / h3
//! dial paths pick that root store up instead of the production webpki one.

use std::sync::{Arc, RwLock};

use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};
use webpki_roots::TLS_SERVER_ROOTS;

/// Build a rustls `ClientConfig` with the webpki root store, no client auth,
/// and the given ALPN protocol list (order = preference).
pub(crate) fn build_client_config(alpn_protocols: &[&[u8]]) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(TLS_SERVER_ROOTS.iter().cloned());
    build_client_config_with_roots(roots, alpn_protocols)
}

/// Same as [`build_client_config`] but with a caller-supplied root store.
/// Used by the test override path so cross-repo integration tests can
/// pin a self-signed root without touching the global webpki list.
fn build_client_config_with_roots(
    roots: RootCertStore,
    alpn_protocols: &[&[u8]],
) -> Arc<ClientConfig> {
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn_protocols.iter().map(|p| p.to_vec()).collect();
    Arc::new(config)
}

#[derive(Clone)]
struct TestTlsConfigs {
    h2: Arc<ClientConfig>,
    h3: Arc<ClientConfig>,
}

/// Process-wide override slot used by the XHTTP h2 / h3 dial paths.
/// `None` (the default) means production webpki. `Some` is set by
/// [`install_test_tls_root`] for in-process integration tests.
/// `RwLock` (not `OnceLock`) so a test fixture can replace the cert
/// across repeated runs in the same `cargo test` binary.
static TEST_TLS_OVERRIDE: RwLock<Option<TestTlsConfigs>> = RwLock::new(None);

/// Replace the XHTTP TLS roots with a single caller-supplied DER
/// certificate. Subsequent calls to [`xhttp_h2_tls_config`] /
/// [`xhttp_h3_tls_config`] return configs trusting only that root.
///
/// Intended exclusively for cross-repo integration tests in
/// `outline-ss-rust` (and any future fixture that brings up a
/// self-signed in-process server). Production callers should leave
/// the override unset so dials fall back to the system webpki list.
///
/// Calls are idempotent and last-writer-wins; the override applies
/// to all subsequent dials in the current process.
pub fn install_test_tls_root(cert_der: CertificateDer<'static>) {
    let mut roots = RootCertStore::empty();
    roots
        .add(cert_der)
        .expect("install_test_tls_root: cert must parse as DER");
    let h2 = build_client_config_with_roots(roots.clone(), &[b"h2"]);
    let h3 = build_client_config_with_roots(roots, &[b"h3"]);
    *TEST_TLS_OVERRIDE
        .write()
        .expect("install_test_tls_root: override lock poisoned") = Some(TestTlsConfigs { h2, h3 });
}

/// Returns the current test override for h2, if any. The XHTTP h2
/// dial path consults this before falling back to the cached
/// production config.
pub(crate) fn xhttp_h2_test_override() -> Option<Arc<ClientConfig>> {
    TEST_TLS_OVERRIDE
        .read()
        .ok()
        .and_then(|guard| guard.as_ref().map(|c| Arc::clone(&c.h2)))
}

/// Returns the current test override for h3, if any.
pub(crate) fn xhttp_h3_test_override() -> Option<Arc<ClientConfig>> {
    TEST_TLS_OVERRIDE
        .read()
        .ok()
        .and_then(|guard| guard.as_ref().map(|c| Arc::clone(&c.h3)))
}
