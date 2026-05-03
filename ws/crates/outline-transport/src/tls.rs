//! Shared rustls `ClientConfig` builder used by HTTP/2, HTTP/3, and
//! raw QUIC (VLESS / SS) transports.
//!
//! Each transport advertises its own ALPN list but shares the same
//! webpki root store and no-client-auth setup; centralising the
//! builder avoids drift if we ever need to, e.g., add a custom
//! certificate verifier or tweak crypto settings — it only has to
//! happen in one place.
//!
//! A test-only override slot lives below: cross-repo integration
//! tests (`outline-ss-rust/tests`) generate a self-signed cert for
//! an in-process server, install it via [`install_test_tls_root`],
//! and every subsequent `build_client_config` call (XHTTP h2/h3,
//! WS h2/h3, raw QUIC vless / ss) trusts that root instead of the
//! production webpki list. The override is consulted on each call,
//! so adding a new ALPN-aware caller doesn't need bespoke wiring.

use std::sync::{Arc, RwLock};

#[cfg(any(test, feature = "test-tls"))]
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};
use webpki_roots::TLS_SERVER_ROOTS;

/// Build a rustls `ClientConfig` with no client auth and the given
/// ALPN protocol list (order = preference). Roots come from the
/// process-wide test override if [`install_test_tls_root`] has
/// populated it, otherwise from the system webpki bundle.
pub(crate) fn build_client_config(alpn_protocols: &[&[u8]]) -> Arc<ClientConfig> {
    if let Some(override_roots) = test_override_roots() {
        return build_client_config_with_roots((*override_roots).clone(), alpn_protocols);
    }
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

/// Process-wide override slot consulted by [`build_client_config`].
/// `None` (the default) means production webpki. `Some` is set by
/// [`install_test_tls_root`] for in-process integration tests.
/// `RwLock` (not `OnceLock`) so a test fixture can replace the cert
/// across repeated runs in the same `cargo test` binary.
static TEST_TLS_OVERRIDE_ROOTS: RwLock<Option<Arc<RootCertStore>>> = RwLock::new(None);

/// Replace the TLS roots used by every XHTTP / WS / raw-QUIC dial
/// in this process with a single caller-supplied DER certificate.
/// Subsequent [`build_client_config`] calls trust only that root.
///
/// Intended exclusively for cross-repo integration tests in
/// `outline-ss-rust` (and any future fixture that brings up a
/// self-signed in-process server). Gated behind the `test-tls` Cargo
/// feature; production builds omit the symbol entirely so dials always
/// fall back to the system webpki list.
///
/// Calls are idempotent and last-writer-wins; the override applies
/// to all subsequent dials in the current process. ALPN-cached
/// configs (e.g. `XHTTP_H3_TLS_CONFIG`) capture the override on
/// their first build, so install before the first dial.
#[cfg(any(test, feature = "test-tls"))]
pub fn install_test_tls_root(cert_der: CertificateDer<'static>) {
    let mut roots = RootCertStore::empty();
    roots
        .add(cert_der)
        .expect("install_test_tls_root: cert must parse as DER");
    *TEST_TLS_OVERRIDE_ROOTS
        .write()
        .expect("install_test_tls_root: override lock poisoned") = Some(Arc::new(roots));
}

fn test_override_roots() -> Option<Arc<RootCertStore>> {
    TEST_TLS_OVERRIDE_ROOTS
        .read()
        .ok()
        .and_then(|guard| guard.clone())
}

/// Test-mode probe used by transports that maintain process-wide
/// runtime-bound caches (the shared QUIC endpoint, e.g.). When the
/// test override is set, the shared endpoint's driver task is bound
/// to the current `#[tokio::test]` runtime and will not survive the
/// next test, so callers must skip the cache and bind a fresh
/// endpoint each dial.
pub(crate) fn test_mode_active() -> bool {
    TEST_TLS_OVERRIDE_ROOTS
        .read()
        .map(|guard| guard.is_some())
        .unwrap_or(false)
}
