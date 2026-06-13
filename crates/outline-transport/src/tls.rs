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

use std::sync::{Arc, OnceLock, RwLock};

use hashbrown::HashMap;
use parking_lot::Mutex;
#[cfg(any(test, feature = "test-tls"))]
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};
use webpki_roots::TLS_SERVER_ROOTS;

use crate::fingerprint_profile::TlsFingerprint;

/// Cache of built client configs keyed by `(tls fingerprint, ALPN list)`.
/// The fingerprint is the dial-scoped value set by
/// [`crate::fingerprint_profile::with_dial_fingerprint`]; `None` (no active
/// scope — probes, raw-QUIC, tests) reproduces the pre-fingerprint default
/// provider and the exact wire shape builds had before this knob landed.
/// Builds are rare (one per distinct key, ever), so a single mutex is fine.
type ClientConfigKey = (Option<TlsFingerprint>, Vec<Vec<u8>>);
static CLIENT_CONFIG_CACHE: OnceLock<Mutex<HashMap<ClientConfigKey, Arc<ClientConfig>>>> =
    OnceLock::new();

/// Build (or return a cached) rustls `ClientConfig` with no client auth and
/// the given ALPN protocol list (order = preference). When a dial-scoped
/// [`TlsFingerprint`] is in effect the ClientHello cipher / kx order is
/// swapped to mimic that browser family (see [`crate::tls_fingerprint`]);
/// otherwise rustls's default provider is used, byte-for-byte as before.
/// Roots come from the process-wide test override if [`install_test_tls_root`]
/// populated it, otherwise from the system webpki bundle.
pub(crate) fn build_client_config(alpn_protocols: &[&[u8]]) -> Arc<ClientConfig> {
    let fp = crate::fingerprint_profile::current_dial_fingerprint();
    let cache = CLIENT_CONFIG_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let key: ClientConfigKey = (fp, alpn_protocols.iter().map(|p| p.to_vec()).collect());
    let mut guard = cache.lock();
    if let Some(existing) = guard.get(&key) {
        return Arc::clone(existing);
    }
    let config = build_client_config_uncached(fp, alpn_protocols);
    guard.insert(key, Arc::clone(&config));
    config
}

/// Public wrapper over [`build_client_config`] used by the HTTPS data-path
/// probe. Sibling to the existing transport callers, with the same root
/// store and test-override behaviour — separated only because probe code
/// lives outside this crate and would otherwise reach into a `pub(crate)`
/// helper. Probes run outside any dial scope, so the fingerprint is `None`
/// and the default provider is used. ALPN list controls what the probe
/// handshake advertises (typical caller passes `[b"h2", b"http/1.1"]`).
pub fn build_https_probe_client_config(alpn_protocols: &[&[u8]]) -> Arc<ClientConfig> {
    build_client_config(alpn_protocols)
}

/// Builds a fresh `ClientConfig` for `(fp, alpn)`, bypassing the cache.
/// `fp = Some(_)` selects the family-specific cipher / kx provider via
/// [`crate::tls_fingerprint::provider_for`]; `None` keeps rustls's default
/// provider (the exact builder used before the fingerprint knob). Roots are
/// the test override when installed, else the system webpki list.
fn build_client_config_uncached(
    fp: Option<TlsFingerprint>,
    alpn_protocols: &[&[u8]],
) -> Arc<ClientConfig> {
    let roots = match test_override_roots() {
        Some(override_roots) => (*override_roots).clone(),
        None => {
            let mut roots = RootCertStore::empty();
            roots.extend(TLS_SERVER_ROOTS.iter().cloned());
            roots
        },
    };
    let mut config = match fp {
        Some(fp) => ClientConfig::builder_with_provider(crate::tls_fingerprint::provider_for(fp))
            .with_safe_default_protocol_versions()
            .expect("ring provider supports TLS 1.2 + 1.3")
            .with_root_certificates(roots)
            .with_no_client_auth(),
        None => ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    };
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
/// to all subsequent dials in the current process. The
/// `(fingerprint, ALPN)` config cache captures the override on its
/// first build per key, so install before the first dial.
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
    TEST_TLS_OVERRIDE_ROOTS.read().ok().and_then(|guard| guard.clone())
}

/// Test-mode probe used by transports that maintain process-wide
/// runtime-bound caches (the shared QUIC endpoint, e.g.). When the
/// test override is set, the shared endpoint's driver task is bound
/// to the current `#[tokio::test]` runtime and will not survive the
/// next test, so callers must skip the cache and bind a fresh
/// endpoint each dial.
///
/// Gated behind `quic`: every caller lives in the QUIC/H3 modules
/// (`h3` implies `quic`), so non-QUIC builds (router) would
/// otherwise carry dead code.
#[cfg(feature = "quic")]
pub(crate) fn test_mode_active() -> bool {
    TEST_TLS_OVERRIDE_ROOTS
        .read()
        .map(|guard| guard.is_some())
        .unwrap_or(false)
}
