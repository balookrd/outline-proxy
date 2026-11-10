//! Shared rustls `ClientConfig` builders, both browser-shaped: one for the TCP TLS
//! carriers (HTTP/1.1, HTTP/2) and the probe ([`crate::tcp_tls_profile`]), one for the
//! QUIC (HTTP/3) carrier (`crate::quic::tls_profile`). Both build through
//! [`crate::tls_hello::build_shaped_client_config`], so the ClientHello follows the
//! dial's browser (Chromium when no dial fingerprint is set). Both configs negotiate
//! TLS 1.3 only; the TCP ClientHello still advertises TLS 1.2, as the browsers do.
//!
//! Each transport advertises its own ALPN list but shares the same
//! webpki root store and no-client-auth setup.
//!
//! A test-only override slot lives below: cross-repo integration
//! tests (`outline-ss-rust/tests`) generate a self-signed cert for
//! an in-process server, install it via [`install_test_tls_root`],
//! and every subsequent `build_client_config` call (XHTTP h2/h3,
//! WS h2/h3) trusts that root instead of the
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
use crate::tls_hello;

/// Cache of built client configs keyed by `(tls fingerprint, ALPN list)`.
/// The fingerprint is the dial-scoped value set by
/// [`crate::fingerprint_profile::with_dial_profile`]; `None` (no active
/// scope — probes, tests) builds the Chromium profile.
/// Builds are rare (one per distinct key, ever), so a single mutex is fine.
///
/// An entry lives for the whole process, and with it the session-ticket store
/// inside the `ClientConfig`: a ticket is offered for as long as the server
/// that issued it says it is valid, the way a browser resumes. The configs
/// used to be rebuilt every ten minutes to drop the tickets, on the grounds
/// that two connections more than that apart could then not be linked by
/// ticket. They are linked anyway — same source address, same SNI — while the
/// rebuild made every dial after the cut-over a full handshake, however
/// recently the client had talked to that server. No browser does that.
type ClientConfigKey = (Option<TlsFingerprint>, Vec<Vec<u8>>);
static CLIENT_CONFIG_CACHE: OnceLock<Mutex<HashMap<ClientConfigKey, Arc<ClientConfig>>>> =
    OnceLock::new();

/// Build (or return a cached) rustls `ClientConfig` with no client auth and
/// the given ALPN protocol list (order = preference), whose ClientHello is that of
/// the dial-scoped [`TlsFingerprint`]'s browser over TCP
/// ([`crate::tcp_tls_profile::for_fingerprint`]; Chromium without a scope).
/// Roots come from the process-wide test override if [`install_test_tls_root`]
/// populated it, otherwise from the system webpki bundle.
pub(crate) fn build_client_config(alpn_protocols: &[&[u8]]) -> Arc<ClientConfig> {
    build_client_config_for(crate::fingerprint_profile::current_dial_fingerprint(), alpn_protocols)
}

/// [`build_client_config`] for an explicit fingerprint instead of the dial scope's.
pub(crate) fn build_client_config_for(
    fp: Option<TlsFingerprint>,
    alpn_protocols: &[&[u8]],
) -> Arc<ClientConfig> {
    let cache = CLIENT_CONFIG_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let key: ClientConfigKey = (fp, alpn_protocols.iter().map(|p| p.to_vec()).collect());
    Arc::clone(
        cache
            .lock()
            .entry(key)
            .or_insert_with(|| build_client_config_uncached(fp, alpn_protocols)),
    )
}

/// Public wrapper used by the HTTPS data-path probe, which lives outside this crate.
/// The ClientHello follows the browser profile the dial path would pick for `url`
/// ([`crate::fingerprint_profile::select`]; Chromium when no strategy is set), so the
/// probe looks like the carrier dials to the same host. Same root store and
/// test-override behaviour as [`build_client_config`]. ALPN controls what the probe
/// handshake advertises (typical caller passes `[b"h2", b"http/1.1"]`).
pub fn build_https_probe_client_config(
    url: &url::Url,
    alpn_protocols: &[&[u8]],
) -> Arc<ClientConfig> {
    build_https_probe_client_config_for(
        crate::fingerprint_profile::select(url).map(|p| p.tls),
        alpn_protocols,
    )
}

/// [`build_https_probe_client_config`] for a probe target given as `host:port`. A target
/// that does not form a URL (and so cannot drive profile selection) still gets the
/// Chromium hello, the same fallback the certificate check uses, instead of failing.
pub fn build_https_probe_client_config_for_target(
    host: &str,
    port: u16,
    alpn_protocols: &[&[u8]],
) -> Arc<ClientConfig> {
    match https_url(host, port) {
        Ok(url) => build_https_probe_client_config(&url, alpn_protocols),
        Err(_) => build_https_probe_client_config_for(None, alpn_protocols),
    }
}

/// `https://{host}:{port}/` with an IPv6 literal bracketed, for profile selection by
/// the probes.
pub fn https_url(host: &str, port: u16) -> Result<url::Url, url::ParseError> {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        url::Url::parse(&format!("https://[{host}]:{port}/"))
    } else {
        url::Url::parse(&format!("https://{host}:{port}/"))
    }
}

/// [`build_https_probe_client_config`] for an explicit fingerprint.
pub(crate) fn build_https_probe_client_config_for(
    fp: Option<TlsFingerprint>,
    alpn_protocols: &[&[u8]],
) -> Arc<ClientConfig> {
    build_client_config_for(fp, alpn_protocols)
}

/// Builds a fresh `ClientConfig` for `(fp, alpn)`, bypassing the cache: the TCP
/// browser profile of `fp`, roots from the test override when installed, else the
/// system webpki list.
fn build_client_config_uncached(
    fp: Option<TlsFingerprint>,
    alpn_protocols: &[&[u8]],
) -> Arc<ClientConfig> {
    let profile = crate::tcp_tls_profile::for_fingerprint(fp);
    tls_hello::build_shaped_client_config(
        profile,
        alpn_protocols,
        tls_hello::webpki_verifier(profile),
    )
}

/// Cache of browser-shaped QUIC configs, keyed and kept like [`CLIENT_CONFIG_CACHE`].
#[cfg(feature = "quic")]
static QUIC_CLIENT_CONFIG_CACHE: OnceLock<Mutex<HashMap<ClientConfigKey, Arc<ClientConfig>>>> =
    OnceLock::new();

/// Build (or return a cached) TLS 1.3 `ClientConfig` for a QUIC dial whose ClientHello
/// matches the browser of `fp` ([`crate::quic::tls_profile`]; `None` = Chromium, as the
/// QUIC transport parameters). Only for QUIC: browsers' TCP ClientHellos differ, so
/// [`build_client_config`] uses the TCP profiles. Roots and the session-ticket lifetime
/// are those of [`build_client_config`].
#[cfg(feature = "quic")]
pub(crate) fn build_quic_client_config(
    fp: Option<TlsFingerprint>,
    alpn_protocols: &[&[u8]],
) -> Arc<ClientConfig> {
    let cache = QUIC_CLIENT_CONFIG_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let key: ClientConfigKey = (fp, alpn_protocols.iter().map(|p| p.to_vec()).collect());
    Arc::clone(
        cache
            .lock()
            .entry(key)
            .or_insert_with(|| build_quic_client_config_uncached(fp, alpn_protocols)),
    )
}

/// [`build_quic_client_config`] without the cache.
#[cfg(feature = "quic")]
pub(crate) fn build_quic_client_config_uncached(
    fp: Option<TlsFingerprint>,
    alpn_protocols: &[&[u8]],
) -> Arc<ClientConfig> {
    let profile = crate::quic::tls_profile::for_fingerprint(fp);
    tls_hello::build_shaped_client_config(
        profile,
        alpn_protocols,
        tls_hello::webpki_verifier(profile),
    )
}

/// Roots for every client config: the test override when installed, else webpki.
pub(crate) fn roots() -> RootCertStore {
    match test_override_roots() {
        Some(override_roots) => (*override_roots).clone(),
        None => {
            let mut roots = RootCertStore::empty();
            roots.extend(TLS_SERVER_ROOTS.iter().cloned());
            roots
        },
    }
}

/// Process-wide override slot consulted by [`build_client_config`].
/// `None` (the default) means production webpki. `Some` is set by
/// [`install_test_tls_root`] for in-process integration tests.
/// `RwLock` (not `OnceLock`) so a test fixture can replace the cert
/// across repeated runs in the same `cargo test` binary.
static TEST_TLS_OVERRIDE_ROOTS: RwLock<Option<Arc<RootCertStore>>> = RwLock::new(None);

/// Replace the TLS roots used by every XHTTP / WS / H3 dial
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

#[cfg(test)]
#[path = "tests/tls.rs"]
mod tests;
