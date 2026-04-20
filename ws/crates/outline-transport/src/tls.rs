//! Shared rustls `ClientConfig` builder used by HTTP/2 and HTTP/3 transports.
//!
//! Both transports want the same webpki root store and no client auth; they
//! only differ in the ALPN protocol they advertise. Centralising the builder
//! avoids drift if we ever need to, e.g., add a custom certificate verifier
//! or tweak crypto settings — it only has to happen in one place.

use std::sync::Arc;

use rustls::{ClientConfig, RootCertStore};
use webpki_roots::TLS_SERVER_ROOTS;

/// Build a rustls `ClientConfig` with the webpki root store, no client auth,
/// and the given ALPN protocol list (order = preference).
pub(crate) fn build_client_config(alpn_protocols: &[&[u8]]) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn_protocols.iter().map(|p| p.to_vec()).collect();
    Arc::new(config)
}
