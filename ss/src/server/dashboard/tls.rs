//! TLS client used by the dashboard proxy to reach HTTPS control-API instances.

use std::sync::Arc;

use rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

pub(super) fn connector() -> TlsConnector {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}
