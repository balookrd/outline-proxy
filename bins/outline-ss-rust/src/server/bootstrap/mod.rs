mod axum;
mod cert_pin;
mod cert_reload;
mod tls;

#[cfg(test)]
pub(in crate::server) use axum::TestTlsHandshakeTimeout;
// Only the control/dashboard listeners reach `serve_plain_listener` through
// this re-export (the plain/metrics listeners call it from within `axum`), and
// only their tests need the timeout override — both live behind `control`.
#[cfg(all(test, feature = "control"))]
pub(in crate::server) use axum::TestHttpHeaderReadTimeout;
#[cfg(test)]
pub(super) use axum::serve_listener;
#[cfg(feature = "control")]
pub(in crate::server) use axum::serve_plain_listener;
pub(super) use axum::{build_app, build_metrics_app, serve_metrics_listener, serve_tcp_listener};
pub(in crate::server) use cert_pin::{CERT_PIN_LEN, cert_fingerprint};
pub(super) use cert_reload::{h3_cert_paths, spawn_cert_reloader};
pub(super) use tls::{ensure_rustls_provider_installed, load_h3_tls_config};
