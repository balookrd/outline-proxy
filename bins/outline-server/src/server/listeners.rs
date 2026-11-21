//! Binds all network sockets and builds the HTTP/3 endpoint.

use anyhow::{Context, Result};
use tokio::net::TcpListener;

use crate::config::Config;

use super::h3::build_h3_server;
use super::h3::vendored::{H3Transport, H3WebSocketServer};

pub(super) struct Bound {
    pub(super) listener: Option<TcpListener>,
    pub(super) metrics_listener: Option<TcpListener>,
    pub(super) h3_server: Option<H3WebSocketServer<H3Transport>>,
    /// Clone of the QUIC endpoint behind `h3_server`, kept so the cert
    /// reloader can swap the listener's TLS config at runtime via
    /// `set_server_config`. `Some` exactly when `h3_server` is.
    pub(super) h3_endpoint: Option<quinn::Endpoint>,
}

pub(super) async fn bind(config: &Config) -> Result<Bound> {
    let listener = if let Some(listen) = config.listen {
        Some(
            TcpListener::bind(listen)
                .await
                .with_context(|| format!("failed to bind {}", listen))?,
        )
    } else {
        None
    };
    let metrics_listener = if config.metrics_enabled() {
        let metrics_listen = config.metrics_listen.expect("metrics listen must exist");
        Some(
            TcpListener::bind(metrics_listen)
                .await
                .with_context(|| format!("failed to bind metrics listener {}", metrics_listen))?,
        )
    } else {
        None
    };
    let (h3_server, h3_endpoint) = if config.h3_enabled() {
        let (server, endpoint) = build_h3_server(config).await?;
        (Some(server), Some(endpoint))
    } else {
        (None, None)
    };
    Ok(Bound {
        listener,
        metrics_listener,
        h3_server,
        h3_endpoint,
    })
}
