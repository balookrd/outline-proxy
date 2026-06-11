//! Binds all network sockets and builds the HTTP/3 endpoint.

use std::sync::Arc;

use anyhow::{Context, Result};
use sockudo_ws::{Http3 as H3Transport, WebSocketServer as H3WebSocketServer};
use tokio::net::{TcpListener, UdpSocket};

use crate::config::Config;

use super::h3::build_h3_server;

pub(super) struct Bound {
    pub(super) listener: Option<TcpListener>,
    pub(super) ss_tcp_listener: Option<TcpListener>,
    pub(super) ss_udp_socket: Option<Arc<UdpSocket>>,
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
    let ss_tcp_listener =
        if let Some(ss_listen) = config.ss_listen {
            Some(TcpListener::bind(ss_listen).await.with_context(|| {
                format!("failed to bind shadowsocks tcp listener {}", ss_listen)
            })?)
        } else {
            None
        };
    let ss_udp_socket = if let Some(ss_listen) = config.ss_listen {
        Some(Arc::new(UdpSocket::bind(ss_listen).await.with_context(|| {
            format!("failed to bind shadowsocks udp socket {}", ss_listen)
        })?))
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
        ss_tcp_listener,
        ss_udp_socket,
        metrics_listener,
        h3_server,
        h3_endpoint,
    })
}
