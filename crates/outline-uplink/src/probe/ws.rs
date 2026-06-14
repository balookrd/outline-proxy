//! Connectivity-only probes: WebSocket handshake and raw-QUIC handshake.
//! Each verifies that the transport layer can be established but does not
//! exercise the tunnelled payload — data-path correctness is covered by the
//! http / dns / tcp_tunnel sub-probes.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use futures_util::SinkExt;
use tokio::sync::Semaphore;
use tracing::debug;

use outline_transport::{
    DialNetworkOptions, DnsCache, SsPathKind, TransportDialOptions, TransportOperation,
    connect_transport,
};

use crate::config::{TransportMode, UplinkTransport};

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_ws_probe(
    cache: &DnsCache,
    _group: &str,
    uplink_name: &str,
    transport: &'static str,
    url: &url::Url,
    mode: TransportMode,
    fwmark: Option<u32>,
    combined_ss_kind: Option<SsPathKind>,
    dial_limit: Arc<Semaphore>,
    _pong_timeout: Duration,
) -> Result<Option<TransportMode>> {
    let _permit = dial_limit.acquire_owned().await.expect("probe dial semaphore closed");
    // Verify WebSocket connectivity only — TCP connect + TLS + HTTP upgrade.
    // Many servers do not respond to WebSocket ping control frames (they expect
    // Shadowsocks data immediately), so we do not send a ping here.  The
    // data-path is checked by the http / dns sub-probes that follow.
    let mut ws_stream = connect_transport(
        TransportDialOptions::new(cache, url, mode, "probe_ws")
            .with_network(DialNetworkOptions { fwmark, ipv6_first: false })
            .with_combined_ss_kind(combined_ss_kind),
    )
    .await
    .with_context(|| TransportOperation::Connect {
        target: format!("WebSocket probe to {url}"),
    })?;
    let downgraded_from = ws_stream.downgraded_from();

    debug!(
        uplink = %uplink_name,
        transport,
        probe = "ws",
        url = %url,
        "WebSocket probe connected, closing"
    );
    if let Err(error) = ws_stream.close().await {
        debug!(
            uplink = %uplink_name,
            transport,
            probe = "ws",
            url = %url,
            error = %error,
            "probe websocket close returned error during teardown"
        );
    }
    Ok(downgraded_from)
}

/// Connectivity-only probe over raw QUIC: opens (or reuses) a per-ALPN
/// `quinn::Connection` to the uplink and immediately drops it. Mirrors
/// [`run_ws_probe`] for the `TransportMode::Quic` dispatch path, where
/// there is no WebSocket handshake to verify.
#[cfg(feature = "quic")]
#[allow(clippy::too_many_arguments)]
pub(super) async fn run_quic_handshake_probe(
    cache: &DnsCache,
    uplink_name: &str,
    transport: &'static str,
    url: &url::Url,
    uplink_transport: UplinkTransport,
    fwmark: Option<u32>,
    ipv6_first: bool,
    dial_limit: Arc<Semaphore>,
) -> Result<Option<TransportMode>> {
    let _permit = dial_limit.acquire_owned().await.expect("probe dial semaphore closed");
    let alpn: &'static [u8] = match uplink_transport {
        UplinkTransport::Vless => outline_transport::quic::ALPN_VLESS,
        UplinkTransport::Ss => outline_transport::quic::ALPN_SS,
    };
    let _conn = outline_transport::quic::connect_quic_uplink(
        cache,
        url,
        fwmark,
        ipv6_first,
        "probe_quic",
        alpn,
    )
    .await
    .with_context(|| TransportOperation::Connect {
        target: format!("raw-QUIC probe to {url}"),
    })?;
    debug!(
        uplink = %uplink_name,
        transport,
        probe = "quic",
        url = %url,
        "raw-QUIC probe connected, releasing"
    );
    // Raw QUIC bypasses the WS layer entirely; no `ws_mode_cache` clamp
    // can apply here, so we never report a downgrade from this probe.
    Ok(None)
}

#[cfg(not(feature = "quic"))]
#[allow(clippy::too_many_arguments)]
pub(super) async fn run_quic_handshake_probe(
    _cache: &DnsCache,
    _uplink_name: &str,
    _transport: &'static str,
    _url: &url::Url,
    _uplink_transport: UplinkTransport,
    _fwmark: Option<u32>,
    _ipv6_first: bool,
    _dial_limit: Arc<Semaphore>,
) -> Result<Option<TransportMode>> {
    Err(anyhow::anyhow!(
        "TransportMode::Quic requested but binary was built without the `quic` feature"
    ))
}
