//! Connectivity-only probe: WebSocket handshake. Verifies that the transport
//! layer can be established but does not exercise the tunnelled payload —
//! data-path correctness is covered by the http / dns / tcp_tunnel sub-probes.

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

use crate::config::TransportMode;

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
