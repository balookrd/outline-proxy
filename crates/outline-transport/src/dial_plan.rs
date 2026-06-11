use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use tokio::time::timeout;
use tokio_tungstenite::client_async_tls;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tracing::{debug, warn};
use url::Url;

#[cfg(feature = "h3")]
use crate::h3::connect_websocket_h3;
use crate::{
    DnsCache, SessionId, TransportMode, TransportOperation, TransportStream, connect_tcp_socket,
    h2::connect_websocket_h2, ws_mode_cache, ws_stream::H1WsStream, xhttp_mode_cache,
};

// Upper bound for the HTTP/1.1 WebSocket handshake (TCP connect + TLS +
// HTTP upgrade). Unlike h2/h3 there is no shared pool to get stuck in, but
// `TcpStream::connect` is bounded only by the OS SYN-retransmit budget
// (Linux ~127s, macOS ~75s), and `client_async_tls` has no timeout of its
// own. Without a bound here the fallback chain h3 -> h2 -> h1 could stall
// for minutes when the server is in a network black hole, before
// `report_runtime_failure` gets a chance to mark the uplink down.
const HTTP1_WS_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Socket-level knobs shared by every HTTP-family dial branch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DialNetworkOptions {
    pub fwmark: Option<u32>,
    pub ipv6_first: bool,
}

/// Cross-transport resumption and retry-negotiation headers for a dial.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DialResumeOptions {
    pub resume_request: Option<SessionId>,
    pub ack_prefix_requested: bool,
    pub symmetric_replay_requested: bool,
    pub client_acked_offset: u64,
}

/// Complete input to the HTTP-family transport dial planner.
#[derive(Clone, Copy)]
pub struct TransportDialOptions<'a> {
    pub cache: &'a DnsCache,
    pub url: &'a Url,
    pub mode: TransportMode,
    pub source: &'static str,
    pub network: DialNetworkOptions,
    pub resume: DialResumeOptions,
}

impl<'a> TransportDialOptions<'a> {
    pub fn new(
        cache: &'a DnsCache,
        url: &'a Url,
        mode: TransportMode,
        source: &'static str,
    ) -> Self {
        Self {
            cache,
            url,
            mode,
            source,
            network: DialNetworkOptions::default(),
            resume: DialResumeOptions::default(),
        }
    }

    pub fn with_network(mut self, network: DialNetworkOptions) -> Self {
        self.network = network;
        self
    }

    pub fn with_resume(mut self, resume: DialResumeOptions) -> Self {
        self.resume = resume;
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DialPlan {
    requested: TransportMode,
    selected: TransportMode,
}

impl DialPlan {
    async fn resolve(options: &TransportDialOptions<'_>) -> Self {
        let requested = options.mode;
        // Two independent per-host caches are queried here: the WS one
        // governs `WsH3 -> WsH2 -> WsH1`, the XHTTP one governs
        // `XhttpH3 -> XhttpH2 -> XhttpH1`. Each is a no-op for modes
        // outside its family, so the order does not matter and the
        // common case costs one extra `RwLock::read` per dial.
        let selected = ws_mode_cache::effective_mode(options.url, requested).await;
        let selected = xhttp_mode_cache::effective_mode(options.url, selected).await;
        if selected != requested {
            debug!(
                url = %options.url,
                requested_mode = %requested,
                selected_mode = %selected,
                "transport mode clamped by per-host downgrade cache"
            );
        }
        Self { requested, selected }
    }

    fn downgrade_marker(self, actual: TransportMode) -> Option<TransportMode> {
        (actual != self.requested).then_some(self.requested)
    }

    async fn connect(self, options: TransportDialOptions<'_>) -> Result<TransportStream> {
        match self.selected {
            TransportMode::WsH1 => self.connect_ws_h1(options).await,
            TransportMode::WsH2 => self.connect_ws_h2_with_h1_fallback(options).await,
            #[cfg(feature = "h3")]
            TransportMode::WsH3 => self.connect_ws_h3_with_fallback(options).await,
            #[cfg(not(feature = "h3"))]
            TransportMode::WsH3 => self.connect_ws_h3_without_feature(options).await,
            TransportMode::Quic => {
                // Raw QUIC bypasses the WebSocket layer entirely; callers must
                // dispatch to `crate::quic::connect_quic_uplink` before reaching
                // this function. Reaching here means a config-routing bug.
                anyhow::bail!(
                    "TransportMode::Quic does not produce a WebSocket stream; \
                     caller must dispatch to the raw-QUIC dial path"
                );
            },
            TransportMode::XhttpH3 => self.connect_xhttp_h3_with_fallback(options).await,
            TransportMode::XhttpH2 => self.connect_xhttp_h2_with_h1_fallback(options, true).await,
            TransportMode::XhttpH1 => self.connect_xhttp_h1(options).await,
        }
    }

    async fn connect_ws_h1(self, options: TransportDialOptions<'_>) -> Result<TransportStream> {
        let (ws_stream, issued, ack_prefix_advertised, symmetric_replay_advertised) =
            connect_websocket_http1(options).await?;
        debug!(url = %options.url, selected_mode = "http1", "websocket transport connected");
        ws_mode_cache::record_success(options.url, TransportMode::WsH1).await;
        Ok(TransportStream::new_http1_with_session(ws_stream, issued)
            .with_downgraded_from(self.downgrade_marker(TransportMode::WsH1))
            .with_ack_prefix_advertised(ack_prefix_advertised)
            .with_symmetric_replay_advertised(symmetric_replay_advertised))
    }

    async fn connect_ws_h2_with_h1_fallback(
        self,
        options: TransportDialOptions<'_>,
    ) -> Result<TransportStream> {
        match connect_websocket_h2(
            options.cache,
            options.url,
            options.network.fwmark,
            options.network.ipv6_first,
            options.source,
            options.resume.resume_request,
            options.resume.ack_prefix_requested,
            options.resume.symmetric_replay_requested,
            options.resume.client_acked_offset,
        )
        .await
        {
            Ok(stream) => {
                debug!(url = %options.url, selected_mode = "h2", "websocket transport connected");
                ws_mode_cache::record_success(options.url, TransportMode::WsH2).await;
                Ok(stream.with_downgraded_from(self.downgrade_marker(TransportMode::WsH2)))
            },
            Err(h2_error) => {
                warn!(
                    url = %options.url,
                    error = %format!("{h2_error:#}"),
                    fallback = "http1",
                    "h2 websocket connect failed, falling back"
                );
                ws_mode_cache::record_failure(options.url, TransportMode::WsH2).await;
                let (ws_stream, issued, ack_prefix_advertised, symmetric_replay_advertised) =
                    connect_websocket_http1(options).await?;
                debug!(url = %options.url, selected_mode = "http1", requested_mode = "h2", "websocket transport connected");
                Ok(TransportStream::new_http1_with_session(ws_stream, issued)
                    .with_downgraded_from(self.downgrade_marker(TransportMode::WsH1))
                    .with_ack_prefix_advertised(ack_prefix_advertised)
                    .with_symmetric_replay_advertised(symmetric_replay_advertised))
            },
        }
    }

    #[cfg(feature = "h3")]
    async fn connect_ws_h3_with_fallback(
        self,
        options: TransportDialOptions<'_>,
    ) -> Result<TransportStream> {
        match connect_websocket_h3(
            options.cache,
            options.url,
            options.network.fwmark,
            options.network.ipv6_first,
            options.source,
            options.resume.resume_request,
            options.resume.ack_prefix_requested,
            options.resume.symmetric_replay_requested,
            options.resume.client_acked_offset,
        )
        .await
        {
            Ok(stream) => {
                debug!(url = %options.url, selected_mode = "h3", "websocket transport connected");
                ws_mode_cache::record_success(options.url, TransportMode::WsH3).await;
                Ok(stream.with_downgraded_from(self.downgrade_marker(TransportMode::WsH3)))
            },
            Err(h3_error) => {
                warn!(
                    url = %options.url,
                    error = %format!("{h3_error:#}"),
                    fallback = "h2",
                    "h3 websocket connect failed, falling back"
                );
                ws_mode_cache::record_failure(options.url, TransportMode::WsH3).await;
                match connect_websocket_h2(
                    options.cache,
                    options.url,
                    options.network.fwmark,
                    options.network.ipv6_first,
                    options.source,
                    options.resume.resume_request,
                    options.resume.ack_prefix_requested,
                    options.resume.symmetric_replay_requested,
                    options.resume.client_acked_offset,
                )
                .await
                {
                    Ok(stream) => {
                        debug!(url = %options.url, selected_mode = "h2", requested_mode = "h3", "websocket transport connected");
                        // Do not call `record_success(H2)` here. The H3 failure above
                        // set cap=H2, and clearing it would make the next dial retry
                        // the H3 handshake immediately.
                        Ok(stream.with_downgraded_from(self.downgrade_marker(TransportMode::WsH2)))
                    },
                    Err(h2_error) => {
                        warn!(
                            url = %options.url,
                            error = %format!("{h2_error:#}"),
                            fallback = "http1",
                            "h2 websocket connect failed after h3 fallback, falling back"
                        );
                        ws_mode_cache::record_failure(options.url, TransportMode::WsH2).await;
                        let (ws_stream, issued, ack_prefix_advertised, symmetric_replay_advertised) =
                            connect_websocket_http1(options).await?;
                        debug!(url = %options.url, selected_mode = "http1", requested_mode = "h3", "websocket transport connected");
                        Ok(TransportStream::new_http1_with_session(ws_stream, issued)
                            .with_downgraded_from(self.downgrade_marker(TransportMode::WsH1))
                            .with_ack_prefix_advertised(ack_prefix_advertised)
                            .with_symmetric_replay_advertised(symmetric_replay_advertised))
                    },
                }
            },
        }
    }

    #[cfg(not(feature = "h3"))]
    async fn connect_ws_h3_without_feature(
        self,
        options: TransportDialOptions<'_>,
    ) -> Result<TransportStream> {
        warn!(url = %options.url, "H3 requested but compiled without h3 feature, falling back to h2");
        ws_mode_cache::record_failure(options.url, TransportMode::WsH3).await;
        match connect_websocket_h2(
            options.cache,
            options.url,
            options.network.fwmark,
            options.network.ipv6_first,
            options.source,
            options.resume.resume_request,
            options.resume.ack_prefix_requested,
            options.resume.symmetric_replay_requested,
            options.resume.client_acked_offset,
        )
        .await
        {
            Ok(stream) => {
                debug!(url = %options.url, selected_mode = "h2", requested_mode = "h3", "websocket transport connected");
                // See sibling H3 success branch: do not clear the cap here.
                Ok(stream.with_downgraded_from(self.downgrade_marker(TransportMode::WsH2)))
            },
            Err(h2_error) => {
                warn!(url = %options.url, error = %format!("{h2_error:#}"), fallback = "http1", "h2 websocket connect failed, falling back");
                ws_mode_cache::record_failure(options.url, TransportMode::WsH2).await;
                let (ws_stream, issued, ack_prefix_advertised, symmetric_replay_advertised) =
                    connect_websocket_http1(options).await?;
                debug!(url = %options.url, selected_mode = "http1", requested_mode = "h3", "websocket transport connected");
                Ok(TransportStream::new_http1_with_session(ws_stream, issued)
                    .with_downgraded_from(self.downgrade_marker(TransportMode::WsH1))
                    .with_ack_prefix_advertised(ack_prefix_advertised)
                    .with_symmetric_replay_advertised(symmetric_replay_advertised))
            },
        }
    }

    async fn connect_xhttp_h3_with_fallback(
        self,
        options: TransportDialOptions<'_>,
    ) -> Result<TransportStream> {
        // h3 carrier first; on dial / handshake failure fall back to h2 (and
        // then h1) carrying the same `resume_request` so the server reattaches
        // the parked upstream instead of creating a fresh session.
        match crate::xhttp::connect_xhttp(
            options.cache,
            options.url,
            self.selected,
            options.network.fwmark,
            options.network.ipv6_first,
            options.resume.resume_request,
            options.resume.ack_prefix_requested,
            options.resume.symmetric_replay_requested,
            options.resume.client_acked_offset,
        )
        .await
        {
            Ok((stream, issued, ack_prefix_advertised, symmetric_replay_advertised)) => {
                debug!(url = %options.url, selected_mode = "xhttp_h3", ?issued, "xhttp h3 connected");
                xhttp_mode_cache::record_success(options.url, self.selected).await;
                Ok(TransportStream::new_xhttp(stream, issued)
                    .with_downgraded_from(self.downgrade_marker(self.selected))
                    .with_ack_prefix_advertised(ack_prefix_advertised)
                    .with_symmetric_replay_advertised(symmetric_replay_advertised))
            },
            Err(h3_error) => {
                warn!(
                    url = %options.url,
                    error = %format!("{h3_error:#}"),
                    fallback = "xhttp_h2",
                    "xhttp h3 dial failed, falling back"
                );
                xhttp_mode_cache::record_failure(options.url, TransportMode::XhttpH3).await;
                self.connect_xhttp_h2_with_h1_fallback(options, false).await
            },
        }
    }

    async fn connect_xhttp_h2_with_h1_fallback(
        self,
        options: TransportDialOptions<'_>,
        record_h2_success: bool,
    ) -> Result<TransportStream> {
        match crate::xhttp::connect_xhttp(
            options.cache,
            options.url,
            TransportMode::XhttpH2,
            options.network.fwmark,
            options.network.ipv6_first,
            options.resume.resume_request,
            options.resume.ack_prefix_requested,
            options.resume.symmetric_replay_requested,
            options.resume.client_acked_offset,
        )
        .await
        {
            Ok((stream, issued, ack_prefix_advertised, symmetric_replay_advertised)) => {
                debug!(
                    url = %options.url,
                    selected_mode = "xhttp_h2",
                    requested_mode = %self.requested,
                    ?issued,
                    "xhttp h2 connected"
                );
                if record_h2_success {
                    xhttp_mode_cache::record_success(options.url, TransportMode::XhttpH2).await;
                }
                Ok(TransportStream::new_xhttp(stream, issued)
                    .with_downgraded_from(self.downgrade_marker(TransportMode::XhttpH2))
                    .with_ack_prefix_advertised(ack_prefix_advertised)
                    .with_symmetric_replay_advertised(symmetric_replay_advertised))
            },
            Err(h2_error) => {
                warn!(
                    url = %options.url,
                    error = %format!("{h2_error:#}"),
                    fallback = "xhttp_h1",
                    requested_mode = %self.requested,
                    "xhttp h2 dial failed, falling back"
                );
                xhttp_mode_cache::record_failure(options.url, TransportMode::XhttpH2).await;
                let (stream, issued, ack_prefix_advertised, symmetric_replay_advertised) =
                    crate::xhttp::connect_xhttp(
                        options.cache,
                        options.url,
                        TransportMode::XhttpH1,
                        options.network.fwmark,
                        options.network.ipv6_first,
                        options.resume.resume_request,
                        options.resume.ack_prefix_requested,
                        options.resume.symmetric_replay_requested,
                        options.resume.client_acked_offset,
                    )
                    .await?;
                debug!(
                    url = %options.url,
                    selected_mode = "xhttp_h1",
                    requested_mode = %self.requested,
                    ?issued,
                    "xhttp packet-up transport connected via h1 fallback"
                );
                Ok(TransportStream::new_xhttp(stream, issued)
                    .with_downgraded_from(self.downgrade_marker(TransportMode::XhttpH1))
                    .with_ack_prefix_advertised(ack_prefix_advertised)
                    .with_symmetric_replay_advertised(symmetric_replay_advertised))
            },
        }
    }

    async fn connect_xhttp_h1(self, options: TransportDialOptions<'_>) -> Result<TransportStream> {
        let (stream, issued, ack_prefix_advertised, symmetric_replay_advertised) =
            crate::xhttp::connect_xhttp(
                options.cache,
                options.url,
                self.selected,
                options.network.fwmark,
                options.network.ipv6_first,
                options.resume.resume_request,
                options.resume.ack_prefix_requested,
                options.resume.symmetric_replay_requested,
                options.resume.client_acked_offset,
            )
            .await?;
        debug!(url = %options.url, selected_mode = "xhttp_h1", ?issued, "xhttp h1 connected");
        xhttp_mode_cache::record_success(options.url, self.selected).await;
        Ok(TransportStream::new_xhttp(stream, issued)
            .with_downgraded_from(self.downgrade_marker(self.selected))
            .with_ack_prefix_advertised(ack_prefix_advertised)
            .with_symmetric_replay_advertised(symmetric_replay_advertised))
    }
}

/// Dial the requested HTTP-family transport, applying per-host downgrade
/// caches and inline fallback chains before returning a unified stream.
pub async fn connect_transport(options: TransportDialOptions<'_>) -> Result<TransportStream> {
    DialPlan::resolve(&options).await.connect(options).await
}

async fn connect_websocket_http1(
    options: TransportDialOptions<'_>,
) -> Result<(H1WsStream, Option<SessionId>, bool, bool)> {
    let mut connect_guard = crate::TransportConnectGuard::new(options.source, "http1");
    let host = options
        .url
        .host_str()
        .ok_or_else(|| anyhow!("URL is missing host: {}", options.url))?;
    let port = options
        .url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("URL is missing port"))?;
    let server_addr = crate::dns::resolve_host_with_preference(
        options.cache,
        host,
        port,
        "failed to resolve websocket host",
        options.network.ipv6_first,
    )
    .await?
    .first()
    .copied()
    .ok_or_else(|| {
        anyhow::Error::new(TransportOperation::DnsResolveNoAddresses {
            host: format!("{host}:{port}"),
        })
    })?;
    let (
        ws_stream,
        issued_session_id,
        ack_prefix_advertised_by_server,
        symmetric_replay_advertised_by_server,
    ) = timeout(HTTP1_WS_CONNECT_TIMEOUT, async {
        let tcp = connect_tcp_socket(server_addr, options.network.fwmark).await?;
        // Build a `Request` so we can attach `X-Outline-*` headers; the
        // default form (`url.as_str().into_client_request()`) hides the
        // builder behind tungstenite's `IntoClientRequest` glue. Errors
        // from `into_client_request` are bubbled up unchanged so they
        // keep the original `tungstenite::Error` causality chain.
        let mut request = options
            .url
            .as_str()
            .into_client_request()
            .context("HTTP/1 websocket request builder failed")?;
        let headers = request.headers_mut();
        if let Some(profile) = crate::fingerprint_profile::select(options.url) {
            // Insert the browser-style identification headers BEFORE the
            // X-Outline-Resume-* pair so a passive observer reads the
            // request as "browser headers, then a couple of custom
            // app-specific ones" -- the same shape an XHR-flavoured WS
            // upgrade from a real page produces.
            crate::fingerprint_profile::apply(
                profile,
                headers,
                crate::fingerprint_profile::SecFetchPreset::WebsocketUpgrade,
            );
        }
        headers.insert(
            crate::resumption::RESUME_CAPABLE_HEADER,
            "1".parse().expect("static header value"),
        );
        if let Some(id) = options.resume.resume_request {
            headers.insert(
                crate::resumption::RESUME_REQUEST_HEADER,
                id.to_hex().parse().expect("hex Session ID is a valid header value"),
            );
        }
        if options.resume.ack_prefix_requested {
            headers.insert(
                crate::resumption::ACK_PREFIX_HEADER,
                "1".parse().expect("static header value"),
            );
        }
        if options.resume.symmetric_replay_requested {
            headers.insert(
                crate::resumption::SYMMETRIC_REPLAY_HEADER,
                "1".parse().expect("static header value"),
            );
        }
        // v2 client-reported downstream-acked offset header. Only sent
        // on retry redials that also advertise v2 AND when the offset
        // is non-zero (a fresh session has no prior bytes to claim).
        if options.resume.symmetric_replay_requested && options.resume.client_acked_offset > 0 {
            let offset_str = options.resume.client_acked_offset.to_string();
            headers.insert(
                crate::resumption::DOWN_ACKED_HEADER,
                offset_str.parse().expect("decimal u64 is a valid header value"),
            );
        }
        let (ws_stream, response) = client_async_tls(request, tcp)
            .await
            .context("HTTP/1 websocket handshake failed")?;
        let issued = response
            .headers()
            .get(crate::resumption::SESSION_RESPONSE_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(SessionId::parse_hex);
        // Echo gating mirrors the h2/h3 paths: only report a positive
        // negotiation when the request advertised the capability AND the
        // server echoed `1`. A spurious echo without a matching request
        // is treated as `false` and the receiver will not look for the
        // Ack-Prefix control frame in the byte stream.
        let ack_prefix_echoed = options.resume.ack_prefix_requested
            && response
                .headers()
                .get(crate::resumption::ACK_PREFIX_HEADER)
                .and_then(|v| v.to_str().ok())
                == Some("1");
        // v2 echo gate: server must echo v2 AND v1 must already be on
        // (per spec, v2 without v1 is undefined wire shape).
        let symmetric_replay_echoed = options.resume.symmetric_replay_requested
            && ack_prefix_echoed
            && response
                .headers()
                .get(crate::resumption::SYMMETRIC_REPLAY_HEADER)
                .and_then(|v| v.to_str().ok())
                == Some("1");
        Ok::<_, anyhow::Error>((ws_stream, issued, ack_prefix_echoed, symmetric_replay_echoed))
    })
    .await
    .map_err(|_| {
        anyhow!(
            "HTTP/1 websocket handshake timed out after {}s connecting to {server_addr}",
            HTTP1_WS_CONNECT_TIMEOUT.as_secs()
        )
    })??;
    connect_guard.finish("success");
    Ok((
        ws_stream,
        issued_session_id,
        ack_prefix_advertised_by_server,
        symmetric_replay_advertised_by_server,
    ))
}
