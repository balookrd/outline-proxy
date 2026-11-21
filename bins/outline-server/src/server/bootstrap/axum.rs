use std::{
    collections::{BTreeSet, HashMap},
    net::IpAddr,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use arc_swap::ArcSwap;
use axum::{Router, routing::any};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder as HyperBuilder,
    service::TowerToHyperService,
};
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    sync::Semaphore,
    task::JoinSet,
    time::{Duration, Instant, timeout, timeout_at},
};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, warn};

use crate::{
    config::{Config, TuningProfile},
    metrics::Metrics,
};

use super::super::{
    cluster::ClusterCtx,
    connect::configure_tcp_stream,
    constants::{
        CERT_RELOAD_POLL_INTERVAL_SECS, H2_CADDY_MAX_CONCURRENT_STREAMS, H2_CADDY_MAX_FRAME_SIZE,
        H2_CADDY_MAX_HEADER_LIST_SIZE, HTTP_GRACEFUL_SHUTDOWN_TIMEOUT_SECS,
        PLAIN_HTTP_HEADER_READ_TIMEOUT_SECS, PLAIN_HTTP_MAX_CONCURRENT_CONNECTIONS,
        TLS_FIRST_REQUEST_TIMEOUT_SECS, TLS_HANDSHAKE_TIMEOUT_SECS, TLS_MAX_CONCURRENT_CONNECTIONS,
    },
    shutdown::ShutdownSignal,
    state::{AppState, AuthPolicy, RoutesSnapshot, Services},
    transport::{
        HttpFallbackContext, XhttpAppProtocol, XhttpAxumState, combined_websocket_upgrade,
        http_fallback_handler, metrics_handler, not_found_handler, root_http_auth_handler,
        sni_fallback, tcp_websocket_upgrade, udp_websocket_upgrade, vless_websocket_upgrade,
        xhttp_handler, xhttp_handler_no_session, xhttp_handler_with_path_seq,
    },
};
use super::cert_reload::{spawn_cert_reloader, tcp_cert_paths};
use super::first_bytes_deadline::FirstBytesDeadline;
use super::tls::build_tcp_tls_acceptor;
use sni_fallback::SniFallbackContext;

pub(in crate::server) fn build_app(
    routes: RoutesSnapshot,
    services: Arc<Services>,
    auth: Arc<AuthPolicy>,
    http_fallback: Option<Arc<HttpFallbackContext>>,
    cluster: Option<Arc<ClusterCtx>>,
) -> Router {
    let mut router = Router::new();

    if auth.http_root_auth {
        router = router.route("/", any(root_http_auth_handler));
    }

    let snap = routes.load();
    // A WS base path present in BOTH the tcp and udp tables is a *combined*
    // path: it carries both legs, told apart by the hidden bit in the
    // `/{token}` segment. Register it once as `<base>/{token}` on the
    // combined handler; split paths keep their bare per-leg routes.
    let combined_ws: BTreeSet<String> = snap
        .tcp
        .keys()
        .filter(|p| snap.udp.contains_key(*p))
        .cloned()
        .collect();
    for path in snap.tcp.keys() {
        if combined_ws.contains(path) {
            router = router.route(&format!("{path}/{{token}}"), any(combined_websocket_upgrade));
        } else {
            router = router.route(path, any(tcp_websocket_upgrade));
        }
    }

    for path in snap.udp.keys() {
        // Combined paths were already registered via the tcp loop above.
        if !combined_ws.contains(path) {
            router = router.route(path, any(udp_websocket_upgrade));
        }
    }

    for path in snap.vless.keys() {
        router = router.route(path, any(vless_websocket_upgrade));
    }
    // One base path serves exactly one protocol; tag each so the merged loop
    // below can stamp the right `XhttpAppProtocol` into its state. An ss base
    // present in both the ss and ss-udp tables is combined — tagged
    // `SsCombined` once (and skipped in the ss-udp chain), so `resolve_route`
    // decodes the session-id bit to pick the tcp or udp table.
    let combined_ss_xhttp: BTreeSet<String> = snap
        .xhttp_ss
        .keys()
        .filter(|p| snap.xhttp_ss_udp.contains_key(*p))
        .cloned()
        .collect();
    let xhttp_bases: Vec<(String, XhttpAppProtocol)> = snap
        .xhttp_vless
        .keys()
        .map(|p| (p.clone(), XhttpAppProtocol::Vless))
        .chain(snap.xhttp_ss.keys().map(|p| {
            let proto = if combined_ss_xhttp.contains(p) {
                XhttpAppProtocol::SsCombined
            } else {
                XhttpAppProtocol::Ss
            };
            (p.clone(), proto)
        }))
        .chain(
            snap.xhttp_ss_udp
                .keys()
                .filter(|p| !combined_ss_xhttp.contains(*p))
                .map(|p| (p.clone(), XhttpAppProtocol::SsUdp)),
        )
        .collect();
    drop(snap);

    let state = AppState {
        routes: Arc::clone(&routes),
        services: Arc::clone(&services),
        auth,
        http_fallback,
        cluster,
    };
    // The h1/h2 fallback handler is only wired when `apply_to_h1` is
    // on. `apply_to_h3 = true, apply_to_h1 = false` keeps the TCP
    // listener honest (404 for unmatched) while still masquerading
    // QUIC traffic through the h3 adapter.
    let h1_fallback_active = state
        .http_fallback
        .as_ref()
        .map(|fb| fb.config.apply_to_h1)
        .unwrap_or(false);
    let fallback_route = if h1_fallback_active {
        any(http_fallback_handler)
    } else {
        any(not_found_handler)
    };
    let mut app = router.fallback(fallback_route).with_state(state.clone());

    // XHTTP routes carry their own `XhttpAxumState`, so they have to
    // be merged in after the main router pins its state. Four route
    // shapes are registered per base, covering every wire form
    // VLESS-XHTTP clients in the wild use:
    //
    // - `<base>/<id>` — every GET (downlink), every stream-one POST
    //   that carries an explicit `?mode=stream-one` selector, and
    //   packet-up uplink POSTs from clients that put `seq` in
    //   `X-Xhttp-Seq` (the legacy `outline-client` convention).
    // - `<base>/<id>/<seq>` — packet-up uplink POSTs that put `seq`
    //   in the URL path. xray / sing-box default placement; what
    //   `happ`, `hiddify`, `v2rayN` send on the wire.
    // - `<base>` and `<base>/` — stream-one POSTs from xray clients
    //   dialing with `sessionId=""` (xray's `OpenStream` does that
    //   for `mode = "stream-one"`, and `ApplyMetaToRequest` skips
    //   the path-append, leaving the URL at the base path with or
    //   without a trailing slash depending on path normalisation).
    //   The handler generates a fresh server-side id and dispatches
    //   into the same stream-one carrier.
    for (base, protocol) in xhttp_bases {
        let xhttp_state = XhttpAxumState {
            base_path: Arc::from(base.as_str()),
            protocol,
            registry: Arc::clone(&services.xhttp_registry),
            parent: state.clone(),
        };
        let route_base = base.clone();
        let route_base_slash = format!("{base}/");
        let route_id = format!("{base}/{{id}}");
        let route_id_seq = format!("{base}/{{id}}/{{seq}}");
        let xhttp_router = Router::new()
            .route(&route_base, any(xhttp_handler_no_session))
            .route(&route_base_slash, any(xhttp_handler_no_session))
            .route(&route_id, any(xhttp_handler))
            .route(&route_id_seq, any(xhttp_handler_with_path_seq))
            .with_state(xhttp_state);
        app = app.merge(xhttp_router);
    }
    app.layer(axum::middleware::map_response(apply_caddy_server_header))
}

async fn apply_caddy_server_header(
    mut response: axum::response::Response,
) -> axum::response::Response {
    let headers = response.headers_mut();
    if !headers.contains_key(axum::http::header::SERVER) {
        headers.insert(axum::http::header::SERVER, axum::http::HeaderValue::from_static("Caddy"));
    }
    response
}

pub(in crate::server) fn build_metrics_app(metrics: Arc<Metrics>, metrics_path: String) -> Router {
    Router::new()
        .route(&metrics_path, any(metrics_handler))
        .with_state(metrics)
}

pub(in crate::server) async fn serve_tcp_listener(
    listener: TcpListener,
    app: Router,
    config: Arc<Config>,
    sni_fallback: Option<Arc<SniFallbackContext>>,
    metrics: Arc<Metrics>,
    shutdown: ShutdownSignal,
) -> Result<()> {
    let app = if config.h3_enabled() {
        let h3_port = config.effective_h3_listen().map(|addr| addr.port()).unwrap_or(443);
        let alt_svc_val =
            axum::http::HeaderValue::from_str(&format!("h3=\":{h3_port}\"; ma=2592000"))
                .expect("valid alt-svc header value");
        app.layer(axum::middleware::map_response(move |mut res: axum::response::Response| {
            let val = alt_svc_val.clone();
            async move {
                let headers = res.headers_mut();
                if !headers.contains_key(axum::http::header::ALT_SVC) {
                    headers.insert(axum::http::header::ALT_SVC, val);
                }
                res
            }
        }))
    } else {
        app
    };

    if config.tcp_tls_enabled() {
        let acceptor = Arc::new(ArcSwap::from_pointee(build_tcp_tls_acceptor(config.as_ref())?));
        spawn_tcp_cert_reloader(Arc::clone(&acceptor), Arc::clone(&config), shutdown.clone());
        serve_tls_listener(
            listener,
            app,
            acceptor,
            config.tuning,
            sni_fallback,
            config.max_connections_per_ip,
            metrics,
            shutdown,
        )
        .await
    } else {
        // SNI fallback only makes sense for the TLS path. Validation
        // already rejects `[sni_fallback]` without TLS so the
        // `Some(_)` branch is unreachable here in practice; assert
        // it explicitly to catch future drift.
        debug_assert!(sni_fallback.is_none(), "sni_fallback requires TLS");
        serve_plain_listener(listener, app, config.tuning, "plain HTTP", shutdown).await
    }
}

/// Serve the plain (non-TLS) HTTP listener. Kept as a thin wrapper over
/// [`serve_plain_listener`] with a default tuning profile so the many
/// integration tests that drive `serve_listener(listener, app, shutdown)`
/// directly keep their signature; the production non-TLS path
/// ([`serve_tcp_listener`]) calls `serve_plain_listener` with the real
/// `config.tuning`, so this wrapper is test-only.
#[cfg(test)]
pub(in crate::server) async fn serve_listener(
    listener: TcpListener,
    app: Router,
    shutdown: ShutdownSignal,
) -> Result<()> {
    serve_plain_listener(listener, app, TuningProfile::default(), "plain HTTP", shutdown).await
}

/// Accept loop for a plain (non-TLS) HTTP listener — used for both the main
/// TCP ingress and the metrics endpoint (`label` distinguishes them in logs).
///
/// Unlike the TLS path there is no handshake to bound the unauthenticated
/// phase, so a freshly accepted socket becomes a hyper connection task
/// immediately — before the peer has proven itself by sending a request. Two
/// bounds keep that from being a free pre-auth slowloris, mirroring
/// [`serve_tls_listener`]:
///
/// - A `PLAIN_HTTP_MAX_CONCURRENT_CONNECTIONS` semaphore caps the number of
///   in-flight connection tasks; the permit is held for the whole connection
///   and released the instant its task returns.
/// - A `PLAIN_HTTP_HEADER_READ_TIMEOUT_SECS` first-byte peek deadline drops a
///   peer that connects and then stays silent (hyper's h1/h2 protocol sniff
///   has no timeout of its own), and the same budget is wired into the builder
///   as HTTP/1 `header_read_timeout` to bound slow-but-nonzero header delivery
///   after the sniff resolves.
pub(in crate::server) async fn serve_plain_listener(
    listener: TcpListener,
    app: Router,
    profile: TuningProfile,
    label: &'static str,
    mut shutdown: ShutdownSignal,
) -> Result<()> {
    let connection_limit = Arc::new(Semaphore::new(PLAIN_HTTP_MAX_CONCURRENT_CONNECTIONS));
    let mut tasks: JoinSet<()> = JoinSet::new();

    loop {
        // Reap already-finished tasks so JoinSet storage stays bounded under
        // long-lived listeners with high connection churn.
        while tasks.try_join_next().is_some() {}

        let permit = tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                debug!(listener = label, "plain HTTP listener stopping on shutdown signal");
                break;
            }
            permit = connection_limit.clone().acquire_owned() => {
                // The semaphore is never closed while the listener is running.
                permit.expect("plain HTTP connection semaphore unexpectedly closed")
            }
        };

        let (stream, peer_addr) = tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                debug!(listener = label, "plain HTTP listener stopping on shutdown signal");
                break;
            }
            res = listener.accept() => match res {
                Ok(v) => v,
                Err(error) => {
                    warn!(listener = label, ?error, "failed to accept plain tcp connection");
                    continue;
                },
            },
        };
        if let Err(error) = configure_tcp_stream(&stream) {
            warn!(listener = label, %peer_addr, ?error, "failed to configure plain tcp connection");
            continue;
        }

        let app = app.clone();
        let mut task_shutdown = shutdown.clone();

        tasks.spawn(async move {
            let _permit = permit;

            // Pre-auth budget: a freshly accepted plain-HTTP peer has sent
            // nothing yet but already holds a permit and a task. hyper's
            // protocol sniff (h1 vs h2c) reads the first bytes with no timeout,
            // and its HTTP/1 `header_read_timeout` only starts once that sniff
            // resolves — so a peer that connects and stays silent would pin
            // both forever. Peek for the first byte under the pre-auth budget;
            // a peer that sends nothing in time is dropped, freeing the permit.
            // Slow-but-nonzero header dribbling past this point is then bounded
            // by the builder's `header_read_timeout`.
            let mut probe = [0u8; 1];
            let peeked = tokio::select! {
                biased;
                _ = task_shutdown.cancelled() => {
                    debug!(listener = label, %peer_addr, "aborting plain http peek on shutdown");
                    return;
                }
                res = timeout(http_header_read_timeout(), stream.peek(&mut probe)) => res,
            };
            match peeked {
                Ok(Ok(0)) => return, // peer closed before sending anything
                Ok(Ok(_)) => {},     // first byte arrived; hand off to hyper
                Ok(Err(error)) => {
                    debug!(listener = label, %peer_addr, ?error, "plain tcp peek failed");
                    return;
                },
                Err(_elapsed) => {
                    debug!(
                        listener = label,
                        %peer_addr,
                        "plain http peer sent no bytes before pre-auth timeout; dropping connection",
                    );
                    return;
                },
            }

            let io = TokioIo::new(stream);
            // Inject `ConnectInfo<SocketAddr>` so the TCP-WS upgrade handler can
            // key the per-route peer-user hint cache, matching what the TLS path
            // (and the former `into_make_service_with_connect_info`) did.
            let app_with_addr = app.layer(axum::Extension(axum::extract::ConnectInfo(peer_addr)));
            let service = TowerToHyperService::new(app_with_addr);
            let builder =
                build_http_server_builder(&profile, Some(http_header_read_timeout()));
            let conn = builder.serve_connection_with_upgrades(io, service);
            tokio::pin!(conn);

            let result = tokio::select! {
                biased;
                res = conn.as_mut() => res,
                _ = task_shutdown.cancelled() => {
                    conn.as_mut().graceful_shutdown();
                    conn.as_mut().await
                }
            };
            if let Err(error) = result
                && !is_benign_http_serve_error(error.as_ref())
            {
                warn!(listener = label, ?error, %peer_addr, "plain http server connection terminated with error");
            }
        });
    }

    let drain_timeout = Duration::from_secs(HTTP_GRACEFUL_SHUTDOWN_TIMEOUT_SECS);
    let drain =
        tokio::time::timeout(drain_timeout, async { while tasks.join_next().await.is_some() {} })
            .await;
    if drain.is_err() {
        warn!(
            listener = label,
            remaining = tasks.len(),
            timeout_secs = HTTP_GRACEFUL_SHUTDOWN_TIMEOUT_SECS,
            "plain HTTP connections did not drain within shutdown timeout; aborting"
        );
        tasks.shutdown().await;
    } else {
        debug!(listener = label, "plain HTTP listener drained all connections");
    }
    Ok(())
}

/// Serve the Prometheus metrics endpoint. Shares the plain-HTTP accept loop so
/// the metrics listener gets the same pre-auth slowloris bounds (connection cap
/// plus first-byte and header-read timeouts) as the main plain ingress; a bound
/// tuning profile is fine here since the endpoint serves only small metric
/// scrapes and never upgrades to WebSocket.
pub(in crate::server) async fn serve_metrics_listener(
    listener: TcpListener,
    app: Router,
    shutdown: ShutdownSignal,
) -> Result<()> {
    serve_plain_listener(listener, app, TuningProfile::default(), "metrics", shutdown).await
}

/// Watches the TCP listener's cert/key files and atomically swaps in a
/// freshly built `TlsAcceptor` when they change, so new connections pick
/// up renewed certificates without a restart.
fn spawn_tcp_cert_reloader(
    acceptor: Arc<ArcSwap<TlsAcceptor>>,
    config: Arc<Config>,
    shutdown: ShutdownSignal,
) {
    let paths = tcp_cert_paths(config.as_ref());
    spawn_cert_reloader(
        "tcp",
        paths,
        Duration::from_secs(CERT_RELOAD_POLL_INTERVAL_SECS),
        shutdown,
        move || {
            let rebuilt = build_tcp_tls_acceptor(config.as_ref())?;
            acceptor.store(Arc::new(rebuilt));
            Ok(())
        },
    );
}

#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};

/// Test-only override for the pre-auth TLS timeout, in milliseconds. `0`
/// means "use the production default". Tests set this to a small value so
/// the slowloris regression coverage runs in ~1 s rather than
/// `TLS_HANDSHAKE_TIMEOUT_SECS`. Shipping code never touches it — there is
/// no setter outside `cfg(test)`.
#[cfg(test)]
static TEST_TLS_HANDSHAKE_TIMEOUT_MS: AtomicU64 = AtomicU64::new(0);

/// Acquire-and-set guard for the pre-auth-timeout override. Locks a single
/// process-wide mutex so listener tests do not race on the atomic, and
/// clears the override on drop. Mirrors `transport::sink::TestTimeoutOverride`.
#[cfg(test)]
pub(in crate::server) struct TestTlsHandshakeTimeout {
    _lock: std::sync::MutexGuard<'static, ()>,
}

#[cfg(test)]
impl TestTlsHandshakeTimeout {
    pub(in crate::server) fn set(d: Duration) -> Self {
        static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let lock = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        TEST_TLS_HANDSHAKE_TIMEOUT_MS.store(d.as_millis() as u64, Ordering::Relaxed);
        Self { _lock: lock }
    }
}

#[cfg(test)]
impl Drop for TestTlsHandshakeTimeout {
    fn drop(&mut self) {
        TEST_TLS_HANDSHAKE_TIMEOUT_MS.store(0, Ordering::Relaxed);
    }
}

/// What a TLS connection will speak, as far as its ALPN says, and so what
/// bounds the wait for its first request:
///
/// - `http/1.1`: the first byte must arrive in time ([`FirstBytesDeadline`]) —
///   hyper's HTTP/1 `header_read_timeout` does not fire on a connection that
///   has sent nothing, as `a_silent_peer_is_dropped_after_the_handshake_…`
///   shows. Once bytes flow, `header_read_timeout` bounds the rest of the
///   header.
/// - `h2`: hyper has no timeout for the client preface, so the stream itself
///   must deliver those 24 bytes in time. After the preface the h2 keep-alive
///   PING takes over.
/// - no ALPN: the protocol is sniffed from the first bytes, and the sniff has
///   no timeout either. As for `http/1.1`: first byte in time, then
///   `header_read_timeout`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PostHandshakeProtocol {
    Http1,
    Http2,
    Unknown,
}

impl PostHandshakeProtocol {
    /// Length of the HTTP/2 client connection preface (RFC 9113, section 3.4).
    const H2_PREFACE_LEN: usize = 24;

    fn from_alpn(alpn: Option<&[u8]>) -> Self {
        match alpn {
            Some(b"h2") => Self::Http2,
            Some(b"http/1.1") => Self::Http1,
            _ => Self::Unknown,
        }
    }

    /// Bytes the stream must deliver before the first-request deadline.
    fn required_first_bytes(self) -> usize {
        match self {
            Self::Http1 | Self::Unknown => 1,
            Self::Http2 => Self::H2_PREFACE_LEN,
        }
    }
}

/// Test-only override for the post-handshake first-request timeout, in
/// milliseconds. `0` means "use the production default".
#[cfg(test)]
static TEST_TLS_FIRST_REQUEST_TIMEOUT_MS: AtomicU64 = AtomicU64::new(0);

/// Acquire-and-set guard for the first-request-timeout override. Mirrors
/// [`TestTlsHandshakeTimeout`].
#[cfg(test)]
pub(in crate::server) struct TestTlsFirstRequestTimeout {
    _lock: std::sync::MutexGuard<'static, ()>,
}

#[cfg(test)]
impl TestTlsFirstRequestTimeout {
    pub(in crate::server) fn set(d: Duration) -> Self {
        static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let lock = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        TEST_TLS_FIRST_REQUEST_TIMEOUT_MS.store(d.as_millis() as u64, Ordering::Relaxed);
        Self { _lock: lock }
    }
}

#[cfg(test)]
impl Drop for TestTlsFirstRequestTimeout {
    fn drop(&mut self) {
        TEST_TLS_FIRST_REQUEST_TIMEOUT_MS.store(0, Ordering::Relaxed);
    }
}

/// Wall-clock budget for the first request after the TLS handshake. See
/// [`TLS_FIRST_REQUEST_TIMEOUT_SECS`] for the rationale.
fn tls_first_request_timeout() -> Duration {
    #[cfg(test)]
    {
        let ms = TEST_TLS_FIRST_REQUEST_TIMEOUT_MS.load(Ordering::Relaxed);
        if ms > 0 {
            return Duration::from_millis(ms);
        }
    }
    Duration::from_secs(TLS_FIRST_REQUEST_TIMEOUT_SECS)
}

/// Wall-clock budget for the unauthenticated pre-handshake phase of a TLS
/// connection. See [`TLS_HANDSHAKE_TIMEOUT_SECS`] for the rationale.
fn tls_handshake_timeout() -> Duration {
    #[cfg(test)]
    {
        let ms = TEST_TLS_HANDSHAKE_TIMEOUT_MS.load(Ordering::Relaxed);
        if ms > 0 {
            return Duration::from_millis(ms);
        }
    }
    Duration::from_secs(TLS_HANDSHAKE_TIMEOUT_SECS)
}

/// Test-only override for the plain-HTTP pre-auth timeout, in milliseconds.
/// `0` means "use the production default". The slowloris regression tests set
/// a small value so they run in well under a second rather than
/// `PLAIN_HTTP_HEADER_READ_TIMEOUT_SECS`. Shipping code never touches it.
#[cfg(test)]
static TEST_HTTP_HEADER_READ_TIMEOUT_MS: AtomicU64 = AtomicU64::new(0);

/// Acquire-and-set guard for the plain-HTTP pre-auth-timeout override. Locks a
/// single process-wide mutex so listener tests do not race on the atomic, and
/// clears the override on drop. Mirrors [`TestTlsHandshakeTimeout`].
#[cfg(test)]
pub(in crate::server) struct TestHttpHeaderReadTimeout {
    _lock: std::sync::MutexGuard<'static, ()>,
}

#[cfg(test)]
impl TestHttpHeaderReadTimeout {
    pub(in crate::server) fn set(d: Duration) -> Self {
        static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let lock = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        TEST_HTTP_HEADER_READ_TIMEOUT_MS.store(d.as_millis() as u64, Ordering::Relaxed);
        Self { _lock: lock }
    }
}

#[cfg(test)]
impl Drop for TestHttpHeaderReadTimeout {
    fn drop(&mut self) {
        TEST_HTTP_HEADER_READ_TIMEOUT_MS.store(0, Ordering::Relaxed);
    }
}

/// Wall-clock budget for the plain (non-TLS) HTTP pre-auth phase: first-byte
/// peek plus HTTP/1 header read. See [`PLAIN_HTTP_HEADER_READ_TIMEOUT_SECS`].
fn http_header_read_timeout() -> Duration {
    #[cfg(test)]
    {
        let ms = TEST_HTTP_HEADER_READ_TIMEOUT_MS.load(Ordering::Relaxed);
        if ms > 0 {
            return Duration::from_millis(ms);
        }
    }
    Duration::from_secs(PLAIN_HTTP_HEADER_READ_TIMEOUT_SECS)
}

/// Per-IP connection tracker for listeners. When `limit` is configured
/// (`Some(n)` where `n > 0`), limits concurrent active connections from any
/// single remote IP address.
#[derive(Clone, Default)]
pub(in crate::server) struct IpConnectionTracker {
    inner: Option<Arc<IpConnectionTrackerInner>>,
}

struct IpConnectionTrackerInner {
    limit: usize,
    counts: Mutex<HashMap<IpAddr, usize>>,
}

pub(in crate::server) struct IpConnectionGuard {
    ip: IpAddr,
    inner: Arc<IpConnectionTrackerInner>,
}

impl Drop for IpConnectionGuard {
    fn drop(&mut self) {
        let mut counts = self.inner.counts.lock().unwrap();
        if let std::collections::hash_map::Entry::Occupied(mut entry) = counts.entry(self.ip) {
            if *entry.get() <= 1 {
                entry.remove();
            } else {
                *entry.get_mut() -= 1;
            }
        }
    }
}

impl IpConnectionTracker {
    pub(in crate::server) fn new(limit: Option<usize>) -> Self {
        let inner = match limit {
            Some(l) if l > 0 => Some(Arc::new(IpConnectionTrackerInner {
                limit: l,
                counts: Mutex::new(HashMap::new()),
            })),
            _ => None,
        };
        Self { inner }
    }

    pub(in crate::server) fn limit(&self) -> usize {
        self.inner.as_ref().map(|i| i.limit).unwrap_or(0)
    }

    pub(in crate::server) fn try_acquire(
        &self,
        ip: IpAddr,
    ) -> Result<Option<IpConnectionGuard>, usize> {
        let inner = match &self.inner {
            Some(inner) => inner,
            None => return Ok(None),
        };
        let mut counts = inner.counts.lock().unwrap();
        let current = counts.entry(ip).or_insert(0);
        if *current >= inner.limit {
            return Err(*current);
        }
        *current += 1;
        Ok(Some(IpConnectionGuard { ip, inner: Arc::clone(inner) }))
    }
}

#[allow(clippy::too_many_arguments)]
async fn serve_tls_listener(
    listener: TcpListener,
    app: Router,
    acceptor: Arc<ArcSwap<TlsAcceptor>>,
    profile: TuningProfile,
    sni_fallback: Option<Arc<SniFallbackContext>>,
    max_connections_per_ip: Option<usize>,
    metrics: Arc<Metrics>,
    mut shutdown: ShutdownSignal,
) -> Result<()> {
    let connection_limit = Arc::new(Semaphore::new(TLS_MAX_CONCURRENT_CONNECTIONS));
    let ip_tracker = IpConnectionTracker::new(max_connections_per_ip);
    let mut tasks: JoinSet<()> = JoinSet::new();

    loop {
        // Reap already-finished tasks so JoinSet storage stays bounded under
        // long-lived listeners with high connection churn.
        while tasks.try_join_next().is_some() {}

        let permit = tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                debug!("TLS listener stopping on shutdown signal");
                break;
            }
            permit = connection_limit.clone().acquire_owned() => {
                // The semaphore is never closed while the listener is running.
                permit.expect("TLS connection semaphore unexpectedly closed")
            }
        };

        let (stream, peer_addr) = tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                debug!("TLS listener stopping on shutdown signal");
                break;
            }
            res = listener.accept() => match res {
                Ok(v) => v,
                Err(error) => {
                    warn!(?error, "failed to accept TLS tcp connection");
                    continue;
                },
            },
        };
        if let Err(error) = configure_tcp_stream(&stream) {
            warn!(%peer_addr, ?error, "failed to configure TLS tcp connection");
            continue;
        }

        let ip_guard = match ip_tracker.try_acquire(peer_addr.ip()) {
            Ok(guard) => guard,
            Err(current) => {
                warn!(
                    %peer_addr,
                    current,
                    limit = ip_tracker.limit(),
                    "dropping TLS tcp connection: per-IP connection limit exceeded"
                );
                continue;
            },
        };

        // Load the current acceptor per connection so a cert reload
        // (which swaps the pointer) takes effect on the next handshake
        // without disturbing connections already in flight.
        let acceptor = acceptor.load_full();
        let app = app.clone();
        let sni_fallback = sni_fallback.clone();
        let metrics = Arc::clone(&metrics);
        let mut task_shutdown = shutdown.clone();

        tasks.spawn(async move {
            let _permit = permit;
            let _ip_guard = ip_guard;
            let mut stream = stream;

            // A single deadline covers the whole unauthenticated pre-handshake
            // phase — the optional SNI peek *and* the rustls handshake. Sharing
            // one budget (rather than one timeout per phase) denies a slowloris
            // peer the trick of being slow in both phases to consume twice the
            // allowance; the permit this task holds is released the moment it
            // returns for any reason, so timing out here is what keeps the
            // `TLS_MAX_CONCURRENT_CONNECTIONS` semaphore from being pinned by
            // peers that never finish authenticating.
            let preauth_deadline = Instant::now() + tls_handshake_timeout();

            // Peek for plain HTTP sent to the HTTPS port before starting the TLS
            // handshake or SNI dispatch. Go's net/http server detects this and
            // replies with a plaintext 400 Bad Request rather than a TLS alert.
            let mut probe = [0u8; 8];
            let peeked = tokio::select! {
                biased;
                _ = task_shutdown.cancelled() => {
                    debug!(%peer_addr, "aborting TLS handshake on shutdown");
                    return;
                }
                res = timeout_at(preauth_deadline, stream.peek(&mut probe)) => res,
            };
            let n = match peeked {
                Ok(Ok(n)) => n,
                Ok(Err(error)) => {
                    debug!(%peer_addr, ?error, "tcp peek failed");
                    return;
                }
                Err(_elapsed) => {
                    if sni_fallback.is_some() {
                        metrics.record_sni_peek_failed("timeout");
                    } else {
                        metrics.record_tls_handshake_failed("timeout");
                    }
                    return;
                }
            };
            if n > 0 && is_plain_http_request(&probe[..n]) {
                // Drain any already-received bytes from the socket so the OS
                // does not send a TCP RST on close (BSD/macOS/Linux emit RST if
                // unread inbound bytes remain when a socket is closed).
                let mut drain = [0u8; 1024];
                while let Ok(read_n) = stream.try_read(&mut drain) {
                    if read_n == 0 {
                        break;
                    }
                }
                const GO_HTTP_ON_HTTPS_RESP: &[u8] =
                    b"HTTP/1.0 400 Bad Request\r\n\r\nClient sent an HTTP request to an HTTPS server.\n";
                let _ = timeout_at(preauth_deadline, stream.write_all(GO_HTTP_ON_HTTPS_RESP)).await;
                let _ = stream.flush().await;
                let _ = stream.shutdown().await;
                metrics.record_tls_handshake_failed("http_on_https");
                debug!(%peer_addr, "plain HTTP request sent to HTTPS listener; sent Go 400 response");
                return;
            }

            // SNI dispatch: when [sni_fallback] is configured, peek
            // the ClientHello before handshake. Foreign SNIs (or no
            // SNI when `allow_no_sni = false`) are spliced as raw
            // TCP to the configured backend; matching SNIs continue
            // through the local TLS terminator with the buffered
            // bytes prepended. Wrapping in `PrependStream` even when
            // the buffer is empty keeps the type uniform across the
            // two branches without paying for `Box<dyn ...>`.
            //
            // `peeked_sni` is `Some(_)` only when sni_fallback ran
            // and observed a `server_name` extension. For the
            // sni_fallback-disabled path the cost of an extra
            // ClientHello peek isn't worth the diagnostic — rustls
            // still gives us a classifiable `io::Error`, just
            // without the SNI label on the log line.
            let (stream_for_handshake, peeked_sni) = if let Some(ctx) = sni_fallback.as_ref() {
                let dispatch = tokio::select! {
                    biased;
                    _ = task_shutdown.cancelled() => {
                        debug!(%peer_addr, "aborting SNI peek on shutdown");
                        return;
                    }
                    res = timeout_at(
                        preauth_deadline,
                        sni_fallback::peek_and_route(ctx, &metrics, stream, peer_addr),
                    ) => res,
                };
                match dispatch {
                    Ok(Ok(sni_fallback::SniDispatchResult::Local(accepted))) => {
                        (accepted.stream, accepted.sni)
                    },
                    Ok(Ok(sni_fallback::SniDispatchResult::Backend {
                        backend_idx,
                        inbound,
                        buffered,
                        sni,
                    })) => {
                        let backend = &ctx.config.backends[backend_idx];
                        debug!(
                            ?peer_addr,
                            ?sni,
                            backend = %backend.authority,
                            "splicing foreign SNI to backend",
                        );
                        let _ = sni_fallback::splice_to_backend(
                            backend,
                            ctx.inbound_listen,
                            inbound,
                            peer_addr,
                            buffered,
                        )
                        .await;
                        return;
                    },
                    Ok(Ok(sni_fallback::SniDispatchResult::Dropped)) => return,
                    Ok(Err(_)) => return,
                    Err(_elapsed) => {
                        // Pre-auth budget spent before a complete ClientHello
                        // arrived: a peer that connected and then went silent
                        // or dribbled bytes (slowloris). Count it under the
                        // SNI-peek failure series and drop the connection,
                        // freeing the permit `_permit` holds.
                        metrics.record_sni_peek_failed("timeout");
                        debug!(
                            %peer_addr,
                            "sni_fallback peek exceeded pre-auth timeout; dropping connection",
                        );
                        return;
                    },
                }
            } else {
                (sni_fallback::PrependStream::new(Vec::new(), stream), None)
            };

            let handshake = tokio::select! {
                biased;
                _ = task_shutdown.cancelled() => {
                    debug!(%peer_addr, "aborting TLS handshake on shutdown");
                    return;
                }
                res = timeout_at(preauth_deadline, acceptor.accept(stream_for_handshake)) => res,
            };
            let tls_stream = match handshake {
                Err(_elapsed) => {
                    // Pre-auth budget spent inside the rustls handshake: a peer
                    // that got past the peek but then stalled the key exchange.
                    // Count it under the TLS-handshake failure series and drop
                    // the connection, freeing the permit `_permit` holds.
                    metrics.record_tls_handshake_failed("timeout");
                    debug!(
                        %peer_addr,
                        "tls handshake exceeded pre-auth timeout; dropping connection",
                    );
                    return;
                },
                Ok(res) => match res {
                    Ok(s) => s,
                    Err(error) => {
                        let reason = classify_tls_handshake_error(&error);
                        metrics.record_tls_handshake_failed(reason.as_str());
                        // For `no_cert_chain` also record the rejected
                        // SNI on a separate per-SNI counter so the
                        // dashboard can break failures down by
                        // hostname for config-gap diagnosis.
                        // Cardinality is bounded inside the metrics
                        // layer (`<overflow>` bucket past the cap).
                        if matches!(reason, TlsHandshakeFailReason::NoCertChain) {
                            metrics.record_tls_handshake_no_cert_chain(peeked_sni.as_deref());
                        }
                        // `closed_early` and `no_cert_chain` are noisy
                        // under scanners and broken-but-harmless
                        // clients. Keep them as `debug` — the metric
                        // still surfaces them on the dashboard. Real
                        // protocol/IO failures stay at `warn` since
                        // they almost always point at a bug or
                        // misconfigured peer.
                        match reason {
                            TlsHandshakeFailReason::ClosedEarly
                            | TlsHandshakeFailReason::NoCertChain => {
                                debug!(
                                    ?error,
                                    %peer_addr,
                                    sni = ?peeked_sni,
                                    reason = reason.as_str(),
                                    "tls handshake failed",
                                );
                            },
                            TlsHandshakeFailReason::ProtocolError
                            | TlsHandshakeFailReason::IoError => {
                                warn!(
                                    ?error,
                                    %peer_addr,
                                    sni = ?peeked_sni,
                                    reason = reason.as_str(),
                                    "tls handshake failed",
                                );
                            },
                        }
                        return;
                    },
                },
            };

            // The handshake is done, but nothing has been asked for yet, and
            // the permit is still held: bound the wait for the first request.
            // What bounds it depends on the negotiated protocol.
            let first_request_timeout = tls_first_request_timeout();
            let alpn = PostHandshakeProtocol::from_alpn(tls_stream.get_ref().1.alpn_protocol());
            let io = TokioIo::new(FirstBytesDeadline::new(
                tls_stream,
                alpn.required_first_bytes(),
                first_request_timeout,
            ));
            // Inject `ConnectInfo<SocketAddr>` so the TCP-WS upgrade
            // handler can key the per-route peer-user hint cache the
            // same way the plain (non-TLS) path does.
            let app_with_addr = app.layer(axum::Extension(axum::extract::ConnectInfo(peer_addr)));
            let service = TowerToHyperService::new(app_with_addr);
            let builder = build_http_server_builder(&profile, Some(first_request_timeout));
            let builder = match alpn {
                PostHandshakeProtocol::Http1 => builder.http1_only(),
                PostHandshakeProtocol::Http2 => builder.http2_only(),
                PostHandshakeProtocol::Unknown => builder,
            };
            let conn = builder.serve_connection_with_upgrades(io, service);
            tokio::pin!(conn);

            let result = tokio::select! {
                biased;
                res = conn.as_mut() => res,
                _ = task_shutdown.cancelled() => {
                    conn.as_mut().graceful_shutdown();
                    conn.as_mut().await
                }
            };
            if let Err(error) = result
                && !is_benign_http_serve_error(error.as_ref())
            {
                warn!(?error, %peer_addr, "tls http server connection terminated with error");
            }
        });
    }

    let drain_timeout = Duration::from_secs(HTTP_GRACEFUL_SHUTDOWN_TIMEOUT_SECS);
    let drain =
        tokio::time::timeout(drain_timeout, async { while tasks.join_next().await.is_some() {} })
            .await;
    if drain.is_err() {
        warn!(
            remaining = tasks.len(),
            timeout_secs = HTTP_GRACEFUL_SHUTDOWN_TIMEOUT_SECS,
            "TLS connections did not drain within shutdown timeout; aborting"
        );
        tasks.shutdown().await;
    } else {
        debug!("TLS listener drained all connections");
    }
    Ok(())
}

fn build_http_server_builder(
    profile: &TuningProfile,
    header_read_timeout: Option<Duration>,
) -> HyperBuilder<TokioExecutor> {
    let mut builder = HyperBuilder::new(TokioExecutor::new());
    if let Some(read_timeout) = header_read_timeout {
        // `header_read_timeout` panics without an HTTP/1 timer, so set one on
        // the same sub-builder. The plain listener wires this to bound slow
        // header delivery; the TLS path passes `None` (its pre-auth handshake
        // budget already covers the unauthenticated phase).
        builder
            .http1()
            .timer(TokioTimer::new())
            .header_read_timeout(Some(read_timeout));
    }
    builder
        .http2()
        .timer(TokioTimer::new())
        .enable_connect_protocol()
        .max_concurrent_streams(H2_CADDY_MAX_CONCURRENT_STREAMS)
        .max_frame_size(H2_CADDY_MAX_FRAME_SIZE)
        .max_header_list_size(H2_CADDY_MAX_HEADER_LIST_SIZE)
        .initial_stream_window_size(Some(profile.h2_stream_window_bytes))
        .initial_connection_window_size(Some(profile.h2_connection_window_bytes))
        .max_send_buf_size(profile.h2_max_send_buf_size)
        .keep_alive_interval(Some(Duration::from_secs(45)))
        .keep_alive_timeout(Duration::from_secs(20));
    builder
}

/// Checks whether peeked initial socket bytes look like a plaintext HTTP request method
/// (matching Go's `tlsRecordHeaderLooksLikeHTTP`).
pub(super) fn is_plain_http_request(peeked: &[u8]) -> bool {
    let methods: &[&[u8]] = &[
        b"GET ",
        b"HEAD ",
        b"POST ",
        b"PUT ",
        b"OPTIONS ",
        b"DELETE ",
        b"PATCH ",
        b"TRACE ",
        b"CONNECT ",
    ];
    if peeked.len() < 4 {
        return false;
    }
    methods.iter().any(|m| {
        let len = m.len().min(peeked.len());
        peeked[..len] == m[..len]
    })
}

fn is_benign_http_serve_error(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(cause) = source {
        if let Some(hy) = cause.downcast_ref::<hyper::Error>()
            && (hy.is_canceled() || hy.is_incomplete_message() || hy.is_closed())
        {
            return true;
        }
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            use std::io::ErrorKind::*;
            if matches!(io.kind(), ConnectionReset | BrokenPipe | UnexpectedEof | ConnectionAborted,)
            {
                return true;
            }
        }
        source = cause.source();
    }
    false
}

/// Bucket for `outline_ss_tls_handshake_failed_total{reason=...}`.
/// Stays in lockstep with the values documented on
/// [`Metrics::record_tls_handshake_failed`].
#[derive(Debug, Clone, Copy)]
pub(super) enum TlsHandshakeFailReason {
    ClosedEarly,
    NoCertChain,
    ProtocolError,
    IoError,
}

impl TlsHandshakeFailReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::ClosedEarly => "closed_early",
            Self::NoCertChain => "no_cert_chain",
            Self::ProtocolError => "protocol_error",
            Self::IoError => "io_error",
        }
    }
}

/// Classify a `tokio_rustls` handshake error into a metric/log bucket.
///
/// `closed_early` is the classic peer-aborted-during-handshake case
/// (RST/FIN/EOF). `no_cert_chain` is rustls' specific signal that
/// `ResolvesServerCert::resolve` returned `None` — almost always a
/// config gap (a SNI was admitted by `[sni_fallback].match_sni` but
/// not registered in `[[server.certs]]`, or no default cert). The
/// remaining rustls protocol errors land in `protocol_error`; raw
/// `io::Error` kinds we don't recognise become `io_error`.
pub(super) fn classify_tls_handshake_error(error: &std::io::Error) -> TlsHandshakeFailReason {
    use std::io::ErrorKind::*;
    match error.kind() {
        UnexpectedEof | ConnectionReset | BrokenPipe | ConnectionAborted => {
            TlsHandshakeFailReason::ClosedEarly
        },
        InvalidData => {
            // rustls wraps its own `Error` inside `io::Error::other`
            // (or `io::Error::new(InvalidData, _)` depending on the
            // path). Downcast to spot the `Error::General(...)`
            // emitted from `server::hs` when the cert resolver yields
            // `None`. The text is matched verbatim because rustls
            // does not export this variant by name; if the upstream
            // string changes the bucket falls back to
            // `protocol_error` and we keep the metric without the
            // misclassification.
            if let Some(inner) = error.get_ref().and_then(|e| e.downcast_ref::<rustls::Error>())
                && let rustls::Error::General(msg) = inner
                && msg == "no server certificate chain resolved"
            {
                return TlsHandshakeFailReason::NoCertChain;
            }
            TlsHandshakeFailReason::ProtocolError
        },
        _ => TlsHandshakeFailReason::IoError,
    }
}

#[cfg(test)]
#[path = "tests/axum.rs"]
mod tests;
