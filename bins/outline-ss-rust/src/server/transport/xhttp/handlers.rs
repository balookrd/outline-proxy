//! axum (HTTP/1.1 + HTTP/2) entry points for XHTTP packet-up.
//!
//! Wired as a single `any` handler per configured base path. The
//! handler dispatches on `Method`: `GET` opens (or resumes) the
//! downlink stream, `POST` enqueues an uplink packet identified
//! by `X-Xhttp-Seq`. Both paths share `XhttpAxumState`, which
//! carries the per-process registry plus the VLESS server/route
//! context needed to spawn the relay task on first contact.

use std::collections::VecDeque;
use std::sync::Arc;

use axum::{
    body::Body,
    extract::{ConnectInfo, OriginalUri, Path, State},
    http::{HeaderMap, Method, StatusCode, Uri, Version},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use futures_util::stream::unfold;
use std::net::SocketAddr;
use tracing::{debug, warn};

use crate::metrics::{AppProtocol, Protocol, Transport};

use super::super::super::state::{AppState, Services, TransportRoute, VlessTransportRoute};
use super::super::resume_headers::{ResumeContext, ResumeResponseEcho};
use super::super::tcp::{WsTcpRouteCtx, run_tcp_relay};
use super::super::vless::{VlessWsRouteCtx, run_vless_relay};
use super::super::{finish_ws_session, is_normal_h3_shutdown, sink};
use super::padding::post_response_headers;
use super::{
    AttachOutcome, FIN_HEADER, SEQ_HEADER, UplinkIngestError, XhttpDuplex, XhttpRegistry,
    XhttpSession, XhttpSubmode, generate_anonymous_session_id, generate_padding_header,
    is_valid_session_id, masquerade_response_headers,
};

/// Cap on the bytes a single POST may carry, to bound memory per
/// request. 256 KiB matches `xray`'s default `scMaxEachPostBytes`
/// upper end and is well above a single TCP MSS, so per-request
/// overhead stays small at typical chunk sizes.
const MAX_POST_BYTES: usize = 256 * 1024;

/// Which application protocol a given XHTTP base path carries. Fixed at
/// route-registration time — one base path serves exactly one protocol —
/// and threaded into every handler so `resolve_route` / `spawn_relay`
/// pick the matching route table and relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::server) enum XhttpAppProtocol {
    Vless,
    Ss,
}

/// State threaded into every XHTTP axum handler. `registry` + `parent`
/// (which carries the per-path route tables and the VLESS/SS server
/// contexts) plus `protocol` are enough to spawn a relay task on first
/// contact and to look up the per-path authentication context.
#[derive(Clone)]
pub(in crate::server) struct XhttpAxumState {
    pub(in crate::server) base_path: Arc<str>,
    pub(in crate::server) protocol: XhttpAppProtocol,
    pub(in crate::server) registry: Arc<XhttpRegistry>,
    pub(in crate::server) parent: AppState,
}

/// A resolved XHTTP route, typed by the protocol the base path carries.
/// Unifies the lookup so the early-404 check stays protocol-agnostic
/// while `spawn_relay` still gets the concrete route record it needs.
/// Shared with the h3 entry point, which builds it from its own
/// per-connection route tables.
#[derive(Clone)]
pub(in crate::server) enum XhttpRoute {
    Vless(Arc<VlessTransportRoute>),
    Ss(Arc<TransportRoute>),
}

/// axum-extracted pieces of a single XHTTP request, bundled so the
/// method/submode dispatcher below stays within a readable arity.
struct XhttpHttpRequest {
    uri: Uri,
    method: Method,
    version: Version,
    headers: HeaderMap,
    peer_addr: SocketAddr,
    body: Body,
}

/// ANY-method handler for the `<base>/<session-id>` route shape.
/// Used by every XHTTP request that does not carry an upload-side
/// sequence number in the URL path — that is: every GET, every
/// stream-one POST, and packet-up POSTs from clients that put `seq`
/// into the `X-Xhttp-Seq` header instead of the URL.
#[allow(clippy::too_many_arguments)]
pub(in crate::server) async fn xhttp_handler(
    State(state): State<XhttpAxumState>,
    Path(session_id): Path<String>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    version: Version,
    headers: HeaderMap,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    body: Body,
) -> Response {
    let request = XhttpHttpRequest {
        uri,
        method,
        version,
        headers,
        peer_addr,
        body,
    };
    dispatch_xhttp(state, session_id, None, request).await
}

/// ANY-method handler for the bare-`<base>` route shape — the
/// xray / sing-box wire format for stream-one carriers that
/// dial without a client-supplied session id (xray's client passes
/// `sessionId=""` to `OpenStream` for `mode = "stream-one"`, and
/// `ApplyMetaToRequest` simply skips the path-append when the id
/// is empty, leaving the URL at `<base>` / `<base>/`). Each
/// stream-one carrier is fully self-contained — request body =
/// uplink, response body = downlink, no companion GET — so a
/// fresh server-side id per request is correct: nothing else has
/// to attach to that registry slot.
pub(in crate::server) async fn xhttp_handler_no_session(
    State(state): State<XhttpAxumState>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    version: Version,
    headers: HeaderMap,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    body: Body,
) -> Response {
    // Only POST makes sense on this shape — GET against `<base>` is
    // a misrouted client (the carrier needs an id to attach the
    // downlink slot to anything reusable).
    if method != Method::POST {
        return short_status(StatusCode::METHOD_NOT_ALLOWED);
    }
    let session_id = generate_anonymous_session_id();
    let request = XhttpHttpRequest {
        uri,
        method,
        version,
        headers,
        peer_addr,
        body,
    };
    dispatch_xhttp(state, session_id, None, request).await
}

/// ANY-method handler for the `<base>/<session-id>/<seq>` route
/// shape — the xray / sing-box default for packet-up uplink POSTs.
/// `seq` is taken from the URL path; the `X-Xhttp-Seq` header is
/// ignored on this route. GET / stream-one on this shape is
/// malformed and returns 400.
#[allow(clippy::too_many_arguments)]
pub(in crate::server) async fn xhttp_handler_with_path_seq(
    State(state): State<XhttpAxumState>,
    Path((session_id, seq)): Path<(String, u64)>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    version: Version,
    headers: HeaderMap,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    body: Body,
) -> Response {
    let request = XhttpHttpRequest {
        uri,
        method,
        version,
        headers,
        peer_addr,
        body,
    };
    dispatch_xhttp(state, session_id, Some(seq), request).await
}

async fn dispatch_xhttp(
    state: XhttpAxumState,
    session_id: String,
    path_seq: Option<u64>,
    request: XhttpHttpRequest,
) -> Response {
    let XhttpHttpRequest {
        uri,
        method,
        version,
        headers,
        peer_addr,
        body,
    } = request;
    if !is_valid_session_id(&session_id) {
        return short_status(StatusCode::BAD_REQUEST);
    }
    // The `?mode=` query selector is our access-key generator's own
    // hint — xray / sing-box clients do not echo it on the wire.
    // The wire-format that xray emits is fully implicit: POST with a
    // seq → packet-up uplink, POST without a seq → stream-one /
    // stream-up uplink (xray's `ApplyMetaToRequest` simply omits the
    // seq segment for the non-packet-up carriers). So we let an
    // explicit `?mode=stream-one` pin the carrier when present, but
    // when it is absent we fall back to the "seq presence picks the
    // carrier" rule — that is what every xray-family client actually
    // produces.
    let submode = XhttpSubmode::parse_query(uri.query());
    match method {
        Method::GET => {
            // `<base>/<id>/<seq>` is uplink-only; a GET on this
            // shape means the client wired the route wrong.
            if path_seq.is_some() {
                return short_status(StatusCode::BAD_REQUEST);
            }
            match submode {
                XhttpSubmode::PacketUp => {
                    xhttp_get(state, session_id, version, peer_addr, &headers).await
                },
                // GET on `?mode=stream-one` is malformed — the
                // carrier is a single bidirectional POST, not a GET.
                XhttpSubmode::StreamOne => short_status(StatusCode::BAD_REQUEST),
            }
        },
        Method::POST => {
            let seq = path_seq.or_else(|| parse_seq(&headers));
            match submode {
                XhttpSubmode::StreamOne => {
                    // Explicit stream-one MUST NOT carry a seq —
                    // mismatch is a client bug, not silent fallback.
                    if seq.is_some() {
                        return short_status(StatusCode::BAD_REQUEST);
                    }
                    xhttp_stream_one(state, session_id, version, peer_addr, headers, body).await
                },
                XhttpSubmode::PacketUp => match seq {
                    Some(_) => {
                        xhttp_post(state, session_id, path_seq, version, peer_addr, headers, body)
                            .await
                    },
                    // No seq, no `?mode=` — the xray default for
                    // stream-one / stream-up. Our stream-one handler
                    // accepts both shapes (it drains the request
                    // body chunk-by-chunk), so `stream-up` mode
                    // clients land here too without extra wiring.
                    None => {
                        xhttp_stream_one(state, session_id, version, peer_addr, headers, body).await
                    },
                },
            }
        },
        _ => short_status(StatusCode::METHOD_NOT_ALLOWED),
    }
}

async fn xhttp_get(
    state: XhttpAxumState,
    session_id: String,
    version: Version,
    peer_addr: SocketAddr,
    headers: &HeaderMap,
) -> Response {
    let route = match resolve_route(&state) {
        Some(route) => route,
        None => {
            warn!(
                base = %state.base_path,
                "no vless route configured for xhttp base path; rejecting GET"
            );
            return short_status(StatusCode::NOT_FOUND);
        },
    };

    let protocol = protocol_from_http_version(version);
    // Parse the resume headers up-front so the create branch below
    // can mint an `issued_session_id` exactly once and stash it in
    // the session for any subsequent reconnect-attach to read back.
    let resume_for_create = ResumeContext::from_request_headers(
        headers,
        &state.parent.services.vless_server.orphan_registry,
    );
    // Snapshot the Ack-Prefix capability bit BEFORE `resume_for_create`
    // moves into `spawn_relay` — the field is still needed by the
    // response-header echo at the bottom of this handler.
    let ack_prefix_for_response = resume_for_create.ack_prefix_requested;
    // v2 Symmetric Downlink Replay echo. Gated at parse time on
    // (a) v1 also requested and (b) registry has v2 capacity, so a
    // true value here is safe to surface in the response.
    let symmetric_replay_for_response = resume_for_create.symmetric_replay_requested;
    let (session, created) = state
        .registry
        .get_or_create(&session_id, resume_for_create.issued_session_id);

    if created {
        spawn_relay(
            Arc::clone(&session),
            &state.parent.services,
            Arc::clone(&state.registry),
            route,
            Arc::clone(&state.base_path),
            protocol,
            peer_addr,
            resume_for_create,
        );
    }

    match session.try_attach_get() {
        AttachOutcome::Ok => {},
        AttachOutcome::Conflict => return short_status(StatusCode::CONFLICT),
        AttachOutcome::Gone => return short_status(StatusCode::GONE),
    }

    debug!(
        method = "GET", ?version, base = %state.base_path, %peer_addr,
        session = %session_id, created,
        "xhttp downlink attached"
    );

    let echo = ResumeResponseEcho {
        session_id: session.issued_resume_id,
        ack_prefix: ack_prefix_for_response,
        symmetric_replay: symmetric_replay_for_response,
    };
    let body = build_downlink_body(Arc::clone(&session));
    let mut response = (StatusCode::OK, body).into_response();
    apply_response_masquerade(response.headers_mut());
    echo.apply(response.headers_mut());
    response
}

async fn xhttp_post(
    state: XhttpAxumState,
    session_id: String,
    path_seq: Option<u64>,
    version: Version,
    peer_addr: SocketAddr,
    headers: HeaderMap,
    body: Body,
) -> Response {
    // Path-based seq (xray / sing-box default placement) wins over
    // the header-based seq, so a client that supplies both does not
    // get a silent disagreement between the two — the URL is the
    // authoritative one in that case.
    let seq = match path_seq.or_else(|| parse_seq(&headers)) {
        Some(seq) => seq,
        None => return short_status(StatusCode::BAD_REQUEST),
    };
    let fin = headers.contains_key(FIN_HEADER);

    let route = match resolve_route(&state) {
        Some(route) => route,
        None => return short_status(StatusCode::NOT_FOUND),
    };
    let protocol = protocol_from_http_version(version);

    // Parse resume headers exactly once. If we end up creating the
    // session below, the minted `issued_session_id` is stashed in
    // `XhttpSession` for every later attach to surface in its
    // response; if we attach to an existing session, this context
    // is dropped — the resume token has been negotiated already by
    // whatever request created the session.
    let resume_for_create = ResumeContext::from_request_headers(
        &headers,
        &state.parent.services.vless_server.orphan_registry,
    );
    // Snapshot before the move into `spawn_relay`. Same rationale as
    // in `xhttp_get`: the response-header echo at the bottom needs
    // the field after `resume_for_create` is gone.
    let ack_prefix_for_response = resume_for_create.ack_prefix_requested;
    // v2 Symmetric Downlink Replay echo. Gated at parse time on
    // (a) v1 also requested and (b) registry has v2 capacity, so a
    // true value here is safe to surface in the response.
    let symmetric_replay_for_response = resume_for_create.symmetric_replay_requested;

    // Auto-create on seq=0 so a client that POSTs before its GET
    // is allowed to establish the session. Refuse seq>0 against a
    // dead session — at that point the client is replaying old
    // packets to a registry slot that has been swept.
    let (session, created) = if seq == 0 {
        state
            .registry
            .get_or_create(&session_id, resume_for_create.issued_session_id)
    } else {
        match state.registry.get(&session_id) {
            Some(s) => (s, false),
            None => return short_status(StatusCode::GONE),
        }
    };

    if session.is_closed() {
        return short_status(StatusCode::GONE);
    }

    if created {
        spawn_relay(
            Arc::clone(&session),
            &state.parent.services,
            Arc::clone(&state.registry),
            route,
            Arc::clone(&state.base_path),
            protocol,
            peer_addr,
            resume_for_create,
        );
    }

    let bytes = match axum::body::to_bytes(body, MAX_POST_BYTES).await {
        Ok(bytes) => bytes,
        Err(error) => {
            debug!(?error, session = %session_id, "xhttp POST body too large or aborted");
            return short_status(StatusCode::PAYLOAD_TOO_LARGE);
        },
    };

    debug!(
        method = "POST", ?version, base = %state.base_path, %peer_addr,
        session = %session_id, seq, len = bytes.len(), fin,
        "xhttp uplink chunk"
    );

    if let Err(error) = session.ingest_uplink(seq, bytes) {
        match error {
            UplinkIngestError::Closed => return short_status(StatusCode::GONE),
            UplinkIngestError::GapTooLarge { expected, got } => {
                warn!(session = %session_id, expected, got, "xhttp uplink seq gap too large; tearing down");
                session.close();
                state.registry.remove(&session_id);
                return short_status(StatusCode::CONFLICT);
            },
            UplinkIngestError::BufferFull => {
                return short_status(StatusCode::SERVICE_UNAVAILABLE);
            },
        }
    }
    if fin {
        session.close_uplink();
    }

    let mut response = StatusCode::OK.into_response();
    let resp_headers = response.headers_mut();
    for (name, value) in post_response_headers() {
        resp_headers.insert(name, value);
    }
    if let Some((name, value)) = generate_padding_header() {
        resp_headers.insert(name, value);
    }
    ResumeResponseEcho {
        session_id: session.issued_resume_id,
        ack_prefix: ack_prefix_for_response,
        symmetric_replay: symmetric_replay_for_response,
    }
    .apply(resp_headers);
    response
}

/// Stream-one carrier on h2: a single bidirectional POST whose
/// request body carries the uplink and whose response body carries
/// the downlink. Falls back with a clear status when h1 is the
/// negotiated version, since plain HTTP/1.1 cannot full-duplex.
async fn xhttp_stream_one(
    state: XhttpAxumState,
    session_id: String,
    version: Version,
    peer_addr: SocketAddr,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if matches!(version, Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11) {
        // Stream-one needs h2 frame interleaving (or h3) to send
        // response frames before the request body has been fully
        // consumed. Reject loudly so the client switches to packet-up.
        return short_status(StatusCode::HTTP_VERSION_NOT_SUPPORTED);
    }
    let route = match resolve_route(&state) {
        Some(route) => route,
        None => {
            warn!(
                base = %state.base_path,
                "no vless route configured for xhttp base path; rejecting stream-one"
            );
            return short_status(StatusCode::NOT_FOUND);
        },
    };
    let protocol = protocol_from_http_version(version);
    let resume_for_create = ResumeContext::from_request_headers(
        &headers,
        &state.parent.services.vless_server.orphan_registry,
    );
    // Snapshot before the move into `spawn_relay`. Same pattern as
    // `xhttp_get` / `xhttp_post`.
    let ack_prefix_for_response = resume_for_create.ack_prefix_requested;
    // v2 Symmetric Downlink Replay echo. Gated at parse time on
    // (a) v1 also requested and (b) registry has v2 capacity, so a
    // true value here is safe to surface in the response.
    let symmetric_replay_for_response = resume_for_create.symmetric_replay_requested;
    let (session, created) = state
        .registry
        .get_or_create(&session_id, resume_for_create.issued_session_id);
    if session.is_closed() {
        return short_status(StatusCode::GONE);
    }
    if created {
        spawn_relay(
            Arc::clone(&session),
            &state.parent.services,
            Arc::clone(&state.registry),
            route,
            Arc::clone(&state.base_path),
            protocol,
            peer_addr,
            resume_for_create,
        );
    }
    // Claim the downlink slot so a parallel packet-up GET on the
    // same id cannot race for the response body. A second
    // stream-one POST gets 409 just like the GET case.
    match session.try_attach_get() {
        AttachOutcome::Ok => {},
        AttachOutcome::Conflict => return short_status(StatusCode::CONFLICT),
        AttachOutcome::Gone => return short_status(StatusCode::GONE),
    }
    debug!(
        method = "POST", mode = "stream-one", ?version, base = %state.base_path,
        %peer_addr, session = %session_id, created,
        "xhttp stream-one duplex attached"
    );

    // Spawn the uplink pump: drain the request body frame-by-frame
    // and push each chunk into the session ring in order. The pump
    // closes the uplink half when the body ends so the relay sees
    // EOF and can decide whether to park or tear down.
    let session_for_uplink = Arc::clone(&session);
    tokio::spawn(async move {
        use http_body_util::BodyExt;
        let mut body = body;
        while let Some(frame) = body.frame().await {
            match frame {
                Ok(frame) => {
                    if let Ok(data) = frame.into_data() {
                        if data.is_empty() {
                            continue;
                        }
                        if session_for_uplink.ingest_uplink_inorder(data).is_err() {
                            break;
                        }
                    }
                },
                Err(error) => {
                    debug!(?error, "xhttp stream-one request body errored");
                    break;
                },
            }
        }
        session_for_uplink.close_uplink();
    });

    let echo = ResumeResponseEcho {
        session_id: session.issued_resume_id,
        ack_prefix: ack_prefix_for_response,
        symmetric_replay: symmetric_replay_for_response,
    };
    let body = build_downlink_body(Arc::clone(&session));
    let mut response = (StatusCode::OK, body).into_response();
    apply_response_masquerade(response.headers_mut());
    echo.apply(response.headers_mut());
    response
}

fn build_downlink_body(session: Arc<XhttpSession>) -> Body {
    // Stream straight from the session ring with no intermediate
    // mpsc: a chunk produced by `push_downlink` is drained here on
    // the next `poll_next`, which gives the h2 layer a direct line
    // of sight into the writer. When axum stops polling (slow or
    // disconnected client), `drain_downlink` is not called, the
    // ring fills, `push_downlink` parks, and the upstream TCP read
    // window collapses naturally. When the client disconnects, the
    // body future is dropped, so is `DownlinkStreamState`, and its
    // `Drop` releases the GET slot for a resumption-style reattach.
    let stream = unfold(
        DownlinkStreamState { session, queue: VecDeque::new() },
        |mut state| async move {
            loop {
                if let Some(chunk) = state.queue.pop_front() {
                    return Some((Ok::<_, std::io::Error>(chunk), state));
                }
                let mut buf: Vec<Bytes> = Vec::new();
                let closed = state.session.drain_downlink(&mut buf);
                state.queue.extend(buf);
                if let Some(chunk) = state.queue.pop_front() {
                    return Some((Ok(chunk), state));
                }
                if closed {
                    return None;
                }
                // Subscribe before re-checking so a chunk that lands
                // between the empty drain above and the await below
                // cannot lose its wake-up.
                let notified = state.session.downlink_notify.notified();
                let mut recheck: Vec<Bytes> = Vec::new();
                let closed_recheck = state.session.drain_downlink(&mut recheck);
                state.queue.extend(recheck);
                if !state.queue.is_empty() {
                    continue;
                }
                if closed_recheck {
                    return None;
                }
                notified.await;
            }
        },
    );
    Body::from_stream(stream)
}

/// Holds the GET-side reader state for the duration of a single
/// downlink HTTP body. Dropping it releases the GET slot — either
/// because the session closed and the stream ended naturally, or
/// because the client went away and axum dropped the body future
/// mid-stream. The latter case is the resumption hook: a fresh GET
/// on the same session id can reattach without waiting for the
/// idle eviction tick.
struct DownlinkStreamState {
    session: Arc<XhttpSession>,
    queue: VecDeque<Bytes>,
}

impl Drop for DownlinkStreamState {
    fn drop(&mut self) {
        self.session.detach_get();
    }
}

/// Spawn the per-session relay task for whichever protocol this base
/// path carries. VLESS rides `run_vless_relay`; SS rides the same
/// `run_tcp_relay` the WS path uses — both are generic over the
/// frame-oriented [`XhttpDuplex`] socket, so only the route context and
/// the metrics `AppProtocol` label differ.
#[allow(clippy::too_many_arguments)]
pub(in crate::server::transport::xhttp) fn spawn_relay(
    session: Arc<XhttpSession>,
    services: &Arc<Services>,
    registry: Arc<XhttpRegistry>,
    route: XhttpRoute,
    base_path: Arc<str>,
    protocol: Protocol,
    peer_addr: SocketAddr,
    resume: ResumeContext,
) {
    let session_for_task = Arc::clone(&session);
    let session_id = Arc::clone(&session.id);
    match route {
        XhttpRoute::Vless(route) => {
            let server = Arc::clone(&services.vless_server);
            let route_ctx = VlessWsRouteCtx {
                users: Arc::clone(&route.users),
                protocol,
                path: base_path,
                candidate_users: Arc::clone(&route.candidate_users),
            };
            let metrics_session =
                server
                    .metrics
                    .open_websocket_session(Transport::Tcp, protocol, AppProtocol::Vless);
            tokio::spawn(async move {
                let socket = XhttpDuplex { session: Arc::clone(&session_for_task) };
                let result =
                    run_vless_relay::<XhttpDuplex>(socket, &server, &route_ctx, resume).await;
                // Always drop the registry slot: even on a clean exit
                // the session id should not be reused for a fresh
                // handshake.
                session_for_task.close();
                registry.remove(&session_id);
                finish_ws_session(metrics_session, classify_relay_result(result), "vless");
            });
        },
        XhttpRoute::Ss(route) => {
            let server = Arc::clone(&services.tcp_server);
            let route_ctx = WsTcpRouteCtx {
                users: Arc::clone(&route.users),
                protocol,
                path: base_path,
                candidate_users: Arc::clone(&route.candidate_users),
                peer_user_cache: Arc::clone(&route.peer_user_cache),
            };
            let metrics_session = server.metrics.open_websocket_session(
                Transport::Tcp,
                protocol,
                AppProtocol::Shadowsocks,
            );
            tokio::spawn(async move {
                let socket = XhttpDuplex { session: Arc::clone(&session_for_task) };
                let result = run_tcp_relay::<XhttpDuplex>(
                    socket,
                    &server,
                    &route_ctx,
                    resume,
                    Some(peer_addr),
                )
                .await;
                session_for_task.close();
                registry.remove(&session_id);
                finish_ws_session(metrics_session, classify_relay_result(result), "ss");
            });
        },
    }
}

/// Demote benign h3-shutdown / probe-rejection so dashboards stay
/// consistent across transports. A no-op mapping today (both `Err`
/// arms return the error) but keeps the hooks wired for both relays.
fn classify_relay_result(result: anyhow::Result<()>) -> anyhow::Result<()> {
    match result {
        Ok(()) => Ok(()),
        Err(error) if is_normal_h3_shutdown(&error) || sink::is_handshake_rejected(&error) => {
            Err(error)
        },
        Err(error) => Err(error),
    }
}

fn parse_seq(headers: &HeaderMap) -> Option<u64> {
    headers.get(SEQ_HEADER)?.to_str().ok()?.trim().parse::<u64>().ok()
}

fn resolve_route(state: &XhttpAxumState) -> Option<XhttpRoute> {
    let routes_snap = state.parent.routes.load();
    let route = match state.protocol {
        XhttpAppProtocol::Vless => routes_snap
            .xhttp_vless
            .get(state.base_path.as_ref())
            .cloned()
            .map(XhttpRoute::Vless),
        XhttpAppProtocol::Ss => routes_snap
            .xhttp_ss
            .get(state.base_path.as_ref())
            .cloned()
            .map(XhttpRoute::Ss),
    };
    drop(routes_snap);
    route
}

fn protocol_from_http_version(version: Version) -> Protocol {
    // XHTTP is its own protocol family on the metrics dashboard:
    // map each HTTP version to its XHTTP-flavoured `Protocol`
    // variant rather than the generic Http1/Http2/Http3, so a
    // Grafana panel can split XHTTP from WebSocket-over-h*
    // cleanly. h1 is reachable for `mode=packet-up` (each packet
    // is its own short request, no full-duplex needed); stream-one
    // rejects h1 with 505 upstream and never lands here on h1.
    match version {
        Version::HTTP_2 => Protocol::XhttpH2,
        Version::HTTP_3 => Protocol::XhttpH3,
        _ => Protocol::XhttpH1,
    }
}

fn apply_response_masquerade(headers: &mut HeaderMap) {
    for (name, value) in masquerade_response_headers() {
        headers.insert(name, value);
    }
    if let Some((name, value)) = generate_padding_header() {
        headers.insert(name, value);
    }
}

fn short_status(status: StatusCode) -> Response {
    let mut response = status.into_response();
    if let Some((name, value)) = generate_padding_header() {
        response.headers_mut().insert(name, value);
    }
    response
}
