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

use super::super::super::state::AppState;
use super::super::tcp::{
    ACK_PREFIX_HEADER, ResumeContext, SESSION_RESPONSE_HEADER, SYMMETRIC_REPLAY_HEADER,
};
use super::super::vless::{VlessWsRouteCtx, VlessWsServerCtx, run_vless_relay};
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

/// State threaded into every XHTTP axum handler. The triple of
/// `registry` + `vless_server` + `routes` is enough to spawn a
/// relay task on first contact and to look up the per-path
/// authentication context.
#[derive(Clone)]
pub(in crate::server) struct XhttpAxumState {
    pub(in crate::server) base_path: Arc<str>,
    pub(in crate::server) registry: Arc<XhttpRegistry>,
    pub(in crate::server) parent: AppState,
}

/// ANY-method handler for the `<base>/<session-id>` route shape.
/// Used by every XHTTP request that does not carry an upload-side
/// sequence number in the URL path — that is: every GET, every
/// stream-one POST, and packet-up POSTs from clients that put `seq`
/// into the `X-Xhttp-Seq` header instead of the URL.
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
    dispatch_xhttp(state, session_id, None, uri, method, version, headers, peer_addr, body).await
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
    dispatch_xhttp(state, session_id, None, uri, method, version, headers, peer_addr, body).await
}

/// ANY-method handler for the `<base>/<session-id>/<seq>` route
/// shape — the xray / sing-box default for packet-up uplink POSTs.
/// `seq` is taken from the URL path; the `X-Xhttp-Seq` header is
/// ignored on this route. GET / stream-one on this shape is
/// malformed and returns 400.
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
    dispatch_xhttp(state, session_id, Some(seq), uri, method, version, headers, peer_addr, body)
        .await
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_xhttp(
    state: XhttpAxumState,
    session_id: String,
    path_seq: Option<u64>,
    uri: Uri,
    method: Method,
    version: Version,
    headers: HeaderMap,
    peer_addr: SocketAddr,
    body: Body,
) -> Response {
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
    let submode = XhttpSubmode::parse(uri.query());
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
            Arc::clone(&state.parent.services.vless_server),
            Arc::clone(&state.registry),
            VlessWsRouteCtx {
                users: Arc::clone(&route.users),
                protocol,
                path: Arc::clone(&state.base_path),
                candidate_users: Arc::clone(&route.candidate_users),
            },
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

    let issued_for_response = session.issued_resume_id;
    let body = build_downlink_body(Arc::clone(&session));
    let mut response = (StatusCode::OK, body).into_response();
    apply_response_masquerade(response.headers_mut());
    if let Some(id) = issued_for_response
        && let Ok(value) = axum::http::HeaderValue::from_str(&id.to_hex())
    {
        response.headers_mut().insert(SESSION_RESPONSE_HEADER, value);
    }
    if ack_prefix_for_response {
        response
            .headers_mut()
            .insert(ACK_PREFIX_HEADER, axum::http::HeaderValue::from_static("1"));
    }
    if symmetric_replay_for_response {
        response
            .headers_mut()
            .insert(SYMMETRIC_REPLAY_HEADER, axum::http::HeaderValue::from_static("1"));
    }
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
            Arc::clone(&state.parent.services.vless_server),
            Arc::clone(&state.registry),
            VlessWsRouteCtx {
                users: Arc::clone(&route.users),
                protocol,
                path: Arc::clone(&state.base_path),
                candidate_users: Arc::clone(&route.candidate_users),
            },
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
    if let Some(id) = session.issued_resume_id
        && let Ok(value) = axum::http::HeaderValue::from_str(&id.to_hex())
    {
        resp_headers.insert(SESSION_RESPONSE_HEADER, value);
    }
    if ack_prefix_for_response {
        resp_headers.insert(ACK_PREFIX_HEADER, axum::http::HeaderValue::from_static("1"));
    }
    if symmetric_replay_for_response {
        resp_headers.insert(SYMMETRIC_REPLAY_HEADER, axum::http::HeaderValue::from_static("1"));
    }
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
            Arc::clone(&state.parent.services.vless_server),
            Arc::clone(&state.registry),
            VlessWsRouteCtx {
                users: Arc::clone(&route.users),
                protocol,
                path: Arc::clone(&state.base_path),
                candidate_users: Arc::clone(&route.candidate_users),
            },
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

    let issued_for_response = session.issued_resume_id;
    let body = build_downlink_body(Arc::clone(&session));
    let mut response = (StatusCode::OK, body).into_response();
    apply_response_masquerade(response.headers_mut());
    if let Some(id) = issued_for_response
        && let Ok(value) = axum::http::HeaderValue::from_str(&id.to_hex())
    {
        response.headers_mut().insert(SESSION_RESPONSE_HEADER, value);
    }
    if ack_prefix_for_response {
        response
            .headers_mut()
            .insert(ACK_PREFIX_HEADER, axum::http::HeaderValue::from_static("1"));
    }
    if symmetric_replay_for_response {
        response
            .headers_mut()
            .insert(SYMMETRIC_REPLAY_HEADER, axum::http::HeaderValue::from_static("1"));
    }
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

fn spawn_relay(
    session: Arc<XhttpSession>,
    server: Arc<VlessWsServerCtx>,
    registry: Arc<XhttpRegistry>,
    route_ctx: VlessWsRouteCtx,
    resume: ResumeContext,
) {
    let session_for_task = Arc::clone(&session);
    let session_id = Arc::clone(&session.id);
    let metrics_session = server.metrics.open_websocket_session(
        Transport::Tcp,
        route_ctx.protocol,
        AppProtocol::Vless,
    );
    tokio::spawn(async move {
        let socket = XhttpDuplex { session: Arc::clone(&session_for_task) };
        let result = run_vless_relay::<XhttpDuplex>(socket, &server, &route_ctx, resume).await;
        // Always drop the registry slot: even on a clean exit the
        // session id should not be reused for a fresh handshake.
        session_for_task.close();
        registry.remove(&session_id);
        // Demote benign h3-shutdown / probe-rejection through the
        // same classifier the WS path uses, so dashboards stay
        // consistent across transports.
        let mapped: anyhow::Result<()> = match result {
            Ok(()) => Ok(()),
            Err(error) if is_normal_h3_shutdown(&error) || sink::is_handshake_rejected(&error) => {
                Err(error)
            },
            Err(error) => Err(error),
        };
        finish_ws_session(metrics_session, mapped, "vless");
    });
}

fn parse_seq(headers: &HeaderMap) -> Option<u64> {
    headers.get(SEQ_HEADER)?.to_str().ok()?.trim().parse::<u64>().ok()
}

fn resolve_route(state: &XhttpAxumState) -> Option<Arc<crate::server::state::VlessTransportRoute>> {
    let routes_snap = state.parent.routes.load();
    let route = routes_snap.xhttp_vless.get(state.base_path.as_ref()).cloned();
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
