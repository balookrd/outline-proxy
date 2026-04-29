//! axum (HTTP/1.1 + HTTP/2) entry points for XHTTP packet-up.
//!
//! Wired as a single `any` handler per configured base path. The
//! handler dispatches on `Method`: `GET` opens (or resumes) the
//! downlink stream, `POST` enqueues an uplink packet identified
//! by `X-Xhttp-Seq`. Both paths share `XhttpAxumState`, which
//! carries the per-process registry plus the VLESS server/route
//! context needed to spawn the relay task on first contact.

use std::sync::Arc;

use axum::{
    body::Body,
    extract::{ConnectInfo, OriginalUri, Path, State},
    http::{HeaderMap, Method, StatusCode, Version},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use futures_util::stream::unfold;
use std::net::SocketAddr;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::metrics::{AppProtocol, Protocol, Transport};

use super::super::super::state::AppState;
use super::super::tcp::{ResumeContext, SESSION_RESPONSE_HEADER};
use super::super::vless::{VlessWsRouteCtx, VlessWsServerCtx, run_vless_relay};
use super::super::{finish_ws_session, is_normal_h3_shutdown, sink};
use super::{
    AttachOutcome, FIN_HEADER, SEQ_HEADER, UplinkIngestError, XhttpDuplex, XhttpRegistry,
    XhttpSession, generate_padding_header, is_valid_session_id, masquerade_response_headers,
};
use super::padding::post_response_headers;

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

/// Single ANY-method handler. Dispatches on `Method` so we don't
/// duplicate state-extraction boilerplate between GET and POST.
pub(in crate::server) async fn xhttp_handler(
    State(state): State<XhttpAxumState>,
    Path(session_id): Path<String>,
    OriginalUri(_uri): OriginalUri,
    method: Method,
    version: Version,
    headers: HeaderMap,
    connect_info: ConnectInfo<SocketAddr>,
    body: Body,
) -> Response {
    let ConnectInfo(peer_addr) = connect_info;
    if !is_valid_session_id(&session_id) {
        return short_status(StatusCode::BAD_REQUEST);
    }
    match method {
        Method::GET => xhttp_get(state, session_id, version, peer_addr, &headers).await,
        Method::POST => xhttp_post(state, session_id, version, peer_addr, headers, body).await,
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
    let (session, created) = state.registry.get_or_create(
        &session_id,
        state.parent.services.vless_server.ws_data_channel_capacity,
        resume_for_create.issued_session_id,
    );

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
    response
}

async fn xhttp_post(
    state: XhttpAxumState,
    session_id: String,
    version: Version,
    peer_addr: SocketAddr,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let seq = match parse_seq(&headers) {
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

    // Auto-create on seq=0 so a client that POSTs before its GET
    // is allowed to establish the session. Refuse seq>0 against a
    // dead session — at that point the client is replaying old
    // packets to a registry slot that has been swept.
    let (session, created) = if seq == 0 {
        state.registry.get_or_create(
            &session_id,
            state.parent.services.vless_server.ws_data_channel_capacity,
            resume_for_create.issued_session_id,
        )
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
    response
}

fn build_downlink_body(session: Arc<XhttpSession>) -> Body {
    // Bridge the session ring to axum's Body via a bounded channel:
    // an internal task drains the ring on `downlink_notify` and
    // pushes chunks to the channel. axum drives the receiver until
    // either the session closes (drain task exits, channel closes)
    // or the client disconnects (channel send fails, drain task
    // detaches the GET slot so a future GET can reattach without
    // waiting for the idle eviction).
    let (chunk_tx, chunk_rx) = mpsc::channel::<Bytes>(8);
    let session_for_task = Arc::clone(&session);
    tokio::spawn(async move {
        let mut buf: Vec<Bytes> = Vec::new();
        let session = session_for_task;
        loop {
            buf.clear();
            let closed = session.drain_downlink(&mut buf);
            for chunk in buf.drain(..) {
                if chunk_tx.send(chunk).await.is_err() {
                    session.detach_get();
                    return;
                }
            }
            if closed {
                break;
            }
            let notified = session.downlink_notify.notified();
            if chunk_tx.is_closed() {
                session.detach_get();
                return;
            }
            tokio::pin!(notified);
            notified.await;
        }
        session.detach_get();
    });

    let stream = unfold(chunk_rx, |mut rx| async move {
        rx.recv().await.map(|chunk| (Ok::<_, std::io::Error>(chunk), rx))
    });
    Body::from_stream(stream)
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
    headers
        .get(SEQ_HEADER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
}

fn resolve_route(
    state: &XhttpAxumState,
) -> Option<Arc<crate::server::state::VlessTransportRoute>> {
    let routes_snap = state.parent.routes.load();
    let route = routes_snap.xhttp_vless.get(state.base_path.as_ref()).cloned();
    drop(routes_snap);
    route
}

fn protocol_from_http_version(version: Version) -> Protocol {
    match version {
        Version::HTTP_2 => Protocol::Http2,
        Version::HTTP_3 => Protocol::Http3,
        _ => Protocol::Http1,
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

