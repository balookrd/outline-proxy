//! HTTP/3 entry point for XHTTP packet-up.
//!
//! Mirrors `handlers::xhttp_handler` but speaks directly to the
//! h3 `RequestStream` because there is no axum body abstraction
//! at this layer. GET drives a long-lived `send_data` loop pinned
//! to the session ring; POST drains the request body, ingests one
//! reordered chunk into the uplink ring, and replies 200.

use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result, anyhow};
use axum::http::{self, HeaderMap, Method, StatusCode, Version};
use bytes::{Buf, Bytes, BytesMut};
use h3::server::RequestStream;
use h3_quinn::BidiStream;
use tracing::{debug, warn};

use crate::{
    metrics::{AppProtocol, Protocol, Transport},
    server::state::VlessTransportRoute,
};

use super::super::tcp::{ResumeContext, SESSION_RESPONSE_HEADER};
use super::super::vless::{VlessWsRouteCtx, VlessWsServerCtx, run_vless_relay};
use super::super::{finish_ws_session, is_normal_h3_shutdown, sink};
use super::{
    AttachOutcome, FIN_HEADER, SEQ_HEADER, UplinkIngestError, XhttpDuplex, XhttpRegistry,
    XhttpSession, generate_padding_header, is_valid_session_id, masquerade_response_headers,
};
use super::padding::post_response_headers;

const MAX_POST_BYTES: usize = 256 * 1024;

/// Dispatcher entry. Called from `h3/http.rs` once a non-CONNECT
/// request has been classified as XHTTP by path lookup. The
/// caller has already split the path into base + session id.
pub(in crate::server) async fn handle_xhttp_h3_request(
    request: http::Request<()>,
    stream: RequestStream<BidiStream<Bytes>, Bytes>,
    registry: Arc<XhttpRegistry>,
    vless_server: Arc<VlessWsServerCtx>,
    route: Arc<VlessTransportRoute>,
    base_path: Arc<str>,
    session_id: String,
    peer_addr: SocketAddr,
) -> Result<()> {
    if !is_valid_session_id(&session_id) {
        return finish_with_status(stream, StatusCode::BAD_REQUEST).await;
    }

    let method = request.method().clone();
    let headers = request.headers().clone();
    let version = request.version();

    match method {
        Method::GET => {
            xhttp_h3_get(
                stream,
                registry,
                vless_server,
                route,
                base_path,
                session_id,
                version,
                peer_addr,
                headers,
            )
            .await
        },
        Method::POST => {
            xhttp_h3_post(
                stream,
                headers,
                registry,
                vless_server,
                route,
                base_path,
                session_id,
                version,
                peer_addr,
            )
            .await
        },
        _ => finish_with_status(stream, StatusCode::METHOD_NOT_ALLOWED).await,
    }
}

#[allow(clippy::too_many_arguments)]
async fn xhttp_h3_get(
    mut stream: RequestStream<BidiStream<Bytes>, Bytes>,
    registry: Arc<XhttpRegistry>,
    vless_server: Arc<VlessWsServerCtx>,
    route: Arc<VlessTransportRoute>,
    base_path: Arc<str>,
    session_id: String,
    version: Version,
    peer_addr: SocketAddr,
    request_headers: HeaderMap,
) -> Result<()> {
    let protocol = protocol_from_h3_version(version);
    let resume_for_create =
        ResumeContext::from_request_headers(&request_headers, &vless_server.orphan_registry);
    let (session, created) = registry.get_or_create(
        &session_id,
        vless_server.ws_data_channel_capacity,
        resume_for_create.issued_session_id,
    );

    if created {
        spawn_relay(
            Arc::clone(&session),
            Arc::clone(&vless_server),
            Arc::clone(&registry),
            VlessWsRouteCtx {
                users: Arc::clone(&route.users),
                protocol,
                path: Arc::clone(&base_path),
                candidate_users: Arc::clone(&route.candidate_users),
            },
            resume_for_create,
        );
    }

    match session.try_attach_get() {
        AttachOutcome::Ok => {},
        AttachOutcome::Conflict => return finish_with_status(stream, StatusCode::CONFLICT).await,
        AttachOutcome::Gone => return finish_with_status(stream, StatusCode::GONE).await,
    }

    debug!(
        method = "GET", version = ?version, base = %base_path, %peer_addr,
        session = %session_id, created,
        "xhttp/h3 downlink attached"
    );

    let issued_for_response = session.issued_resume_id;
    let mut response = http::Response::builder()
        .status(StatusCode::OK)
        .body(())
        .context("failed to build xhttp/h3 GET response")?;
    apply_response_masquerade(response.headers_mut());
    if let Some(id) = issued_for_response
        && let Ok(value) = axum::http::HeaderValue::from_str(&id.to_hex())
    {
        response.headers_mut().insert(SESSION_RESPONSE_HEADER, value);
    }
    if let Err(error) = stream.send_response(response).await {
        session.detach_get();
        return Err(anyhow!(error)).context("failed to send xhttp/h3 GET response head");
    }

    let result =
        drive_downlink_h3(&mut stream, Arc::clone(&session)).await;
    session.detach_get();
    let _ = stream.finish().await;
    result
}

#[allow(clippy::too_many_arguments)]
async fn xhttp_h3_post(
    mut stream: RequestStream<BidiStream<Bytes>, Bytes>,
    headers: HeaderMap,
    registry: Arc<XhttpRegistry>,
    vless_server: Arc<VlessWsServerCtx>,
    route: Arc<VlessTransportRoute>,
    base_path: Arc<str>,
    session_id: String,
    version: Version,
    peer_addr: SocketAddr,
) -> Result<()> {
    let seq = match parse_seq(&headers) {
        Some(seq) => seq,
        None => return finish_with_status(stream, StatusCode::BAD_REQUEST).await,
    };
    let fin = headers.contains_key(FIN_HEADER);
    let protocol = protocol_from_h3_version(version);

    let resume_for_create =
        ResumeContext::from_request_headers(&headers, &vless_server.orphan_registry);
    let (session, created) = if seq == 0 {
        registry.get_or_create(
            &session_id,
            vless_server.ws_data_channel_capacity,
            resume_for_create.issued_session_id,
        )
    } else {
        match registry.get(&session_id) {
            Some(s) => (s, false),
            None => return finish_with_status(stream, StatusCode::GONE).await,
        }
    };

    if session.is_closed() {
        return finish_with_status(stream, StatusCode::GONE).await;
    }

    if created {
        spawn_relay(
            Arc::clone(&session),
            Arc::clone(&vless_server),
            Arc::clone(&registry),
            VlessWsRouteCtx {
                users: Arc::clone(&route.users),
                protocol,
                path: Arc::clone(&base_path),
                candidate_users: Arc::clone(&route.candidate_users),
            },
            resume_for_create,
        );
    }

    let mut body = BytesMut::new();
    loop {
        match stream.recv_data().await {
            Ok(Some(chunk)) => {
                let mut chunk = chunk;
                while chunk.has_remaining() {
                    let read = chunk.chunk();
                    if body.len() + read.len() > MAX_POST_BYTES {
                        return finish_with_status(stream, StatusCode::PAYLOAD_TOO_LARGE).await;
                    }
                    body.extend_from_slice(read);
                    let consumed = read.len();
                    chunk.advance(consumed);
                }
            },
            Ok(None) => break,
            Err(error) => {
                debug!(?error, session = %session_id, "xhttp/h3 POST recv_data failed");
                return Err(anyhow!(error)).context("failed to read xhttp/h3 POST body");
            },
        }
    }

    let bytes = body.freeze();
    debug!(
        method = "POST", version = ?version, base = %base_path, %peer_addr,
        session = %session_id, seq, len = bytes.len(), fin,
        "xhttp/h3 uplink chunk"
    );
    if let Err(error) = session.ingest_uplink(seq, bytes) {
        match error {
            UplinkIngestError::Closed => return finish_with_status(stream, StatusCode::GONE).await,
            UplinkIngestError::GapTooLarge { expected, got } => {
                warn!(session = %session_id, expected, got, "xhttp/h3 uplink seq gap; tearing down");
                session.close();
                registry.remove(&session_id);
                return finish_with_status(stream, StatusCode::CONFLICT).await;
            },
            UplinkIngestError::BufferFull => {
                return finish_with_status(stream, StatusCode::SERVICE_UNAVAILABLE).await;
            },
        }
    }
    if fin {
        session.close_uplink();
    }

    let mut response = http::Response::builder()
        .status(StatusCode::OK)
        .body(())
        .context("failed to build xhttp/h3 POST response")?;
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
    stream
        .send_response(response)
        .await
        .map_err(|error| anyhow!(error))
        .context("failed to send xhttp/h3 POST response")?;
    let _ = stream.finish().await;
    Ok(())
}

async fn drive_downlink_h3(
    stream: &mut RequestStream<BidiStream<Bytes>, Bytes>,
    session: Arc<XhttpSession>,
) -> Result<()> {
    let mut buf: Vec<Bytes> = Vec::new();
    loop {
        buf.clear();
        let closed = session.drain_downlink(&mut buf);
        for chunk in buf.drain(..) {
            if let Err(error) = stream.send_data(chunk).await {
                let error = anyhow::Error::from(error);
                if is_normal_h3_shutdown(&error) {
                    debug!("xhttp/h3 GET stream closed by peer");
                    return Ok(());
                }
                return Err(error.context("xhttp/h3 GET send_data failed"));
            }
        }
        if closed {
            return Ok(());
        }
        let notified = session.downlink_notify.notified();
        // Recheck after subscribing — see `duplex::recv` for the
        // matching pattern; this avoids a missed wake-up if the
        // relay pushes a chunk between our drain and our await.
        let mut recheck: Vec<Bytes> = Vec::new();
        let closed_recheck = session.drain_downlink(&mut recheck);
        if !recheck.is_empty() {
            for chunk in recheck {
                if let Err(error) = stream.send_data(chunk).await {
                    if is_normal_h3_shutdown(&anyhow!(error.to_string())) {
                        return Ok(());
                    }
                    return Err(anyhow!(error)).context("xhttp/h3 GET send_data failed");
                }
            }
            if closed_recheck {
                return Ok(());
            }
            continue;
        }
        if closed_recheck {
            return Ok(());
        }
        notified.await;
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
        session_for_task.close();
        registry.remove(&session_id);
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
    headers.get(SEQ_HEADER)?.to_str().ok()?.trim().parse().ok()
}

fn protocol_from_h3_version(version: Version) -> Protocol {
    if version == Version::HTTP_3 {
        Protocol::Http3
    } else {
        // h3 endpoint should only see HTTP/3, but keep a sane
        // fallback so the metric isn't mis-labelled if quinn
        // surprises us.
        Protocol::Http3
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

async fn finish_with_status(
    mut stream: RequestStream<BidiStream<Bytes>, Bytes>,
    status: StatusCode,
) -> Result<()> {
    let mut response = http::Response::builder()
        .status(status)
        .body(())
        .context("failed to build xhttp/h3 status response")?;
    if let Some((name, value)) = generate_padding_header() {
        response.headers_mut().insert(name, value);
    }
    stream
        .send_response(response)
        .await
        .map_err(|error| anyhow!(error))
        .context("failed to send xhttp/h3 status response")?;
    let _ = stream.finish().await;
    Ok(())
}

