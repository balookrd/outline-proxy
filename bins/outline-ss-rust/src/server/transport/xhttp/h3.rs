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

use crate::metrics::Protocol;
use crate::server::cluster::ClusterCtx;

use super::super::super::state::Services;
use super::super::is_normal_h3_shutdown;
use super::super::resume_headers::{ResumeContext, ResumeResponseEcho};
use super::handlers::{XhttpRoute, spawn_relay, xhttp_edge_plan, xhttp_issued_id};
use super::padding::post_response_headers;
use super::{
    AttachOutcome, FIN_HEADER, SEQ_HEADER, UplinkIngestError, XhttpRegistry, XhttpSession,
    XhttpSubmode, generate_padding_header, is_valid_session_id, masquerade_response_headers,
};

const MAX_POST_BYTES: usize = 256 * 1024;

/// Session-routing context shared by every xhttp/h3 entry point: the
/// process-wide session registry, the shared service bundle, and the
/// (VLESS or SS) route the request's base path resolved to. Built once
/// per request by `h3/http.rs` and threaded through the method/submode
/// dispatch below. The relay itself is spawned via the shared
/// [`spawn_relay`], identical to the axum h1/h2 path.
pub(in crate::server) struct XhttpH3Ctx {
    pub(in crate::server) registry: Arc<XhttpRegistry>,
    pub(in crate::server) services: Arc<Services>,
    pub(in crate::server) route: XhttpRoute,
    pub(in crate::server) base_path: Arc<str>,
    /// Mesh-cluster runtime; `Some` only when clustered. Read on a session-
    /// creating request to relay a foreign-shard resume to its home.
    pub(in crate::server) cluster: Option<Arc<ClusterCtx>>,
}

/// Dispatcher entry. Called from `h3/http.rs` once a non-CONNECT
/// request has been classified as XHTTP by path lookup. The caller
/// has already split the path into base + session id and, when the
/// URL was the xray / sing-box `<base>/<id>/<seq>` shape, the
/// per-packet seq.
pub(in crate::server) async fn handle_xhttp_h3_request(
    request: http::Request<()>,
    stream: RequestStream<BidiStream<Bytes>, Bytes>,
    ctx: XhttpH3Ctx,
    session_id: String,
    path_seq: Option<u64>,
    peer_addr: SocketAddr,
) -> Result<()> {
    if !is_valid_session_id(&session_id) {
        return finish_with_status(stream, StatusCode::BAD_REQUEST).await;
    }

    let method = request.method().clone();
    let headers = request.headers().clone();
    let version = request.version();
    // Mirror the axum dispatch logic in `handlers::dispatch_xhttp` —
    // see the long comment there for why the `?mode=` query is only
    // a fallback hint and seq presence is the wire-level signal that
    // picks the carrier for xray-style clients.
    let submode = XhttpSubmode::parse_query(request.uri().query());

    match method {
        Method::GET => {
            if path_seq.is_some() {
                return finish_with_status(stream, StatusCode::BAD_REQUEST).await;
            }
            match submode {
                XhttpSubmode::PacketUp => {
                    xhttp_h3_get(stream, &ctx, session_id, version, peer_addr, headers).await
                },
                XhttpSubmode::StreamOne => {
                    finish_with_status(stream, StatusCode::BAD_REQUEST).await
                },
            }
        },
        Method::POST => {
            let seq = path_seq.or_else(|| parse_seq(&headers));
            match submode {
                XhttpSubmode::StreamOne => {
                    if seq.is_some() {
                        return finish_with_status(stream, StatusCode::BAD_REQUEST).await;
                    }
                    xhttp_h3_stream_one(stream, headers, &ctx, session_id, version, peer_addr).await
                },
                XhttpSubmode::PacketUp => match seq {
                    Some(_) => {
                        xhttp_h3_post(
                            stream, headers, &ctx, session_id, path_seq, version, peer_addr,
                        )
                        .await
                    },
                    None => {
                        xhttp_h3_stream_one(stream, headers, &ctx, session_id, version, peer_addr)
                            .await
                    },
                },
            }
        },
        _ => finish_with_status(stream, StatusCode::METHOD_NOT_ALLOWED).await,
    }
}

async fn xhttp_h3_get(
    mut stream: RequestStream<BidiStream<Bytes>, Bytes>,
    ctx: &XhttpH3Ctx,
    session_id: String,
    version: Version,
    peer_addr: SocketAddr,
    request_headers: HeaderMap,
) -> Result<()> {
    let protocol = protocol_from_h3_version(version);
    let resume_for_create =
        ResumeContext::from_request_headers(&request_headers, &ctx.services.orphan_registry);
    // Captured before `resume_for_create` moves into spawn_relay; echoed in
    // the response like the h1/h2 XHTTP handlers do.
    let ack_prefix_for_response = resume_for_create.ack_prefix_requested;
    let symmetric_replay_for_response = resume_for_create.symmetric_replay_requested;
    let edge =
        xhttp_edge_plan(ctx.cluster.as_ref(), &ctx.services.orphan_registry, &request_headers);
    let (session, created) = match ctx
        .registry
        .get_or_create(&session_id, xhttp_issued_id(&edge, &resume_for_create))
    {
        Some(pair) => pair,
        None => {
            ctx.services
                .tcp_server
                .metrics
                .record_xhttp_session_rejected(protocol, "max_sessions");
            warn!(base = %ctx.base_path, "xhttp session registry at capacity; rejecting session");
            return finish_with_status(stream, StatusCode::SERVICE_UNAVAILABLE).await;
        },
    };

    if created
        && !spawn_relay(
            Arc::clone(&session),
            &ctx.services,
            Arc::clone(&ctx.registry),
            ctx.route.clone(),
            Arc::clone(&ctx.base_path),
            protocol,
            peer_addr,
            resume_for_create,
            edge,
        )
    {
        return finish_with_status(stream, StatusCode::SERVICE_UNAVAILABLE).await;
    }

    match session.try_attach_get() {
        AttachOutcome::Ok => {},
        AttachOutcome::Conflict => return finish_with_status(stream, StatusCode::CONFLICT).await,
        AttachOutcome::Gone => return finish_with_status(stream, StatusCode::GONE).await,
    }

    debug!(
        method = "GET", version = ?version, base = %ctx.base_path, %peer_addr,
        session = %session_id, created,
        "xhttp/h3 downlink attached"
    );

    let issued_for_response = session.issued_resume_id;
    let mut response = http::Response::builder()
        .status(StatusCode::OK)
        .body(())
        .context("failed to build xhttp/h3 GET response")?;
    apply_response_masquerade(response.headers_mut());
    ResumeResponseEcho {
        session_id: issued_for_response,
        ack_prefix: ack_prefix_for_response,
        symmetric_replay: symmetric_replay_for_response,
    }
    .apply(response.headers_mut());
    if let Err(error) = stream.send_response(response).await {
        session.detach_get();
        return Err(anyhow!(error)).context("failed to send xhttp/h3 GET response head");
    }

    let result = drive_downlink_h3(&mut stream, Arc::clone(&session)).await;
    session.detach_get();
    let _ = stream.finish().await;
    result
}

async fn xhttp_h3_post(
    mut stream: RequestStream<BidiStream<Bytes>, Bytes>,
    headers: HeaderMap,
    ctx: &XhttpH3Ctx,
    session_id: String,
    path_seq: Option<u64>,
    version: Version,
    peer_addr: SocketAddr,
) -> Result<()> {
    // Path-based seq (xray / sing-box default) wins over the header
    // form, mirroring the axum-side rule.
    let seq = match path_seq.or_else(|| parse_seq(&headers)) {
        Some(seq) => seq,
        None => return finish_with_status(stream, StatusCode::BAD_REQUEST).await,
    };
    let fin = headers.contains_key(FIN_HEADER);
    let protocol = protocol_from_h3_version(version);

    let resume_for_create =
        ResumeContext::from_request_headers(&headers, &ctx.services.orphan_registry);
    // Captured before `resume_for_create` moves on; echoed in the response
    // like the h1/h2 XHTTP handlers do.
    let ack_prefix_for_response = resume_for_create.ack_prefix_requested;
    let symmetric_replay_for_response = resume_for_create.symmetric_replay_requested;
    let edge = xhttp_edge_plan(ctx.cluster.as_ref(), &ctx.services.orphan_registry, &headers);
    let (session, created) = if seq == 0 {
        match ctx
            .registry
            .get_or_create(&session_id, xhttp_issued_id(&edge, &resume_for_create))
        {
            Some(pair) => pair,
            None => {
                ctx.services
                    .tcp_server
                    .metrics
                    .record_xhttp_session_rejected(protocol, "max_sessions");
                warn!(base = %ctx.base_path, "xhttp session registry at capacity; rejecting session");
                return finish_with_status(stream, StatusCode::SERVICE_UNAVAILABLE).await;
            },
        }
    } else {
        match ctx.registry.get(&session_id) {
            Some(s) => (s, false),
            None => return finish_with_status(stream, StatusCode::GONE).await,
        }
    };

    if session.is_closed() {
        return finish_with_status(stream, StatusCode::GONE).await;
    }

    if created
        && !spawn_relay(
            Arc::clone(&session),
            &ctx.services,
            Arc::clone(&ctx.registry),
            ctx.route.clone(),
            Arc::clone(&ctx.base_path),
            protocol,
            peer_addr,
            resume_for_create,
            edge,
        )
    {
        return finish_with_status(stream, StatusCode::SERVICE_UNAVAILABLE).await;
    }

    let mut body_parts: Vec<Bytes> = Vec::new();
    let mut body_len = 0usize;
    loop {
        match stream.recv_data().await {
            Ok(Some(chunk)) => {
                let mut chunk = chunk;
                let remaining = chunk.remaining();
                if body_len + remaining > MAX_POST_BYTES {
                    return finish_with_status(stream, StatusCode::PAYLOAD_TOO_LARGE).await;
                }
                if remaining > 0 {
                    // Zero-copy `split_to` for the h3-quinn `Bytes`-backed buf;
                    // the common single-DATA-frame POST is then forwarded with no
                    // copy at all (the `1 =>` arm below moves it out).
                    body_parts.push(chunk.copy_to_bytes(remaining));
                    body_len += remaining;
                }
            },
            Ok(None) => break,
            Err(error) => {
                debug!(?error, session = %session_id, "xhttp/h3 POST recv_data failed");
                return Err(anyhow!(error)).context("failed to read xhttp/h3 POST body");
            },
        }
    }

    let bytes = match body_parts.len() {
        0 => Bytes::new(),
        1 => body_parts.pop().expect("len == 1"),
        _ => {
            let mut acc = BytesMut::with_capacity(body_len);
            for part in &body_parts {
                acc.extend_from_slice(part);
            }
            acc.freeze()
        },
    };
    debug!(
        method = "POST", version = ?version, base = %ctx.base_path, %peer_addr,
        session = %session_id, seq, len = bytes.len(), fin,
        "xhttp/h3 uplink chunk"
    );
    if let Err(error) = session.ingest_uplink(seq, bytes) {
        match error {
            UplinkIngestError::Closed => return finish_with_status(stream, StatusCode::GONE).await,
            UplinkIngestError::GapTooLarge { expected, got } => {
                warn!(session = %session_id, expected, got, "xhttp/h3 uplink seq gap; tearing down");
                session.close();
                ctx.registry.remove(&session_id);
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
    ResumeResponseEcho {
        session_id: session.issued_resume_id,
        ack_prefix: ack_prefix_for_response,
        symmetric_replay: symmetric_replay_for_response,
    }
    .apply(resp_headers);
    stream
        .send_response(response)
        .await
        .map_err(|error| anyhow!(error))
        .context("failed to send xhttp/h3 POST response")?;
    let _ = stream.finish().await;
    Ok(())
}

/// Stream-one carrier on h3: takes a single bidirectional QUIC
/// stream, splits it into send/receive halves and runs uplink and
/// downlink concurrently. Mirrors the h2/axum variant.
async fn xhttp_h3_stream_one(
    mut stream: RequestStream<BidiStream<Bytes>, Bytes>,
    headers: HeaderMap,
    ctx: &XhttpH3Ctx,
    session_id: String,
    version: Version,
    peer_addr: SocketAddr,
) -> Result<()> {
    let protocol = protocol_from_h3_version(version);
    let resume_for_create =
        ResumeContext::from_request_headers(&headers, &ctx.services.orphan_registry);
    // Captured before `resume_for_create` moves on; echoed in the response
    // like the h1/h2 XHTTP handlers do.
    let ack_prefix_for_response = resume_for_create.ack_prefix_requested;
    let symmetric_replay_for_response = resume_for_create.symmetric_replay_requested;
    let edge = xhttp_edge_plan(ctx.cluster.as_ref(), &ctx.services.orphan_registry, &headers);
    let (session, created) = match ctx
        .registry
        .get_or_create(&session_id, xhttp_issued_id(&edge, &resume_for_create))
    {
        Some(pair) => pair,
        None => {
            ctx.services
                .tcp_server
                .metrics
                .record_xhttp_session_rejected(protocol, "max_sessions");
            warn!(base = %ctx.base_path, "xhttp session registry at capacity; rejecting session");
            return finish_with_status(stream, StatusCode::SERVICE_UNAVAILABLE).await;
        },
    };
    if session.is_closed() {
        return finish_with_status(stream, StatusCode::GONE).await;
    }
    if created
        && !spawn_relay(
            Arc::clone(&session),
            &ctx.services,
            Arc::clone(&ctx.registry),
            ctx.route.clone(),
            Arc::clone(&ctx.base_path),
            protocol,
            peer_addr,
            resume_for_create,
            edge,
        )
    {
        return finish_with_status(stream, StatusCode::SERVICE_UNAVAILABLE).await;
    }
    match session.try_attach_get() {
        AttachOutcome::Ok => {},
        AttachOutcome::Conflict => return finish_with_status(stream, StatusCode::CONFLICT).await,
        AttachOutcome::Gone => return finish_with_status(stream, StatusCode::GONE).await,
    }
    debug!(
        method = "POST", mode = "stream-one", version = ?version, base = %ctx.base_path,
        %peer_addr, session = %session_id, created,
        "xhttp/h3 stream-one duplex attached"
    );

    let mut response = http::Response::builder()
        .status(StatusCode::OK)
        .body(())
        .context("failed to build xhttp/h3 stream-one response")?;
    apply_response_masquerade(response.headers_mut());
    ResumeResponseEcho {
        session_id: session.issued_resume_id,
        ack_prefix: ack_prefix_for_response,
        symmetric_replay: symmetric_replay_for_response,
    }
    .apply(response.headers_mut());
    if let Err(error) = stream.send_response(response).await {
        session.detach_get();
        return Err(anyhow!(error)).context("failed to send xhttp/h3 stream-one response head");
    }

    // Split into send/recv halves so the uplink and downlink loops
    // can borrow `stream` concurrently — h3 0.0.8 surfaces this as
    // `RequestStream::split`.
    let (send_half, mut recv_half) = stream.split();
    // Uplink pump: drain request body chunks, ingest in order.
    let session_for_uplink = Arc::clone(&session);
    let uplink_task = tokio::spawn(async move {
        loop {
            match recv_half.recv_data().await {
                Ok(Some(chunk)) => {
                    // `copy_to_bytes` is a zero-copy `split_to` for the h3-quinn
                    // `Bytes`-backed buf — forward the DATA frame without copying
                    // every segment into a fresh `BytesMut`.
                    let mut chunk = chunk;
                    let remaining = chunk.remaining();
                    let bytes = chunk.copy_to_bytes(remaining);
                    if !bytes.is_empty() && session_for_uplink.ingest_uplink_inorder(bytes).is_err()
                    {
                        break;
                    }
                },
                Ok(None) => break,
                Err(error) => {
                    debug!(?error, "xhttp/h3 stream-one recv_data failed");
                    break;
                },
            }
        }
        session_for_uplink.close_uplink();
    });

    // Downlink pump: drain `session.downlink` and feed it to the
    // QUIC send half. Reuses the same wait-then-recheck pattern as
    // `drive_downlink_h3` so a chunk pushed between drain and notify
    // is not lost.
    let result = drive_downlink_send_only(send_half, Arc::clone(&session)).await;
    session.detach_get();
    let _ = uplink_task.await;
    result
}

/// Variant of `drive_downlink_h3` operating on the *send* half of
/// a `split()`-ed RequestStream so the uplink half can be borrowed
/// concurrently. The chunk-loop is structurally identical; kept as
/// a dedicated function to avoid generic-over-stream-half plumbing.
async fn drive_downlink_send_only(
    mut send: RequestStream<<BidiStream<Bytes> as h3::quic::BidiStream<Bytes>>::SendStream, Bytes>,
    session: Arc<XhttpSession>,
) -> Result<()> {
    let mut buf: Vec<Bytes> = Vec::new();
    loop {
        buf.clear();
        let closed = session.drain_downlink(&mut buf);
        for chunk in buf.drain(..) {
            if let Err(error) = send.send_data(chunk).await {
                let error = anyhow::Error::from(error);
                if is_normal_h3_shutdown(&error) {
                    let _ = send.finish().await;
                    return Ok(());
                }
                let _ = send.finish().await;
                return Err(error.context("xhttp/h3 stream-one send_data failed"));
            }
        }
        if closed {
            let _ = send.finish().await;
            return Ok(());
        }
        let notified = session.downlink_notify.notified();
        let mut recheck: Vec<Bytes> = Vec::new();
        let closed_recheck = session.drain_downlink(&mut recheck);
        if !recheck.is_empty() {
            for chunk in recheck {
                if let Err(error) = send.send_data(chunk).await {
                    let error = anyhow::Error::from(error);
                    if is_normal_h3_shutdown(&error) {
                        let _ = send.finish().await;
                        return Ok(());
                    }
                    let _ = send.finish().await;
                    return Err(error.context("xhttp/h3 stream-one send_data failed"));
                }
            }
            if closed_recheck {
                let _ = send.finish().await;
                return Ok(());
            }
            continue;
        }
        if closed_recheck {
            let _ = send.finish().await;
            return Ok(());
        }
        notified.await;
    }
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

fn parse_seq(headers: &HeaderMap) -> Option<u64> {
    headers.get(SEQ_HEADER)?.to_str().ok()?.trim().parse().ok()
}

fn protocol_from_h3_version(version: Version) -> Protocol {
    // The h3 listener can only deliver requests on HTTP/3 — both
    // arms still resolve to `XhttpH3` so the metric stays
    // unsurprising even if quinn ever surfaces something else.
    let _ = version;
    Protocol::XhttpH3
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
