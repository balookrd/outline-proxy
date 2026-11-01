//! HTTP/3 carrier for the client-side XHTTP packet-up driver.
//!
//! Mirrors the h2 path in the parent module but rides QUIC instead
//! of TCP+TLS+h2. Every session runs its own h3 handshake — there is
//! no shared-connection pool here because XHTTP sessions are 1:1 with
//! their VLESS upstream and have no cache key — but the UDP socket
//! under it is the shared per-address-family endpoint the native
//! `ws_h3` carrier uses, unless the dial needs an fwmark.
//!
//! This module is gated behind the `h3` feature: it pulls in `quinn`
//! and the `h3` / `h3-quinn` crates that the rest of the H3 path
//! already depends on.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bytes::{Buf, Bytes};
use h3::client::SendRequest;
use http::{HeaderMap, Method, Request, Version};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::protocol::Message;
use tracing::{debug, warn};
use url::Url;

use outline_metrics as metrics;
use outline_wire::h3_datagram::DatagramDemux;

use crate::TransportOperation;
use crate::dns::resolve_host_with_preference;
use crate::dns_cache::DnsCache;
use crate::guards::AbortOnDrop;
use crate::h3::H3DatagramBinding;
use crate::h3::vendored::{H3RequestStreamHandle, request_quarter_stream_id};
use crate::resumption::SessionId;

use super::stream::io_ws_err;
use crate::request_headers::{HttpVersion, RequestKind};

use super::{
    InboundSender, OutboundReceiver, SESSION_RESPONSE_HEADER, SessionRequest, SsPathKind,
    XhttpStream, XhttpSubmode, XhttpTarget, build_session_request_headers, generate_session_id,
    inbound_channel, outbound_channel,
};

/// Same dial budget the h2 path uses — keeps fallback windows
/// uniform across carriers.
use crate::dial_timeouts::fresh_connect_timeout;

/// Upper bound for a single packet-up POST (open stream, send body, read
/// response) on an already-established QUIC connection.
///
/// `fresh_connect_timeout()` only covers the handshake, so without this bound a
/// server that accepts the request stream and then goes silent leaves
/// `recv_response()` pending forever: QUIC keep-alive (8–12 s) keeps
/// `max_idle_timeout` (30 s, from the browser profile) from ever firing, and the POST task holds a
/// `SendRequest` clone, which is what keeps the h3 connection — and the UDP
/// socket under it — alive. The budget is far more than a healthy path needs
/// for one uplink frame (compare the 7 s the WS-over-H3 carrier allows for
/// opening a stream) while still bounding the stall.
const POST_TIMEOUT: Duration = Duration::from_secs(30);

#[cfg(test)]
#[path = "tests/h3.rs"]
mod tests;

// The H3 QUIC client config is shared with the WS-over-H3 carrier in
// `crate::quic` (`h3_quic_client_config`): keyed by dial fingerprint so the
// XHTTP-over-H3 ClientHello mimics the same browser family as the other
// carriers, with the same per-process keep-alive / idle jitter and the same
// QUIC datagram settings.

/// Where an anchor request may bind UDP over HTTP/3 datagrams: the session's
/// QUIC connection and its datagram demux. Passed only when the dial offers
/// datagrams and the connection can carry them.
type DatagramOffer<'a> = (&'a quinn::Connection, &'a Arc<DatagramDemux>);

/// What a session-opening request (the packet-up GET, or the stream-one POST)
/// negotiated. Returned next to the request stream, which goes to the driver.
struct OpenedSession {
    issued: Option<SessionId>,
    ack_prefix_echo: bool,
    symmetric_replay_echo: bool,
    udp_records: bool,
    /// `Some` when the server accepted UDP over HTTP/3 datagrams on this
    /// request's stream.
    datagram: Option<H3DatagramBinding>,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn connect_xhttp_h3(
    cache: &DnsCache,
    url: &Url,
    submode: XhttpSubmode,
    network: crate::dial_plan::DialNetworkOptions,
    resume_request: Option<SessionId>,
    ack_prefix_requested: bool,
    symmetric_replay_requested: bool,
    client_acked_offset: u64,
    combined_ss_kind: Option<SsPathKind>,
    datagram_records: bool,
    udp_datagram: bool,
) -> Result<(XhttpStream, Option<SessionId>, bool, bool)> {
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("xhttp/h3 url missing host: {url}"))?
        .to_owned();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("xhttp/h3 url missing port and no scheme default: {url}"))?;
    let base_path = url.path().trim_end_matches('/').to_owned();
    if base_path.is_empty() {
        bail!("xhttp/h3 url path must be a non-empty base (e.g. /xh): {url}");
    }
    if !matches!(url.scheme(), "https" | "wss") {
        // h3 is only ever TLS — bail loudly if the caller hands us
        // an `http://` URL by mistake instead of silently downgrading.
        bail!("xhttp/h3 requires an https/wss URL, got scheme {:?}", url.scheme());
    }
    // Profile picked once per dial — every GET / POST in this h3
    // session shares the same browser identity. Same shape as the h2
    // path, the `Option` is `Copy` so it threads freely into spawned
    // sub-tasks below.
    let profile = crate::fingerprint_profile::select(url);

    let dial = async {
        let addrs = resolve_host_with_preference(
            cache,
            &host,
            port,
            "failed to resolve xhttp/h3 host",
            network.ipv6_first,
            network.ipv4_only,
        )
        .await?;
        let server_addr = *addrs.first().ok_or_else(|| {
            anyhow::Error::new(TransportOperation::DnsResolveNoAddresses { host: host.clone() })
        })?;

        let super::h3_pool::PooledCarrier {
            send_request,
            loss_probe,
            carrier: quic_carrier,
            connection,
            datagrams,
        } = super::h3_pool::acquire(server_addr, &host, port, network.fwmark).await?;
        // The offer goes out only where datagrams can flow: the dial asked for
        // it (an SS-UDP session) AND this connection has a demultiplexer.
        let datagram_offer: Option<DatagramOffer<'_>> = datagrams
            .as_ref()
            .filter(|_| udp_datagram)
            .map(|demux| (&connection, demux));
        let session_id = generate_session_id(combined_ss_kind)?;

        let authority = super::authority_for(true, &host, port);
        let target = Arc::new(XhttpTarget {
            scheme: "https".to_string(),
            authority,
            base_path: base_path.clone(),
            session_id: session_id.clone(),
        });

        let (in_tx, in_rx) = inbound_channel();
        let (out_tx, out_rx) = outbound_channel();

        let (opened, driver, active_submode) = match submode {
            XhttpSubmode::PacketUp => {
                let (opened, request_stream) = open_h3_get(
                    send_request.clone(),
                    &target,
                    resume_request,
                    ack_prefix_requested,
                    symmetric_replay_requested,
                    client_acked_offset,
                    datagram_records,
                    datagram_offer,
                    profile,
                )
                .await?;
                let driver = tokio::spawn(driver_loop_h3(
                    send_request,
                    target.clone(),
                    in_tx,
                    out_rx,
                    request_stream,
                    datagram_records,
                    opened.datagram.is_some(),
                    profile,
                ));
                (opened, driver, XhttpSubmode::PacketUp)
            },
            XhttpSubmode::StreamOne => {
                // The h3 client closes the connection with `H3_NO_ERROR`
                // when the last `SendRequest` drops, so we must keep one
                // alive for the lifetime of the bidi stream — otherwise
                // the request body's send_data calls race the close
                // frame and the server sees `ApplicationClose` before
                // any application bytes flow. `open_h3_stream_one`
                // takes ownership of its own copy; the cloned guard
                // moves into the driver task and is dropped only when
                // the carrier shuts down for real.
                //
                // On dial-time failure we retry packet-up on the same
                // QUIC connection (mirror of the h2 inline fallback).
                // The handshake cost is sunk; if stream-one is broken
                // on this network path, packet-up usually still works
                // because it issues one short bidi stream per POST
                // instead of one long-lived one.
                match open_h3_stream_one(
                    send_request.clone(),
                    &target,
                    resume_request,
                    ack_prefix_requested,
                    symmetric_replay_requested,
                    client_acked_offset,
                    datagram_records,
                    datagram_offer,
                    profile,
                )
                .await
                {
                    Ok((opened, request_stream)) => {
                        let driver = tokio::spawn(driver_loop_h3_stream_one(
                            send_request,
                            in_tx,
                            out_rx,
                            request_stream,
                        ));
                        crate::xhttp_submode_cache::record_success(url, XhttpSubmode::StreamOne)
                            .await;
                        (opened, driver, XhttpSubmode::StreamOne)
                    },
                    Err(stream_err) => {
                        warn!(
                            %url,
                            error = %format!("{stream_err:#}"),
                            "xhttp h3 stream-one failed, falling back to packet-up on same connection"
                        );
                        crate::xhttp_submode_cache::record_failure(url, XhttpSubmode::StreamOne)
                            .await;
                        let (opened, request_stream) = open_h3_get(
                            send_request.clone(),
                            &target,
                            resume_request,
                            ack_prefix_requested,
                            symmetric_replay_requested,
                            client_acked_offset,
                            datagram_records,
                            datagram_offer,
                            profile,
                        )
                        .await?;
                        let driver = tokio::spawn(driver_loop_h3(
                            send_request,
                            target.clone(),
                            in_tx,
                            out_rx,
                            request_stream,
                            datagram_records,
                            opened.datagram.is_some(),
                            profile,
                        ));
                        (opened, driver, XhttpSubmode::PacketUp)
                    },
                }
            },
        };

        let OpenedSession {
            issued: issued_session_id,
            ack_prefix_echo,
            symmetric_replay_echo,
            udp_records,
            datagram,
            ..
        } = opened;
        debug!(
            %url, %session_id, mode = "xhttp_h3", ?submode, ?active_submode,
            ?issued_session_id, ?resume_request, ack_prefix_requested, ack_prefix_echo,
            udp_datagram = datagram.is_some(),
            "xhttp h3 session opened"
        );
        Ok::<_, anyhow::Error>((
            XhttpStream::from_channels(
                in_rx,
                out_tx,
                AbortOnDrop::new(driver),
                active_submode,
                true,
                udp_records,
                loss_probe,
                quic_carrier,
            )
            .with_h3_datagram(datagram),
            issued_session_id,
            ack_prefix_echo,
            symmetric_replay_echo,
        ))
    };

    timeout(fresh_connect_timeout(), dial)
        .await
        .with_context(|| format!("xhttp/h3 dial to {url} timed out"))?
        .with_context(|| format!("xhttp/h3 dial to {url} failed"))
}

/// Synchronously opens the long-lived h3 GET, awaits response
/// headers, and surfaces the optional `X-Outline-Session` token.
/// The returned `RequestStream` is used by the driver task for body
/// draining. Mirrors `open_h2_get` in the parent module.
#[allow(clippy::too_many_arguments)]
async fn open_h3_get(
    mut send: SendRequest<h3_quinn::OpenStreams, Bytes>,
    target: &XhttpTarget,
    resume_request: Option<SessionId>,
    ack_prefix_requested: bool,
    symmetric_replay_requested: bool,
    client_acked_offset: u64,
    datagram_records: bool,
    datagram_offer: Option<DatagramOffer<'_>>,
    profile: Option<&'static crate::fingerprint_profile::Profile>,
) -> Result<(OpenedSession, H3RequestStreamHandle)> {
    let mut req = Request::builder()
        .method(Method::GET)
        .uri(target.full_uri())
        .version(Version::HTTP_3)
        .body(())
        .context("failed to build xhttp/h3 GET request")?;
    let origin = target.web_origin();
    *req.headers_mut() = build_session_request_headers(
        SessionRequest {
            profile,
            kind: RequestKind::FetchGet,
            version: HttpVersion::H3,
            origin: &origin,
            host: None,
        },
        resume_request,
        ack_prefix_requested,
        symmetric_replay_requested,
        client_acked_offset,
        datagram_records,
        datagram_offer.is_some(),
    )?;
    let mut stream = send
        .send_request(req)
        .await
        .map_err(|error| anyhow!(error))
        .context("xhttp/h3 GET send_request failed")?;
    let registration = register_anchor(datagram_offer, &stream);
    stream
        .finish()
        .await
        .map_err(|error| anyhow!(error))
        .context("xhttp/h3 GET stream finish failed")?;
    let resp = stream
        .recv_response()
        .await
        .map_err(|error| anyhow!(error))
        .context("xhttp/h3 GET recv_response failed")?;
    if !resp.status().is_success() {
        bail!("xhttp/h3 GET returned {}", resp.status());
    }
    let opened = OpenedSession::negotiated(
        resp.headers(),
        ack_prefix_requested,
        symmetric_replay_requested,
        datagram_records,
        registration,
    );
    Ok((opened, stream))
}

/// Registers an anchor request's stream in the connection's datagram demux
/// right after the request goes out, before the response is read: the server
/// may send its first datagram as soon as it accepts, and one arriving for an
/// unregistered stream is dropped as unknown. `None` when not offering.
fn register_anchor(
    offer: Option<DatagramOffer<'_>>,
    stream: &H3RequestStreamHandle,
) -> Option<H3DatagramBinding> {
    offer.map(|(connection, demux)| {
        let quarter_stream_id = request_quarter_stream_id(stream);
        H3DatagramBinding {
            connection: connection.clone(),
            quarter_stream_id,
            registration: demux.register(quarter_stream_id),
        }
    })
}

impl OpenedSession {
    /// Reads the negotiation echoes off the anchor's response. `registration`
    /// is `Some` iff this request offered datagrams; it is kept only when the
    /// server accepted, and dropped (unregistered) otherwise.
    fn negotiated(
        headers: &HeaderMap,
        ack_prefix_requested: bool,
        symmetric_replay_requested: bool,
        datagram_records: bool,
        registration: Option<H3DatagramBinding>,
    ) -> Self {
        let issued = headers
            .get(SESSION_RESPONSE_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(SessionId::parse_hex);
        let ack_prefix_echo = ack_prefix_requested && super::parse_ack_prefix_echo(headers);
        let symmetric_replay_echo = symmetric_replay_requested
            && ack_prefix_echo
            && super::parse_symmetric_replay_echo(headers);
        let udp_records = super::parse_udp_records_echo(datagram_records, headers);
        let offered = registration.is_some();
        let accepted = super::parse_udp_datagram_echo(offered, headers);
        if offered {
            let state = if accepted { "negotiated" } else { "declined" };
            metrics::record_udp_h3_datagram_session("xhttp_h3", state);
        }
        Self {
            issued,
            ack_prefix_echo,
            symmetric_replay_echo,
            udp_records,
            datagram: registration.filter(|_| accepted),
        }
    }
}

/// Generic over the QUIC types for the same reason [`post_one`] is: production
/// instantiates it with `h3_quinn`, tests with an in-process stub.
///
/// `udp_datagrams`: the session agreed UDP over HTTP/3 datagrams, so its
/// uplink may never POST and the closing FIN goes out regardless.
#[allow(clippy::too_many_arguments)]
async fn driver_loop_h3<T, S>(
    send_request: SendRequest<T, Bytes>,
    target: Arc<XhttpTarget>,
    in_tx: InboundSender,
    mut out_rx: OutboundReceiver,
    body_stream: h3::client::RequestStream<S, Bytes>,
    datagram_records: bool,
    udp_datagrams: bool,
    profile: Option<&'static crate::fingerprint_profile::Profile>,
) where
    T: h3::quic::OpenStreams<Bytes> + Clone + Send + 'static,
    T::BidiStream: Send,
    S: h3::quic::RecvStream + Send + 'static,
    S::Buf: Send,
{
    // GET drain sub-task. Headers were already received by
    // `open_h3_get`; this only pulls body chunks.
    let drain_in_tx = in_tx.clone();
    let _drain_task = AbortOnDrop::new(tokio::spawn(async move {
        if let Err(error) = drain_h3_body(body_stream, &drain_in_tx).await {
            debug!(?error, "xhttp/h3 GET reader exited");
            let _ = drain_in_tx
                .send_control(Err(io_ws_err("xhttp/h3 downlink ended")))
                .await;
        } else {
            let _ = drain_in_tx.send_control(Ok(Message::Close(None))).await;
        }
    }));

    // Per-POST request template, built once per session: h3 puts the
    // authority in the `:authority` pseudo-header (from the URI). We clone
    // this map per POST (setting its `Content-Length`) and append the seq to
    // the URL prefix instead of rebuilding the browser headers and
    // re-`format!`-ing the URI per frame.
    let base_headers =
        Arc::new(build_post_headers(&target.web_origin(), datagram_records, profile));
    let uri_prefix: Arc<str> = Arc::from(target.uri_seq_prefix());

    // POSTs run concurrently but stay owned by this driver: a detached
    // `tokio::spawn` would survive the `AbortOnDrop` that tears the driver down
    // with its `XhttpStream`, and each orphan holds a `SendRequest` clone —
    // enough to keep the QUIC connection, its driver task and the endpoint
    // underneath alive until the POST's own deadline expires.
    let mut posts: JoinSet<()> = JoinSet::new();
    // Shared with the FIN guard — see the h2 sibling; an aborted driver never
    // reaches the bottom of this function, but its locals still drop.
    let next_seq = Arc::new(AtomicU64::new(0));
    let fin = {
        let send_request = send_request.clone();
        let uri_prefix = Arc::clone(&uri_prefix);
        let base_headers = Arc::clone(&base_headers);
        super::FinOnDrop::new(Arc::clone(&next_seq), move |seq| {
            Box::pin(send_fin(send_request, uri_prefix, base_headers, seq))
        })
        .even_unposted(udp_datagrams)
    };
    loop {
        let queued = match out_rx.recv().await {
            Some(queued) => queued,
            None => break,
        };
        let (msg, permit) = queued.into_parts();
        let bytes = match msg {
            Message::Binary(b) => b,
            Message::Ping(_) | Message::Pong(_) => continue,
            Message::Text(_) => {
                let _ = in_tx
                    .send_control(Err(io_ws_err("xhttp/h3 does not carry text")))
                    .await;
                continue;
            },
            Message::Close(_) => break,
            _ => continue,
        };
        let seq = next_seq.fetch_add(1, Ordering::Relaxed);
        let send = send_request.clone();
        let base_headers = Arc::clone(&base_headers);
        let uri_prefix = Arc::clone(&uri_prefix);
        let in_tx_for_err = in_tx.clone();
        posts.spawn(async move {
            // Permit rides the POST — the bytes are resident until h3 has sent
            // them, so the queue budget must keep covering them.
            let _permit = permit;
            if let Err(error) = post_one_bounded(send, &uri_prefix, &base_headers, seq, bytes).await
            {
                warn!(?error, seq, "xhttp/h3 POST failed");
                let _ = in_tx_for_err
                    .send_control(Err(io_ws_err("xhttp/h3 uplink POST failed")))
                    .await;
            }
        });
        // Reap completed POSTs so the set tracks only what is in flight
        // instead of growing with the session's frame count.
        while posts.try_join_next().is_some() {}
    }
    // Orderly shutdown (uplink queue closed or a Close frame): let the POSTs
    // already on the wire finish so the tail of the uplink is not truncated.
    // Each is capped by `POST_TIMEOUT`, so this drain is bounded. An aborted
    // driver never reaches this point — dropping the `JoinSet` aborts the
    // in-flight POSTs instead, which is exactly what bounds the leak.
    while posts.join_next().await.is_some() {}
    // Dropping `fin` here — after the drain — is what puts the FIN on the wire;
    // see the h2 sibling for why the ordering matters.
    drop(fin);
    debug!("xhttp/h3 driver exiting");
}

/// Closes the session's uplink with an empty `X-Xhttp-Fin` POST — the h3 twin of
/// the h2 sibling's `send_fin`; see [`super::FinOnDrop`].
async fn send_fin<T>(
    send: SendRequest<T, Bytes>,
    uri_prefix: Arc<str>,
    base_headers: Arc<HeaderMap>,
    seq: u64,
) where
    T: h3::quic::OpenStreams<Bytes> + Clone + Send + 'static,
    T::BidiStream: Send,
{
    let headers = super::fin_post_headers(&base_headers);
    let post = post_one(send, &uri_prefix, &headers, seq, Bytes::new());
    match timeout(super::FIN_TIMEOUT, post).await {
        Ok(Ok(())) => {},
        Ok(Err(error)) => debug!(?error, seq, "xhttp/h3 FIN POST failed"),
        Err(_) => debug!(seq, "xhttp/h3 FIN POST timed out"),
    }
}

/// Header map shared by every packet-up POST in an h3 session (see
/// [`super::build_post_template`]; h3 follows the h2 table). The authority
/// rides the `:authority` pseudo-header.
pub(super) fn build_post_headers(
    origin: &str,
    datagram_records: bool,
    profile: Option<&'static crate::fingerprint_profile::Profile>,
) -> HeaderMap {
    super::build_post_template(profile, HttpVersion::H3, origin, None, datagram_records)
}

/// Stream-one carrier on h3: a single bidirectional QUIC stream.
/// Open synchronously, await response headers, then hand the
/// stream to the driver task which splits it into send/recv halves
/// running concurrently.
#[allow(clippy::too_many_arguments)]
async fn open_h3_stream_one(
    mut send: SendRequest<h3_quinn::OpenStreams, Bytes>,
    target: &XhttpTarget,
    resume_request: Option<SessionId>,
    ack_prefix_requested: bool,
    symmetric_replay_requested: bool,
    client_acked_offset: u64,
    datagram_records: bool,
    datagram_offer: Option<DatagramOffer<'_>>,
    profile: Option<&'static crate::fingerprint_profile::Profile>,
) -> Result<(OpenedSession, H3RequestStreamHandle)> {
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(target.full_uri_with_submode(XhttpSubmode::StreamOne))
        .version(Version::HTTP_3)
        .body(())
        .context("failed to build xhttp/h3 stream-one request")?;
    // A streaming `fetch()` POST: no `Content-Length` (the body is the live
    // uplink).
    let origin = target.web_origin();
    *req.headers_mut() = build_session_request_headers(
        SessionRequest {
            profile,
            kind: RequestKind::FetchPost,
            version: HttpVersion::H3,
            origin: &origin,
            host: None,
        },
        resume_request,
        ack_prefix_requested,
        symmetric_replay_requested,
        client_acked_offset,
        datagram_records,
        datagram_offer.is_some(),
    )?;
    let mut stream = send
        .send_request(req)
        .await
        .map_err(|error| anyhow!(error))
        .context("xhttp/h3 stream-one send_request failed")?;
    let registration = register_anchor(datagram_offer, &stream);
    // Unlike packet-up GET we DO NOT call `finish()` here — the
    // request body is the live uplink.
    let resp = stream
        .recv_response()
        .await
        .map_err(|error| anyhow!(error))
        .context("xhttp/h3 stream-one recv_response failed")?;
    if !resp.status().is_success() {
        bail!("xhttp/h3 stream-one returned {}", resp.status());
    }
    let opened = OpenedSession::negotiated(
        resp.headers(),
        ack_prefix_requested,
        symmetric_replay_requested,
        datagram_records,
        registration,
    );
    Ok((opened, stream))
}

/// Generic over the QUIC types for the same reason [`driver_loop_h3`] is:
/// production instantiates it with `h3_quinn`, tests with an in-process stub.
async fn driver_loop_h3_stream_one<T, S>(
    // Anchors the connection's `SendRequest` count at >0 so dropping
    // the bidi stream below doesn't take the h3 connection down with
    // it via `H3_NO_ERROR`. The handle is otherwise unused — stream-one
    // never opens a second request.
    _send_request_guard: SendRequest<T, Bytes>,
    in_tx: InboundSender,
    mut out_rx: OutboundReceiver,
    stream: h3::client::RequestStream<S, Bytes>,
) where
    T: h3::quic::OpenStreams<Bytes> + Clone + Send + 'static,
    S: h3::quic::BidiStream<Bytes> + Send + 'static,
    S::SendStream: Send,
    S::RecvStream: Send + 'static,
    <S::RecvStream as h3::quic::RecvStream>::Buf: Send,
{
    let (mut send_half, recv_half) = stream.split();
    // Spawn the response-body drain on the receive half.
    let drain_in_tx = in_tx.clone();
    let _drain_task = AbortOnDrop::new(tokio::spawn(async move {
        if let Err(error) = drain_h3_body(recv_half, &drain_in_tx).await {
            debug!(?error, "xhttp/h3 stream-one downlink reader exited");
            let _ = drain_in_tx
                .send_control(Err(io_ws_err("xhttp/h3 stream-one downlink ended")))
                .await;
        } else {
            let _ = drain_in_tx.send_control(Ok(Message::Close(None))).await;
        }
    }));
    // Uplink pump: every Binary message becomes a body chunk on
    // the send half. Calling `finish()` at exit closes the request
    // body cleanly so the server sees EOF and can park or tear down.
    // The permit is released only once `send_data` has taken the bytes.
    let mut send_failed = false;
    while let Some(queued) = out_rx.recv().await {
        let (msg, _permit) = queued.into_parts();
        match msg {
            Message::Binary(b) => {
                if let Err(error) = send_half.send_data(b).await {
                    debug!(?error, "xhttp/h3 stream-one send_data failed");
                    send_failed = true;
                    break;
                }
            },
            Message::Ping(_) | Message::Pong(_) => continue,
            Message::Text(_) => {
                let _ = in_tx.send_control(Err(io_ws_err("xhttp does not carry text"))).await;
                continue;
            },
            Message::Close(_) => break,
            _ => continue,
        }
    }
    if send_failed {
        // A failed write leaves h3-quinn's `writing` slot occupied, so the
        // GREASE frame `finish()` would emit is a second `send_data` into that
        // slot — h3 escalates the resulting misuse error to a connection-level
        // `H3_INTERNAL_ERROR` and the whole shared QUIC carrier collapses,
        // killing every other session riding it. FIN the stream directly.
        let _ = crate::h3::vendored::finish_send_side_without_grease(&mut send_half).await;
    } else {
        let _ = send_half.finish().await;
    }
    debug!("xhttp/h3 stream-one driver exiting");
}

/// Generic over the stream type so it works on both the bidi
/// stream packet-up uses and the receive-half a stream-one split
/// produces.
async fn drain_h3_body<S>(
    mut stream: h3::client::RequestStream<S, Bytes>,
    in_tx: &InboundSender,
) -> Result<()>
where
    S: h3::quic::RecvStream,
{
    loop {
        let chunk = match stream.recv_data().await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(error) => return Err(anyhow!(error)).context("xhttp/h3 GET recv_data failed"),
        };
        // h3's chunk is `impl Buf`; for the h3-quinn `Bytes`-backed buf
        // `copy_to_bytes` is a zero-copy `split_to`, so forward the chunk
        // whole instead of copying every segment into a fresh `BytesMut`.
        // A genuinely segmented buf falls back to the same copy — never worse.
        let mut chunk = chunk;
        let remaining = chunk.remaining();
        let bytes = chunk.copy_to_bytes(remaining);
        if bytes.is_empty() {
            continue;
        }
        let len = bytes.len();
        if in_tx.send(Ok(Message::Binary(bytes)), len).await.is_err() {
            return Ok(());
        }
    }
    Ok(())
}

/// One packet-up POST under [`POST_TIMEOUT`]. On expiry the inner future is
/// dropped, which drops both the request stream and this task's `SendRequest`
/// clone — the last of those is what lets h3 close the QUIC connection instead
/// of parking it on an unresponsive server forever.
async fn post_one_bounded<T>(
    send: SendRequest<T, Bytes>,
    uri_prefix: &str,
    base_headers: &HeaderMap,
    seq: u64,
    payload: Bytes,
) -> Result<()>
where
    T: h3::quic::OpenStreams<Bytes>,
{
    match timeout(POST_TIMEOUT, post_one(send, uri_prefix, base_headers, seq, payload)).await {
        Ok(result) => result,
        Err(_) => bail!("xhttp/h3 POST seq={seq} timed out after {}s", POST_TIMEOUT.as_secs()),
    }
}

/// Generic over the QUIC stream opener so the packet-up POST can be
/// exercised against an in-process stub; production always instantiates
/// it with `h3_quinn::OpenStreams`.
async fn post_one<T>(
    mut send: SendRequest<T, Bytes>,
    uri_prefix: &str,
    base_headers: &HeaderMap,
    seq: u64,
    payload: Bytes,
) -> Result<()>
where
    T: h3::quic::OpenStreams<Bytes>,
{
    // Path-based seq matches xray / sing-box's default placement and
    // mirrors the h2 sibling — keep the wire shape identical across
    // h2 and h3 so a backend cannot tell which version the client
    // negotiated by looking at the uplink URLs.
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(format!("{uri_prefix}{seq}"))
        .version(Version::HTTP_3)
        .body(())
        .context("failed to build xhttp/h3 POST request")?;
    *req.headers_mut() = base_headers.clone();
    super::set_post_content_length(req.headers_mut(), payload.len());
    let mut stream = send
        .send_request(req)
        .await
        .map_err(|error| anyhow!(error))
        .context("xhttp/h3 POST send_request failed")?;
    stream
        .send_data(payload)
        .await
        .map_err(|error| anyhow!(error))
        .context("xhttp/h3 POST send_data failed")?;
    stream
        .finish()
        .await
        .map_err(|error| anyhow!(error))
        .context("xhttp/h3 POST finish failed")?;
    let resp = stream
        .recv_response()
        .await
        .map_err(|error| anyhow!(error))
        .context("xhttp/h3 POST recv_response failed")?;
    let status = resp.status();
    // Drain any small response body so h3 can release the stream
    // promptly (server-side `post_response_headers` mirrors content,
    // not bytes).
    while let Ok(Some(_)) = stream.recv_data().await {}
    if !status.is_success() {
        bail!("xhttp/h3 POST seq={seq} returned {status}");
    }
    Ok(())
}
