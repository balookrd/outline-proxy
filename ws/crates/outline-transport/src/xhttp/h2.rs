//! H/2 carrier for the XHTTP packet-up and stream-one submodes.
//!
//! Owns the TLS-config singleton, the h2 handshake, the GET/POST/stream-one
//! request builders, the long-lived driver task, and the dial-time inline
//! stream-one→packet-up retry. The dispatcher in `super` calls
//! [`connect_xhttp_h2`] for `TransportMode::XhttpH2`.

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use bytes::Bytes;
use http::{Method, Request, Version};
use http_body_util::{BodyExt, StreamBody};
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::{Error as WsError, protocol::Message};
use tokio_util::sync::PollSender;
use tracing::{debug, warn};
use url::Url;

use crate::config::TransportMode;
use crate::dns::resolve_host_with_preference;
use crate::dns_cache::DnsCache;
use crate::guards::AbortOnDrop;
use crate::resumption::SessionId;
use crate::{TransportOperation, connect_tcp_socket};

use super::stream::{BoxedIo, drain_hyper_body, io_ws_err};
use super::{
    INBOUND_CHANNEL_CAPACITY, OUTBOUND_CHANNEL_CAPACITY, RESUME_CAPABLE_HEADER,
    RESUME_REQUEST_HEADER, RequestBody, XhttpStream, XhttpSubmode, XhttpTarget,
    default_port_for, empty_request_body, full_request_body, generate_session_id,
    parse_session_response, resolve_effective_submode,
};

/// Time budget for the initial dial: TCP + TLS + h2 handshake +
/// first POST/GET ack. Matches the bound used by the WS h2 dial
/// in `h2/shared.rs` for parity with manager-level retry windows.
const FRESH_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// TLS config (h2 ALPN) cached lazily — built once per process.
static XHTTP_H2_TLS_CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();

fn h2_tls_config() -> Arc<rustls::ClientConfig> {
    // `build_client_config` consults the test override slot itself, so
    // a `OnceLock` here is fine: the first call captures whichever
    // root store is current, and tests that need the override install
    // it before the first dial.
    Arc::clone(XHTTP_H2_TLS_CONFIG.get_or_init(|| crate::tls::build_client_config(&[b"h2"])))
}

pub(super) async fn connect_xhttp_h2(
    cache: &DnsCache,
    url: &Url,
    mode: TransportMode,
    fwmark: Option<u32>,
    ipv6_first: bool,
    resume_request: Option<SessionId>,
) -> Result<(XhttpStream, Option<SessionId>)> {
    let submode = resolve_effective_submode(url, mode).await;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("xhttp url missing host: {url}"))?
        .to_owned();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("xhttp url missing port and no scheme default: {url}"))?;
    let base_path = url.path().trim_end_matches('/').to_owned();
    if base_path.is_empty() {
        bail!("xhttp url path must be a non-empty base (e.g. /xh): {url}");
    }
    let use_tls = matches!(url.scheme(), "https" | "wss");
    // Profile picked once per dial — every GET / POST in this h2
    // session shares the same browser identity so an observer never
    // sees a single peer split across two fingerprints.
    let profile = crate::fingerprint_profile::select(url);

    let dial = async {
        let addrs =
            resolve_host_with_preference(cache, &host, port, "failed to resolve xhttp host", ipv6_first)
                .await?;
        let server_addr = *addrs.first().ok_or_else(|| {
            anyhow::Error::new(TransportOperation::DnsResolveNoAddresses { host: host.clone() })
        })?;
        let send_request = h2_handshake(server_addr, &host, use_tls, fwmark).await?;
        let session_id = generate_session_id()?;

        let (in_tx, in_rx) = mpsc::channel::<Result<Message, WsError>>(INBOUND_CHANNEL_CAPACITY);
        let (out_tx, out_rx) = mpsc::channel::<Message>(OUTBOUND_CHANNEL_CAPACITY);

        let authority = if port == default_port_for(use_tls) {
            host.clone()
        } else {
            format!("{host}:{port}")
        };
        let scheme = if use_tls { "https" } else { "http" };
        let target = Arc::new(XhttpTarget {
            scheme: scheme.into(),
            authority,
            base_path: base_path.into(),
            session_id: session_id.clone(),
        });

        let (issued_session_id, driver, active_submode) = match submode {
            XhttpSubmode::PacketUp => {
                // Open the GET synchronously so the resume-id
                // round-trip completes before we hand the stream to
                // the caller. The body drain is spawned as a
                // sub-task; POSTs are pipelined per `start_send`.
                let (issued, body) =
                    open_h2_get(send_request.clone(), &target, resume_request, profile).await?;
                let driver = tokio::spawn(driver_loop_h2(
                    send_request,
                    target.clone(),
                    in_tx,
                    out_rx,
                    body,
                    profile,
                ));
                (issued, driver, XhttpSubmode::PacketUp)
            },
            XhttpSubmode::StreamOne => {
                // Stream-one is a single bidirectional POST: open
                // it synchronously to read response headers, then
                // hand the response body and the request-body
                // sender to the driver. On dial-time failure we
                // retry packet-up on the same h2 connection — the
                // TCP/TLS/h2 cost is sunk and the failure is most
                // likely middlebox-shaped (the CDN refused to
                // forward the streaming request body), so trying
                // the simpler carrier on the surviving connection
                // recovers without burning a fresh handshake.
                match open_h2_stream_one(send_request.clone(), &target, resume_request, profile)
                    .await
                {
                    Ok((issued, body, frame_tx)) => {
                        let driver = tokio::spawn(driver_loop_h2_stream_one(
                            in_tx, out_rx, body, frame_tx,
                        ));
                        crate::xhttp_submode_cache::record_success(url, XhttpSubmode::StreamOne)
                            .await;
                        (issued, driver, XhttpSubmode::StreamOne)
                    },
                    Err(stream_err) => {
                        warn!(
                            %url,
                            error = %format!("{stream_err:#}"),
                            "xhttp h2 stream-one failed, falling back to packet-up on same connection"
                        );
                        crate::xhttp_submode_cache::record_failure(url, XhttpSubmode::StreamOne)
                            .await;
                        let (issued, body) =
                            open_h2_get(send_request.clone(), &target, resume_request, profile)
                                .await?;
                        let driver = tokio::spawn(driver_loop_h2(
                            send_request,
                            target.clone(),
                            in_tx,
                            out_rx,
                            body,
                            profile,
                        ));
                        (issued, driver, XhttpSubmode::PacketUp)
                    },
                }
            },
        };

        debug!(
            %url, %session_id, mode = "xhttp_h2", ?submode, ?active_submode,
            ?issued_session_id, ?resume_request,
            "xhttp session opened"
        );
        Ok::<_, anyhow::Error>((
            XhttpStream {
                incoming: in_rx,
                outgoing: PollSender::new(out_tx),
                closed: false,
                active_submode,
                _driver: AbortOnDrop::new(driver),
            },
            issued_session_id,
        ))
    };

    timeout(FRESH_CONNECT_TIMEOUT, dial)
        .await
        .with_context(|| format!("xhttp dial to {url} timed out"))?
        .with_context(|| format!("xhttp dial to {url} failed"))
}

/// Issues the long-lived GET, awaits response headers, and pulls
/// out the optional `X-Outline-Session` resume token. The body is
/// returned for the caller to drain in its own sub-task. Surfacing
/// the issued id synchronously (rather than via a side channel) is
/// what lets the dial path stash the token in the resume cache
/// before any data flows.
async fn open_h2_get(
    mut send: http2::SendRequest<RequestBody>,
    target: &XhttpTarget,
    resume_request: Option<SessionId>,
    profile: Option<&'static crate::fingerprint_profile::Profile>,
) -> Result<(Option<SessionId>, hyper::body::Incoming)> {
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(target.full_uri())
        .version(Version::HTTP_2)
        .header(http::header::HOST, target.authority.as_str())
        .header(RESUME_CAPABLE_HEADER, "1");
    if let Some(id) = resume_request {
        builder = builder.header(RESUME_REQUEST_HEADER, id.to_hex());
    }
    let mut req = builder
        .body(empty_request_body())
        .context("failed to build xhttp GET request")?;
    if let Some(profile) = profile {
        crate::fingerprint_profile::apply(
            profile,
            req.headers_mut(),
            crate::fingerprint_profile::SecFetchPreset::XhrCors,
        );
    }
    send.ready().await.context("xhttp h2 not ready for GET")?;
    let resp = send
        .send_request(req)
        .await
        .context("xhttp GET send_request failed")?;
    if !resp.status().is_success() {
        bail!("xhttp GET returned {}", resp.status());
    }
    let issued = parse_session_response(resp.headers());
    Ok((issued, resp.into_body()))
}

/// Stream-one carrier on h2: a single bidirectional POST whose
/// request body is the uplink and whose response body is the
/// downlink. The synchronously-built `frame_tx` lets the driver
/// task feed body chunks into the request stream, while the
/// returned `Incoming` is consumed by the downlink drain.
async fn open_h2_stream_one(
    mut send: http2::SendRequest<RequestBody>,
    target: &XhttpTarget,
    resume_request: Option<SessionId>,
    profile: Option<&'static crate::fingerprint_profile::Profile>,
) -> Result<(
    Option<SessionId>,
    hyper::body::Incoming,
    mpsc::Sender<hyper::body::Frame<Bytes>>,
)> {
    // Sized to match `OUTBOUND_CHANNEL_CAPACITY` so a long-lived
    // stream-one POST has the same burst window as packet-up; h2
    // flow control on the wire still bounds real memory.
    let (frame_tx, frame_rx) = mpsc::channel::<hyper::body::Frame<Bytes>>(OUTBOUND_CHANNEL_CAPACITY);
    let body_stream = futures_util::stream::unfold(frame_rx, |mut rx| async move {
        rx.recv().await.map(|frame| (Ok::<_, Infallible>(frame), rx))
    });
    let body: RequestBody = StreamBody::new(body_stream).boxed();

    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(target.full_uri_with_submode(XhttpSubmode::StreamOne))
        .version(Version::HTTP_2)
        .header(http::header::HOST, target.authority.as_str())
        .header(RESUME_CAPABLE_HEADER, "1");
    if let Some(id) = resume_request {
        builder = builder.header(RESUME_REQUEST_HEADER, id.to_hex());
    }
    let mut req = builder
        .body(body)
        .context("failed to build xhttp stream-one request")?;
    if let Some(profile) = profile {
        crate::fingerprint_profile::apply(
            profile,
            req.headers_mut(),
            crate::fingerprint_profile::SecFetchPreset::XhrCors,
        );
    }
    send.ready().await.context("xhttp h2 not ready for stream-one")?;
    let resp = send
        .send_request(req)
        .await
        .context("xhttp stream-one send_request failed")?;
    if !resp.status().is_success() {
        bail!("xhttp stream-one returned {}", resp.status());
    }
    let issued = parse_session_response(resp.headers());
    Ok((issued, resp.into_body(), frame_tx))
}

async fn driver_loop_h2_stream_one(
    in_tx: mpsc::Sender<Result<Message, WsError>>,
    mut out_rx: mpsc::Receiver<Message>,
    body: hyper::body::Incoming,
    frame_tx: mpsc::Sender<hyper::body::Frame<Bytes>>,
) {
    // Spawn the response-body drain as a sub-task so the uplink
    // pump below can run concurrently. The shape mirrors
    // `driver_loop_h2` for packet-up.
    let drain_in_tx = in_tx.clone();
    let _drain_task = AbortOnDrop::new(tokio::spawn(async move {
        if let Err(error) = drain_hyper_body(body, &drain_in_tx).await {
            debug!(?error, "xhttp stream-one downlink reader exited");
            let _ = drain_in_tx
                .send(Err(io_ws_err("xhttp stream-one downlink ended")))
                .await;
        } else {
            let _ = drain_in_tx.send(Ok(Message::Close(None))).await;
        }
    }));

    // Uplink pump: every Message::Binary becomes a body frame on
    // the request stream. Closing `frame_tx` (we drop it on exit)
    // ends the request body and lets the server see EOF.
    while let Some(msg) = out_rx.recv().await {
        match msg {
            Message::Binary(b) => {
                if frame_tx
                    .send(hyper::body::Frame::data(b))
                    .await
                    .is_err()
                {
                    break;
                }
            },
            Message::Ping(_) | Message::Pong(_) => continue,
            Message::Text(_) => {
                let _ = in_tx
                    .send(Err(io_ws_err("xhttp does not carry text")))
                    .await;
                continue;
            },
            Message::Close(_) => break,
            _ => continue,
        }
    }
    drop(frame_tx);
    debug!("xhttp stream-one driver exiting");
}

async fn h2_handshake(
    addr: SocketAddr,
    host: &str,
    use_tls: bool,
    fwmark: Option<u32>,
) -> Result<http2::SendRequest<RequestBody>> {
    let tcp = connect_tcp_socket(addr, fwmark).await?;
    if use_tls {
        let connector = TlsConnector::from(h2_tls_config());
        let server_name = if let Ok(ip) = host.parse::<IpAddr>() {
            ServerName::IpAddress(ip.into())
        } else {
            ServerName::try_from(host.to_string())
                .map_err(|_| anyhow!("invalid TLS server name for xhttp: {host}"))?
        };
        let tls = connector
            .connect(server_name, tcp)
            .await
            .context("TLS handshake for xhttp failed")?;
        spawn_h2(TokioIo::new(BoxedIo::Tls(tls))).await
    } else {
        // Plain h2 over TCP — used by tests and trusted-network
        // deployments. Production callers should run TLS.
        spawn_h2(TokioIo::new(BoxedIo::Plain(tcp))).await
    }
}

async fn spawn_h2<T>(io: TokioIo<T>) -> Result<http2::SendRequest<RequestBody>>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (send_request, conn) = http2::Builder::new(TokioExecutor::new())
        .handshake(io)
        .await
        .context("xhttp h2 handshake failed")?;
    // Hyper's connection future drives the multiplexer; without this
    // background task the whole mux freezes after the handshake.
    tokio::spawn(async move {
        if let Err(error) = conn.await {
            debug!(?error, "xhttp h2 connection ended");
        }
    });
    Ok(send_request)
}

async fn driver_loop_h2(
    send_request: http2::SendRequest<RequestBody>,
    target: Arc<XhttpTarget>,
    in_tx: mpsc::Sender<Result<Message, WsError>>,
    mut out_rx: mpsc::Receiver<Message>,
    body: hyper::body::Incoming,
    profile: Option<&'static crate::fingerprint_profile::Profile>,
) {
    // GET drain sub-task. The GET request and response headers were
    // already exchanged synchronously in `connect_xhttp_h2`; this task
    // just pulls body chunks until EOF and forwards them to the
    // inbound channel.
    let drain_in_tx = in_tx.clone();
    let _drain_task = AbortOnDrop::new(tokio::spawn(async move {
        if let Err(error) = drain_hyper_body(body, &drain_in_tx).await {
            debug!(?error, "xhttp GET reader exited");
            let _ = drain_in_tx.send(Err(io_ws_err("xhttp downlink ended"))).await;
        } else {
            // Clean EOF on the response body — surface a Close so
            // upstream sees a recognisable shutdown rather than a
            // silent stop.
            let _ = drain_in_tx.send(Ok(Message::Close(None))).await;
        }
    }));

    // POST loop: pop messages, send them with monotonically-
    // increasing seq. Pipelined — we spawn the actual hyper send
    // as a sub-task so successive POSTs can overlap on the wire.
    let mut next_seq: u64 = 0;
    loop {
        let msg = match out_rx.recv().await {
            Some(msg) => msg,
            None => break,
        };
        let bytes = match msg {
            Message::Binary(b) => b,
            Message::Ping(_) | Message::Pong(_) => continue,
            Message::Text(_) => {
                let _ = in_tx.send(Err(io_ws_err("xhttp does not carry text"))).await;
                continue;
            },
            Message::Close(_) => break,
            _ => continue,
        };
        let seq = next_seq;
        next_seq = next_seq.saturating_add(1);
        let mut send = send_request.clone();
        let target = Arc::clone(&target);
        let in_tx_for_err = in_tx.clone();
        // Hyper requires `ready().await` before issuing a new
        // stream; doing it inline serialises POSTs against
        // _hyper's_ flow-control state but does not serialise
        // against the actual wire — once the request is queued the
        // POST runs to completion concurrently.
        if let Err(error) = send.ready().await {
            warn!(?error, "xhttp h2 connection lost while waiting for capacity");
            let _ = in_tx
                .send(Err(io_ws_err("xhttp h2 stream not ready")))
                .await;
            break;
        }
        tokio::spawn(async move {
            if let Err(error) = post_one(send, target.as_ref(), seq, bytes, profile).await {
                warn!(?error, seq, "xhttp POST failed");
                let _ = in_tx_for_err
                    .send(Err(io_ws_err("xhttp uplink POST failed")))
                    .await;
            }
        });
    }
    debug!("xhttp driver exiting");
}

async fn post_one(
    mut send: http2::SendRequest<RequestBody>,
    target: &XhttpTarget,
    seq: u64,
    payload: Bytes,
    profile: Option<&'static crate::fingerprint_profile::Profile>,
) -> Result<()> {
    // Path-based seq (`<base>/<session>/<seq>`) is xray / sing-box's
    // default placement; the server matches both shapes but emitting
    // path-based here keeps the wire byte-identical to what xray
    // produces, so an on-path observer cannot tell our client apart
    // from a vanilla xray one.
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(target.full_uri_with_seq(seq))
        .version(Version::HTTP_2)
        .header(http::header::HOST, target.authority.as_str())
        .body(full_request_body(payload))
        .context("failed to build xhttp POST request")?;
    if let Some(profile) = profile {
        crate::fingerprint_profile::apply(
            profile,
            req.headers_mut(),
            crate::fingerprint_profile::SecFetchPreset::XhrCors,
        );
    }
    let resp = send
        .send_request(req)
        .await
        .context("xhttp POST send_request failed")?;
    let status = resp.status();
    // Drain the (small) response body so hyper releases the stream.
    let _ = resp.into_body().collect().await;
    if !status.is_success() {
        bail!("xhttp POST seq={seq} returned {status}");
    }
    Ok(())
}
