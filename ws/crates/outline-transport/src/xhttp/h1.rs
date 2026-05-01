//! HTTP/1.1 carrier for the client-side XHTTP packet-up driver.
//!
//! Last-resort fallback when both `xhttp_h3` and `xhttp_h2` are
//! blocked. h1 has no multiplexing — a single TCP connection only
//! carries one in-flight request at a time and pipelining is too
//! brittle in the presence of CDN/proxy intermediaries — so this
//! module dials **two** keep-alive sockets per session:
//!
//! * **Downlink GET** — long-lived, chunked response body. The whole
//!   socket is dedicated to the response stream for the lifetime of
//!   the session.
//! * **Uplink POSTs** — strictly serialised on a second socket, one
//!   request at a time, awaiting `ready()` and the full response
//!   between sends. This is the deliberate trade-off: throughput is
//!   strictly worse than h2/h3, but the wire shape stays identical
//!   (path-based `<base>/<session>/<seq>`) and a hostile path can't
//!   distinguish us from a vanilla xray-style XHTTP/H1 client.
//!
//! Stream-one is not implemented here — the user-facing fallback
//! chain (`xhttp_h3 → xhttp_h2 → xhttp_h1`) only covers packet-up.
//! A `bail!` in `connect_xhttp_h1` catches misuse loudly instead of
//! silently downgrading the carrier shape.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use http::{Method, Request, Version};
use http_body_util::BodyExt;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::{Error as WsError, protocol::Message};
use tracing::{debug, warn};
use url::Url;

use crate::TransportOperation;
use crate::dns::resolve_host_with_preference;
use crate::dns_cache::DnsCache;
use crate::guards::AbortOnDrop;
use crate::resumption::SessionId;
use crate::connect_tcp_socket;

use super::{
    BoxedIo, INBOUND_CHANNEL_CAPACITY, OUTBOUND_CHANNEL_CAPACITY, RESUME_CAPABLE_HEADER,
    RESUME_REQUEST_HEADER, RequestBody, XhttpStream, XhttpSubmode, XhttpTarget,
    default_port_for, drain_hyper_body, empty_request_body, full_request_body,
    generate_session_id, io_ws_err, parse_session_response,
};

/// Same dial budget as the h2/h3 paths — keeps fallback windows
/// uniform across carriers.
const FRESH_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Cached TLS config with `http/1.1` ALPN. Built once per process.
static XHTTP_H1_TLS_CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();

fn h1_tls_config() -> Arc<rustls::ClientConfig> {
    Arc::clone(XHTTP_H1_TLS_CONFIG.get_or_init(|| crate::tls::build_client_config(&[b"http/1.1"])))
}

pub(super) async fn connect_xhttp_h1(
    cache: &DnsCache,
    url: &Url,
    submode: XhttpSubmode,
    fwmark: Option<u32>,
    ipv6_first: bool,
    resume_request: Option<SessionId>,
) -> Result<(XhttpStream, Option<SessionId>)> {
    if !matches!(submode, XhttpSubmode::PacketUp) {
        bail!("xhttp/h1 carrier supports packet-up only (got submode {submode:?})");
    }

    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("xhttp/h1 url missing host: {url}"))?
        .to_owned();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("xhttp/h1 url missing port and no scheme default: {url}"))?;
    let base_path = url.path().trim_end_matches('/').to_owned();
    if base_path.is_empty() {
        bail!("xhttp/h1 url path must be a non-empty base (e.g. /xh): {url}");
    }
    let use_tls = matches!(url.scheme(), "https" | "wss");
    // Profile is picked once per dial — every GET / POST in this
    // session shares the same browser identity so a single peer
    // never sees one session split across two fingerprints.
    let profile = crate::fingerprint_profile::select(url);

    let dial = async {
        let addrs = resolve_host_with_preference(
            cache,
            &host,
            port,
            "failed to resolve xhttp/h1 host",
            ipv6_first,
        )
        .await?;
        let server_addr = *addrs.first().ok_or_else(|| {
            anyhow::Error::new(TransportOperation::DnsResolveNoAddresses { host: host.clone() })
        })?;

        // Dial two keep-alive sockets: downlink GET on `down_send`,
        // serialised uplink POSTs on `up_send`. They cost two TCP
        // connections (and two TLS handshakes) per session — the
        // explicit price h1 charges for not multiplexing.
        let down_send = h1_handshake(server_addr, &host, use_tls, fwmark).await?;
        let up_send = h1_handshake(server_addr, &host, use_tls, fwmark).await?;
        let session_id = generate_session_id()?;

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

        let (in_tx, in_rx) = mpsc::channel::<Result<Message, WsError>>(INBOUND_CHANNEL_CAPACITY);
        let (out_tx, out_rx) = mpsc::channel::<Message>(OUTBOUND_CHANNEL_CAPACITY);

        // Open the GET synchronously so the resume-id round-trip
        // completes before we hand the stream to the caller. Mirrors
        // the h2/h3 packet-up dial shape.
        let (issued_session_id, body) =
            open_h1_get(down_send, &target, resume_request, profile).await?;
        let driver = tokio::spawn(driver_loop_h1(
            up_send,
            target.clone(),
            in_tx,
            out_rx,
            body,
            profile,
        ));

        debug!(
            %url, %session_id, mode = "xhttp_h1",
            ?issued_session_id, ?resume_request,
            "xhttp h1 session opened"
        );
        Ok::<_, anyhow::Error>((
            XhttpStream::from_channels(
                in_rx,
                out_tx,
                AbortOnDrop::new(driver),
                XhttpSubmode::PacketUp,
            ),
            issued_session_id,
        ))
    };

    timeout(FRESH_CONNECT_TIMEOUT, dial)
        .await
        .with_context(|| format!("xhttp/h1 dial to {url} timed out"))?
        .with_context(|| format!("xhttp/h1 dial to {url} failed"))
}

async fn h1_handshake(
    addr: SocketAddr,
    host: &str,
    use_tls: bool,
    fwmark: Option<u32>,
) -> Result<http1::SendRequest<RequestBody>> {
    let tcp = connect_tcp_socket(addr, fwmark).await?;
    if use_tls {
        let connector = TlsConnector::from(h1_tls_config());
        let server_name = if let Ok(ip) = host.parse::<IpAddr>() {
            ServerName::IpAddress(ip.into())
        } else {
            ServerName::try_from(host.to_string())
                .map_err(|_| anyhow!("invalid TLS server name for xhttp/h1: {host}"))?
        };
        let tls = connector
            .connect(server_name, tcp)
            .await
            .context("TLS handshake for xhttp/h1 failed")?;
        spawn_h1(TokioIo::new(BoxedIo::Tls(tls))).await
    } else {
        spawn_h1(TokioIo::new(BoxedIo::Plain(tcp))).await
    }
}

async fn spawn_h1<T>(io: TokioIo<T>) -> Result<http1::SendRequest<RequestBody>>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (send_request, conn) = http1::Builder::new()
        .handshake(io)
        .await
        .context("xhttp h1 handshake failed")?;
    // Hyper's connection future drives the keep-alive loop; without
    // this background task the socket freezes immediately after the
    // first request.
    tokio::spawn(async move {
        if let Err(error) = conn.await {
            debug!(?error, "xhttp h1 connection ended");
        }
    });
    Ok(send_request)
}

async fn open_h1_get(
    mut send: http1::SendRequest<RequestBody>,
    target: &XhttpTarget,
    resume_request: Option<SessionId>,
    profile: Option<&'static crate::fingerprint_profile::Profile>,
) -> Result<(Option<SessionId>, hyper::body::Incoming)> {
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(target.full_uri())
        .version(Version::HTTP_11)
        .header(http::header::HOST, target.authority.as_str())
        .header(RESUME_CAPABLE_HEADER, "1");
    if let Some(id) = resume_request {
        builder = builder.header(RESUME_REQUEST_HEADER, id.to_hex());
    }
    let mut req = builder
        .body(empty_request_body())
        .context("failed to build xhttp/h1 GET request")?;
    if let Some(profile) = profile {
        crate::fingerprint_profile::apply(
            profile,
            req.headers_mut(),
            crate::fingerprint_profile::SecFetchPreset::XhrCors,
        );
    }
    send.ready().await.context("xhttp h1 not ready for GET")?;
    let resp = send
        .send_request(req)
        .await
        .context("xhttp/h1 GET send_request failed")?;
    if !resp.status().is_success() {
        bail!("xhttp/h1 GET returned {}", resp.status());
    }
    let issued = parse_session_response(resp.headers());
    Ok((issued, resp.into_body()))
}

async fn driver_loop_h1(
    mut up_send: http1::SendRequest<RequestBody>,
    target: Arc<XhttpTarget>,
    in_tx: mpsc::Sender<Result<Message, WsError>>,
    mut out_rx: mpsc::Receiver<Message>,
    body: hyper::body::Incoming,
    profile: Option<&'static crate::fingerprint_profile::Profile>,
) {
    // GET drain sub-task. Headers were exchanged synchronously in
    // `open_h1_get`; this task just pulls body chunks until EOF and
    // forwards them to the inbound channel.
    let drain_in_tx = in_tx.clone();
    let _drain_task = AbortOnDrop::new(tokio::spawn(async move {
        if let Err(error) = drain_hyper_body(body, &drain_in_tx).await {
            debug!(?error, "xhttp/h1 GET reader exited");
            let _ = drain_in_tx
                .send(Err(io_ws_err("xhttp/h1 downlink ended")))
                .await;
        } else {
            let _ = drain_in_tx.send(Ok(Message::Close(None))).await;
        }
    }));

    // POST loop: strictly serialised on the uplink connection.
    // h1 only allows one in-flight request per socket, and pipelining
    // is too unreliable through CDN/proxy intermediaries to risk —
    // await each POST to completion before starting the next.
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
                let _ = in_tx
                    .send(Err(io_ws_err("xhttp/h1 does not carry text")))
                    .await;
                continue;
            },
            Message::Close(_) => break,
            _ => continue,
        };
        let seq = next_seq;
        next_seq = next_seq.saturating_add(1);
        if let Err(error) = up_send.ready().await {
            warn!(?error, "xhttp h1 uplink connection lost while waiting for capacity");
            let _ = in_tx
                .send(Err(io_ws_err("xhttp/h1 uplink not ready")))
                .await;
            break;
        }
        if let Err(error) = post_one(&mut up_send, target.as_ref(), seq, bytes, profile).await {
            warn!(?error, seq, "xhttp/h1 POST failed");
            let _ = in_tx
                .send(Err(io_ws_err("xhttp/h1 uplink POST failed")))
                .await;
            // A single POST failure tears the keep-alive socket down
            // (hyper's connection task will exit on the next read), so
            // breaking the driver loop here matches reality — we
            // can't recover the in-flight stream without re-dialing.
            break;
        }
    }
    debug!("xhttp/h1 driver exiting");
}

async fn post_one(
    send: &mut http1::SendRequest<RequestBody>,
    target: &XhttpTarget,
    seq: u64,
    payload: bytes::Bytes,
    profile: Option<&'static crate::fingerprint_profile::Profile>,
) -> Result<()> {
    // Path-based seq matches xray / sing-box's `PlacementPath` default
    // and mirrors the h2/h3 siblings — the wire URL stays byte-identical
    // across all three carriers.
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(target.full_uri_with_seq(seq))
        .version(Version::HTTP_11)
        .header(http::header::HOST, target.authority.as_str())
        .header(http::header::CONTENT_LENGTH, payload.len())
        .body(full_request_body(payload))
        .context("failed to build xhttp/h1 POST request")?;
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
        .context("xhttp/h1 POST send_request failed")?;
    let status = resp.status();
    // Drain the (small) response body so hyper releases the keep-alive
    // socket back into the ready state for the next POST.
    let _ = resp.into_body().collect().await;
    if !status.is_success() {
        bail!("xhttp/h1 POST seq={seq} returned {status}");
    }
    Ok(())
}

