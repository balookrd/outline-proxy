//! HTTP/3 carrier for the client-side XHTTP packet-up driver.
//!
//! Mirrors the h2 path in the parent module but rides QUIC instead
//! of TCP+TLS+h2. We spin up a per-session quinn endpoint + h3
//! handshake; there is no shared-connection pool here because XHTTP
//! sessions are 1:1 with their VLESS upstream and have no cache key.
//!
//! This module is gated behind the `h3` feature: it pulls in `quinn`
//! and the `h3` / `h3-quinn` crates that the rest of the H3 path
//! already depends on.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bytes::{Buf, Bytes, BytesMut};
use h3::client::SendRequest;
use http::{Method, Request, Version};
use rustls::pki_types::ServerName;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::{Error as WsError, protocol::Message};
use tracing::{debug, warn};
use url::Url;

use crate::dns::resolve_host_with_preference;
use crate::dns_cache::DnsCache;
use crate::guards::AbortOnDrop;
use crate::TransportOperation;

use super::{
    INBOUND_CHANNEL_CAPACITY, OUTBOUND_CHANNEL_CAPACITY, SEQ_HEADER, XhttpStream, XhttpTarget,
    generate_session_id, io_ws_err,
};

/// Same dial budget the h2 path uses — keeps fallback windows
/// uniform across carriers.
const FRESH_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Cached TLS config with `h3` ALPN. Built once per process.
static XHTTP_H3_TLS_CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();

fn h3_tls_config() -> Arc<rustls::ClientConfig> {
    Arc::clone(XHTTP_H3_TLS_CONFIG.get_or_init(|| crate::tls::build_client_config(&[b"h3"])))
}

fn h3_quic_client_config() -> quinn::ClientConfig {
    let tls = h3_tls_config();
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from((*tls).clone())
        .expect("xhttp h3 TLS config is always QUIC-compatible");
    let mut config = quinn::ClientConfig::new(Arc::new(quic));
    let mut transport = quinn::TransportConfig::default();
    // Match the rest of the H3 client: 30 s idle, 10 s keepalive.
    // The XHTTP session is long-lived (the GET stays open for the
    // lifetime of the VLESS upstream), so the keepalive timer is
    // primarily defending NAT mappings rather than detecting peer
    // death — the GET response body itself doubles as a liveness
    // signal once data starts flowing.
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    transport.max_idle_timeout(Some(
        Duration::from_secs(30)
            .try_into()
            .expect("valid xhttp h3 QUIC idle timeout"),
    ));
    config.transport_config(Arc::new(transport));
    config
}

pub(super) async fn connect_xhttp_h3(
    cache: &DnsCache,
    url: &Url,
    fwmark: Option<u32>,
    ipv6_first: bool,
) -> Result<XhttpStream> {
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

    let dial = async {
        let addrs = resolve_host_with_preference(
            cache,
            &host,
            port,
            "failed to resolve xhttp/h3 host",
            ipv6_first,
        )
        .await?;
        let server_addr = *addrs.first().ok_or_else(|| {
            anyhow::Error::new(TransportOperation::DnsResolveNoAddresses { host: host.clone() })
        })?;

        let send_request = h3_handshake(server_addr, &host, fwmark).await?;
        let session_id = generate_session_id()?;

        let authority = if port == 443 { host.clone() } else { format!("{host}:{port}") };
        let target = Arc::new(XhttpTarget {
            scheme: "https".to_string(),
            authority,
            base_path: base_path.clone(),
            session_id: session_id.clone(),
        });

        let (in_tx, in_rx) = mpsc::channel::<Result<Message, WsError>>(INBOUND_CHANNEL_CAPACITY);
        let (out_tx, out_rx) = mpsc::channel::<Message>(OUTBOUND_CHANNEL_CAPACITY);
        let driver = tokio::spawn(driver_loop(send_request, target, in_tx, out_rx));

        debug!(%url, %session_id, mode = "xhttp_h3", "xhttp packet-up h3 session opened");
        Ok::<_, anyhow::Error>(XhttpStream::from_channels(in_rx, out_tx, AbortOnDrop::new(driver)))
    };

    timeout(FRESH_CONNECT_TIMEOUT, dial)
        .await
        .with_context(|| format!("xhttp/h3 dial to {url} timed out"))?
        .with_context(|| format!("xhttp/h3 dial to {url} failed"))
}

async fn h3_handshake(
    server_addr: SocketAddr,
    host: &str,
    fwmark: Option<u32>,
) -> Result<SendRequest<h3_quinn::OpenStreams, Bytes>> {
    let bind_addr = crate::bind_addr_for(server_addr);
    let socket = crate::bind_udp_socket(bind_addr, fwmark)?;
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .with_context(|| format!("failed to bind xhttp/h3 QUIC endpoint on {bind_addr}"))?;

    let server_name = if let Ok(ip) = host.parse::<IpAddr>() {
        ServerName::IpAddress(ip.into())
    } else {
        ServerName::try_from(host.to_string())
            .map_err(|_| anyhow!("invalid TLS server name for xhttp/h3: {host}"))?
    };
    let server_name_str = match &server_name {
        ServerName::DnsName(name) => name.as_ref().to_owned(),
        ServerName::IpAddress(_) => host.to_string(),
        _ => host.to_string(),
    };
    let connecting = endpoint
        .connect_with(h3_quic_client_config(), server_addr, &server_name_str)
        .with_context(|| format!("failed to initiate xhttp/h3 QUIC connection to {server_addr}"))?;
    let connection = connecting
        .await
        .with_context(|| format!("xhttp/h3 QUIC handshake failed for {server_addr}"))?;
    let (mut driver, send_request) = h3::client::new(h3_quinn::Connection::new(connection))
        .await
        .context("xhttp/h3 HTTP/3 handshake failed")?;
    // Spawn the h3 connection driver. The send_request handle stays
    // usable as long as the driver keeps running; on driver exit any
    // outstanding RequestStream sees a closed-stream error, which
    // the GET / POST loops treat as terminal and shut the session
    // down via `XhttpSession::close()` indirectly through `in_tx`.
    tokio::spawn(async move {
        let close = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        debug!(?close, "xhttp/h3 driver closed");
    });
    // Keep the endpoint alive for the duration of the session by
    // anchoring it in a task-owning closure: when the driver task
    // (above) exits, this side has nothing else holding the endpoint
    // and it drops cleanly. The connection's `Drop` wakes the driver
    // task to flush close frames.
    let _endpoint_guard = endpoint;
    Ok(send_request)
}

async fn driver_loop(
    send_request: SendRequest<h3_quinn::OpenStreams, Bytes>,
    target: Arc<XhttpTarget>,
    in_tx: mpsc::Sender<Result<Message, WsError>>,
    mut out_rx: mpsc::Receiver<Message>,
) {
    // GET reader sub-task: opens the long-lived downlink and pushes
    // every chunk it receives onto the inbound channel. Mirrors the
    // h2 path so `XhttpStream::poll_next` is carrier-agnostic.
    let get_send = send_request.clone();
    let get_target = Arc::clone(&target);
    let get_in_tx = in_tx.clone();
    let _get_task = AbortOnDrop::new(tokio::spawn(async move {
        if let Err(error) = drive_get(get_send, get_target, &get_in_tx).await {
            debug!(?error, "xhttp/h3 GET reader exited");
            let _ = get_in_tx.send(Err(io_ws_err("xhttp/h3 downlink ended"))).await;
        } else {
            let _ = get_in_tx.send(Ok(Message::Close(None))).await;
        }
    }));

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
                    .send(Err(io_ws_err("xhttp/h3 does not carry text")))
                    .await;
                continue;
            },
            Message::Close(_) => break,
            _ => continue,
        };
        let seq = next_seq;
        next_seq = next_seq.saturating_add(1);
        let send = send_request.clone();
        let target = Arc::clone(&target);
        let in_tx_for_err = in_tx.clone();
        tokio::spawn(async move {
            if let Err(error) = post_one(send, target.as_ref(), seq, bytes).await {
                warn!(?error, seq, "xhttp/h3 POST failed");
                let _ = in_tx_for_err
                    .send(Err(io_ws_err("xhttp/h3 uplink POST failed")))
                    .await;
            }
        });
    }
    debug!("xhttp/h3 driver exiting");
}

async fn drive_get(
    mut send: SendRequest<h3_quinn::OpenStreams, Bytes>,
    target: Arc<XhttpTarget>,
    in_tx: &mpsc::Sender<Result<Message, WsError>>,
) -> Result<()> {
    let req = Request::builder()
        .method(Method::GET)
        .uri(target.full_uri())
        .version(Version::HTTP_3)
        .body(())
        .context("failed to build xhttp/h3 GET request")?;
    let mut stream = send
        .send_request(req)
        .await
        .map_err(|error| anyhow!(error))
        .context("xhttp/h3 GET send_request failed")?;
    // GET has no body; close the request side so the server can
    // start streaming the response immediately.
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
    loop {
        let chunk = match stream.recv_data().await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(error) => return Err(anyhow!(error)).context("xhttp/h3 GET recv_data failed"),
        };
        // h3's chunk is `impl Buf` — copy contiguous segments out
        // until the chunk is drained, then forward as a single
        // Message::Binary. Coalescing avoids per-segment allocations
        // on the inbound channel and matches the h2 path's framing.
        let mut chunk = chunk;
        let mut acc = BytesMut::with_capacity(chunk.remaining());
        while chunk.has_remaining() {
            let segment = chunk.chunk();
            acc.extend_from_slice(segment);
            let consumed = segment.len();
            chunk.advance(consumed);
        }
        if !acc.is_empty()
            && in_tx.send(Ok(Message::Binary(acc.freeze()))).await.is_err()
        {
            return Ok(());
        }
    }
    Ok(())
}

async fn post_one(
    mut send: SendRequest<h3_quinn::OpenStreams, Bytes>,
    target: &XhttpTarget,
    seq: u64,
    payload: Bytes,
) -> Result<()> {
    let req = Request::builder()
        .method(Method::POST)
        .uri(target.full_uri())
        .version(Version::HTTP_3)
        .header(SEQ_HEADER, seq.to_string())
        .body(())
        .context("failed to build xhttp/h3 POST request")?;
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
