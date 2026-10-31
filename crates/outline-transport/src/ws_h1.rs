//! Client side of the HTTP/1.1 WebSocket upgrade (`ws_h1`), written by hand.
//!
//! tungstenite's client handshake writes `Host`, `Connection`, `Upgrade`,
//! `Sec-WebSocket-Version` and `Sec-WebSocket-Key` first, in that order and
//! case, and every other header lowercase — no browser sends that. Here the
//! request head is built by [`crate::request_headers`] (the profile browser's
//! order and case) and written as is; the response is verified per RFC 6455
//! §4.2.2 and the socket is handed to tokio-tungstenite with whatever bytes
//! followed the response head ([`WebSocketStream::from_partially_read`]).

use anyhow::{Context, Result, anyhow, bail};
use http::{HeaderMap, HeaderName, HeaderValue};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::Role;

/// Upper bound on the response head (status line + headers). Our server's
/// 101 is a few hundred bytes; anything this large is not a WebSocket peer.
const MAX_RESPONSE_HEAD: usize = 16 * 1024;
/// Header slots for parsing the response head (tungstenite's own limit).
const MAX_RESPONSE_HEADERS: usize = 124;

/// A fresh `Sec-WebSocket-Key` (16 random bytes, base64).
pub(crate) fn generate_key() -> String {
    tokio_tungstenite::tungstenite::handshake::client::generate_key()
}

/// Write `request_head` (a complete upgrade request carrying
/// `Sec-WebSocket-Key: key`), read and verify the `101` response, and return
/// the WebSocket plus the response headers (for the `X-Outline-Resume*`
/// echo).
pub(crate) async fn client_handshake<S>(
    mut stream: S,
    request_head: &[u8],
    key: &str,
) -> Result<(WebSocketStream<S>, HeaderMap)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream
        .write_all(request_head)
        .await
        .context("failed to send websocket upgrade request")?;
    stream
        .flush()
        .await
        .context("failed to send websocket upgrade request")?;

    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    let (head_len, headers) = loop {
        let n = stream
            .read(&mut chunk)
            .await
            .context("failed to read websocket upgrade response")?;
        if n == 0 {
            // A typed `UnexpectedEof` so error classification reports the
            // peer closing mid-handshake as a closed connection.
            return Err(anyhow::Error::new(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed before the websocket upgrade response",
            )));
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(parsed) = parse_response_head(&buf, key)? {
            break parsed;
        }
        if buf.len() > MAX_RESPONSE_HEAD {
            bail!("websocket upgrade response head exceeds {MAX_RESPONSE_HEAD} bytes");
        }
    };
    let leftover = buf.split_off(head_len);
    let ws = WebSocketStream::from_partially_read(
        stream,
        leftover,
        Role::Client,
        Some(crate::ws_client_config()),
    )
    .await;
    Ok((ws, headers))
}

/// Parse and verify the response head at the start of `buf`. `Ok(None)` while
/// it is incomplete; `Ok(Some((head length, headers)))` once a valid `101`
/// has arrived.
pub(crate) fn parse_response_head(buf: &[u8], key: &str) -> Result<Option<(usize, HeaderMap)>> {
    let mut slots = [httparse::EMPTY_HEADER; MAX_RESPONSE_HEADERS];
    let mut response = httparse::Response::new(&mut slots);
    let head_len = match response.parse(buf) {
        Ok(httparse::Status::Partial) => return Ok(None),
        Ok(httparse::Status::Complete(len)) => len,
        Err(httparse::Error::TooManyHeaders) => {
            bail!("websocket upgrade response has more than {MAX_RESPONSE_HEADERS} headers")
        },
        Err(e) => return Err(anyhow::Error::new(e).context("malformed websocket upgrade response")),
    };
    let code = response
        .code
        .ok_or_else(|| anyhow!("websocket upgrade response has no status"))?;
    if code != 101 {
        bail!("websocket upgrade rejected: HTTP {code}");
    }
    // A WebSocket upgrade is an HTTP/1.1 exchange (RFC 6455 §4.1).
    if response.version != Some(1) {
        bail!("websocket upgrade response is not HTTP/1.1");
    }
    let mut headers = HeaderMap::new();
    for h in response.headers.iter() {
        let name = HeaderName::from_bytes(h.name.as_bytes())
            .context("invalid header name in websocket upgrade response")?;
        let value = HeaderValue::from_bytes(h.value)
            .context("invalid header value in websocket upgrade response")?;
        headers.append(name, value);
    }
    let has_token = |name: http::header::HeaderName, token: &str| {
        headers.get_all(name).iter().any(|v| {
            v.to_str()
                .map(|s| s.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
                .unwrap_or(false)
        })
    };
    if !has_token(http::header::UPGRADE, "websocket") {
        bail!("websocket upgrade response lacks `Upgrade: websocket`");
    }
    if !has_token(http::header::CONNECTION, "upgrade") {
        bail!("websocket upgrade response lacks `Connection: Upgrade`");
    }
    let expected = derive_accept_key(key.as_bytes());
    match headers.get(http::header::SEC_WEBSOCKET_ACCEPT) {
        Some(accept) if accept.as_bytes() == expected.as_bytes() => {},
        _ => bail!("websocket upgrade response has a wrong `Sec-WebSocket-Accept`"),
    }
    // We never request a subprotocol, so the server must not select one
    // (RFC 6455 §4.2.2).
    if headers.contains_key(http::header::SEC_WEBSOCKET_PROTOCOL) {
        bail!("server selected a websocket subprotocol that was not requested");
    }
    // The request offers `permessage-deflate` like a browser, but this client
    // does not implement it: a server that accepted it would send compressed
    // frames we would misread. Our server never accepts it.
    if headers.contains_key(http::header::SEC_WEBSOCKET_EXTENSIONS) {
        bail!("server negotiated a websocket extension this client does not implement");
    }
    Ok(Some((head_len, headers)))
}

#[cfg(test)]
#[path = "tests/ws_h1.rs"]
mod tests;
