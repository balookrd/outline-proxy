//! Tests for [`crate::ws_h1`]: the upgrade request a whole `ws_h1` dial puts
//! on the wire (raw bytes captured by a loopback server) against the measured
//! browser requests, and the verification of the `101` response.

use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use http::HeaderMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::{Message, Role};
use url::Url;

use super::{client_handshake, parse_response_head};
use crate::dial_plan::DialResumeOptions;
use crate::fingerprint_profile::{PROFILES, Profile, TlsFingerprint, with_pinned_profile};
use crate::resumption::SessionId;
use crate::tests::{MEASURED_WS_KEY, MeasuredKind, measured_browser_headers, measured_profiles};
use crate::{DnsCache, TransportDialOptions, TransportMode, connect_transport};

/// Read one request head off `socket` (up to the blank line).
async fn read_head(socket: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let n = socket.read(&mut byte).await.unwrap();
        assert_eq!(n, 1, "client closed before the end of the request head");
        head.push(byte[0]);
    }
    head
}

fn header_value<'a>(head: &'a str, name: &str) -> &'a str {
    head.lines()
        .find_map(|l| {
            let (n, v) = l.split_once(": ")?;
            n.eq_ignore_ascii_case(name).then_some(v)
        })
        .unwrap_or_else(|| panic!("no {name} in {head}"))
}

/// Run a real `ws_h1` dial to a loopback server pinned to `profile`; return
/// the request head the server received, after a WebSocket echo round-trip.
async fn dial_and_capture(profile: Option<&'static Profile>, resume: DialResumeOptions) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let head = String::from_utf8(read_head(&mut socket).await).unwrap();
        let key = header_value(&head, "sec-websocket-key").to_owned();
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade\r\nupgrade: websocket\r\n\
             sec-websocket-accept: {}\r\n\r\n",
            derive_accept_key(key.as_bytes())
        );
        socket.write_all(response.as_bytes()).await.unwrap();
        let mut ws = WebSocketStream::from_raw_socket(socket, Role::Server, None).await;
        if let Some(Ok(msg)) = ws.next().await {
            ws.send(msg).await.unwrap();
        }
        head
    });

    let url = Url::parse(&format!("ws://localhost:{port}/ws?x=1")).unwrap();
    let cache = DnsCache::default();
    let options =
        TransportDialOptions::new(&cache, &url, TransportMode::WsH1, "test").with_resume(resume);
    let stream = with_pinned_profile(profile, connect_transport(options))
        .await
        .unwrap();
    let crate::TransportStream::Http1 { inner, .. } = stream else {
        panic!("ws_h1 dial returned another carrier");
    };
    let mut ws = inner;
    ws.send(Message::Binary(b"ping".to_vec().into())).await.unwrap();
    let echoed = ws.next().await.unwrap().unwrap();
    assert_eq!(echoed, Message::Binary(b"ping".to_vec().into()));
    server.await.unwrap()
}

fn resume() -> DialResumeOptions {
    DialResumeOptions {
        resume_request: Some(SessionId::from_bytes([7; 16])),
        ack_prefix_requested: true,
        symmetric_replay_requested: false,
        client_acked_offset: 0,
    }
}

/// The measured request with the dial's own authority and key, then the
/// `X-Outline-Resume*` headers in the browser's case.
fn expected_head(profile: &Profile, authority: &str, key: &str) -> String {
    let mut out = String::from("GET /ws?x=1 HTTP/1.1\r\n");
    for (name, value) in measured_browser_headers(profile, MeasuredKind::WebSocket, true) {
        // The dial is `ws://`, so the page origin is `http://`.
        let value = value
            .replace("https://example.test:8443", &format!("http://{authority}"))
            .replace("example.test:8443", authority)
            .replace(MEASURED_WS_KEY, key);
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str("X-Outline-Resume-Capable: 1\r\n");
    out.push_str(&format!("X-Outline-Resume: {}\r\n", SessionId::from_bytes([7; 16]).to_hex()));
    out.push_str("X-Outline-Resume-Ack-Prefix: 1\r\n\r\n");
    out
}

#[tokio::test]
async fn ws_h1_dial_writes_the_measured_browser_request() {
    for profile in measured_profiles() {
        let head = dial_and_capture(Some(profile), resume()).await;
        let authority = header_value(&head, "host").to_owned();
        assert!(authority.starts_with("localhost:"), "{head}");
        let key = header_value(&head, "sec-websocket-key").to_owned();
        assert_eq!(head, expected_head(profile, &authority, &key), "profile={}", profile.name);
    }
}

/// Safari and no profile keep the request tungstenite used to write: its
/// five headers first in its case, everything else lowercase.
#[tokio::test]
async fn ws_h1_dial_without_an_aligned_profile_keeps_the_historical_request() {
    let safari = PROFILES.iter().find(|p| p.tls == TlsFingerprint::Safari).unwrap();
    for profile in [Some(safari), None] {
        let head = dial_and_capture(profile, DialResumeOptions::default()).await;
        let names: Vec<&str> = head
            .lines()
            .skip(1)
            .filter_map(|l| l.split_once(": ").map(|(n, _)| n))
            .collect();
        let mut expected =
            vec!["Host", "Connection", "Upgrade", "Sec-WebSocket-Version", "Sec-WebSocket-Key"];
        if profile.is_some() {
            expected.extend([
                "user-agent",
                "accept",
                "accept-language",
                "accept-encoding",
                "sec-fetch-site",
                "sec-fetch-mode",
                "sec-fetch-dest",
            ]);
        }
        expected.push("x-outline-resume-capable");
        assert_eq!(names, expected, "profile={:?}", profile.map(|p| p.name));
        if profile.is_some() {
            assert_eq!(header_value(&head, "sec-fetch-dest"), "websocket");
            assert_eq!(header_value(&head, "accept"), safari.accept);
        }
    }
}

const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

fn response(extra: &str) -> String {
    format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n{extra}\r\n",
        derive_accept_key(KEY.as_bytes())
    )
}

#[test]
fn response_head_is_verified() {
    let ok = response("X-Outline-Session: abc\r\n");
    let (len, headers) = parse_response_head(ok.as_bytes(), KEY).unwrap().unwrap();
    assert_eq!(len, ok.len());
    assert_eq!(headers.get("x-outline-session").unwrap(), "abc");

    // Incomplete: wait for more.
    assert!(parse_response_head(&ok.as_bytes()[..20], KEY).unwrap().is_none());

    let reject = |raw: String, why: &str| {
        let err = parse_response_head(raw.as_bytes(), KEY).unwrap_err();
        assert!(format!("{err:#}").contains(why), "{why}: {err:#}");
    };
    reject("HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n".into(), "HTTP 404");
    reject(
        response("").replace(&derive_accept_key(KEY.as_bytes()), "AAAA"),
        "Sec-WebSocket-Accept",
    );
    reject(response("").replace("Upgrade: websocket\r\n", ""), "Upgrade: websocket");
    reject(response("").replacen("HTTP/1.1", "HTTP/1.0", 1), "not HTTP/1.1");
    // No subprotocol is ever requested.
    reject(
        response("Sec-WebSocket-Protocol: chat\r\n"),
        "subprotocol that was not requested",
    );
    // We offer permessage-deflate like a browser but do not implement it.
    reject(
        response("Sec-WebSocket-Extensions: permessage-deflate\r\n"),
        "extension this client does not implement",
    );
}

/// Bytes the server sends right after the `101` (the first frame, in the
/// same segment) reach the WebSocket, not the floor.
#[tokio::test]
async fn bytes_after_the_response_head_are_kept() {
    let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        let _ = server_io.read(&mut buf).await.unwrap();
        // 101 + an unmasked binary frame "hi" in one write.
        let mut out = response("").into_bytes();
        out.extend_from_slice(&[0x82, 0x02, b'h', b'i']);
        server_io.write_all(&out).await.unwrap();
        server_io
    });
    let (mut ws, headers): (_, HeaderMap) =
        client_handshake(client_io, b"GET / HTTP/1.1\r\n\r\n", KEY)
            .await
            .unwrap();
    assert!(headers.contains_key("sec-websocket-accept"));
    let msg = ws.next().await.unwrap().unwrap();
    assert_eq!(msg, Message::Binary(b"hi".to_vec().into()));
    let _keep = Arc::new(server.await.unwrap());
}

/// More headers than the old 64-slot limit still parse; one past the new
/// limit is reported as such, not as a generic malformed response.
#[test]
fn response_head_header_limit() {
    let many =
        |n: usize| -> String { (0..n).map(|i| format!("X-H{i}: v\r\n")).collect::<String>() };
    // 3 protocol headers + extras: stay within 124 slots.
    let ok = response(&many(100));
    let (len, headers) = parse_response_head(ok.as_bytes(), KEY).unwrap().unwrap();
    assert_eq!(len, ok.len());
    assert_eq!(headers.get("x-h99").unwrap(), "v");

    let err = parse_response_head(response(&many(130)).as_bytes(), KEY).unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("more than 124 headers"), "{text}");
    assert!(!text.contains("malformed"), "{text}");
}

/// EOF before the response head is a typed `UnexpectedEof`, which error
/// classification reports as a closed transport.
#[tokio::test]
async fn eof_before_the_response_head_is_unexpected_eof() {
    let (client_io, mut server_io) = tokio::io::duplex(1024);
    // Read the request, then close without answering.
    let server = tokio::spawn(async move {
        let mut buf = [0u8; 64];
        let _ = server_io.read(&mut buf).await.unwrap();
    });
    let err = client_handshake(client_io, b"GET / HTTP/1.1\r\n\r\n", KEY)
        .await
        .expect_err("handshake must fail");
    assert_eq!(
        crate::error_classify::find_io_error_kind(&err),
        Some(std::io::ErrorKind::UnexpectedEof),
        "{err:#}"
    );
    assert!(crate::error_classify::is_transport_level_disconnect(&err));
    server.await.unwrap();
}

/// `Host` and `Origin` leave the scheme's default port out and keep any other.
#[test]
fn authority_and_origin_follow_the_default_port_rule() {
    use crate::dial_plan::url_authority;
    use crate::request_headers::web_origin;
    for (url, secure, host, origin) in [
        ("wss://host/", true, "host", "https://host"),
        ("wss://host:443/ws", true, "host", "https://host"),
        ("wss://host:8443/ws", true, "host:8443", "https://host:8443"),
        ("ws://host/", false, "host", "http://host"),
        ("ws://host:8080/", false, "host:8080", "http://host:8080"),
        ("wss://[::1]/", true, "[::1]", "https://[::1]"),
        ("wss://[::1]:8443/", true, "[::1]:8443", "https://[::1]:8443"),
    ] {
        let url = Url::parse(url).unwrap();
        let authority = url_authority(&url).unwrap();
        assert_eq!(authority, host, "{url}");
        assert_eq!(web_origin(secure, &authority), origin, "{url}");
    }
}
