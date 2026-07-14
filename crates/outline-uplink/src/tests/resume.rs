//! TCP session resumption is owned by the **session**, not by the uplink.
//!
//! A `SessionId` is server-minted and, on a resume hit, makes the server
//! re-attach the upstream parked under that id — ignoring the target in the new
//! handshake ("the parked target is authoritative"). So an id may only ever be
//! presented back by the session it was issued to. It used to live in a
//! process-global cache keyed `<resume-scope>#tcp` — one slot per uplink,
//! last-write-wins — which every fresh TCP dial read: with two concurrent
//! sessions on one uplink, session B's fresh dial could present session A's id
//! and, if A was parked (exactly what a dying carrier does), get spliced onto
//! A's destination.
//!
//! These tests pin the two halves of the invariant: a fresh dial presents no id
//! at all, and a redial presents the id of the redialing session — never
//! whatever happens to be cached for the uplink.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_tungstenite::accept_hdr_async;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::{HeaderMap, HeaderValue};
use url::Url;

use outline_transport::{SessionId, global_resume_cache};
use outline_wire::resume::{
    ACK_PREFIX_HEADER, RESUME_CAPABLE_HEADER, RESUME_REQUEST_HEADER, SESSION_RESPONSE_HEADER,
};

use crate::types::{UplinkCandidate, UplinkManager};

use super::{lb, make_uplink, probe_disabled};

/// A mock WS server that plays the resumption-enabled server: it captures the
/// upgrade request headers of every connection (so the test can inspect what
/// the client presented) and mints a Session ID per connection, returned in the
/// `X-Outline-Session` response header. Accepted sockets are parked until
/// shutdown so the dialed streams stay alive.
// The `accept_hdr_async` callback's `Result<Response, ErrorResponse>` return is
// a tungstenite-imposed signature; the large `Err` variant is not ours to box.
#[allow(clippy::result_large_err)]
async fn spawn_resume_server(
    minted: Vec<SessionId>,
) -> (Url, mpsc::UnboundedReceiver<HeaderMap>, oneshot::Sender<()>, JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (headers_tx, headers_rx) = mpsc::unbounded_channel();
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let next = AtomicUsize::new(0);
        let mut live = Vec::new();
        loop {
            let stream = tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok((stream, _)) => stream,
                    Err(_) => break,
                },
                _ = &mut shutdown_rx => break,
            };
            let headers_tx = headers_tx.clone();
            // Mint one id per connection, exactly as the server does on every
            // upgrade that advertises `Resume-Capable` (fresh dial or resume).
            let issued = minted
                .get(next.fetch_add(1, Ordering::SeqCst))
                .copied()
                .unwrap_or_else(|| SessionId::from_bytes([0xFF; 16]));
            let callback = |req: &Request, mut resp: Response| -> Result<Response, ErrorResponse> {
                let _ = headers_tx.send(req.headers().clone());
                resp.headers_mut().insert(
                    SESSION_RESPONSE_HEADER,
                    HeaderValue::from_str(&issued.to_hex()).unwrap(),
                );
                Ok(resp)
            };
            match accept_hdr_async(stream, callback).await {
                Ok(ws) => live.push(ws),
                Err(_) => break,
            }
        }
    });
    (Url::parse(&format!("ws://{addr}/tcp")).unwrap(), headers_rx, shutdown_tx, task)
}

async fn next_headers(rx: &mut mpsc::UnboundedReceiver<HeaderMap>) -> HeaderMap {
    tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("the dial must reach the mock server within the timeout")
        .expect("the mock server must capture the upgrade request headers")
}

/// A fresh TCP dial is a **new session**: it advertises `Resume-Capable` but
/// presents no `X-Outline-Resume` id — not even when the process-global cache
/// holds a parked id for this very uplink (which is what another concurrent
/// session on the same uplink would have left behind). Regression guard for the
/// wrong-site splice: presenting a foreign id on a resume hit re-attaches that
/// session's upstream, and the server ignores the target we just sent.
#[tokio::test]
async fn fresh_tcp_dial_presents_no_resume_id() {
    let minted = SessionId::from_bytes([0x11; 16]);
    let (url, mut headers_rx, shutdown_tx, task) = spawn_resume_server(vec![minted]).await;

    // Another session's id, parked in the global cache under this uplink's TCP
    // key. The pre-fix dial path read exactly this slot.
    let decoy = SessionId::from_bytes([0xAA; 16]);
    let uplink = make_uplink("fresh-dial-uplink", url.as_str());
    global_resume_cache().store("fresh-dial-uplink#tcp", decoy);

    let manager =
        UplinkManager::new_for_test("test", vec![uplink.clone()], probe_disabled(), lb()).unwrap();
    let candidate = UplinkCandidate { index: 0, uplink: uplink.into() };

    let ws = manager
        .connect_tcp_ws_fresh(&candidate, "test")
        .await
        .expect("fresh dial must succeed against the mock server");

    let headers = next_headers(&mut headers_rx).await;
    assert_eq!(
        headers.get(RESUME_CAPABLE_HEADER).and_then(|v| v.to_str().ok()),
        Some("1"),
        "a fresh dial still advertises resume capability so the server mints an id",
    );
    assert!(
        headers.get(RESUME_REQUEST_HEADER).is_none(),
        "a fresh dial must present NO resume id, got {:?}",
        headers.get(RESUME_REQUEST_HEADER),
    );

    // The id the server minted rides on the stream — that is how the session
    // that ends up owning this carrier learns its own id.
    assert_eq!(
        ws.issued_session_id(),
        Some(minted),
        "the minted id must be readable off the TransportStream",
    );
    // ...and the TCP path neither reads nor writes the global cache, so the
    // decoy slot is left exactly as it was (no last-write-wins clobber).
    assert_eq!(
        global_resume_cache().get("fresh-dial-uplink#tcp"),
        Some(decoy),
        "the TCP dial path must not write the process-global resume cache",
    );

    global_resume_cache().forget("fresh-dial-uplink#tcp");
    let _ = shutdown_tx.send(());
    task.abort();
}

/// A redial presents the id **the redialing session** was issued, even when a
/// different id is cached for the uplink. This is the mid-session-retry /
/// soft-switch path: the id is threaded in explicitly by the session that owns
/// it, and the shared cache is never consulted.
#[tokio::test]
async fn wire_handover_redial_presents_the_id_without_asking_for_replay() {
    let re_minted = SessionId::from_bytes([0x44; 16]);
    let (url, mut headers_rx, shutdown_tx, task) = spawn_resume_server(vec![re_minted]).await;

    let our_session = SessionId::from_bytes([0x55; 16]);
    let uplink = make_uplink("handover-uplink", url.as_str());

    let manager =
        UplinkManager::new_for_test("test", vec![uplink.clone()], probe_disabled(), lb()).unwrap();
    let candidate = UplinkCandidate { index: 0, uplink: uplink.into() };

    let ws = manager
        .connect_tcp_ws_redial(&candidate, "test", Some(our_session))
        .await
        .expect("wire-handover redial must succeed against the mock server");

    let headers = next_headers(&mut headers_rx).await;
    assert_eq!(
        headers.get(RESUME_REQUEST_HEADER).and_then(|v| v.to_str().ok()),
        Some(our_session.to_hex().as_str()),
        "a wire handover must present this session's own id so a parked upstream is re-attached",
    );
    // A handover has no ring buffer, so it must not ask the server for replay
    // control frames it would be unable to honour.
    assert!(
        headers.get(ACK_PREFIX_HEADER).is_none(),
        "a wire handover must not advertise Ack-Prefix: it owns no replay ring",
    );
    assert_eq!(ws.issued_session_id(), Some(re_minted));

    let _ = shutdown_tx.send(());
    task.abort();
}

#[tokio::test]
async fn redial_presents_the_sessions_own_id_not_a_cached_one() {
    let re_minted = SessionId::from_bytes([0x22; 16]);
    let (url, mut headers_rx, shutdown_tx, task) = spawn_resume_server(vec![re_minted]).await;

    // What the *other* session parked under this uplink's key — the pre-fix
    // code would have presented this.
    let other_session = SessionId::from_bytes([0xBB; 16]);
    // What *our* session was issued on the carrier that just died.
    let our_session = SessionId::from_bytes([0x33; 16]);
    let uplink = make_uplink("redial-uplink", url.as_str());
    global_resume_cache().store("redial-uplink#tcp", other_session);

    let manager =
        UplinkManager::new_for_test("test", vec![uplink.clone()], probe_disabled(), lb()).unwrap();
    let candidate = UplinkCandidate { index: 0, uplink: uplink.into() };

    let ws = manager
        .connect_tcp_ws_redial_with_ack_prefix(&candidate, "test", Some(our_session))
        .await
        .expect("redial must succeed against the mock server");

    let headers = next_headers(&mut headers_rx).await;
    assert_eq!(
        headers.get(RESUME_REQUEST_HEADER).and_then(|v| v.to_str().ok()),
        Some(our_session.to_hex().as_str()),
        "the redial must present the redialing session's own id",
    );
    assert_ne!(
        headers.get(RESUME_REQUEST_HEADER).and_then(|v| v.to_str().ok()),
        Some(other_session.to_hex().as_str()),
        "the redial must never present another session's cached id",
    );
    // The resume hit mints a new id; the session must carry *that* one into any
    // further redial.
    assert_eq!(ws.issued_session_id(), Some(re_minted));

    global_resume_cache().forget("redial-uplink#tcp");
    let _ = shutdown_tx.send(());
    task.abort();
}

/// A session that never received an id (server without resumption, direct
/// socket, …) redials with `None` — and presents nothing, rather than falling
/// back to whatever the uplink's cache slot holds.
#[tokio::test]
async fn redial_without_a_session_id_presents_nothing() {
    let (url, mut headers_rx, shutdown_tx, task) = spawn_resume_server(Vec::new()).await;

    let decoy = SessionId::from_bytes([0xCC; 16]);
    let uplink = make_uplink("idless-redial-uplink", url.as_str());
    global_resume_cache().store("idless-redial-uplink#tcp", decoy);

    let manager =
        UplinkManager::new_for_test("test", vec![uplink.clone()], probe_disabled(), lb()).unwrap();
    let candidate = UplinkCandidate { index: 0, uplink: uplink.into() };

    let _ws = manager
        .connect_tcp_ws_redial_with_symmetric_replay(&candidate, "test", None, 4096)
        .await
        .expect("redial must succeed against the mock server");

    let headers = next_headers(&mut headers_rx).await;
    assert!(
        headers.get(RESUME_REQUEST_HEADER).is_none(),
        "a session with no id of its own must present none, got {:?}",
        headers.get(RESUME_REQUEST_HEADER),
    );

    global_resume_cache().forget("idless-redial-uplink#tcp");
    let _ = shutdown_tx.send(());
    task.abort();
}

/// Two concurrent sessions on the same uplink each get their own id off their
/// own stream — there is no single slot for them to overwrite. This is the
/// scenario that used to splice session B onto session A's destination.
#[tokio::test]
async fn concurrent_fresh_dials_own_distinct_ids() {
    let first = SessionId::from_bytes([0x44; 16]);
    let second = SessionId::from_bytes([0x55; 16]);
    let (url, mut headers_rx, shutdown_tx, task) = spawn_resume_server(vec![first, second]).await;

    let uplink = make_uplink("concurrent-uplink", url.as_str());
    let manager =
        UplinkManager::new_for_test("test", vec![uplink.clone()], probe_disabled(), lb()).unwrap();
    let candidate = Arc::new(UplinkCandidate { index: 0, uplink: uplink.into() });

    // Sequential dials (the mock accepts one at a time), but they model two
    // independent sessions: the second must not inherit the first one's id.
    let session_a = manager
        .connect_tcp_ws_fresh(&candidate, "test")
        .await
        .expect("session A dial must succeed");
    let headers_a = next_headers(&mut headers_rx).await;
    let session_b = manager
        .connect_tcp_ws_fresh(&candidate, "test")
        .await
        .expect("session B dial must succeed");
    let headers_b = next_headers(&mut headers_rx).await;

    assert!(
        headers_a.get(RESUME_REQUEST_HEADER).is_none()
            && headers_b.get(RESUME_REQUEST_HEADER).is_none(),
        "neither fresh dial may present a resume id",
    );
    assert_eq!(session_a.issued_session_id(), Some(first));
    assert_eq!(
        session_b.issued_session_id(),
        Some(second),
        "session B owns the id minted for B, not the one minted for A",
    );

    let _ = shutdown_tx.send(());
    task.abort();
}
