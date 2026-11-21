//! Behavioural coverage for the pre-auth WebSocket message-size cap applied to
//! the SS/VLESS upgrade paths. The upgrade handlers require a full `AppState`,
//! so these tests exercise the exact clamp helper the handlers call
//! (`apply_ws_limits`) through a real axum server + tungstenite client, which is
//! what actually enforces the ceiling. Without the clamp the axum default
//! (64 MiB message / 16 MiB frame) would echo the oversized message back.

use std::net::{Ipv4Addr, SocketAddr};

use axum::{
    Router,
    extract::ws::{Message, WebSocketUpgrade},
    response::Response,
    routing::any,
};
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message as ClientMessage;

use super::super::{WS_MAX_MESSAGE_SIZE, apply_ws_limits};

/// Upgrade handler that clamps limits exactly as the production upgrade sites do
/// and echoes back any binary message it manages to receive whole.
async fn echo_upgrade(ws: WebSocketUpgrade) -> Response {
    apply_ws_limits(ws).on_upgrade(|mut socket| async move {
        while let Some(Ok(msg)) = socket.recv().await {
            if let Message::Binary(data) = msg
                && socket.send(Message::Binary(data)).await.is_err()
            {
                break;
            }
        }
    })
}

async fn spawn_echo_server() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().route("/", any(echo_upgrade));
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service()).await.unwrap();
    });
    addr
}

#[tokio::test]
async fn oversized_ws_message_is_rejected_not_echoed() {
    let addr = spawn_echo_server().await;
    let (mut ws, _) = connect_async(format!("ws://{addr}/")).await.unwrap();

    // One byte over the cap: a single frame whose declared length exceeds
    // `max_frame_size`, so tungstenite refuses it at header-parse time. The
    // server closes the connection as soon as it reads that length, which can
    // surface on our side as a write error mid-body (the socket is gone before
    // the whole payload is flushed) — that is itself proof the frame was
    // rejected before being buffered whole, so a send error is an accepted
    // outcome.
    let oversized = vec![0u8; WS_MAX_MESSAGE_SIZE + 1];
    if ws.send(ClientMessage::Binary(oversized.into())).await.is_err() {
        return;
    }

    // If the write went through, the server must still not echo the oversized
    // payload back: it either closes the connection or tears it down.
    match ws.next().await {
        None => {},
        Some(Ok(ClientMessage::Close(_))) => {},
        Some(Err(_)) => {},
        Some(Ok(ClientMessage::Binary(b))) => {
            panic!("oversized message was accepted and echoed ({} bytes)", b.len());
        },
        Some(other) => panic!("unexpected reply to oversized message: {other:?}"),
    }
}

#[tokio::test]
async fn message_at_the_limit_is_accepted_and_echoed() {
    let addr = spawn_echo_server().await;
    let (mut ws, _) = connect_async(format!("ws://{addr}/")).await.unwrap();

    // Exactly at the cap: tungstenite rejects only strictly-larger frames, so a
    // legitimate max-size carrier message must still pass through and echo back.
    let at_limit = vec![7u8; WS_MAX_MESSAGE_SIZE];
    ws.send(ClientMessage::Binary(at_limit.into())).await.unwrap();

    match ws.next().await {
        Some(Ok(ClientMessage::Binary(b))) => assert_eq!(b.len(), WS_MAX_MESSAGE_SIZE),
        other => panic!("at-limit message should echo, got {other:?}"),
    }
}
