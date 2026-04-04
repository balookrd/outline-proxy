//! Axum Pub/Sub Chat Server using sockudo-ws
//!
//! A complete chat room example demonstrating:
//! - Axum HTTP server with WebSocket upgrade
//! - sockudo-ws high-performance pub/sub system
//! - Multiple chat rooms (topics)
//! - Pusher-style socket IDs
//!
//! Run with: cargo run --example axum_pubsub_chat
//!
//! Test with multiple websocket clients (e.g., websocat):
//!   websocat ws://127.0.0.1:3000/ws
//!
//! Commands:
//!   /join <room>    - Join a chat room
//!   /leave <room>   - Leave a chat room
//!   /rooms          - List your rooms
//!   /who            - Show your socket ID
//!   /stats          - Show server stats
//!   <message>       - Broadcast to all your rooms

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{Response, StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use hyper_util::rt::TokioIo;
use tokio::sync::mpsc;

use sockudo_ws::handshake::generate_accept_key;
use sockudo_ws::pubsub::PubSub;
use sockudo_ws::{Config, Message, WebSocketStream};

/// Shared application state
struct AppState {
    pubsub: Arc<PubSub>,
}

#[tokio::main]
async fn main() {
    // Create shared pub/sub system
    let pubsub = Arc::new(PubSub::new());
    let state = Arc::new(AppState { pubsub });

    let app = Router::new()
        .route("/", get(index_handler))
        .route("/ws", get(ws_handler))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("===========================================");
    println!("  Axum + sockudo-ws Pub/Sub Chat Server");
    println!("===========================================");
    println!();
    println!("Server: http://{}", addr);
    println!("WebSocket: ws://{}/ws", addr);
    println!();
    println!("Commands:");
    println!("  /join <room>  - Join a chat room");
    println!("  /leave <room> - Leave a chat room");
    println!("  /rooms        - List your rooms");
    println!("  /who          - Show your socket ID");
    println!("  /stats        - Show server stats");
    println!("  <message>     - Broadcast to all your rooms");
    println!();

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn index_handler() -> impl IntoResponse {
    "sockudo-ws Chat Server - Connect via WebSocket at /ws"
}

async fn ws_handler(State(state): State<Arc<AppState>>, req: Request) -> impl IntoResponse {
    // Validate WebSocket upgrade request
    let key = match req.headers().get("sec-websocket-key") {
        Some(k) => k.to_str().unwrap_or("").to_string(),
        None => return StatusCode::BAD_REQUEST.into_response(),
    };

    // Generate accept key
    let accept_key = generate_accept_key(&key);
    let pubsub = state.pubsub.clone();

    // Spawn handler for after upgrade
    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let io = TokioIo::new(upgraded);
                if let Err(e) = handle_socket(io, pubsub).await {
                    eprintln!("WebSocket error: {}", e);
                }
            }
            Err(e) => eprintln!("Upgrade error: {}", e),
        }
    });

    // Return 101 Switching Protocols
    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::UPGRADE, "websocket")
        .header(header::CONNECTION, "Upgrade")
        .header("Sec-WebSocket-Accept", accept_key)
        .body(Body::empty())
        .unwrap()
}

async fn handle_socket<S>(stream: S, pubsub: Arc<PubSub>) -> sockudo_ws::error::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // Create WebSocket stream
    let config = Config::builder()
        .max_payload_length(64 * 1024)
        .idle_timeout(300) // 5 minutes
        .build();

    let (mut reader, mut writer) = WebSocketStream::server(stream, config).split();

    // Create subscriber with Pusher-style socket ID
    let (tx, mut rx) = mpsc::unbounded_channel();
    let socket_id = PubSub::generate_socket_id();
    let subscriber_id = pubsub.create_subscriber_with_id(&socket_id, tx);

    // Track rooms for this connection
    let mut rooms: Vec<String> = Vec::new();

    // Send welcome message
    writer
        .send(Message::text(format!(
            "Welcome! Your socket ID: {}\nType /join <room> to join a chat room.",
            socket_id
        )))
        .await?;

    loop {
        tokio::select! {
            // Handle incoming WebSocket messages
            msg = reader.next() => {
                match msg {
                    Some(Ok(Message::Text(data))) => {
                        let text = String::from_utf8_lossy(&data);
                        let text = text.trim();

                        if text.starts_with("/join ") {
                            let room = text.strip_prefix("/join ").unwrap().trim();
                            if !room.is_empty() && !rooms.contains(&room.to_string()) {
                                pubsub.subscribe(subscriber_id, room);
                                rooms.push(room.to_string());

                                // Notify the user
                                writer.send(Message::text(format!(
                                    "Joined room '{}'. {} users in this room.",
                                    room,
                                    pubsub.topic_subscriber_count(room)
                                ))).await?;

                                // Announce to others in the room
                                pubsub.publish_excluding(
                                    subscriber_id,
                                    room,
                                    Message::text(format!("[{}] joined the room", socket_id))
                                );
                            } else if rooms.contains(&room.to_string()) {
                                writer.send(Message::text(format!(
                                    "Already in room '{}'",
                                    room
                                ))).await?;
                            }
                        } else if text.starts_with("/leave ") {
                            let room = text.strip_prefix("/leave ").unwrap().trim();
                            if pubsub.unsubscribe(subscriber_id, room) {
                                // Announce departure before leaving
                                pubsub.publish_excluding(
                                    subscriber_id,
                                    room,
                                    Message::text(format!("[{}] left the room", socket_id))
                                );

                                rooms.retain(|r| r != room);
                                writer.send(Message::text(format!(
                                    "Left room '{}'",
                                    room
                                ))).await?;
                            } else {
                                writer.send(Message::text(format!(
                                    "Not in room '{}'",
                                    room
                                ))).await?;
                            }
                        } else if text == "/rooms" {
                            if rooms.is_empty() {
                                writer.send(Message::text(
                                    "Not in any rooms. Use /join <room> to join one."
                                )).await?;
                            } else {
                                let room_list: Vec<String> = rooms.iter().map(|r| {
                                    format!("{} ({} users)", r, pubsub.topic_subscriber_count(r))
                                }).collect();
                                writer.send(Message::text(format!(
                                    "Your rooms: {}",
                                    room_list.join(", ")
                                ))).await?;
                            }
                        } else if text == "/who" {
                            writer.send(Message::text(format!(
                                "Your socket ID: {}",
                                socket_id
                            ))).await?;
                        } else if text == "/stats" {
                            writer.send(Message::text(format!(
                                "Server stats:\n  Topics: {}\n  Subscribers: {}\n  Messages: {}",
                                pubsub.topic_count(),
                                pubsub.subscriber_count(),
                                pubsub.messages_published()
                            ))).await?;
                        } else if !text.is_empty() && !text.starts_with("/") {
                            // Broadcast message to all rooms
                            if rooms.is_empty() {
                                writer.send(Message::text(
                                    "Join a room first with /join <room>"
                                )).await?;
                            } else {
                                let formatted = format!("[{}]: {}", socket_id, text);
                                let msg = Message::text(formatted);
                                let mut total_sent = 0;
                                for room in &rooms {
                                    let result = pubsub.publish_excluding(
                                        subscriber_id,
                                        room,
                                        msg.clone()
                                    );
                                    total_sent += result.count();
                                }
                                // Echo confirmation (optional - remove for cleaner UX)
                                if total_sent > 0 {
                                    writer.send(Message::text(format!(
                                        "(sent to {} users)",
                                        total_sent
                                    ))).await?;
                                }
                            }
                        } else if text.starts_with("/") {
                            writer.send(Message::text(
                                "Unknown command. Available: /join /leave /rooms /who /stats"
                            )).await?;
                        }
                    }
                    Some(Ok(Message::Binary(data))) => {
                        // Broadcast binary to all rooms
                        let msg = Message::Binary(data);
                        for room in &rooms {
                            pubsub.publish_excluding(subscriber_id, room, msg.clone());
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        break;
                    }
                    Some(Ok(_)) => {} // Ping/Pong handled automatically
                    Some(Err(e)) => {
                        eprintln!("WebSocket error: {}", e);
                        break;
                    }
                }
            }

            // Handle messages from pub/sub (from other users)
            Some(msg) = rx.recv() => {
                if writer.send(msg).await.is_err() {
                    break;
                }
            }
        }
    }

    // Announce departure from all rooms
    for room in &rooms {
        pubsub.publish_excluding(
            subscriber_id,
            room,
            Message::text(format!("[{}] disconnected", socket_id)),
        );
    }

    // Cleanup subscriber (auto-unsubscribes from all topics)
    pubsub.remove_subscriber(subscriber_id);
    println!("Client {} disconnected", socket_id);

    Ok(())
}
