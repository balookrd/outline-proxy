//! Axum WebSocket Split with Compression Example
//!
//! This example demonstrates the split() functionality with permessage-deflate
//! compression enabled. Both compressed and uncompressed WebSockets support
//! splitting into independent reader and writer halves.
//!
//! Run with: cargo run --example axum_split_deflate --features "axum-integration,permessage-deflate"

use std::net::SocketAddr;

use axum::{Router, response::IntoResponse, routing::get};
use sockudo_ws::axum_integration::WebSocketUpgrade;
use sockudo_ws::{Compression, Config, Message};

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route(
            "/",
            get(|| async { "WebSocket Split + Deflate Test - connect to /ws" }),
        )
        .route("/ws", get(ws_handler));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!(
        "Axum WebSocket Split + Deflate server listening on http://{}",
        addr
    );
    println!(
        "Connect to ws://{}/ws with a client that supports deflate",
        addr
    );
    println!("\nThis server demonstrates split() with compression by:");
    println!("1. Negotiating permessage-deflate compression");
    println!("2. Splitting the compressed WebSocket into reader/writer");
    println!("3. Reading and writing concurrently from separate tasks");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn ws_handler(ws: WebSocketUpgrade) -> impl IntoResponse {
    // Enable compression with Dedicated mode (per-connection compressor)
    let config = Config::builder()
        .compression(Compression::Dedicated)
        .build();

    ws.config(config).on_upgrade(handle_socket)
}

async fn handle_socket(socket: sockudo_ws::axum_integration::WebSocket) {
    println!("New WebSocket connection established");

    // Split the WebSocket into reader and writer
    // This works for BOTH compressed and uncompressed connections!
    let (mut reader, mut writer) = socket.split();

    // Create a channel to send messages from reader to writer
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Message>();

    // Spawn reader task
    let reader_handle = tokio::spawn(async move {
        println!("Reader task started (with decompression)");
        while let Some(msg) = reader.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    let text_str = String::from_utf8_lossy(&text);
                    println!(
                        "Received (decompressed): {} ({} bytes)",
                        text_str,
                        text.len()
                    );
                    // Send to writer task for echo
                    if tx.send(Message::Text(text)).is_err() {
                        break;
                    }
                }
                Ok(Message::Binary(data)) => {
                    println!("Received binary (decompressed): {} bytes", data.len());
                    if tx.send(Message::Binary(data)).is_err() {
                        break;
                    }
                }
                Ok(Message::Close(frame)) => {
                    println!("Received close frame: {:?}", frame);
                    break;
                }
                Ok(_) => {} // Ping/Pong handled automatically
                Err(e) => {
                    eprintln!("Reader error: {}", e);
                    break;
                }
            }
        }
        println!("Reader task finished");
    });

    // Spawn writer task
    let writer_handle = tokio::spawn(async move {
        println!("Writer task started (with compression)");
        let mut heartbeat_interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
        let mut heartbeat_count = 0u32;

        loop {
            tokio::select! {
                // Send heartbeat periodically
                _ = heartbeat_interval.tick() => {
                    heartbeat_count += 1;
                    // Large heartbeat message to demonstrate compression benefit
                    let msg = format!(
                        "Heartbeat #{}: {}",
                        heartbeat_count,
                        "ping ".repeat(20)
                    );
                    println!("Sending heartbeat (will be compressed): {} bytes", msg.len());
                    if writer.send(Message::text(msg)).await.is_err() {
                        eprintln!("Failed to send heartbeat");
                        break;
                    }
                }
                // Echo messages from reader
                Some(msg) = rx.recv() => {
                    println!("Echoing message back (with compression)");
                    if writer.send(msg).await.is_err() {
                        eprintln!("Failed to echo message");
                        break;
                    }
                }
            }
        }
        println!("Writer task finished");
    });

    // Wait for both tasks to complete
    let _ = tokio::join!(reader_handle, writer_handle);
    println!("WebSocket connection closed");
}
