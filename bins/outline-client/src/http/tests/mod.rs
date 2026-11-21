//! Test helpers shared by the control and dashboard HTTP test modules.

use std::future::Future;
use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Drive one raw HTTP request against `serve` and return `(status, body)`.
///
/// `parts` are written in order with a short pause between them, and the write
/// half is deliberately never closed — this is the shape needed to test a
/// server that answers *before* the announced body has arrived.
///
/// Both details matter. The pause lets the server drain each part out of the
/// socket, so nothing is left unread when it closes — unread bytes on close
/// mean RST, which discards the very response the test asserts on. And keeping
/// the write half open avoids a FIN (tokio half-closes on drop) racing the
/// early answer, which hyper reports as an incomplete message and answers with
/// nothing at all.
pub(crate) async fn streamed_request<F, Fut>(parts: Vec<Vec<u8>>, serve: F) -> (u16, String)
where
    F: FnOnce(TcpStream) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send,
{
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        serve(stream).await;
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    let (mut client_read, mut client_write) = client.split();
    let upload = async {
        for (index, part) in parts.iter().enumerate() {
            if index > 0 {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            if client_write.write_all(part).await.is_err() {
                break;
            }
        }
        std::future::pending::<()>().await
    };

    let mut response = Vec::new();
    let finished = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::select! {
            _ = upload => {},
            _ = client_read.read_to_end(&mut response) => {},
        }
    })
    .await;
    assert!(finished.is_ok(), "server did not answer the streamed request in time");
    server_task.abort();

    split_response(&response)
}

/// Split a raw HTTP response into `(status, body)`; status is `0` when nothing
/// parseable arrived.
pub(crate) fn split_response(raw: &[u8]) -> (u16, String) {
    let response = String::from_utf8_lossy(raw).into_owned();
    let mut parts = response.splitn(2, "\r\n\r\n");
    let head = parts.next().unwrap_or_default();
    let body = parts.next().unwrap_or_default().to_string();
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    (status, body)
}
