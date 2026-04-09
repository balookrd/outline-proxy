mod dns;
mod guards;
mod protocol;
mod socket;
mod stream;
mod tcp;
mod udp;

pub use socket::{init_h2_window_sizes, init_udp_socket_bufs};
pub use stream::AnyWsStream;
pub use tcp::{TcpShadowsocksReader, TcpShadowsocksWriter};
pub use udp::UdpWsTransport;

#[cfg(feature = "h3")]
pub(crate) use dns::resolve_host_with_preference;
pub(crate) use guards::UpstreamTransportGuard;
#[cfg(feature = "h3")]
pub(crate) use guards::{AbortOnDrop, TransportConnectGuard};
pub(crate) use socket::{bind_addr_for, bind_udp_socket};
#[cfg(feature = "h3")]
pub(crate) use socket::{format_authority, websocket_path};

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tracing::{debug, warn};
use url::Url;

use crate::types::{ServerAddr, WsTransportMode};

use dns::resolve_server_addr;
use guards::TransportConnectGuard as Guard;
use socket::{connect_tcp_socket, connect_websocket_h2, connect_websocket_http1};
use udp::OVERSIZED_UDP_UPLINK_DROP_ERR;

#[cfg(feature = "h3")]
use crate::transport_h3::connect_websocket_h3;

// ── Public connect API ────────────────────────────────────────────────────────

pub async fn connect_websocket(
    url: &Url,
    mode: WsTransportMode,
    fwmark: Option<u32>,
    ipv6_first: bool,
) -> Result<AnyWsStream> {
    connect_websocket_with_source(url, mode, fwmark, ipv6_first, "direct").await
}

pub async fn connect_websocket_with_source(
    url: &Url,
    mode: WsTransportMode,
    fwmark: Option<u32>,
    ipv6_first: bool,
    source: &'static str,
) -> Result<AnyWsStream> {
    match mode {
        WsTransportMode::Http1 => {
            let ws_stream = connect_websocket_http1(url, fwmark, ipv6_first, source).await?;
            debug!(url = %url, selected_mode = "http1", "websocket transport connected");
            Ok(AnyWsStream::Http1 { inner: ws_stream })
        }
        WsTransportMode::H2 => match connect_websocket_h2(url, fwmark, ipv6_first, source).await {
            Ok(stream) => {
                debug!(url = %url, selected_mode = "h2", "websocket transport connected");
                Ok(stream)
            }
            Err(h2_error) => {
                warn!(
                    url = %url,
                    error = %format!("{h2_error:#}"),
                    fallback = "http1",
                    "h2 websocket connect failed, falling back"
                );
                let ws_stream = connect_websocket_http1(url, fwmark, ipv6_first, source).await?;
                debug!(url = %url, selected_mode = "http1", requested_mode = "h2", "websocket transport connected");
                Ok(AnyWsStream::Http1 { inner: ws_stream })
            }
        },
        #[cfg(feature = "h3")]
        WsTransportMode::H3 => match connect_websocket_h3(url, fwmark, ipv6_first, source).await {
            Ok(stream) => {
                debug!(url = %url, selected_mode = "h3", "websocket transport connected");
                Ok(stream)
            }
            Err(h3_error) => {
                warn!(
                    url = %url,
                    error = %format!("{h3_error:#}"),
                    fallback = "h2",
                    "h3 websocket connect failed, falling back"
                );
                match connect_websocket_h2(url, fwmark, ipv6_first, source).await {
                    Ok(stream) => {
                        debug!(url = %url, selected_mode = "h2", requested_mode = "h3", "websocket transport connected");
                        Ok(stream)
                    }
                    Err(h2_error) => {
                        warn!(
                            url = %url,
                            error = %format!("{h2_error:#}"),
                            fallback = "http1",
                            "h2 websocket connect failed after h3 fallback, falling back"
                        );
                        let ws_stream =
                            connect_websocket_http1(url, fwmark, ipv6_first, source).await?;
                        debug!(url = %url, selected_mode = "http1", requested_mode = "h3", "websocket transport connected");
                        Ok(AnyWsStream::Http1 { inner: ws_stream })
                    }
                }
            }
        },
        #[cfg(not(feature = "h3"))]
        WsTransportMode::H3 => {
            warn!(url = %url, "H3 requested but compiled without h3 feature, falling back to h2");
            match connect_websocket_h2(url, fwmark, ipv6_first, source).await {
                Ok(stream) => {
                    debug!(url = %url, selected_mode = "h2", requested_mode = "h3", "websocket transport connected");
                    Ok(stream)
                }
                Err(h2_error) => {
                    warn!(url = %url, error = %format!("{h2_error:#}"), fallback = "http1", "h2 websocket connect failed, falling back");
                    let ws_stream =
                        connect_websocket_http1(url, fwmark, ipv6_first, source).await?;
                    debug!(url = %url, selected_mode = "http1", requested_mode = "h3", "websocket transport connected");
                    Ok(AnyWsStream::Http1 { inner: ws_stream })
                }
            }
        }
    }
}

pub async fn connect_shadowsocks_tcp_with_source(
    addr: &ServerAddr,
    fwmark: Option<u32>,
    ipv6_first: bool,
    source: &'static str,
) -> Result<tokio::net::TcpStream> {
    let mut connect_guard = Guard::new(source, "tcp");
    let server_addr = resolve_server_addr(addr, ipv6_first).await?;
    let stream = connect_tcp_socket(server_addr, fwmark).await?;
    connect_guard.finish("success");
    Ok(stream)
}

pub async fn connect_shadowsocks_udp_with_source(
    addr: &ServerAddr,
    fwmark: Option<u32>,
    ipv6_first: bool,
    source: &'static str,
) -> Result<UdpSocket> {
    let mut connect_guard = Guard::new(source, "udp");
    let server_addr = resolve_server_addr(addr, ipv6_first).await?;
    let bind_addr = bind_addr_for(server_addr);
    let socket = if fwmark.is_some() {
        UdpSocket::from_std(bind_udp_socket(bind_addr, fwmark)?)
            .context("failed to adopt UDP socket into tokio")?
    } else {
        UdpSocket::bind(bind_addr)
            .await
            .with_context(|| format!("failed to bind UDP socket on {bind_addr}"))?
    };
    socket
        .connect(server_addr)
        .await
        .with_context(|| format!("failed to connect UDP socket to {server_addr}"))?;
    connect_guard.finish("success");
    Ok(socket)
}

pub fn is_dropped_oversized_udp_error(error: &anyhow::Error) -> bool {
    format!("{error:#}").contains(OVERSIZED_UDP_UPLINK_DROP_ERR)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, UdpSocket};

    use crate::types::CipherKind;

    #[tokio::test]
    async fn tcp_writer_splits_large_aead_payload_into_multiple_chunks() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 128 * 1024];
            let mut total = 0usize;
            loop {
                let read = stream.read(&mut buf[total..]).await.unwrap();
                if read == 0 {
                    break;
                }
                total += read;
            }
            total
        });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (_reader_half, writer_half) = stream.into_split();
        let cipher = CipherKind::Chacha20IetfPoly1305;
        let master_key = cipher.derive_master_key("password").unwrap();
        let lifetime = UpstreamTransportGuard::new("test", "tcp");
        let mut writer =
            TcpShadowsocksWriter::connect_socket(writer_half, cipher, &master_key, lifetime)
                .unwrap();
        let payload = vec![0x42; 40_000];

        writer.send_chunk(&payload).await.unwrap();
        writer.close().await.unwrap();

        let total = server.await.unwrap();
        assert!(total > payload.len());
    }

    #[tokio::test]
    async fn udp_socket_transport_close_wakes_blocked_reader() {
        let transport = Arc::new(
            UdpWsTransport::from_socket(
                UdpSocket::bind(("127.0.0.1", 0)).await.unwrap(),
                CipherKind::Chacha20IetfPoly1305,
                "password",
                "test",
            )
            .unwrap(),
        );
        let reader_transport = Arc::clone(&transport);
        let read_task = tokio::spawn(async move { reader_transport.read_packet().await });

        transport.close().await.unwrap();

        let error = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            read_task.await.unwrap().unwrap_err()
        })
        .await
        .unwrap();
        assert!(format!("{error:#}").contains("udp transport closed"));
    }
}
