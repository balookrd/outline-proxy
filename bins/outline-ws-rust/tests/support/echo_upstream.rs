#![allow(dead_code)]
//! Local TCP + UDP echo server used as the tunnel's *destination*.
//!
//! `outline-ss-rust` always performs a real outbound connect to the target
//! encoded in the SS / VLESS header — there is no built-in loopback. The e2e
//! tests therefore stand up this echo upstream and pass its `127.0.0.1:<port>`
//! address as the SOCKS5 CONNECT / UDP target (`atyp = 0x01` IPv4, so the
//! server never needs DNS). Whatever the client writes through the tunnel comes
//! straight back, which lets a test assert byte-for-byte data integrity across
//! a failover.
//!
//! The server owns a small multi-threaded tokio runtime so `start()` can be
//! called from the synchronous `#[test]` bodies that drive traffic with
//! blocking `std::net` sockets (matching `proxy_test_utils.rs`). Dropping the
//! handle drops the runtime, which aborts the background accept loops.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::runtime::{Builder, Runtime};

pub struct EchoUpstream {
    tcp_addr: SocketAddr,
    udp_addr: SocketAddr,
    tcp_connections: Arc<AtomicUsize>,
    // Held to keep the accept loops alive; dropped last.
    _rt: Runtime,
}

impl EchoUpstream {
    /// Bind a TCP + UDP echo pair on `127.0.0.1:0` and start serving.
    pub fn start() -> io::Result<Self> {
        let rt = Builder::new_multi_thread().worker_threads(1).enable_all().build()?;
        let tcp_connections = Arc::new(AtomicUsize::new(0));

        let (tcp_listener, tcp_addr) = rt.block_on(async {
            let l = TcpListener::bind(("127.0.0.1", 0)).await?;
            let a = l.local_addr()?;
            io::Result::Ok((l, a))
        })?;
        let (udp_socket, udp_addr) = rt.block_on(async {
            let s = UdpSocket::bind(("127.0.0.1", 0)).await?;
            let a = s.local_addr()?;
            io::Result::Ok((s, a))
        })?;

        // TCP: echo every connection back via a bidirectional copy of read→write.
        let conn_counter = Arc::clone(&tcp_connections);
        rt.spawn(async move {
            loop {
                let Ok((mut sock, _peer)) = tcp_listener.accept().await else {
                    break;
                };
                conn_counter.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    let mut buf = [0u8; 16 * 1024];
                    loop {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if sock.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            },
                        }
                    }
                });
            }
        });

        // UDP: bounce every datagram straight back to its sender.
        rt.spawn(async move {
            let mut buf = [0u8; 64 * 1024];
            while let Ok((n, from)) = udp_socket.recv_from(&mut buf).await {
                let _ = udp_socket.send_to(&buf[..n], from).await;
            }
        });

        Ok(Self {
            tcp_addr,
            udp_addr,
            tcp_connections,
            _rt: rt,
        })
    }

    /// Address to hand the tunnel as the TCP CONNECT target.
    pub fn tcp_addr(&self) -> SocketAddr {
        self.tcp_addr
    }

    /// Address to hand the tunnel as the UDP target.
    pub fn udp_addr(&self) -> SocketAddr {
        self.udp_addr
    }

    /// Number of TCP connections the server has accepted — a sanity signal
    /// that traffic actually reached the upstream through the tunnel.
    pub fn tcp_connections(&self) -> usize {
        self.tcp_connections.load(Ordering::Relaxed)
    }
}
