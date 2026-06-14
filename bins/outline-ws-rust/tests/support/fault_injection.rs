#![allow(dead_code)]
//! Fault injectors that stand in for a "downed" sub-uplink / uplink without
//! Docker or iptables.
//!
//! * [`RejectingListener`] — accepts the TCP connection and immediately closes
//!   it. The client's WebSocket / XHTTP handshake fails fast with a reset
//!   (no waiting for the 10 s `FRESH_CONNECT_TIMEOUT`), so it is the default
//!   "broken wire" for dial-driven wire / cross-uplink failover. It also keeps
//!   the port bound for the whole test, so the address can't be recycled by
//!   the OS the way a closed reserved port can.
//! * [`BlackholeListener`] — accepts and then stays silent, never answering the
//!   handshake. Reproduces a DPI black-hole; the client only gives up after the
//!   10 s connect timeout, so it is reserved for the explicit slow
//!   timeout-pathway case.
//! * [`MidSessionBreaker`] — a transparent TCP splice between the client and a
//!   live server. `cut()` drops every in-flight splice mid-stream while the
//!   backend keeps running, so the client re-dials the same URL and the
//!   server's session-resumption path engages (Ack-Prefix resume).
//!
//! Each injector owns a small tokio runtime so `start()` is synchronous and the
//! bound address is available immediately for config generation.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::net::TcpListener;
use tokio::runtime::{Builder, Runtime};
use tokio::sync::watch;

fn rt() -> io::Result<Runtime> {
    Builder::new_multi_thread().worker_threads(1).enable_all().build()
}

// ── RejectingListener ────────────────────────────────────────────────────────

/// Accepts and instantly closes every connection → fast handshake reset.
pub struct RejectingListener {
    addr: SocketAddr,
    accepted: Arc<AtomicUsize>,
    _rt: Runtime,
}

impl RejectingListener {
    pub fn start() -> io::Result<Self> {
        let rt = rt()?;
        let accepted = Arc::new(AtomicUsize::new(0));
        let (listener, addr) = rt.block_on(async {
            let l = TcpListener::bind(("127.0.0.1", 0)).await?;
            let a = l.local_addr()?;
            io::Result::Ok((l, a))
        })?;
        let counter = Arc::clone(&accepted);
        rt.spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::Relaxed);
                // Drop immediately: the peer sees the handshake fail at once.
                drop(sock);
            }
        });
        Ok(Self { addr, accepted, _rt: rt })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn ws_url(&self, path: &str) -> String {
        format!("ws://{}{}", self.addr, path)
    }

    pub fn http_url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }

    pub fn accepted(&self) -> usize {
        self.accepted.load(Ordering::Relaxed)
    }
}

// ── BlackholeListener ────────────────────────────────────────────────────────

/// Accepts and stays silent forever → client gives up only after its connect
/// timeout (~10 s). Reserved for the explicit slow timeout-pathway case.
pub struct BlackholeListener {
    addr: SocketAddr,
    _rt: Runtime,
}

impl BlackholeListener {
    pub fn start() -> io::Result<Self> {
        let rt = rt()?;
        let (listener, addr) = rt.block_on(async {
            let l = TcpListener::bind(("127.0.0.1", 0)).await?;
            let a = l.local_addr()?;
            io::Result::Ok((l, a))
        })?;
        rt.spawn(async move {
            let mut held = Vec::new();
            // Hold each socket so the peer's connection stays open but unanswered.
            while let Ok((sock, _)) = listener.accept().await {
                held.push(sock);
            }
        });
        Ok(Self { addr, _rt: rt })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn ws_url(&self, path: &str) -> String {
        format!("ws://{}{}", self.addr, path)
    }

    pub fn http_url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }
}

// ── MidSessionBreaker ────────────────────────────────────────────────────────

/// Transparent TCP splice `client ↔ backend` that can sever live carriers on
/// demand. Put `front_addr()` in the client config as the wire endpoint and
/// `backend` = the real server's listen address. `cut()` advances a generation
/// counter; every splice that started on an older generation tears down (both
/// halves dropped), so the carrier dies mid-stream while the backend stays up
/// and accepts the client's resume redial.
pub struct MidSessionBreaker {
    front_addr: SocketAddr,
    cut_tx: watch::Sender<u64>,
    splices_open: Arc<AtomicUsize>,
    splices_total: Arc<AtomicUsize>,
    _rt: Runtime,
}

impl MidSessionBreaker {
    pub fn start(backend: SocketAddr) -> io::Result<Self> {
        let rt = rt()?;
        let (cut_tx, _cut_rx) = watch::channel(0u64);
        let splices_open = Arc::new(AtomicUsize::new(0));
        let splices_total = Arc::new(AtomicUsize::new(0));

        let (listener, front_addr) = rt.block_on(async {
            let l = TcpListener::bind(("127.0.0.1", 0)).await?;
            let a = l.local_addr()?;
            io::Result::Ok((l, a))
        })?;

        let cut_tx_for_loop = cut_tx.clone();
        let open = Arc::clone(&splices_open);
        let total = Arc::clone(&splices_total);
        rt.spawn(async move {
            loop {
                let Ok((client, _)) = listener.accept().await else {
                    break;
                };
                let cut_rx = cut_tx_for_loop.subscribe();
                let generation = *cut_rx.borrow();
                let open = Arc::clone(&open);
                let total = Arc::clone(&total);
                tokio::spawn(async move {
                    total.fetch_add(1, Ordering::Relaxed);
                    open.fetch_add(1, Ordering::Relaxed);
                    let _ = splice(client, backend, cut_rx, generation).await;
                    open.fetch_sub(1, Ordering::Relaxed);
                });
            }
        });

        Ok(Self {
            front_addr,
            cut_tx,
            splices_open,
            splices_total,
            _rt: rt,
        })
    }

    pub fn front_addr(&self) -> SocketAddr {
        self.front_addr
    }

    pub fn ws_url(&self, path: &str) -> String {
        format!("ws://{}{}", self.front_addr, path)
    }

    pub fn http_url(&self, path: &str) -> String {
        format!("http://{}{}", self.front_addr, path)
    }

    /// Sever every currently-open splice. New connections after this call
    /// splice normally to the (still-live) backend.
    pub fn cut(&self) {
        self.cut_tx.send_modify(|g| *g += 1);
    }

    pub fn splices_open(&self) -> usize {
        self.splices_open.load(Ordering::Relaxed)
    }

    /// Total splices opened over the breaker's lifetime — a non-trivial signal
    /// that the client re-dialled after a `cut()`.
    pub fn splices_total(&self) -> usize {
        self.splices_total.load(Ordering::Relaxed)
    }
}

/// Splice one client connection to a fresh backend connection. On `cut`, an
/// invalid WebSocket frame is injected into the downlink before the sockets are
/// dropped: the client then classifies the failure as an *upstream runtime
/// failure* (a corrupt frame / AEAD-decrypt error — NOT a clean
/// "connection reset without closing handshake", which `is_ws_closed` treats as
/// a graceful close that does NOT retry). That corrupt-frame condition is what
/// triggers the Ack-Prefix mid-session retry on the client.
async fn splice(
    client: tokio::net::TcpStream,
    backend: SocketAddr,
    mut cut_rx: watch::Receiver<u64>,
    started_at: u64,
) -> io::Result<()> {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let server = tokio::net::TcpStream::connect(backend).await?;
    let (mut cr, mut cw) = client.into_split();
    let (mut sr, mut sw) = server.into_split();
    let mut up = [0u8; 16 * 1024];
    let mut down = [0u8; 16 * 1024];

    loop {
        tokio::select! {
            // client → server
            read = cr.read(&mut up) => match read {
                Ok(0) | Err(_) => break,
                Ok(n) => { if sw.write_all(&up[..n]).await.is_err() { break; } },
            },
            // server → client
            read = sr.read(&mut down) => match read {
                Ok(0) | Err(_) => break,
                Ok(n) => { if cw.write_all(&down[..n]).await.is_err() { break; } },
            },
            _ = wait_for_cut(&mut cut_rx, started_at) => {
                // 1. Send the server a WebSocket CLOSE frame (masked, empty
                //    payload) so its frame reader returns `WsFrame::Close` and
                //    reaches the park path. A bare TCP FIN / RST would surface
                //    as a WS *receive failure* that bubbles out via `?` and
                //    skips parking, so the resume would never find the session.
                const WS_CLOSE_MASKED: [u8; 6] = [0x88, 0x80, 0x00, 0x00, 0x00, 0x00];
                let _ = sw.write_all(&WS_CLOSE_MASKED).await;
                let _ = sw.flush().await;
                let _ = sw.shutdown().await;
                drop(sr);
                // 2. Let the server park the session into its orphan registry.
                tokio::time::sleep(Duration::from_millis(500)).await;
                // 3. Corrupt the client's downlink (reserved opcode + bogus
                //    length) so the client classifies this as an upstream
                //    runtime failure — the trigger for Ack-Prefix mid-session
                //    retry — rather than a graceful ws-close (which never
                //    retries).
                let _ = cw.write_all(&[0xFF; 16]).await;
                let _ = cw.flush().await;
                return Ok(());
            }
        }
    }
    Ok(())
}

/// Resolve once the cut generation advances past `started_at`.
async fn wait_for_cut(cut_rx: &mut watch::Receiver<u64>, started_at: u64) {
    loop {
        if *cut_rx.borrow() != started_at {
            return;
        }
        if cut_rx.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}
