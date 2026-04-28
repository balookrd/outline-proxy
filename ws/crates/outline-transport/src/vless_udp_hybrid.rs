//! Hybrid VLESS UDP mux: starts on raw QUIC, pivots to WS over H2 the
//! first time the QUIC path fails before any session has succeeded.
//!
//! Mirrors the SS-UDP raw-QUIC fallback in
//! `outline_uplink::manager::standby::acquire_udp_standby_or_connect`,
//! but moved inside the mux because VLESS UDP sessions dial lazily on
//! the first packet to a given target — there is no single cold dial we
//! can guard at acquire time. The hybrid wrapper lets the caller keep a
//! single `UdpSessionTransport::VlessQuic` handle whose internals can
//! pivot from QUIC to WS without rebuilding the surrounding session
//! entry, and forwards every downlink datagram from whichever inner mux
//! is currently active through one shared receiver.

#![cfg(feature = "quic")]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use bytes::Bytes;
use parking_lot::RwLock;
use tokio::sync::{Mutex as AsyncMutex, mpsc};
use tracing::warn;

use crate::vless::VlessUdpSessionMux;
use crate::vless_quic_mux::VlessUdpQuicMux;
use crate::{AbortOnDrop, WsClosed};

/// Synchronous callback fired the moment the mux pivots from QUIC to WS.
/// Receives the QUIC dial error so the caller can record it (e.g. via
/// `UplinkManager::note_advanced_mode_dial_failure`).
pub type FallbackNotifier = Arc<dyn Fn(&anyhow::Error) + Send + Sync>;

/// Lazy factory for the WS fallback mux. Invoked at most once: when the
/// QUIC mux raises an error before any session has succeeded. Returns a
/// fully-built [`VlessUdpSessionMux`] with the same target URL / UUID /
/// limits as the QUIC mux but configured to dial WS instead.
pub type WsFallbackFactory = Box<dyn FnOnce() -> VlessUdpSessionMux + Send>;

pub struct VlessUdpHybridMux {
    state: RwLock<MuxState>,
    /// Set after the first successful `send_packet` on the QUIC mux.
    /// Latched: once true, runtime errors on the QUIC mux propagate to
    /// the caller instead of triggering a WS fallback (the QUIC path
    /// has clearly worked at least once, so an error there is a real
    /// failure of an established session, not an unreachable QUIC peer).
    quic_succeeded_once: AtomicBool,
    ws_factory: AsyncMutex<Option<WsFallbackFactory>>,
    on_fallback: Option<FallbackNotifier>,
    out_tx: mpsc::Sender<Result<Bytes>>,
    out_rx: AsyncMutex<mpsc::Receiver<Result<Bytes>>>,
}

enum MuxState {
    Quic { mux: Arc<VlessUdpQuicMux>, _proxy: AbortOnDrop },
    Ws { mux: Arc<VlessUdpSessionMux>, _proxy: AbortOnDrop },
}

#[derive(Clone)]
enum Active {
    Quic(Arc<VlessUdpQuicMux>),
    Ws(Arc<VlessUdpSessionMux>),
}

impl VlessUdpHybridMux {
    /// Wrap a freshly-built QUIC mux in the hybrid envelope. The hybrid
    /// owns the QUIC mux from now on and stays QUIC-only until the first
    /// dial failure, at which point `ws_factory` is consumed to mint a
    /// WS-mode replacement.
    pub fn from_quic(
        quic: VlessUdpQuicMux,
        ws_factory: WsFallbackFactory,
        on_fallback: Option<FallbackNotifier>,
    ) -> Self {
        let (out_tx, out_rx) = mpsc::channel::<Result<Bytes>>(256);
        let quic = Arc::new(quic);
        let proxy = spawn_quic_proxy(Arc::clone(&quic), out_tx.clone());
        Self {
            state: RwLock::new(MuxState::Quic { mux: quic, _proxy: proxy }),
            quic_succeeded_once: AtomicBool::new(false),
            ws_factory: AsyncMutex::new(Some(ws_factory)),
            on_fallback,
            out_tx,
            out_rx: AsyncMutex::new(out_rx),
        }
    }

    pub async fn send_packet(&self, socks5_payload: &[u8]) -> Result<()> {
        let active = self.snapshot_active();
        match active {
            Active::Quic(quic) => match quic.send_packet(socks5_payload).await {
                Ok(()) => {
                    self.quic_succeeded_once.store(true, Ordering::Relaxed);
                    Ok(())
                }
                Err(e) => {
                    if self.quic_succeeded_once.load(Ordering::Relaxed) {
                        return Err(e);
                    }
                    if let Some(ws) = self.install_ws_state(&e).await {
                        ws.send_packet(socks5_payload).await
                    } else {
                        Err(e)
                    }
                }
            },
            Active::Ws(ws) => ws.send_packet(socks5_payload).await,
        }
    }

    pub async fn read_packet(&self) -> Result<Bytes> {
        let mut rx = self.out_rx.lock().await;
        rx.recv().await.ok_or_else(|| anyhow::Error::from(WsClosed))?
    }

    pub async fn close(&self) -> Result<()> {
        let active = self.snapshot_active();
        match active {
            Active::Quic(mux) => mux.close().await,
            Active::Ws(mux) => mux.close().await,
        }
    }

    fn snapshot_active(&self) -> Active {
        match &*self.state.read() {
            MuxState::Quic { mux, .. } => Active::Quic(Arc::clone(mux)),
            MuxState::Ws { mux, .. } => Active::Ws(Arc::clone(mux)),
        }
    }

    async fn install_ws_state(&self, error: &anyhow::Error) -> Option<Arc<VlessUdpSessionMux>> {
        let mut factory_guard = self.ws_factory.lock().await;
        if let Some(factory) = factory_guard.take() {
            warn!(
                error = %format!("{error:#}"),
                "VLESS UDP raw-QUIC dial failed before any session succeeded; falling back to WS"
            );
            if let Some(cb) = &self.on_fallback {
                cb(error);
            }
            let ws = Arc::new(factory());
            let proxy = spawn_ws_proxy(Arc::clone(&ws), self.out_tx.clone());
            // Replace state. The previous QUIC mux + its proxy task
            // drop here: AbortOnDrop on the proxy aborts it before any
            // QUIC error can leak into out_tx and be observed by the
            // hybrid's caller as a spurious failure.
            let mut state = self.state.write();
            *state = MuxState::Ws { mux: Arc::clone(&ws), _proxy: proxy };
            return Some(ws);
        }
        // Factory already consumed by a concurrent caller; pick the
        // installed WS mux from the state.
        drop(factory_guard);
        match &*self.state.read() {
            MuxState::Ws { mux, .. } => Some(Arc::clone(mux)),
            MuxState::Quic { .. } => None,
        }
    }
}

fn spawn_quic_proxy(
    mux: Arc<VlessUdpQuicMux>,
    out_tx: mpsc::Sender<Result<Bytes>>,
) -> AbortOnDrop {
    AbortOnDrop::new(tokio::spawn(async move {
        loop {
            match mux.read_packet().await {
                Ok(b) => {
                    if out_tx.send(Ok(b)).await.is_err() {
                        return;
                    }
                }
                Err(e) => {
                    let _ = out_tx.send(Err(e)).await;
                    return;
                }
            }
        }
    }))
}

fn spawn_ws_proxy(
    mux: Arc<VlessUdpSessionMux>,
    out_tx: mpsc::Sender<Result<Bytes>>,
) -> AbortOnDrop {
    AbortOnDrop::new(tokio::spawn(async move {
        loop {
            match mux.read_packet().await {
                Ok(b) => {
                    if out_tx.send(Ok(b)).await.is_err() {
                        return;
                    }
                }
                Err(e) => {
                    let _ = out_tx.send(Err(e)).await;
                    return;
                }
            }
        }
    }))
}
