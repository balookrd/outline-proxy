//! VLESS-UDP session mux over raw QUIC.
//!
//! Mirror of [`crate::vless::VlessUdpSessionMux`] but the per-target
//! sessions ride on [`crate::quic::vless_udp::VlessUdpQuicSession`]
//! over a shared QUIC connection. The connection-level demuxer
//! ([`crate::quic::vless_udp::VlessUdpDemuxer`]) takes care of routing
//! inbound datagrams by `session_id_4B_BE` to the right session, so
//! each target — like in the WS path — gets its own logical session
//! but they all share one QUIC connection (hence one TLS handshake,
//! one congestion-control state, etc.).
//!
//! Public API matches the WS mux exactly:
//!
//! * `send_packet(socks5_payload)` — the SOCKS5 atyp prefix is parsed
//!   to pick / open a session; only the inner UDP payload crosses the
//!   wire.
//!
//! * `read_packet() -> Bytes` — downlink datagrams arrive prefixed
//!   with the originating session's SOCKS5 atyp / addr / port so the
//!   caller can use the same parser as the SS UDP path.

#![cfg(feature = "quic")]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use bytes::{Bytes, BytesMut};
use parking_lot::Mutex as SyncMutex;
use socks5_proto::TargetAddr;
use tokio::sync::{Mutex, mpsc, watch};
use tracing::debug;
use url::Url;

use crate::quic::vless_udp::VlessUdpQuicSession;
use crate::quic_connect::connect_vless_udp_session_quic;
use crate::vless::VlessUdpMuxLimits;
use crate::{AbortOnDrop, DnsCache, TransportOperation, UpstreamTransportGuard, WsClosed};

pub struct VlessUdpQuicMux {
    dial: VlessUdpQuicDialer,
    limits: VlessUdpMuxLimits,
    sessions: Arc<Mutex<HashMap<TargetAddr, Arc<VlessUdpQuicSessionEntry>>>>,
    downlink_tx: mpsc::Sender<Result<Bytes>>,
    downlink_rx: Mutex<mpsc::Receiver<Result<Bytes>>>,
    close_signal: watch::Sender<bool>,
    _janitor_task: Option<AbortOnDrop>,
    _lifetime: Arc<UpstreamTransportGuard>,
}

#[derive(Clone)]
struct VlessUdpQuicDialer {
    dns_cache: Arc<DnsCache>,
    url: Url,
    uuid: [u8; 16],
    fwmark: Option<u32>,
    ipv6_first: bool,
    source: &'static str,
}

struct VlessUdpQuicSessionEntry {
    session: Arc<VlessUdpQuicSession>,
    last_use: SyncMutex<Instant>,
    _reader_task: AbortOnDrop,
}

impl VlessUdpQuicSessionEntry {
    fn touch(&self) {
        *self.last_use.lock() = Instant::now();
    }

    fn last_use(&self) -> Instant {
        *self.last_use.lock()
    }
}

impl VlessUdpQuicMux {
    pub fn new(
        dns_cache: Arc<DnsCache>,
        url: Url,
        uuid: [u8; 16],
        fwmark: Option<u32>,
        ipv6_first: bool,
        source: &'static str,
        limits: VlessUdpMuxLimits,
    ) -> Self {
        let (close_signal, _close_rx) = watch::channel(false);
        let (downlink_tx, downlink_rx) = mpsc::channel::<Result<Bytes>>(256);
        let sessions: Arc<Mutex<HashMap<TargetAddr, Arc<VlessUdpQuicSessionEntry>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let janitor_task = limits.session_idle_timeout.map(|idle| {
            spawn_janitor(
                Arc::clone(&sessions),
                idle,
                limits.janitor_interval,
                close_signal.subscribe(),
            )
        });
        Self {
            dial: VlessUdpQuicDialer {
                dns_cache,
                url,
                uuid,
                fwmark,
                ipv6_first,
                source,
            },
            limits,
            sessions,
            downlink_tx,
            downlink_rx: Mutex::new(downlink_rx),
            close_signal,
            _janitor_task: janitor_task,
            _lifetime: UpstreamTransportGuard::new(source, "udp"),
        }
    }

    pub async fn send_packet(&self, socks5_payload: &[u8]) -> Result<()> {
        let (target, consumed) = TargetAddr::from_wire_bytes(socks5_payload)
            .context("vless udp quic: failed to parse SOCKS5 header from outbound payload")?;
        let inner = &socks5_payload[consumed..];
        let entry = self.session_for(&target).await?;
        entry.touch();
        entry.session.send_packet(inner).await
    }

    pub async fn read_packet(&self) -> Result<Bytes> {
        let mut rx = self.downlink_rx.lock().await;
        rx.recv().await.ok_or_else(|| anyhow::Error::from(WsClosed))?
    }

    pub async fn close(&self) -> Result<()> {
        self.close_signal.send_replace(true);
        let sessions = {
            let mut guard = self.sessions.lock().await;
            std::mem::take(&mut *guard)
        };
        for (_, entry) in sessions {
            let _ = entry.session.close().await;
        }
        Ok(())
    }

    async fn session_for(&self, target: &TargetAddr) -> Result<Arc<VlessUdpQuicSessionEntry>> {
        {
            let guard = self.sessions.lock().await;
            if let Some(entry) = guard.get(target) {
                entry.touch();
                return Ok(Arc::clone(entry));
            }
        }
        let session = Arc::new(
            connect_vless_udp_session_quic(
                &self.dial.dns_cache,
                &self.dial.url,
                self.dial.fwmark,
                self.dial.ipv6_first,
                self.dial.source,
                &self.dial.uuid,
                target,
            )
            .await
            .with_context(|| TransportOperation::Connect {
                target: format!("vless udp quic session to {target}"),
            })?,
        );
        let reader_task = spawn_session_reader(
            Arc::clone(&session),
            target.clone(),
            self.downlink_tx.clone(),
            self.close_signal.subscribe(),
        );
        let entry = Arc::new(VlessUdpQuicSessionEntry {
            session,
            last_use: SyncMutex::new(Instant::now()),
            _reader_task: reader_task,
        });
        let evicted = {
            let mut guard = self.sessions.lock().await;
            if let Some(existing) = guard.get(target) {
                let existing = Arc::clone(existing);
                existing.touch();
                drop(guard);
                let _ = entry.session.close().await;
                return Ok(existing);
            }
            let evicted = if guard.len() >= self.limits.max_sessions {
                evict_lru(&mut guard)
            } else {
                None
            };
            guard.insert(target.clone(), Arc::clone(&entry));
            evicted
        };
        if let Some(victim) = evicted {
            debug!(
                target: "outline_transport::vless_quic",
                "vless udp quic mux at max_sessions, evicted LRU session to make room"
            );
            let _ = victim.session.close().await;
        }
        Ok(entry)
    }
}

fn evict_lru(
    guard: &mut HashMap<TargetAddr, Arc<VlessUdpQuicSessionEntry>>,
) -> Option<Arc<VlessUdpQuicSessionEntry>> {
    let oldest = guard
        .iter()
        .min_by_key(|(_, entry)| entry.last_use())
        .map(|(k, _)| k.clone())?;
    guard.remove(&oldest)
}

fn spawn_janitor(
    sessions: Arc<Mutex<HashMap<TargetAddr, Arc<VlessUdpQuicSessionEntry>>>>,
    idle: Duration,
    interval: Duration,
    mut close_rx: watch::Receiver<bool>,
) -> AbortOnDrop {
    AbortOnDrop::new(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await;
        loop {
            tokio::select! {
                biased;
                _ = close_rx.changed() => {
                    if *close_rx.borrow() { return; }
                }
                _ = ticker.tick() => {}
            }
            let now = Instant::now();
            let expired: Vec<Arc<VlessUdpQuicSessionEntry>> = {
                let mut guard = sessions.lock().await;
                let keys: Vec<TargetAddr> = guard
                    .iter()
                    .filter(|(_, e)| now.saturating_duration_since(e.last_use()) >= idle)
                    .map(|(k, _)| k.clone())
                    .collect();
                keys.into_iter().filter_map(|k| guard.remove(&k)).collect()
            };
            for entry in expired {
                let _ = entry.session.close().await;
            }
        }
    }))
}

fn spawn_session_reader(
    session: Arc<VlessUdpQuicSession>,
    target: TargetAddr,
    downlink_tx: mpsc::Sender<Result<Bytes>>,
    mut close_rx: watch::Receiver<bool>,
) -> AbortOnDrop {
    AbortOnDrop::new(tokio::spawn(async move {
        let prefix = match target.to_wire_bytes() {
            Ok(b) => b,
            Err(error) => {
                let _ = downlink_tx
                    .send(Err(anyhow::Error::from(error)
                        .context("vless udp quic: failed to encode target")))
                    .await;
                return;
            }
        };
        loop {
            let payload = tokio::select! {
                biased;
                _ = close_rx.changed() => {
                    if *close_rx.borrow() { return; }
                    continue;
                }
                res = session.read_packet() => match res {
                    Ok(p) => p,
                    Err(error) => {
                        let _ = downlink_tx.send(Err(error)).await;
                        return;
                    }
                },
            };
            let mut framed = BytesMut::with_capacity(prefix.len() + payload.len());
            framed.extend_from_slice(&prefix);
            framed.extend_from_slice(&payload);
            if downlink_tx.send(Ok(framed.freeze())).await.is_err() {
                return;
            }
        }
    }))
}
