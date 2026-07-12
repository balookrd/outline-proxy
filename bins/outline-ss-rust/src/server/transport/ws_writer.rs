use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use tokio::sync::mpsc;

use outline_wire::padding::{ControlSignal, encode_control_frame_into};

use crate::metrics::{AppProtocol, Metrics, Protocol, Transport};

use super::super::constants::WS_CONTROL_FLUSH_INTERVAL_SECS;
use super::carrier_padding::CoverParams;
use super::throughput_monitor::ThroughputMonitor;
use super::ws_socket::WsSocket;

/// Far-future deadline parked on the cover timer when cover is disabled (the
/// `if cover.is_some()` select guard keeps the arm inert; this just avoids an
/// `Option<Sleep>` dance). One day is comfortably beyond any real session.
const COVER_DISABLED_PARK: Duration = Duration::from_secs(86_400);

// The metrics-context args (transport/protocol/app_protocol) are a cohesive
// group already threaded this way across the transport layer; cover adds one
// more. Grouping them would be a cross-cutting refactor beyond this change.
#[allow(clippy::too_many_arguments)]
pub(super) async fn run_ws_writer<T: WsSocket>(
    mut writer: T::Writer,
    mut outbound_ctrl_rx: mpsc::Receiver<T::Msg>,
    mut outbound_data_rx: mpsc::Receiver<T::Msg>,
    metrics: Arc<Metrics>,
    transport_kind: Transport,
    protocol: Protocol,
    app_protocol: AppProtocol,
    cover: Option<CoverParams>,
    // `Some` only on a padded carrier with downstream-throttle detection on
    // (VLESS-over-WS): the writer counts outbound bytes into it and, when the
    // tick pings `signal()`, emits one control frame nudging the client to
    // switch uplinks. `None` keeps the legacy path byte-for-byte identical.
    monitor: Option<Arc<ThroughputMonitor>>,
) -> Result<()> {
    let result = async {
        // Periodically drain any control-frame responses the transport
        // buffered (chiefly a Pong the split reader queued in reply to a
        // client keepalive Ping). On a quiet datagram channel neither
        // `recv` ever fires, so without this tick the reactive Pong would
        // sit unsent and the client's read-idle watchdog would trip. The
        // flush delivers it WITHOUT emitting a server-originated Ping —
        // unsafe on H3, where it races stream teardown on a `shuffle_timer`
        // reroll and escalates to a connection-level `H3_INTERNAL_ERROR`.
        // The `biased` ordering keeps the flush a last resort: a closed
        // ctrl/data channel (teardown) is observed first, so we exit
        // rather than write into a stream that is already finishing.
        let mut flush_tick =
            tokio::time::interval(Duration::from_secs(WS_CONTROL_FLUSH_INTERVAL_SECS));
        flush_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        flush_tick.tick().await; // skip the immediate first tick

        // Idle cover timer. Parked far in the future when cover is off (the
        // `if cover.is_some()` guard keeps the arm inert); when on, it is armed
        // to the next jittered gap and reset after every real data write, so a
        // cover frame fires only on a genuinely quiet channel — never
        // interleaved with live traffic. A cover frame is a `Binary` message
        // (`real_len = 0`), so it is H3-safe: unlike a server-originated Ping
        // it cannot escalate to `H3_INTERNAL_ERROR`, and the peer's decoder
        // drops it transparently.
        let cover_sleep = tokio::time::sleep(COVER_DISABLED_PARK);
        tokio::pin!(cover_sleep);
        if let Some(c) = &cover {
            cover_sleep.as_mut().reset(tokio::time::Instant::now() + c.next_gap());
        }

        let mut ctrl_open = true;
        loop {
            if ctrl_open {
                tokio::select! {
                    biased;
                    msg = outbound_ctrl_rx.recv() => match msg {
                        Some(m) => T::send(&mut writer, m).await?,
                        None => ctrl_open = false,
                    },
                    msg = outbound_data_rx.recv() => match msg {
                        Some(m) => {
                            send_data::<T>(
                                &mut writer, m, &metrics, transport_kind, protocol, app_protocol,
                                monitor.as_ref(),
                            ).await?;
                            arm_cover(cover_sleep.as_mut(), &cover);
                        },
                        None => break,
                    },
                    _ = flush_tick.tick() => T::flush(&mut writer).await?,
                    _ = cover_sleep.as_mut(), if cover.is_some() => {
                        send_cover::<T>(
                            &mut writer, &metrics, transport_kind, protocol, app_protocol, &cover,
                        ).await?;
                        arm_cover(cover_sleep.as_mut(), &cover);
                    },
                    _ = throttle_signalled(&monitor), if monitor.is_some() => {
                        send_control_frame::<T>(&mut writer).await?;
                    },
                }
            } else {
                tokio::select! {
                    biased;
                    msg = outbound_data_rx.recv() => match msg {
                        Some(m) => {
                            send_data::<T>(
                                &mut writer, m, &metrics, transport_kind, protocol, app_protocol,
                                monitor.as_ref(),
                            ).await?;
                            arm_cover(cover_sleep.as_mut(), &cover);
                        },
                        None => break,
                    },
                    _ = flush_tick.tick() => T::flush(&mut writer).await?,
                    _ = cover_sleep.as_mut(), if cover.is_some() => {
                        send_cover::<T>(
                            &mut writer, &metrics, transport_kind, protocol, app_protocol, &cover,
                        ).await?;
                        arm_cover(cover_sleep.as_mut(), &cover);
                    },
                    _ = throttle_signalled(&monitor), if monitor.is_some() => {
                        send_control_frame::<T>(&mut writer).await?;
                    },
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;
    T::finish(&mut writer).await;
    result
}

/// Re-arms the cover timer to the next jittered idle gap. No-op when cover is
/// off (the timer stays parked and the select guard inert).
fn arm_cover(sleep: std::pin::Pin<&mut tokio::time::Sleep>, cover: &Option<CoverParams>) {
    if let Some(c) = cover {
        sleep.reset(tokio::time::Instant::now() + c.next_gap());
    }
}

/// Emits one pad-only cover frame on the downlink. Routed through `send_data`
/// so it shows up in the binary-frame "out" metric exactly like real traffic.
async fn send_cover<T: WsSocket>(
    writer: &mut T::Writer,
    metrics: &Metrics,
    transport_kind: Transport,
    protocol: Protocol,
    app_protocol: AppProtocol,
    cover: &Option<CoverParams>,
) -> Result<()> {
    if let Some(c) = cover {
        let frame = Bytes::from(c.frame());
        // Cover frames are keepalive padding, not data toward the client, so
        // they are not counted as outbound throughput (`None`).
        send_data::<T>(
            writer,
            T::binary_msg(frame),
            metrics,
            transport_kind,
            protocol,
            app_protocol,
            None,
        )
        .await?;
    }
    Ok(())
}

/// Records the binary-frame metric (when applicable) and writes a single
/// downlink message. Shared by the ctrl-open and ctrl-closed select arms so
/// the data-send path stays identical regardless of control-channel state.
async fn send_data<T: WsSocket>(
    writer: &mut T::Writer,
    msg: T::Msg,
    metrics: &Metrics,
    transport_kind: Transport,
    protocol: Protocol,
    app_protocol: AppProtocol,
    monitor: Option<&Arc<ThroughputMonitor>>,
) -> Result<()> {
    if let Some(len) = T::binary_len(&msg) {
        metrics.record_websocket_binary_frame(transport_kind, protocol, app_protocol, "down", len);
        if let Some(m) = monitor {
            m.add_outbound(len as u64);
        }
    }
    T::send(writer, msg).await
}

/// Awaits the throttle tick's wake-up. Parked forever when no monitor is set
/// (the `if monitor.is_some()` select guard keeps the arm inert), so callers
/// can wire it unconditionally.
async fn throttle_signalled(monitor: &Option<Arc<ThroughputMonitor>>) {
    match monitor {
        Some(m) => m.signal().notified().await,
        None => std::future::pending().await,
    }
}

/// Emits one downstream-throttle control frame on the downlink. Wire-identical
/// to a cover frame (`real_len = 0`), so it is H3-safe and a padding-unaware
/// peer drops it transparently. The recognised client routes it to an uplink
/// switch.
async fn send_control_frame<T: WsSocket>(writer: &mut T::Writer) -> Result<()> {
    let mut frame = Vec::new();
    // The pad is the fixed 6-byte control prefix; `encode_control_frame_into`
    // only errors on an oversized segment, which is impossible here.
    encode_control_frame_into(&mut frame, ControlSignal::ThrottleSwitchUplink, &[])
        .expect("control frame prefix never overflows the u16 pad length");
    T::send(writer, T::binary_msg(Bytes::from(frame))).await
}
