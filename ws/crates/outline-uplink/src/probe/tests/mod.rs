//! Test-only in-memory VLESS loopback transport.
//!
//! Used by the HTTP and TCP-tunnel probe regression tests to exercise the
//! probe I/O without standing up a real WebSocket / QUIC endpoint. A pair
//! of `tokio::sync::mpsc` channels stand in for the network: the client
//! `VlessTcpWriter` writes frames into the client→server channel, and the
//! fake server task parses the VLESS request header off the first frame,
//! captures everything that follows as the "application stream", and
//! replies with a synthetic VLESS response (`[VERSION, addons_len=0]`) plus
//! whatever payload bytes the test supplies.

#![cfg(test)]

use std::sync::Arc;

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::{Mutex, mpsc};

use outline_transport::frame_io::{FrameSink, FrameSource};
use outline_transport::{
    TcpReader, TcpWriter, UpstreamTransportGuard, VlessTcpReader, VlessTcpWriter,
};

use crate::config::TargetAddr;

const VLESS_VERSION: u8 = 0x00;
const VLESS_ATYP_IPV4: u8 = 0x01;
const VLESS_ATYP_DOMAIN: u8 = 0x02;
const VLESS_ATYP_IPV6: u8 = 0x03;

/// Sender half of the in-memory pipe.
struct ChanSink {
    tx: mpsc::UnboundedSender<Bytes>,
}

#[async_trait]
impl FrameSink for ChanSink {
    async fn send_frame(&mut self, data: Bytes) -> Result<()> {
        self.tx.send(data).map_err(|_| anyhow!("loopback sink: peer dropped"))
    }

    async fn close(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Receiver half of the in-memory pipe.
struct ChanSource {
    rx: Mutex<mpsc::UnboundedReceiver<Bytes>>,
}

#[async_trait]
impl FrameSource for ChanSource {
    async fn recv_frame(&mut self) -> Result<Option<Bytes>> {
        Ok(self.rx.lock().await.recv().await)
    }

    fn closed_cleanly(&self) -> bool {
        true
    }
}

/// Captured server-side view of one fake-VLESS conversation.
pub(super) struct VlessServerCapture {
    /// Target carried in the VLESS request header. Currently unused by the
    /// regression tests but exposed for future cases that want to assert
    /// the probe dialed the right host:port.
    #[allow(dead_code)]
    pub target: TargetAddr,
    /// Concatenation of every application byte the client wrote after the
    /// VLESS request header. For the probe regression tests the assertion
    /// is "this contains the HTTP request and nothing else" — i.e., no
    /// SOCKS5 atyp/addr/port leak from a stray `target_wire` send.
    pub app_stream: Vec<u8>,
}

/// Decode a VLESS TCP request header off the first client-to-server frame
/// and return the target plus any leftover application bytes that were
/// concatenated after the header in that same frame.
fn parse_request_header(frame: &[u8]) -> Result<(TargetAddr, Vec<u8>)> {
    if frame.len() < 1 + 16 + 1 + 1 + 2 + 1 {
        return Err(anyhow!("vless request frame too short: {} bytes", frame.len()));
    }
    if frame[0] != VLESS_VERSION {
        return Err(anyhow!("bad vless version {:#x}", frame[0]));
    }
    let mut idx = 1 + 16; // skip version + uuid
    let addons_len = frame[idx] as usize;
    idx += 1;
    if frame.len() < idx + addons_len + 1 + 2 + 1 {
        return Err(anyhow!("vless request frame truncated in addons"));
    }
    idx += addons_len;
    let _cmd = frame[idx];
    idx += 1;
    let port = u16::from_be_bytes([frame[idx], frame[idx + 1]]);
    idx += 2;
    let atyp = frame[idx];
    idx += 1;
    let target = match atyp {
        VLESS_ATYP_IPV4 => {
            if frame.len() < idx + 4 {
                return Err(anyhow!("vless request: short ipv4 addr"));
            }
            let octets = [frame[idx], frame[idx + 1], frame[idx + 2], frame[idx + 3]];
            idx += 4;
            TargetAddr::IpV4(std::net::Ipv4Addr::from(octets), port)
        },
        VLESS_ATYP_IPV6 => {
            if frame.len() < idx + 16 {
                return Err(anyhow!("vless request: short ipv6 addr"));
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&frame[idx..idx + 16]);
            idx += 16;
            TargetAddr::IpV6(std::net::Ipv6Addr::from(o), port)
        },
        VLESS_ATYP_DOMAIN => {
            if frame.len() < idx + 1 {
                return Err(anyhow!("vless request: missing domain length"));
            }
            let dlen = frame[idx] as usize;
            idx += 1;
            if frame.len() < idx + dlen {
                return Err(anyhow!("vless request: short domain bytes"));
            }
            let host = std::str::from_utf8(&frame[idx..idx + dlen])?.to_owned();
            idx += dlen;
            TargetAddr::Domain(host, port)
        },
        other => return Err(anyhow!("vless request: bad atyp {other:#x}")),
    };
    Ok((target, frame[idx..].to_vec()))
}

/// Build a (`TcpWriter::Vless`, `TcpReader::Vless`) pair backed by an
/// in-memory loopback against a fake VLESS server task. The server reads
/// frames from the client, captures the application stream, and replies
/// with a single frame `[VERSION, 0x00] || server_payload`. The capture
/// handle resolves once the client closes the writer.
pub(super) fn spawn_vless_loopback(
    server_payload: &'static [u8],
) -> (TcpWriter, TcpReader, tokio::task::JoinHandle<Result<VlessServerCapture>>) {
    let (c2s_tx, c2s_rx_init) = mpsc::unbounded_channel::<Bytes>();
    let (s2c_tx, s2c_rx) = mpsc::unbounded_channel::<Bytes>();
    let mut c2s_rx: mpsc::UnboundedReceiver<Bytes> = c2s_rx_init;

    // Probe code only ever calls `to_wire_bytes()` against the target it
    // supplies to `connect_probe_tcp`, never reads it back; the uuid is
    // similarly opaque on the test side. Use any fixed values.
    let uuid = [0x42u8; 16];
    let target = TargetAddr::Domain("example.com".to_string(), 80);

    let lifetime = UpstreamTransportGuard::new("probe_test", "tcp");

    let sink = ChanSink { tx: c2s_tx };
    let source = ChanSource { rx: Mutex::new(s2c_rx) };
    let writer = VlessTcpWriter::with_sink(Box::new(sink), &uuid, &target, Arc::clone(&lifetime));
    let reader = VlessTcpReader::with_source(Box::new(source), lifetime);

    let server = tokio::spawn(async move {
        let first = c2s_rx
            .recv()
            .await
            .ok_or_else(|| anyhow!("loopback: client closed before sending request header"))?;
        let (target, leftover) = parse_request_header(&first)?;
        let mut app_stream = leftover;
        // VLESS response header: version + zero-length addons. Bundling the
        // synthetic upstream payload into the same frame keeps the reader
        // path simple — `VlessTcpReader::read_chunk` strips the header and
        // returns the trailing bytes.
        let mut response = Vec::with_capacity(2 + server_payload.len());
        response.push(VLESS_VERSION);
        response.push(0x00);
        response.extend_from_slice(server_payload);
        s2c_tx
            .send(Bytes::from(response))
            .map_err(|_| anyhow!("loopback: client dropped before reading response"))?;

        // Drain anything the client writes after the request header — the
        // probe code path may follow up with more frames (HTTP body, etc.).
        while let Some(frame) = c2s_rx.recv().await {
            app_stream.extend_from_slice(&frame);
        }
        Ok(VlessServerCapture { target, app_stream })
    });

    (TcpWriter::Vless(writer), TcpReader::Vless(reader), server)
}
