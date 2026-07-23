//! Resource-bound invariants for the SS-over-WebSocket TCP relay.
//!
//! Both tests target the leak vector `AbortOnDrop` exists to close (see
//! [`crate::server::abort`]): the spawned upstream→client relay task must
//! never outlive the session that owns it. The upstream fixture accepts a
//! connection and then stays silent — an idle database, SSH session or
//! long-poll — because that is the only shape where an orphaned reader
//! waits forever instead of exiting on the next upstream EOF.

use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::num::NonZeroUsize;

use axum::http::HeaderMap;
use bytes::BytesMut;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use super::super::ws_socket::{WsFrame, WsSocket};
use super::*;
use crate::config::CipherKind;
use crate::protocol::TargetAddr;
use crate::server::abort::AbortOnDrop;
use crate::server::nat::UdpResponseSender;
use crate::server::peer_user_cache::PeerUserCache;
use crate::server::tests::sample_config;

/// One scripted inbound event on the client side of the carrier.
enum Step {
    /// A WS Binary frame from the client.
    Binary(Bytes),
    /// `recv` fails: the client vanished without a closing handshake
    /// (TCP RST, QUIC reset, tungstenite `ResetWithoutClosingHandshake`).
    Reset,
}

enum MockMsg {
    Binary(Bytes),
    Ctrl,
}

struct MockWs {
    steps: VecDeque<Step>,
    writer_alive: oneshot::Sender<()>,
}

struct MockReader(VecDeque<Step>);

struct MockWriter {
    /// Never read. The test observes when `run_ws_writer` returned by
    /// awaiting the paired receiver: it resolves the moment this writer
    /// half is dropped, which can only happen once every clone of the
    /// outbound data sender — including the one the relay task holds in
    /// its `ChannelSink` — is gone.
    _writer_alive: oneshot::Sender<()>,
}

impl WsSocket for MockWs {
    type Msg = MockMsg;
    type Reader = MockReader;
    type Writer = MockWriter;

    fn split_io(self) -> (Self::Reader, Self::Writer) {
        (MockReader(self.steps), MockWriter { _writer_alive: self.writer_alive })
    }

    async fn recv(reader: &mut Self::Reader) -> Result<Option<Self::Msg>> {
        match reader.0.pop_front() {
            Some(Step::Binary(data)) => Ok(Some(MockMsg::Binary(data))),
            Some(Step::Reset) => Err(anyhow!("connection reset without closing handshake")),
            // Script exhausted: the client stream ended without a Close
            // frame, which the relay reads as end-of-stream.
            None => Ok(None),
        }
    }

    async fn send(_writer: &mut Self::Writer, _msg: Self::Msg) -> Result<()> {
        Ok(())
    }

    async fn finish(_writer: &mut Self::Writer) {}

    async fn flush(_writer: &mut Self::Writer) -> Result<()> {
        Ok(())
    }

    fn is_h3() -> bool {
        false
    }

    fn classify(msg: Self::Msg) -> WsFrame {
        match msg {
            MockMsg::Binary(data) => WsFrame::Binary(data),
            // The script never feeds control frames inbound.
            MockMsg::Ctrl => WsFrame::Pong,
        }
    }

    fn binary_msg(data: Bytes) -> Self::Msg {
        MockMsg::Binary(data)
    }
    fn close_msg() -> Self::Msg {
        MockMsg::Ctrl
    }
    fn close_try_again_msg() -> Self::Msg {
        MockMsg::Ctrl
    }
    fn ping_msg() -> Self::Msg {
        MockMsg::Ctrl
    }
    fn pong_msg(_payload: Bytes) -> Self::Msg {
        MockMsg::Ctrl
    }
    fn binary_len(msg: &Self::Msg) -> Option<usize> {
        match msg {
            MockMsg::Binary(data) => Some(data.len()),
            MockMsg::Ctrl => None,
        }
    }
    fn msg_len(msg: &Self::Msg) -> usize {
        match msg {
            MockMsg::Binary(data) => data.len(),
            MockMsg::Ctrl => 0,
        }
    }
    fn make_udp_response_sender(
        _tx: mpsc::Sender<Self::Msg>,
        _protocol: Protocol,
        _app_protocol: AppProtocol,
        _scheme: PaddingScheme,
        _monitor: Option<Arc<super::super::throughput_monitor::ThroughputMonitor>>,
    ) -> UdpResponseSender {
        unimplemented!("the tcp relay never builds a udp response sender")
    }
}

/// Upstream that accepts connections and then goes silent forever: it never
/// writes, never reads and never closes. Models the idle-but-open targets
/// (database, SSH, long-poll, idle gRPC) against which an orphaned
/// upstream→client reader can wait indefinitely.
async fn spawn_silent_upstream() -> Result<(SocketAddr, AbortOnDrop<()>)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let mut accepted = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            accepted.push(stream);
        }
    });
    Ok((addr, AbortOnDrop::new(task)))
}

fn test_user() -> Result<UserKey> {
    Ok(UserKey::new("bob", "secret-b", None, CipherKind::Chacha20IetfPoly1305, None)?)
}

/// Session-resumption is left disabled so `try_park_on_drop` bails out
/// immediately and the teardown takes the non-park branch.
fn test_contexts(user: &UserKey) -> (WsTcpServerCtx, WsTcpRouteCtx) {
    let metrics = Metrics::new(&sample_config((Ipv4Addr::LOCALHOST, 3000).into()));
    let server = WsTcpServerCtx {
        metrics: Arc::clone(&metrics),
        dns_cache: DnsCache::new(Duration::from_secs(60)),
        prefer_ipv4_upstream: false,
        outbound_ipv6: None,
        orphan_registry: Arc::new(OrphanRegistry::new_disabled(metrics)),
        ws_data_channel_capacity: 8,
    };
    let route = WsTcpRouteCtx {
        users: Arc::from(vec![user.clone()]),
        protocol: Protocol::Http1,
        path: Arc::from("/tcp"),
        candidate_users: Arc::from(vec![user.id_arc()]),
        peer_user_cache: Arc::new(PeerUserCache::new(
            NonZeroUsize::new(16).expect("non-zero capacity"),
        )),
        padding: PaddingScheme::disabled(),
    };
    (server, route)
}

/// One SS-AEAD chunk carrying just the target address — the handshake that
/// makes the relay dial upstream and spawn the upstream→client task.
fn ss_handshake_frame(user: &UserKey, target: SocketAddr) -> Result<Bytes> {
    let plaintext = TargetAddr::from(target).to_wire_bytes()?;
    let mut encryptor = AeadStreamEncryptor::new(user, None)?;
    let mut buf = BytesMut::new();
    encryptor.encrypt_chunk(&plaintext, &mut buf)?;
    Ok(buf.freeze())
}

/// A client that vanishes mid-session without a Close frame makes `T::recv`
/// error, and the `?` unwinds `run_tcp_relay` past every teardown branch.
/// The spawned upstream→client task must still be cancelled: otherwise it
/// keeps the upstream socket and its `outbound_data_tx` clone alive against
/// a silent-but-open upstream, leaking a task plus two sockets per
/// disconnect with no upper bound.
#[tokio::test]
async fn client_reset_cancels_upstream_relay_task() -> Result<()> {
    let (upstream_addr, _upstream) = spawn_silent_upstream().await?;
    let user = test_user()?;
    let (server, route) = test_contexts(&user);
    let (writer_alive, writer_gone) = oneshot::channel();
    let socket = MockWs {
        steps: VecDeque::from_iter([
            Step::Binary(ss_handshake_frame(&user, upstream_addr)?),
            Step::Reset,
        ]),
        writer_alive,
    };
    let resume = ResumeContext::from_request_headers(&HeaderMap::new(), &server.orphan_registry);

    run_tcp_relay::<MockWs>(socket, &server, &route, resume, None, None)
        .await
        .expect_err("a client reset must surface as an error");

    // The writer task returns only once every clone of the outbound data
    // sender is gone, so its writer half being dropped is proof that the
    // relay task was cancelled rather than detached.
    tokio::time::timeout(Duration::from_secs(5), writer_gone)
        .await
        .map_err(|_| {
            anyhow!(
                "upstream→client relay task outlived the session: it still holds the \
                 outbound data channel open"
            )
        })?
        .ok();
    Ok(())
}

/// The client stream ends without a Close frame (`recv` → `Ok(None)`), so
/// teardown takes the non-park branch that joins the relay task. Against a
/// silent-but-open upstream that join never returns unless the relay is
/// asked to stop first, hanging the whole session future — and with it the
/// carrier task, the upstream socket and the writer task.
#[tokio::test]
async fn client_eof_without_close_does_not_hang_teardown() -> Result<()> {
    let (upstream_addr, _upstream) = spawn_silent_upstream().await?;
    let user = test_user()?;
    let (server, route) = test_contexts(&user);
    let (writer_alive, _writer_gone) = oneshot::channel();
    let socket = MockWs {
        steps: VecDeque::from_iter([Step::Binary(ss_handshake_frame(&user, upstream_addr)?)]),
        writer_alive,
    };
    let resume = ResumeContext::from_request_headers(&HeaderMap::new(), &server.orphan_registry);

    tokio::time::timeout(
        Duration::from_secs(5),
        run_tcp_relay::<MockWs>(socket, &server, &route, resume, None, None),
    )
    .await
    .map_err(|_| anyhow!("teardown hung joining the upstream→client relay task"))??;
    Ok(())
}
