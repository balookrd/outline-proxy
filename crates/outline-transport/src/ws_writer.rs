//! Shared WebSocket writer task for `outline-transport`.
//!
//! Used by both `frame_io_ws` (VLESS byte-chunk and datagram pipes) and
//! `tcp_transport::writer::transport` (SS-over-WS / SS-over-XHTTP).

use std::pin::Pin;
use std::time::Duration;

use futures_util::{Sink, SinkExt};
use outline_net::time::CoverTimer;
use outline_wire::padding_frames::CoverParams;
use tokio::sync::{mpsc, watch};
use tokio::time::{Sleep, sleep};
use tokio_tungstenite::tungstenite::Error as WsError;
use tokio_tungstenite::tungstenite::protocol::Message;

use crate::AbortOnDrop;
use crate::carrier_queue::{self, BudgetedSender};
use crate::ws_writer_diag::{KIND_COVER, KIND_CTRL, KIND_DATA, send_or_report};

/// Control frames are tiny and rare (Ping/Pong/Close); a deeper queue would
/// only delay close propagation.
const WS_CTRL_CHANNEL_CAPACITY: usize = 8;

/// Configuration for [`spawn_ws_writer`].
pub(crate) struct WsWriterOptions {
    /// Idle cover traffic parameters; `None` disables cover frames.
    pub cover: Option<CoverParams>,
    /// Optional hold window for coalescing an initial header (`held_tx`) with
    /// the first binary data frame. When `None`, `held_tx` is not created.
    pub hold_header: Option<Duration>,
    /// Diagnostic writer label (`WRITER_SS` or `WRITER_FRAME`).
    pub diag_writer: &'static str,
    /// When `true`, receiving `Message::Close(_)` on `data_rx` closes the sink
    /// and stops the writer task (used by `WsDatagramChannel::close`).
    pub stop_on_data_close_frame: bool,
}

/// Handles returned by [`spawn_ws_writer`].
pub(crate) struct WsWriterHandles {
    pub task: AbortOnDrop,
    pub data_tx: BudgetedSender<Message>,
    pub ctrl_tx: mpsc::Sender<Message>,
    pub held_tx: Option<mpsc::Sender<Vec<u8>>>,
    pub exit_rx: watch::Receiver<bool>,
}

/// Signals that the writer task has stopped, whichever way it stopped: a clean
/// Close, a write error, or an abort from [`AbortOnDrop`] when the carrier is
/// dropped. Held inside the task, so the notification is tied to the task's
/// future being dropped rather than to any one exit path.
struct WriterExit(watch::Sender<bool>);

impl Drop for WriterExit {
    fn drop(&mut self) {
        self.0.send_replace(true);
    }
}

/// Moves any header already buffered in `held_rx` into `held`.
fn take_pending_held(held_rx: &mut Option<mpsc::Receiver<Vec<u8>>>, held: &mut Option<Vec<u8>>) {
    let Some(rx) = held_rx.as_mut() else {
        return;
    };
    while let Ok(h) = rx.try_recv() {
        held.get_or_insert_with(Vec::new).extend_from_slice(&h);
    }
}

/// Sends the held SS2022 header (if any) as its own message.
async fn flush_held<S>(
    ws_sink: &mut S,
    held: &mut Option<Vec<u8>>,
    diag_writer: &'static str,
) -> bool
where
    S: Sink<Message, Error = WsError> + Unpin,
{
    match held.take() {
        Some(h) => send_or_report(ws_sink, Message::Binary(h.into()), diag_writer, KIND_DATA).await,
        None => true,
    }
}

async fn recv_held(held_rx: &mut Option<mpsc::Receiver<Vec<u8>>>) -> Option<Vec<u8>> {
    held_rx.as_mut()?.recv().await
}

async fn wait_hold(hold_sleep: &mut Option<Pin<Box<Sleep>>>) {
    if let Some(sleep) = hold_sleep.as_mut() {
        sleep.as_mut().await;
    }
}

/// Spawns the WebSocket writer loop over `sink`.
pub(crate) fn spawn_ws_writer<S>(sink: S, options: WsWriterOptions) -> WsWriterHandles
where
    S: Sink<Message, Error = WsError> + Unpin + Send + 'static,
{
    let (data_tx, mut data_rx) = carrier_queue::channel::<Message>();
    let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<Message>(WS_CTRL_CHANNEL_CAPACITY);
    let (held_tx, mut held_rx) = match options.hold_header {
        Some(_) => {
            let (tx, rx) = mpsc::channel::<Vec<u8>>(1);
            (Some(tx), Some(rx))
        },
        None => (None, None),
    };
    let (exit_tx, exit_rx) = watch::channel(false);
    let task = tokio::spawn(async move {
        let _exit = WriterExit(exit_tx);
        let mut ws_sink = sink;
        let mut ctrl_open = true;
        let mut held: Option<Vec<u8>> = None;
        let mut hold_sleep: Option<Pin<Box<Sleep>>> = None;
        let mut cover = CoverTimer::new(options.cover);

        loop {
            tokio::select! {
                biased;
                // First, so a header queued together with a control message
                // is always in `held` (and flushed) before that message.
                h = recv_held(&mut held_rx), if held_rx.is_some() => match h {
                    Some(h) => match &mut held {
                        Some(existing) => existing.extend_from_slice(&h),
                        None => {
                            held = Some(h);
                            if let Some(dur) = options.hold_header {
                                hold_sleep = Some(Box::pin(sleep(dur)));
                            }
                        },
                    },
                    None => held_rx = None,
                },
                msg = ctrl_rx.recv(), if ctrl_open => match msg {
                    Some(m) => {
                        take_pending_held(&mut held_rx, &mut held);
                        hold_sleep = None;
                        if !flush_held(&mut ws_sink, &mut held, options.diag_writer).await {
                            return;
                        }
                        if !send_or_report(&mut ws_sink, m, options.diag_writer, KIND_CTRL).await {
                            return;
                        }
                        cover.rearm();
                    },
                    None => ctrl_open = false,
                },
                msg = data_rx.recv() => match msg {
                    Some(queued) => {
                        // The byte permit lives until the frame reaches the
                        // sink — see `carrier_queue`.
                        let (m, permit) = queued.into_parts();
                        if options.stop_on_data_close_frame && matches!(m, Message::Close(_)) {
                            take_pending_held(&mut held_rx, &mut held);
                            let _ = flush_held(&mut ws_sink, &mut held, options.diag_writer).await;
                            let _ = ws_sink.close().await;
                            return;
                        }
                        // Ordering invariant: the producer finishes the
                        // `held_tx` send before it sends on `data_tx`, so a
                        // header preceding this message is already buffered
                        // in `held_rx` even if the select did not see it.
                        take_pending_held(&mut held_rx, &mut held);
                        hold_sleep = None;
                        let m = match (held.take(), m) {
                            (Some(mut h), Message::Binary(p)) => {
                                h.extend_from_slice(&p);
                                Message::Binary(h.into())
                            },
                            (Some(h), m) => {
                                if !send_or_report(
                                    &mut ws_sink,
                                    Message::Binary(h.into()),
                                    options.diag_writer,
                                    KIND_DATA,
                                )
                                .await
                                {
                                    return;
                                }
                                m
                            },
                            (None, m) => m,
                        };
                        if !send_or_report(&mut ws_sink, m, options.diag_writer, KIND_DATA).await {
                            return;
                        }
                        drop(permit);
                        cover.rearm();
                    },
                    None => {
                        take_pending_held(&mut held_rx, &mut held);
                        let _ = flush_held(&mut ws_sink, &mut held, options.diag_writer).await;
                        let _ = ws_sink.close().await;
                        return;
                    },
                },
                _ = wait_hold(&mut hold_sleep), if hold_sleep.is_some() => {
                    hold_sleep = None;
                    if !flush_held(&mut ws_sink, &mut held, options.diag_writer).await {
                        return;
                    }
                    cover.rearm();
                },
                // Never ahead of a held header: the hold timer flushes it first.
                _ = cover.wait(), if cover.is_enabled() && held.is_none() => {
                    if let Some(frame) = cover.frame()
                        && !send_or_report(
                            &mut ws_sink,
                            Message::Binary(frame),
                            options.diag_writer,
                            KIND_COVER,
                        )
                        .await
                    {
                        return;
                    }
                    cover.rearm();
                },
            }
        }
    });

    WsWriterHandles {
        task: AbortOnDrop::new(task),
        data_tx,
        ctrl_tx,
        held_tx,
        exit_rx,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};

    use futures_util::Sink;
    use tokio::time::Duration;
    use tokio_tungstenite::tungstenite::Error as WsError;
    use tokio_tungstenite::tungstenite::protocol::Message;

    use super::{WsWriterOptions, spawn_ws_writer};
    use crate::ws_writer_diag::WRITER_SS;

    #[derive(Clone, Default)]
    struct MockSink {
        sent: Arc<Mutex<VecDeque<Message>>>,
        closed: Arc<Mutex<bool>>,
    }

    impl Sink<Message> for MockSink {
        type Error = WsError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
            self.sent.lock().unwrap().push_back(item);
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            *self.closed.lock().unwrap() = true;
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn held_header_coalesces_with_first_binary_message() {
        let sink = MockSink::default();
        let sent = sink.sent.clone();
        let mut handles = spawn_ws_writer(
            sink,
            WsWriterOptions {
                cover: None,
                hold_header: Some(Duration::from_millis(50)),
                diag_writer: WRITER_SS,
                stop_on_data_close_frame: false,
            },
        );

        let held_tx = handles.held_tx.take().expect("held_tx must be Some");
        held_tx.send(b"HDR".to_vec()).await.unwrap();
        handles
            .data_tx
            .send(Message::Binary(b"BODY".to_vec().into()), 4)
            .await
            .unwrap();

        drop(held_tx);
        drop(handles.data_tx);
        let _ = handles.exit_rx.wait_for(|&exited| exited).await;

        let items = sent.lock().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0], Message::Binary(b"HDRBODY".to_vec().into()));
    }

    #[tokio::test(start_paused = true)]
    async fn held_header_flushes_after_hold_timeout() {
        let sink = MockSink::default();
        let sent = sink.sent.clone();
        let mut handles = spawn_ws_writer(
            sink,
            WsWriterOptions {
                cover: None,
                hold_header: Some(Duration::from_millis(50)),
                diag_writer: WRITER_SS,
                stop_on_data_close_frame: false,
            },
        );

        let held_tx = handles.held_tx.take().expect("held_tx must be Some");
        held_tx.send(b"HDR".to_vec()).await.unwrap();

        tokio::task::yield_now().await;
        assert!(sent.lock().unwrap().is_empty());

        tokio::time::advance(Duration::from_millis(50)).await;
        tokio::task::yield_now().await;

        {
            let items = sent.lock().unwrap();
            assert_eq!(items.len(), 1);
            assert_eq!(items[0], Message::Binary(b"HDR".to_vec().into()));
        }

        drop(held_tx);
        drop(handles.data_tx);
        let _ = handles.exit_rx.wait_for(|&exited| exited).await;
    }

    #[tokio::test]
    async fn exit_rx_notifies_and_sink_closes_on_data_close_or_drop() {
        let sink = MockSink::default();
        let closed = sink.closed.clone();
        let mut handles = spawn_ws_writer(
            sink,
            WsWriterOptions {
                cover: None,
                hold_header: None,
                diag_writer: WRITER_SS,
                stop_on_data_close_frame: true,
            },
        );
        assert!(handles.held_tx.is_none());

        handles.data_tx.send_control(Message::Close(None)).await.unwrap();
        let _ = handles.exit_rx.wait_for(|&exited| exited).await;
        assert!(*closed.lock().unwrap());
    }
}
