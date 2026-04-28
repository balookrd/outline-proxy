//! Cooperative shutdown signalling for listener/accept loops.
//!
//! A [`ShutdownSender`] is created once in [`super::run`] and the OS signal
//! handler flips it on SIGTERM/SIGINT. Every `serve_*` function gets its own
//! [`ShutdownSignal`] (a `watch` receiver) and calls [`ShutdownSignal::cancelled`]
//! inside a `select!` so accept loops exit promptly without killing
//! already-established connections.
//!
//! Tests that exercise a single `serve_*` helper can use
//! [`ShutdownSignal::never`] to opt out of cancellation.

use tokio::sync::watch;
use tracing::info;

/// Sends the one-shot "please shut down" notification to every subscriber.
pub(crate) struct ShutdownSender {
    tx: watch::Sender<bool>,
}

impl ShutdownSender {
    pub(crate) fn send(&self) {
        // `send` only fails if no receivers remain, which means nothing is
        // listening — safe to ignore.
        let _ = self.tx.send(true);
    }
}

/// A cloneable handle used by accept loops to observe shutdown.
#[derive(Clone)]
pub(crate) struct ShutdownSignal {
    rx: watch::Receiver<bool>,
}

impl ShutdownSignal {
    /// Signal that never fires. Intended for tests of individual `serve_*`
    /// helpers that don't exercise the graceful-shutdown path.
    #[cfg(test)]
    pub(crate) fn never() -> Self {
        let (tx, rx) = watch::channel(false);
        // Leak the sender so the channel is never closed (closed channel would
        // make `changed()` return immediately).
        Box::leak(Box::new(tx));
        Self { rx }
    }

    /// Resolves when shutdown has been requested. Cheap to `.await` repeatedly —
    /// once triggered, subsequent awaits return immediately.
    pub(crate) async fn cancelled(&mut self) {
        // Already signalled (possibly before we subscribed).
        if *self.rx.borrow_and_update() {
            return;
        }
        // Wait until the sender flips the value. If the sender is dropped we
        // treat that as "shutdown" as well — the server is clearly going away.
        while self.rx.changed().await.is_ok() {
            if *self.rx.borrow_and_update() {
                return;
            }
        }
    }
}

pub(crate) fn shutdown_channel() -> (ShutdownSender, ShutdownSignal) {
    let (tx, rx) = watch::channel(false);
    (ShutdownSender { tx }, ShutdownSignal { rx })
}

/// Blocks until SIGTERM/SIGINT (Unix) or Ctrl-C (Windows) is delivered.
pub(crate) async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(error) => {
                tracing::warn!(?error, "failed to install SIGTERM handler");
                let _ = tokio::signal::ctrl_c().await;
                info!("received Ctrl-C, starting graceful shutdown");
                return;
            },
        };
        let mut sigint = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(error) => {
                tracing::warn!(?error, "failed to install SIGINT handler");
                let _ = tokio::signal::ctrl_c().await;
                info!("received Ctrl-C, starting graceful shutdown");
                return;
            },
        };
        tokio::select! {
            _ = sigterm.recv() => info!("received SIGTERM, starting graceful shutdown"),
            _ = sigint.recv()  => info!("received SIGINT, starting graceful shutdown"),
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        info!("received Ctrl-C, starting graceful shutdown");
    }
}

#[cfg(test)]
#[path = "tests/shutdown.rs"]
mod tests;
