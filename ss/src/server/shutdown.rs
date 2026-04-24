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
mod tests {
    use std::time::Duration;

    use super::{ShutdownSignal, shutdown_channel};

    #[tokio::test]
    async fn cancelled_returns_after_sender_signals() {
        let (tx, mut rx) = shutdown_channel();
        let signal_task = tokio::spawn(async move { rx.cancelled().await });

        // Give the subscriber a moment to start awaiting before we flip the
        // flag — also verifies the task doesn't resolve early.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!signal_task.is_finished(), "signal fired before send");

        tx.send();
        signal_task.await.expect("signal task panicked");
    }

    #[tokio::test]
    async fn cancelled_returns_immediately_if_already_signalled() {
        let (tx, mut rx) = shutdown_channel();
        tx.send();

        // Second subscriber that never observed the transition still sees the
        // stored `true` via `borrow_and_update`.
        let mut late = rx.clone();
        tokio::time::timeout(Duration::from_millis(100), rx.cancelled())
            .await
            .expect("existing subscriber should observe stored signal");
        tokio::time::timeout(Duration::from_millis(100), late.cancelled())
            .await
            .expect("late subscriber should observe stored signal");
    }

    #[tokio::test]
    async fn all_subscribers_wake_once_signal_fires() {
        let (tx, rx) = shutdown_channel();
        let subscribers = (0..4)
            .map(|_| {
                let mut rx = rx.clone();
                tokio::spawn(async move { rx.cancelled().await })
            })
            .collect::<Vec<_>>();

        tokio::time::sleep(Duration::from_millis(20)).await;
        for task in &subscribers {
            assert!(!task.is_finished());
        }

        tx.send();
        for task in subscribers {
            tokio::time::timeout(Duration::from_millis(200), task)
                .await
                .expect("subscriber did not wake")
                .expect("subscriber task panicked");
        }
    }

    #[tokio::test]
    async fn never_signal_does_not_fire() {
        let mut never = ShutdownSignal::never();
        let elapsed = tokio::time::timeout(Duration::from_millis(50), never.cancelled()).await;
        assert!(elapsed.is_err(), "never-signal must not fire");
    }
}
