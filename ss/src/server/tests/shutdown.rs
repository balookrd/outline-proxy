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
