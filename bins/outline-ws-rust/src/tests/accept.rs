use super::*;

use std::time::Duration;

use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(5);

/// With every connection slot taken, the accept loop must still observe
/// shutdown: parking on the semaphore alone would keep SIGTERM unnoticed until
/// some in-flight connection happens to finish.
#[tokio::test]
async fn permit_wait_yields_to_shutdown_when_saturated() {
    let conn_sem = Arc::new(Semaphore::new(1));
    let held = Arc::clone(&conn_sem).acquire_owned().await.unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let waiter = {
        let conn_sem = Arc::clone(&conn_sem);
        let mut shutdown_rx = shutdown_rx.clone();
        tokio::spawn(async move {
            acquire_permit_or_shutdown(&conn_sem, &mut shutdown_rx)
                .await
                .is_some()
        })
    };
    // Let the waiter park on the exhausted semaphore before shutdown fires.
    tokio::task::yield_now().await;
    shutdown_tx.send(true).unwrap();

    let got_permit = timeout(WAIT, waiter)
        .await
        .expect("waiting for a slot must not outlive shutdown")
        .unwrap();
    assert!(!got_permit, "shutdown must win over an exhausted semaphore");
    drop(held);
}

/// The shutdown race must not steal the normal path: a slot freed by a
/// finishing connection is still handed to the waiting accept loop.
#[tokio::test]
async fn permit_wait_returns_the_slot_once_freed() {
    let conn_sem = Arc::new(Semaphore::new(1));
    let held = Arc::clone(&conn_sem).acquire_owned().await.unwrap();
    // Keep the sender alive for the whole test: a dropped sender resolves
    // `changed()` with an error, which would look like shutdown.
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);

    let waiter = {
        let conn_sem = Arc::clone(&conn_sem);
        let mut shutdown_rx = shutdown_rx.clone();
        tokio::spawn(async move {
            acquire_permit_or_shutdown(&conn_sem, &mut shutdown_rx)
                .await
                .is_some()
        })
    };
    tokio::task::yield_now().await;
    drop(held);

    let got_permit = timeout(WAIT, waiter)
        .await
        .expect("a freed slot must be handed over promptly")
        .unwrap();
    assert!(got_permit, "a freed slot must still be acquired");
}
