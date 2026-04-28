use std::time::Duration;

use super::*;
use tokio::sync::Notify;

struct DropSignal {
    notify: std::sync::Arc<Notify>,
}

impl Drop for DropSignal {
    fn drop(&mut self) {
        self.notify.notify_one();
    }
}

#[tokio::test]
async fn drive_tcp_session_tasks_aborts_uplink_when_downlink_finishes_first() {
    let uplink_dropped = std::sync::Arc::new(Notify::new());
    let uplink_dropped_clone = std::sync::Arc::clone(&uplink_dropped);
    let uplink = async move {
        let _drop_signal = DropSignal { notify: uplink_dropped_clone };
        std::future::pending::<Result<UplinkOutcome, anyhow::Error>>().await
    };
    let downlink = async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        Ok::<(), anyhow::Error>(())
    };

    tokio::time::timeout(Duration::from_secs(1), drive_tcp_session_tasks(uplink, downlink, None, Arc::from("test"), Duration::from_secs(30)))
        .await
        .expect("driver should return once downlink finishes")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), uplink_dropped.notified())
        .await
        .expect("uplink should be dropped when downlink wins");
}

#[tokio::test]
async fn drive_tcp_session_tasks_waits_for_downlink_after_socket_half_close() {
    let downlink_completed = std::sync::Arc::new(Notify::new());
    let downlink_completed_clone = std::sync::Arc::clone(&downlink_completed);
    let uplink =
        async move { Ok::<UplinkOutcome, anyhow::Error>(UplinkOutcome::Finished) };
    let downlink = async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        downlink_completed_clone.notify_one();
        Ok::<(), anyhow::Error>(())
    };

    tokio::time::timeout(Duration::from_secs(1), drive_tcp_session_tasks(uplink, downlink, None, Arc::from("test"), Duration::from_secs(30)))
        .await
        .expect("driver should wait for downlink after client EOF")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), downlink_completed.notified())
        .await
        .expect("downlink should be allowed to finish");
}

#[tokio::test]
async fn drive_tcp_session_tasks_idle_watcher_fires_and_aborts_both_tasks() {
    let uplink_dropped = std::sync::Arc::new(Notify::new());
    let downlink_dropped = std::sync::Arc::new(Notify::new());
    let uplink_dropped_clone = std::sync::Arc::clone(&uplink_dropped);
    let downlink_dropped_clone = std::sync::Arc::clone(&downlink_dropped);
    let uplink = async move {
        let _drop_signal = DropSignal { notify: uplink_dropped_clone };
        std::future::pending::<Result<UplinkOutcome, anyhow::Error>>().await
    };
    let downlink = async move {
        let _drop_signal = DropSignal { notify: downlink_dropped_clone };
        std::future::pending::<Result<(), anyhow::Error>>().await
    };

    // Activity channel is never signalled, so the watcher must fire and
    // abort both stalled tasks.  The senders are kept alive inside the
    // data tasks' closures (they only drop when the tasks are aborted),
    // mirroring how `serve_tcp_connect` wires them in.
    let (activity_tx, activity_rx) = mpsc::unbounded_channel::<()>();
    let _uplink_tx = activity_tx.clone();
    let _downlink_tx = activity_tx.clone();
    drop(activity_tx);

    tokio::time::timeout(
        Duration::from_secs(1),
        drive_tcp_session_tasks(
            uplink,
            downlink,
            Some(IdleGuard::new(activity_rx, Duration::from_millis(30))),
            Arc::from("test"),
            Duration::from_secs(30),
        ),
    )
    .await
    .expect("driver should return once the idle watcher fires")
    .unwrap();
    tokio::time::timeout(Duration::from_secs(1), uplink_dropped.notified())
        .await
        .expect("uplink should be dropped when idle fires");
    tokio::time::timeout(Duration::from_secs(1), downlink_dropped.notified())
        .await
        .expect("downlink should be dropped when idle fires");
}

#[tokio::test]
async fn drive_tcp_session_tasks_activity_resets_idle_deadline() {
    let (activity_tx, activity_rx) = mpsc::unbounded_channel::<()>();
    let uplink_tx = activity_tx.clone();
    let downlink_tx = activity_tx.clone();
    drop(activity_tx);

    let uplink = async move {
        // Signal activity every 20 ms for 200 ms, then finish.  Keeps
        // the 50 ms idle deadline alive so the watcher cannot fire.
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let _ = uplink_tx.send(());
        }
        Ok::<UplinkOutcome, anyhow::Error>(UplinkOutcome::Finished)
    };
    let downlink = async move {
        tokio::time::sleep(Duration::from_millis(210)).await;
        drop(downlink_tx);
        Ok::<(), anyhow::Error>(())
    };

    tokio::time::timeout(
        Duration::from_secs(1),
        drive_tcp_session_tasks(
            uplink,
            downlink,
            Some(IdleGuard::new(activity_rx, Duration::from_millis(50))),
            Arc::from("test"),
            Duration::from_secs(30),
        ),
    )
    .await
    .expect("driver should return once tasks finish naturally")
    .unwrap();
}

#[tokio::test]
async fn drive_tcp_session_tasks_aborts_downlink_after_websocket_client_eof() {
    let downlink_dropped = std::sync::Arc::new(Notify::new());
    let downlink_dropped_clone = std::sync::Arc::clone(&downlink_dropped);
    let uplink =
        async move { Ok::<UplinkOutcome, anyhow::Error>(UplinkOutcome::CloseSession) };
    let downlink = async move {
        let _drop_signal = DropSignal { notify: downlink_dropped_clone };
        std::future::pending::<Result<(), anyhow::Error>>().await
    };

    tokio::time::timeout(Duration::from_secs(1), drive_tcp_session_tasks(uplink, downlink, None, Arc::from("test"), Duration::from_secs(30)))
        .await
        .expect("driver should return once websocket-backed client EOF is observed")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), downlink_dropped.notified())
        .await
        .expect("downlink should be aborted after websocket-backed client EOF");
}
