use std::sync::mpsc;
use std::time::Duration;

/// The `/proc` walk behind the process sampler must run on the blocking pool,
/// not on a runtime worker.
///
/// Proof without timing luck: on a current-thread runtime the collector blocks
/// until an ordinary async task hands it a token. That token can only arrive if
/// the runtime thread is free to poll that task — i.e. if the collector is not
/// sitting on it. An inline collector deadlocks here until the recv times out.
#[tokio::test(flavor = "current_thread")]
async fn blocking_collector_leaves_the_runtime_free_to_poll_tasks() {
    let (token_tx, token_rx) = mpsc::channel::<()>();
    let async_task = tokio::spawn(async move {
        let _ = token_tx.send(());
    });

    let progressed =
        super::collect_off_runtime(move || token_rx.recv_timeout(Duration::from_secs(5)).is_ok())
            .await;

    assert_eq!(
        progressed,
        Some(true),
        "runtime made no progress while the /proc collector ran — collector is not offloaded"
    );
    async_task.await.expect("async task panicked");
}

/// Offloading must not change what the sampler observes: the snapshot published
/// after the `.await` carries the same fields a direct call would produce.
#[tokio::test(flavor = "current_thread")]
async fn offloaded_snapshot_matches_a_direct_sample() {
    let direct = crate::memory::sample_process_memory();
    let offloaded = super::collect_off_runtime(crate::memory::sample_process_memory)
        .await
        .expect("blocking sampler task must not fail");

    assert_eq!(offloaded.heap_mode, direct.heap_mode);
    assert_eq!(offloaded.rss_bytes.is_some(), direct.rss_bytes.is_some());
    assert_eq!(offloaded.virtual_bytes.is_some(), direct.virtual_bytes.is_some());
    assert_eq!(offloaded.thread_count.is_some(), direct.thread_count.is_some());
    assert_eq!(offloaded.fd_snapshot.is_some(), direct.fd_snapshot.is_some());
}
