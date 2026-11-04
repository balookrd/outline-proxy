use std::time::Duration;

use tokio::time::timeout;

use super::*;

/// Whether `admit` returns promptly, i.e. the POST fits the window now.
async fn fits(window: &Arc<UplinkWindow>, seq: u64) -> Option<WindowSlot> {
    timeout(Duration::from_millis(50), window.admit(seq)).await.ok()
}

/// The window stops the POST that would run `max_posts` seqs ahead of the
/// oldest unfinished one — the overrun that made the server tear the session
/// down.
#[tokio::test]
async fn blocks_the_post_that_runs_too_far_ahead() {
    let window = UplinkWindow::with_limit(4);
    let mut slots = Vec::new();
    for seq in 0..4 {
        slots.push(fits(&window, seq).await.expect("within the window"));
    }
    assert!(fits(&window, 4).await.is_none(), "seq 4 is 4 ahead of seq 0");
}

/// A stalled head keeps the window shut even when everything after it has
/// finished: the server still holds those later bodies, waiting for the head.
#[tokio::test]
async fn finished_posts_above_a_stalled_head_do_not_open_the_window() {
    let window = UplinkWindow::with_limit(4);
    let head = fits(&window, 0).await.unwrap();
    for seq in 1..4 {
        drop(fits(&window, seq).await.unwrap());
    }
    assert!(fits(&window, 4).await.is_none());
    drop(head);
    assert!(fits(&window, 4).await.is_some(), "the head finishing slides the window past 3");
}

/// A driver parked in `admit` wakes when the head finishes.
#[tokio::test]
async fn a_waiting_post_wakes_when_the_head_finishes() {
    let window = UplinkWindow::with_limit(1);
    let head = fits(&window, 0).await.unwrap();
    let waiter = tokio::spawn({
        let window = Arc::clone(&window);
        async move { window.admit(1).await }
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!waiter.is_finished());
    drop(head);
    timeout(Duration::from_secs(1), waiter).await.expect("woken").unwrap();
}

/// A POST task aborted mid-flight hands its slot back: the window is anchored
/// on live POSTs only, so an abort cannot wedge it shut.
#[tokio::test]
async fn an_aborted_post_frees_its_slot() {
    let window = UplinkWindow::with_limit(1);
    let holder = tokio::spawn({
        let window = Arc::clone(&window);
        async move {
            let _slot = window.admit(0).await;
            std::future::pending::<()>().await;
        }
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(fits(&window, 1).await.is_none(), "seq 1 waits behind the live seq 0");
    holder.abort();
    let _ = holder.await;
    assert!(fits(&window, 1).await.is_some(), "aborting the task drops the slot");
}
