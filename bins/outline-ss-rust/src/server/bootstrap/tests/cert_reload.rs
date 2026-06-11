use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use tokio::time::{Duration, sleep};

use super::{ReloadTracker, fingerprint, spawn_cert_reloader};
use crate::server::shutdown::shutdown_channel;

/// Per-test scratch directory under the system temp dir. Unique per test
/// name and process so parallel test threads don't collide.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "outline-ss-cert-reload-{}-{}",
        name,
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn fingerprint_stable_when_unchanged() {
    let dir = scratch("fp-stable");
    let path = dir.join("cert.pem");
    std::fs::write(&path, b"contents").unwrap();
    let paths = vec![path];
    assert_eq!(fingerprint(&paths), fingerprint(&paths));
}

#[test]
fn fingerprint_changes_on_content_change() {
    let dir = scratch("fp-content");
    let path = dir.join("cert.pem");
    std::fs::write(&path, b"v1").unwrap();
    let paths = vec![path.clone()];
    let before = fingerprint(&paths);
    std::fs::write(&path, b"v2").unwrap();
    assert_ne!(before, fingerprint(&paths), "edited content must change the fingerprint");
}

#[test]
fn fingerprint_distinguishes_missing_file() {
    let dir = scratch("fp-missing");
    let present = dir.join("present.pem");
    let absent = dir.join("absent.pem");
    std::fs::write(&present, b"x").unwrap();
    let with_absent = fingerprint(&[present.clone(), absent.clone()]);
    std::fs::write(&absent, b"x").unwrap();
    let with_present = fingerprint(&[present, absent]);
    assert_ne!(with_absent, with_present, "a file appearing must change the fingerprint");
}

#[test]
fn reload_tracker_skips_unchanged_state() {
    let mut tracker = ReloadTracker::new(1);
    assert!(!tracker.should_attempt(1), "baseline state is already live");
}

#[test]
fn reload_tracker_attempts_each_new_state_once() {
    let mut tracker = ReloadTracker::new(1);
    // A new state is attempted once...
    assert!(tracker.should_attempt(2));
    // ...but not re-attempted (no warn spam) until it changes again.
    assert!(!tracker.should_attempt(2));
    // A further change is attempted again.
    assert!(tracker.should_attempt(3));
}

#[test]
fn reload_tracker_marks_applied_to_avoid_reloading_live_state() {
    let mut tracker = ReloadTracker::new(1);
    assert!(tracker.should_attempt(2));
    tracker.mark_applied(2);
    assert!(!tracker.should_attempt(2), "the now-live state must not reload again");
    // Reverting to a state that was never applied is still picked up.
    assert!(tracker.should_attempt(1));
}

#[tokio::test]
async fn reloader_fires_once_per_change_and_stays_quiet_otherwise() {
    let dir = scratch("loop-fire");
    let path = dir.join("cert.pem");
    std::fs::write(&path, b"v1").unwrap();

    let calls = Arc::new(AtomicUsize::new(0));
    let calls_inner = Arc::clone(&calls);
    let (tx, rx) = shutdown_channel();

    spawn_cert_reloader("test", vec![path.clone()], Duration::from_millis(50), rx, move || {
        calls_inner.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });

    // No change yet → no reload.
    sleep(Duration::from_millis(180)).await;
    assert_eq!(calls.load(Ordering::SeqCst), 0, "must not reload an unchanged file");

    // Change → exactly one reload.
    std::fs::write(&path, b"v2").unwrap();
    sleep(Duration::from_millis(250)).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1, "a change triggers a single reload");

    // Still no further change → no further reloads.
    sleep(Duration::from_millis(250)).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1, "a stable file does not re-reload");

    tx.send();
}

#[tokio::test]
async fn reloader_retries_after_a_failed_reload() {
    let dir = scratch("loop-retry");
    let path = dir.join("cert.pem");
    std::fs::write(&path, b"good-1").unwrap();

    let ok = Arc::new(AtomicUsize::new(0));
    let err = Arc::new(AtomicUsize::new(0));
    let ok_inner = Arc::clone(&ok);
    let err_inner = Arc::clone(&err);
    let watched = path.clone();
    let (tx, rx) = shutdown_channel();

    // Simulates a half-written rotation: the reload fails while the file
    // holds "bad" and succeeds again once it settles on a good value.
    spawn_cert_reloader("test", vec![path.clone()], Duration::from_millis(50), rx, move || {
        if std::fs::read(&watched).unwrap_or_default() == b"bad" {
            err_inner.fetch_add(1, Ordering::SeqCst);
            anyhow::bail!("simulated bad cert/key pair");
        }
        ok_inner.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });

    // Let the watcher capture "good-1" as its baseline before we mutate
    // the file, mirroring production where startup loads the files first.
    sleep(Duration::from_millis(120)).await;

    // First change lands a bad pair: reload is attempted and fails once.
    std::fs::write(&path, b"bad").unwrap();
    sleep(Duration::from_millis(250)).await;
    assert_eq!(err.load(Ordering::SeqCst), 1, "bad state is attempted exactly once");
    assert_eq!(ok.load(Ordering::SeqCst), 0);

    // Rotation completes: the watcher must recover and apply the good pair.
    std::fs::write(&path, b"good-2").unwrap();
    sleep(Duration::from_millis(250)).await;
    assert_eq!(ok.load(Ordering::SeqCst), 1, "watcher recovers once the files settle");
    assert_eq!(err.load(Ordering::SeqCst), 1, "the bad state is not retried/spammed");

    tx.send();
}
