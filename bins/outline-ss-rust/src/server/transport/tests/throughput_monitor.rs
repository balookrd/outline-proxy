use super::{ThrottleDetectParams, ThroughputMonitor, window_is_throttled};
use std::sync::atomic::Ordering;

fn params_on() -> ThrottleDetectParams {
    ThrottleDetectParams {
        enabled: true,
        ratio: 2.0,
        min_in_bytes_per_sec: 1_000_000,
        ..ThrottleDetectParams::default()
    }
}

#[test]
fn disabled_never_triggers() {
    let p = ThrottleDetectParams { enabled: false, ..params_on() };
    // Even an egregious throttle is ignored when the feature is off.
    assert!(!window_is_throttled(50_000_000, 0, true, &p));
}

#[test]
fn triggers_when_inbound_outruns_outbound_with_backlog() {
    let p = params_on();
    // 10 MB/s in, 1 MB/s out, backlog present → 10x ratio, well over 2x.
    assert!(window_is_throttled(10_000_000, 1_000_000, true, &p));
}

#[test]
fn no_trigger_without_backlog() {
    let p = params_on();
    // Same lopsided rates but no backlog: the client may simply have nothing
    // queued (e.g. a momentary read gap), not a throttle.
    assert!(!window_is_throttled(10_000_000, 1_000_000, false, &p));
}

#[test]
fn no_trigger_below_min_inbound_floor() {
    let p = params_on();
    // Inbound below the actionable floor: a slow flow, not worth a switch,
    // even with a lopsided ratio and backlog.
    assert!(!window_is_throttled(500_000, 1_000, true, &p));
}

#[test]
fn no_trigger_when_ratio_not_met() {
    let p = params_on();
    // 3 MB/s in vs 2 MB/s out = 1.5x, under the 2x bar.
    assert!(!window_is_throttled(3_000_000, 2_000_000, true, &p));
}

#[test]
fn zero_outbound_with_backlog_and_inbound_triggers() {
    let p = params_on();
    // Reading from the internet, nothing reaching the client, backlog present:
    // the strongest throttle signal.
    assert!(window_is_throttled(5_000_000, 0, true, &p));
}

#[test]
fn counters_accumulate() {
    let m = ThroughputMonitor::new(params_on());
    m.add_inbound(100);
    m.add_inbound(50);
    m.add_outbound(40);
    m.note_backlog();
    assert_eq!(m.in_bytes.load(Ordering::Relaxed), 150);
    assert_eq!(m.out_bytes.load(Ordering::Relaxed), 40);
    assert!(m.backlog_seen.swap(false, Ordering::Relaxed));
}
