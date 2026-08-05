//! The wire loop's contract, which is easy to get subtly wrong in two ways:
//! a failure *after* the dial (the SS handshake, say) must retire the wire
//! just as a failed dial does, and exhausting the chain must surface one
//! error without any intermediate parent-level runtime failure — otherwise
//! one broken carrier flaps the whole uplink out of the candidate set.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Result, anyhow};
use tracing::field::{Field, Visit};
use tracing::subscriber::Interest;
use tracing::{Event, Level, Metadata, Subscriber, span};

use crate::manager::wire_dial::WireAttempt;
use crate::types::TransportKind;

use super::{sample_manager_with_no_fallbacks, sample_manager_with_three_fallbacks};

#[tokio::test]
async fn a_build_failure_advances_the_chain_just_like_a_dial_failure() {
    let manager = sample_manager_with_three_fallbacks().await;
    let candidate = manager.tcp_candidates_for_test(0).await;
    let attempts = Arc::new(AtomicUsize::new(0));

    let seen = Arc::clone(&attempts);
    let result: Result<(u8, u8)> = manager
        .dial_over_wires(&candidate, TransportKind::Tcp, true, move |wire| {
            let seen = Arc::clone(&seen);
            async move {
                seen.fetch_add(1, Ordering::SeqCst);
                if wire == 3 {
                    Ok(WireAttempt::Built(wire))
                } else {
                    // Stands in for an SS handshake that fails after a
                    // perfectly successful dial.
                    Err(anyhow!("handshake failed on wire {wire}"))
                }
            }
        })
        .await;

    let (value, wire) = result.expect("wire 3 succeeds");
    assert_eq!(value, 3);
    assert_eq!(wire, 3, "the winning wire is reported to the caller");
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        4,
        "every wire is tried once, in order, until one builds"
    );
}

#[tokio::test]
async fn exhausting_every_wire_yields_one_error() {
    let manager = sample_manager_with_three_fallbacks().await;
    let candidate = manager.tcp_candidates_for_test(0).await;

    let result: Result<(u8, u8)> = manager
        .dial_over_wires(&candidate, TransportKind::Tcp, true, |wire| async move {
            Err(anyhow!("wire {wire} is down"))
        })
        .await;

    let error = result.expect_err("no wire can build");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("all wires failed"),
        "the caller needs one error it can attribute to the uplink, got: {rendered}"
    );
}

#[tokio::test]
async fn a_single_wire_failure_carries_no_all_wires_failed_wrapper() {
    // Gate-off (and any uplink with no fallbacks) only ever attempts wire 0,
    // so its failure must surface exactly as it did before this loop existed
    // — not wrapped in a context meant for a genuine multi-wire exhaustion.
    // That wrapper doubles the uplink name into the error text and, worse,
    // becomes the metric `detail` label (see
    // `normalize_other_runtime_failure_detail`), burying the real cause.
    let manager = sample_manager_with_three_fallbacks().await;
    let candidate = manager.tcp_candidates_for_test(0).await;

    let result: Result<(u8, u8)> = manager
        .dial_over_wires(&candidate, TransportKind::Tcp, false, |wire| async move {
            Err(anyhow!("wire {wire} is down"))
        })
        .await;

    let error = result.expect_err("the only wire tried fails");
    let rendered = format!("{error:#}");
    assert_eq!(
        rendered, "wire 0 is down",
        "a single-wire attempt must not gain the multi-wire wrapper, got: {rendered}"
    );
}

#[tokio::test]
async fn a_not_applicable_wire_is_skipped_without_recording_an_outcome() {
    let manager = sample_manager_with_three_fallbacks().await;
    let candidate = manager.tcp_candidates_for_test(0).await;

    let (value, wire) = manager
        .dial_over_wires(&candidate, TransportKind::Tcp, true, |wire| async move {
            if wire == 0 {
                Ok(WireAttempt::NotApplicable)
            } else {
                Ok(WireAttempt::Built(wire))
            }
        })
        .await
        .expect("a later wire builds");

    assert_eq!(value, wire);
    assert_ne!(wire, 0);
    assert_eq!(
        manager.wire_outcome_count_for_test(0, TransportKind::Tcp, 0),
        0,
        "a wire that never ran must not move its own state machine"
    );
}

#[tokio::test]
async fn gate_off_records_no_outcome_even_on_failure() {
    // `tun_wire_dial` off means a node is deployed inert: it must be able to
    // fail its only attempt (wire 0) without touching the shared active-wire
    // state machine, because the SOCKS ingress on the same `UplinkManager`
    // reads that state when it builds its own dial order. If gate-off wrote
    // outcomes, a flag documented as inert would change SOCKS's behaviour.
    let manager = sample_manager_with_three_fallbacks().await;
    let candidate = manager.tcp_candidates_for_test(0).await;

    let result: Result<(u8, u8)> = manager
        .dial_over_wires(&candidate, TransportKind::Tcp, false, |wire| async move {
            Err(anyhow!("wire {wire} is down"))
        })
        .await;

    result.expect_err("the only wire tried fails");
    assert_eq!(
        manager.wire_outcome_count_for_test(0, TransportKind::Tcp, 0),
        0,
        "gate-off must not record any outcome, even a failure on wire 0"
    );
}

/// Every `WARN`-level event's message, captured while the current thread
/// holds a [`capture_warnings`] guard.
#[derive(Clone, Default)]
struct RecordedWarnings(Arc<Mutex<Vec<String>>>);

impl RecordedWarnings {
    fn count(&self) -> usize {
        self.0.lock().unwrap().len()
    }
}

struct MessageVisitor(String);

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }
}

std::thread_local! {
    /// Which test on *this* thread wants `WARN`-level events routed to it, if
    /// any. Per-thread, not a single shared slot: the standard test harness
    /// runs multiple `#[tokio::test]`s concurrently on separate OS threads
    /// (a `#[tokio::test]` body runs entirely on the one thread that polls
    /// it, since the default runtime flavor is `current_thread`), and each
    /// test's capture must only ever see events from its own dial attempt.
    static CAPTURING: std::cell::RefCell<Option<RecordedWarnings>> =
        const { std::cell::RefCell::new(None) };
}

/// A single, process-wide `Subscriber`, installed once via
/// `set_global_default`, that routes `WARN`-level events to whichever
/// thread's [`CAPTURING`] slot is currently set.
///
/// The crate has no existing seam for asserting on log output, so this is
/// built directly on `tracing`'s core `Subscriber` trait. It is deliberately
/// process-global rather than the more obvious per-test
/// `tracing::subscriber::set_default`: `tracing-core` caches each callsite's
/// `Interest` (always/sometimes/never) globally, and the very first time a
/// callsite fires, it resolves that cache by asking the *firing* thread's
/// *own* ambient dispatcher — not the dispatcher of whichever thread
/// installed a subscriber. This file's other multi-wire tests
/// (`a_build_failure_advances_the_chain_just_like_a_dial_failure`,
/// `exhausting_every_wire_yields_one_error`) also hit this crate's `warn!`
/// callsite once the predicate below fires for them, and they run with no
/// subscriber of their own. Under `cargo test`'s default parallelism, one of
/// those could be the first caller to touch the callsite while running
/// concurrently with a per-test scoped dispatcher on a different thread —
/// resolving interest against its own no-op ambient dispatcher and caching
/// the callsite as permanently uninteresting, silently dropping the event on
/// *every* thread afterwards, including the one actually capturing. (This
/// was observed directly: a per-test `tracing::subscriber::set_default`
/// version of this fixture passed reliably alone but flaked under `cargo
/// test`'s full parallel run.) A single global subscriber sidesteps this
/// because `tracing-core` only ever sees one dispatcher registered in the
/// whole process, so its fast path resolves to it unconditionally, on any
/// thread, in any order.
struct GlobalCapturingSubscriber;

impl Subscriber for GlobalCapturingSubscriber {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= &Level::WARN
    }

    // Belt-and-suspenders alongside being the only-ever-registered
    // dispatcher (see the struct docs): forces every event at every callsite
    // to re-check `enabled()` dynamically rather than trusting a cached
    // always/never verdict.
    fn register_callsite(&self, _metadata: &'static Metadata<'static>) -> Interest {
        Interest::sometimes()
    }

    fn new_span(&self, _span: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }

    fn record(&self, _span: &span::Id, _values: &span::Record<'_>) {}

    fn record_follows_from(&self, _span: &span::Id, _follows: &span::Id) {}

    fn event(&self, event: &Event<'_>) {
        if event.metadata().level() != &Level::WARN {
            return;
        }
        CAPTURING.with(|slot| {
            if let Some(recorder) = slot.borrow().as_ref() {
                let mut visitor = MessageVisitor(String::new());
                event.record(&mut visitor);
                recorder.0.lock().unwrap().push(visitor.0);
            }
        });
    }

    fn enter(&self, _span: &span::Id) {}

    fn exit(&self, _span: &span::Id) {}
}

static INSTALL_GLOBAL_CAPTURE: std::sync::Once = std::sync::Once::new();

/// Start capturing this thread's `WARN`-level events. Returns the recorder
/// together with a guard that stops capturing on drop; hold the guard for the
/// duration of the call under test.
///
/// Installs [`GlobalCapturingSubscriber`] as the process's global default on
/// first use — safe under concurrent callers since `Once` makes the install
/// idempotent and blocks until whichever caller wins has finished, and
/// nothing else in this crate's test binary calls `set_global_default` (a
/// second call would return `Err` and leave that other subscriber in place,
/// silently defeating capture — see the struct docs for why this shape
/// exists at all).
fn capture_warnings() -> (RecordedWarnings, impl Drop) {
    INSTALL_GLOBAL_CAPTURE.call_once(|| {
        let _ = tracing::subscriber::set_global_default(GlobalCapturingSubscriber);
    });
    let recorder = RecordedWarnings::default();
    CAPTURING.with(|slot| *slot.borrow_mut() = Some(recorder.clone()));

    struct ClearOnDrop;
    impl Drop for ClearOnDrop {
        fn drop(&mut self) {
            CAPTURING.with(|slot| *slot.borrow_mut() = None);
        }
    }

    (recorder, ClearOnDrop)
}

#[tokio::test]
async fn single_wire_uplink_stays_silent_on_dial_failure_even_with_fallbacks_allowed() {
    // Pins the fix to the finding in final-review-fixes.md: the predicate
    // must be `allow_fallbacks && multi_wire`, not `allow_fallbacks` alone.
    // The deleted per-ingress SOCKS loops (`e464d917`) had an explicit
    // `total_wires == 1` short-circuit that logged nothing at all — a
    // single-wire uplink emitting a `warn!` on every failed dial would be a
    // brand-new noise source with no prior existence to dedupe against.
    let manager = sample_manager_with_no_fallbacks().await;
    let candidate = manager.tcp_candidates_for_test(0).await;
    let (recorded, _guard) = capture_warnings();

    let result: Result<(u8, u8)> = manager
        .dial_over_wires(&candidate, TransportKind::Tcp, true, |wire| async move {
            Err(anyhow!("wire {wire} is down"))
        })
        .await;

    result.expect_err("the only wire fails");
    assert_eq!(
        recorded.count(),
        0,
        "a single-wire uplink must not gain a warning the old SOCKS short-circuit never emitted"
    );
}

#[tokio::test]
async fn multi_wire_uplink_warns_once_per_failed_wire_with_fallbacks_allowed() {
    // The other half of the same pin: a genuine multi-wire chain must keep
    // the operator-facing `warn!` this loop restored, one line per failed
    // wire, so a wire that fails every dial is not invisible in the journal.
    let manager = sample_manager_with_three_fallbacks().await;
    let candidate = manager.tcp_candidates_for_test(0).await;
    let (recorded, _guard) = capture_warnings();

    let result: Result<(u8, u8)> = manager
        .dial_over_wires(&candidate, TransportKind::Tcp, true, |wire| async move {
            Err(anyhow!("wire {wire} is down"))
        })
        .await;

    result.expect_err("no wire can build");
    assert_eq!(recorded.count(), 4, "each of the four wires must warn once on its failed dial");
}
