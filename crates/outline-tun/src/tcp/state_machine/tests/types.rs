use crate::tcp::tests::tcp_flow_state_for_tests;

/// In a debug build — where this crate's tests normally run — discharging more
/// pending downlink bytes than were charged is a loud drift signal, not a quiet
/// clamp. Keeping the `debug_assert` is the point: the clamp underneath it is a
/// release-only backstop, so it must not mask an accounting bug in tests.
#[cfg(debug_assertions)]
#[tokio::test]
#[should_panic(expected = "discharging more pending downlink bytes than were charged")]
async fn discharging_more_than_charged_trips_the_debug_assert() {
    let mut state = tcp_flow_state_for_tests().await;
    state.charge_pending_server(4);
    state.discharge_pending_server(10);
}

/// The release half of the pair above: with overflow checks and the
/// `debug_assert` compiled out, an over-discharge must clamp at zero instead of
/// wrapping `pending_server_bytes_total` to ~2^64. A wrapped total would report
/// an absurd downlink backlog for the flow and — through the engine-wide budget
/// it mirrors into — gate every new flow on the engine.
#[cfg(not(debug_assertions))]
#[tokio::test]
async fn discharging_more_than_charged_clamps_the_flow_total_and_the_global_budget() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let mut state = tcp_flow_state_for_tests().await;
    let global = Arc::new(AtomicUsize::new(1000));
    state.pending_budget_global = Some(Arc::clone(&global));

    state.charge_pending_server(4);
    state.discharge_pending_server(10);

    assert_eq!(state.pending_server_bytes_total, 0, "the flow total must clamp at zero");
    assert_eq!(
        global.load(Ordering::Relaxed),
        1000,
        "the engine-wide budget may only give back what this flow charged"
    );
}
