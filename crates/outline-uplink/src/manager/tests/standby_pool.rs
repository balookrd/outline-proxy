//! Refill-gate state machine.
//!
//! The gate exists to collapse the burst of refill tasks a pool take used to
//! spawn (one per popped entry, stale ones included). Its two rules pull in
//! opposite directions and are tested here in isolation: coalesce while a task
//! is *queued*, but never swallow a request that arrives once the task has
//! started working — that request's slot would otherwise stay empty until the
//! 15 s maintenance sweep.

use super::super::standby_pool::RefillGate;

#[test]
fn gate_coalesces_requests_while_a_task_is_queued() {
    let gate = RefillGate::new();

    assert!(gate.try_claim(), "the first request must spawn a task");
    assert!(!gate.try_claim(), "a second request must fold into the queued task");
    assert!(!gate.try_claim(), "and so must every further one");
    assert_eq!(gate.spawned(), 1, "the burst must collapse into a single spawn");
}

#[test]
fn gate_admits_a_fresh_task_once_the_queued_one_starts() {
    let gate = RefillGate::new();

    assert!(gate.try_claim());
    // The task released the claim as its first action: it is now running and may
    // already have sampled the pool length, so a take that drains a slot from
    // here on has to be able to queue its own refill.
    gate.release();

    assert!(gate.try_claim(), "a request arriving after the task started must spawn");
    assert_eq!(gate.spawned(), 2);
}
