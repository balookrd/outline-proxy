use std::time::Duration;

use super::*;

#[test]
fn the_phase_mark_reports_the_last_step_reached() {
    let mark = PhaseMark::new();
    assert_eq!(mark.get(), Phase::Queue);
    for phase in [Phase::Dial, Phase::Send, Phase::Read, Phase::Queue] {
        mark.set(phase);
        assert_eq!(mark.get(), phase);
    }
}

#[test]
fn a_stall_names_its_budget_and_step() {
    assert_eq!(
        format!("{:#}", stalled(Duration::from_millis(4900), Phase::Read)),
        "no answer within 4900 ms at read"
    );
    assert_eq!(
        format!("{:#}", stalled(Duration::from_millis(5000), Phase::Dial)),
        "no answer within 5000 ms at dial"
    );
    assert_eq!(Phase::Queue.to_string(), "queue");
    assert_eq!(Phase::Send.to_string(), "send");
}
