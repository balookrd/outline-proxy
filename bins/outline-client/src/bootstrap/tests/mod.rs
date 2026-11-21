use outline_transport::FingerprintProfileStrategy as Fp;

use super::any_process_stable;

#[test]
fn global_process_stable_applies_to_uplinks_without_override() {
    assert!(any_process_stable(Fp::ProcessStable, [None]));
}

#[test]
fn per_uplink_override_enables_process_stable_under_a_different_global() {
    assert!(any_process_stable(Fp::None, [None, Some(Fp::ProcessStable)]));
}

#[test]
fn overrides_can_turn_off_a_process_stable_global() {
    assert!(!any_process_stable(Fp::ProcessStable, [Some(Fp::None), Some(Fp::Random)]));
}

#[test]
fn no_uplinks_means_no_process_stable_scope() {
    assert!(!any_process_stable(Fp::ProcessStable, []));
}
