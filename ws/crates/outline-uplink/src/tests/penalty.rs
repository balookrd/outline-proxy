use std::time::Duration;

use super::update_rtt_ewma;

#[test]
fn rtt_ewma_smooths_new_samples() {
    let mut current = Some(Duration::from_millis(100));
    update_rtt_ewma(&mut current, Some(Duration::from_millis(300)), 0.25);
    assert_eq!(current, Some(Duration::from_millis(150)));
}
