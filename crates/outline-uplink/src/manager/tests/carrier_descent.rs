use outline_transport::TransportMode;

use super::*;

const ALL_MODES: [TransportMode; 6] = [
    TransportMode::WsH1,
    TransportMode::WsH2,
    TransportMode::WsH3,
    TransportMode::XhttpH1,
    TransportMode::XhttpH2,
    TransportMode::XhttpH3,
];

#[test]
fn descent_table_matches_the_documented_chains() {
    assert_eq!(one_step_down(TransportMode::WsH3), Some(TransportMode::WsH2));
    assert_eq!(one_step_down(TransportMode::WsH2), Some(TransportMode::WsH1));
    assert_eq!(one_step_down(TransportMode::XhttpH3), Some(TransportMode::XhttpH2));
    assert_eq!(one_step_down(TransportMode::XhttpH2), Some(TransportMode::XhttpH1));
    assert_eq!(one_step_down(TransportMode::WsH1), None);
    assert_eq!(one_step_down(TransportMode::XhttpH1), None);
}

#[test]
fn walk_up_table_matches_the_documented_chains() {
    assert_eq!(one_step_up(TransportMode::WsH1), Some(TransportMode::WsH2));
    assert_eq!(one_step_up(TransportMode::WsH2), Some(TransportMode::WsH3));
    assert_eq!(one_step_up(TransportMode::XhttpH1), Some(TransportMode::XhttpH2));
    assert_eq!(one_step_up(TransportMode::XhttpH2), Some(TransportMode::XhttpH3));
    // Family tops have nothing higher.
    assert_eq!(one_step_up(TransportMode::WsH3), None);
    assert_eq!(one_step_up(TransportMode::XhttpH3), None);
}

#[test]
fn descent_stays_in_family_and_strictly_lowers_rank() {
    for mode in ALL_MODES {
        if let Some(next) = one_step_down(mode) {
            assert!(family(next) == family(mode), "descent must not change family");
            assert!(rank(next) < rank(mode), "descent must strictly lower rank");
        }
    }
}

#[test]
fn walk_up_stays_in_family_and_strictly_raises_rank() {
    for mode in ALL_MODES {
        if let Some(next) = one_step_up(mode) {
            assert!(family(next) == family(mode), "walk-up must not change family");
            assert!(rank(next) > rank(mode), "walk-up must strictly raise rank");
        }
    }
}

#[test]
fn floor_predicate_matches_descent_exhaustion() {
    for mode in ALL_MODES {
        assert_eq!(is_carrier_floor_mode(mode), one_step_down(mode).is_none());
    }
    assert!(is_carrier_floor_mode(TransportMode::WsH1));
    assert!(is_carrier_floor_mode(TransportMode::XhttpH1));
    assert!(!is_carrier_floor_mode(TransportMode::WsH3));
}

#[test]
fn every_descent_is_reversible_within_the_ws_and_xhttp_chains() {
    // Walking down then up returns to the starting carrier for every
    // in-family step.
    for mode in ALL_MODES {
        if let Some(down) = one_step_down(mode) {
            assert_eq!(one_step_up(down), Some(mode));
        }
    }
}
