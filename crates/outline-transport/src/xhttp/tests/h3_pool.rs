use super::{XHTTP_H3_CARRIER_CAP, XHTTP_H3_CARRIER_MAX, XHTTP_H3_CARRIER_MIN};
use crate::h3::choose_slot;

/// Slot loads for a pool where `open` carriers hold the given session counts
/// and the remaining slots are empty.
fn loads(open: &[u64]) -> Vec<Option<u64>> {
    let mut slots: Vec<Option<u64>> = open.iter().copied().map(Some).collect();
    slots.resize(XHTTP_H3_CARRIER_MAX as usize, None);
    slots
}

fn pick(open: &[u64]) -> u8 {
    choose_slot(&loads(open), XHTTP_H3_CARRIER_MIN, XHTTP_H3_CARRIER_CAP)
}

/// Below the floor, a session opens a new carrier even though an existing one
/// has room. Packing everything onto carrier 0 would mean one connection-level
/// collapse takes every session on the uplink with it.
#[test]
fn below_the_floor_a_new_carrier_is_opened() {
    assert_eq!(pick(&[]), 0, "an empty pool starts at slot 0");
    assert_eq!(pick(&[1]), 1, "one carrier is below MIN, so open the next slot");
}

/// At and above the floor, sessions pack onto the least-loaded carrier instead
/// of opening more. This is what makes the pool a memory win: each extra
/// carrier is another UDP socket and another 2.87 MiB receive buffer.
#[test]
fn at_the_floor_sessions_pack_onto_the_least_loaded_carrier() {
    assert_eq!(pick(&[5, 3]), 1, "slot 1 carries fewer sessions");
    assert_eq!(pick(&[3, 5]), 0, "and the other way round");
}

/// Once every open carrier is at CAP, growth resumes — otherwise a busy uplink
/// would pile unbounded sessions onto a fixed number of connections.
#[test]
fn a_full_pool_grows_until_max() {
    let full = XHTTP_H3_CARRIER_CAP;
    assert_eq!(pick(&[full, full]), 2, "both at CAP, so open a third carrier");
    assert_eq!(
        pick(&[full - 1, full]),
        0,
        "a carrier still under CAP takes the session before a new one is opened"
    );
}

/// At MAX carriers, all of them full, the policy overflows onto the least
/// loaded rather than opening connection number MAX+1. The ceiling is the
/// whole point: unbounded connections is the behaviour this pool removes.
#[test]
fn at_max_the_pool_overflows_instead_of_growing() {
    let mut open = vec![XHTTP_H3_CARRIER_CAP; XHTTP_H3_CARRIER_MAX as usize];
    open[3] = XHTTP_H3_CARRIER_CAP + 7;
    let slots: Vec<Option<u64>> = open.iter().copied().map(Some).collect();

    let chosen = choose_slot(&slots, XHTTP_H3_CARRIER_MIN, XHTTP_H3_CARRIER_CAP);
    assert!(chosen < XHTTP_H3_CARRIER_MAX, "never picks a slot past the ceiling");
    assert_ne!(chosen, 3, "and never the most loaded carrier");
}
