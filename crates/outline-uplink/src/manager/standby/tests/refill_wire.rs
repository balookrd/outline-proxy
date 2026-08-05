//! What a warm-standby refill dials once the pool follows the active wire.
//!
//! `StandbyCtx` is built from a [`WireSpec`](crate::WireSpec) for the wire the
//! pool is prewarming, but for a while it still read the **parent** uplink for
//! three of the dial's inputs: the transport family, the routing mark and the
//! address-family preference. On a single-wire uplink the two are the same
//! object and nothing showed. On the fleet's own shape — VLESS primary, SS
//! fallbacks — they are not, and refill is the dominant dial producer
//! (~12.8k/day against ~2.9k from the TUN ingress itself), so every
//! consequence below repeats for as long as the pool sits on a fallback.

use outline_transport::DialNetworkOptions;

use crate::config::{TransportMode, UplinkTransport};
use crate::types::TransportKind;

use super::sample_manager_with_vless_primary_and_ss_fallback;

/// A silent carrier downgrade observed on a refill dial belongs to the wire
/// that dial was for. Reported against the parent-level entry point instead,
/// it caps **primary** — a carrier that never failed — for
/// `mode_downgrade_duration`, while the fallback wire's own descent slot stays
/// empty so `wire_is_at_carrier_floor` never reports it at floor and the
/// rotation gate is never released for it.
///
/// Both wires are configured at `xhttp_h3` here, which is what makes the
/// mis-park silent: the parent-level sanity check (same family, strictly lower
/// rank) passes just as happily against primary's configured mode as against
/// the fallback's, so nothing rejects the trigger — it simply lands in the
/// wrong slot.
#[tokio::test]
async fn a_refill_downgrade_caps_the_wire_it_dialed_not_primary() {
    let manager = sample_manager_with_vless_primary_and_ss_fallback().await;
    manager.test_set_active_wire(0, TransportKind::Tcp, 1);
    let ctx = manager.standby_ctx_for_test(0, TransportKind::Tcp).await;
    assert_eq!(
        ctx.wire, 1,
        "the pool follows the active wire, so this refill is dialing wire 1"
    );

    // What `connect_transport` reports when the dial was asked for `xhttp_h3`
    // and silently came back on `xhttp_h2`.
    ctx.note_dial_downgrade(TransportMode::XhttpH3);

    assert_eq!(
        manager.effective_tcp_mode_for_wire(0, 0).await,
        TransportMode::XhttpH3,
        "primary was never dialed and must not be capped by a fallback's downgrade",
    );
    assert_eq!(
        manager.effective_tcp_mode_for_wire(0, 1).await,
        TransportMode::XhttpH2,
        "the descent belongs to wire 1's own slot — an empty slot there also \
         strands the rotation gate below the carrier floor",
    );
}

/// The UDP counterpart of the family read, and the one where getting it wrong
/// corrupts traffic rather than just mis-parking a slot.
///
/// A pooled SS-UDP carrier must negotiate XHTTP datagram record framing at
/// dial time — the negotiation rides the request headers and cannot be added
/// afterwards. Keyed off the VLESS parent instead of the SS wire, the refill
/// pools a carrier with no record boundaries; `acquire_udp_on_wire` then takes
/// the SS branch, the wire tags match, the pop succeeds, and every datagram
/// reused off that carrier loses its framing with no protocol-level recovery.
#[tokio::test]
async fn a_udp_refill_on_an_ss_fallback_wire_negotiates_datagram_records() {
    let manager = sample_manager_with_vless_primary_and_ss_fallback().await;
    manager.test_set_active_wire(0, TransportKind::Udp, 1);
    let ctx = manager.standby_ctx_for_test(0, TransportKind::Udp).await;

    assert_eq!(ctx.wire, 1, "the UDP pool follows the active wire too");
    assert_eq!(
        ctx.wire_transport,
        UplinkTransport::Ss,
        "wire 1 is SS even though its parent is VLESS — that is the whole shape",
    );
    assert!(
        ctx.dial_datagram_records(),
        "an SS-UDP carrier pooled under a VLESS parent still has to negotiate \
         record framing, or every reused datagram loses its boundaries",
    );
}

/// The mirror: the VLESS primary's own UDP pool must keep opting out. A fix
/// that simply hard-coded `true` on the UDP plane would claim record framing
/// for a carrier that frames its own records.
#[tokio::test]
async fn a_udp_refill_on_the_vless_primary_does_not_ask_for_datagram_records() {
    let manager = sample_manager_with_vless_primary_and_ss_fallback().await;
    manager.test_set_active_wire(0, TransportKind::Udp, 0);
    let ctx = manager.standby_ctx_for_test(0, TransportKind::Udp).await;

    assert_eq!(ctx.wire, 0);
    assert!(
        !ctx.dial_datagram_records(),
        "VLESS frames its own records; asking for XHTTP record framing here \
         would claim a negotiation the parent path never makes",
    );
}

/// The remaining two wire-dependent dial inputs. They are not a corruption
/// bug like the two above — a fallback pinned to another egress simply gets
/// prewarmed out of the wrong interface — but they came from the same wrong
/// source, so they get the same cover: nothing on this path may read the
/// parent for a value the `WireSpec` carries.
#[tokio::test]
async fn a_refill_dials_with_the_wires_own_network_options() {
    let manager = sample_manager_with_vless_primary_and_ss_fallback().await;
    manager.test_set_active_wire(0, TransportKind::Tcp, 1);
    let ctx = manager.standby_ctx_for_test(0, TransportKind::Tcp).await;

    assert_eq!(
        ctx.dial_network_options(),
        DialNetworkOptions { fwmark: Some(0x12), ipv6_first: true },
        "wire 1 pins its own mark and prefers v6; the parent pins neither",
    );
}
