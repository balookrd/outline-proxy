//! Tests for the pure client-start shaping decision in [`crate::ws_stream`].

use super::shapes_client_start_for;
use crate::xhttp::XhttpSubmode;

#[test]
fn plain_ws_carriers_shape_the_client_start() {
    // Http1 / H2 carry no XHTTP submode.
    assert!(shapes_client_start_for(false, None));
}

#[test]
fn h3_never_shapes() {
    assert!(!shapes_client_start_for(true, None));
    // XHTTP over h3 is h3 too, whatever the submode.
    assert!(!shapes_client_start_for(true, Some(XhttpSubmode::StreamOne)));
    assert!(!shapes_client_start_for(true, Some(XhttpSubmode::PacketUp)));
}

#[test]
fn xhttp_packet_up_does_not_shape() {
    assert!(!shapes_client_start_for(false, Some(XhttpSubmode::PacketUp)));
}

#[test]
fn xhttp_stream_one_on_tcp_shapes() {
    assert!(shapes_client_start_for(false, Some(XhttpSubmode::StreamOne)));
}
