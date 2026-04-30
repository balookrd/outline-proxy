use super::*;

mod proxy_protocol;

#[test]
fn h3_no_error_through_sockudo_io_other_is_benign() {
    // Reproduces the production cause chain: h3 ConnectionError stringified
    // into io::Error::other, then wrapped as sockudo_ws::Error::Io, then
    // anyhow-contexted by ws_socket.rs.
    let h3_msg = "Connection error: Remote error: ApplicationClose: H3_NO_ERROR";
    let io = std::io::Error::other(h3_msg.to_string());
    let sockudo = sockudo_ws::Error::Io(io);
    let err = anyhow::Error::from(sockudo).context("websocket receive failure");

    assert_eq!(classify_error(&err), Some(BenignClose::H3NoError));
    assert!(is_normal_h3_shutdown(&err));
    assert!(is_expected_ws_close(&err));
}
