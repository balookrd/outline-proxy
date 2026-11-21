use super::*;
use tokio::io::AsyncReadExt;

/// `reject_tcp_connection` must send a SOCKS5 REP=0x02 (not allowed) reply and
/// return `Ok(())` without forwarding any data.
#[tokio::test]
async fn reject_tcp_connection_sends_not_allowed_reply() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let connect_fut = tokio::net::TcpStream::connect(addr);
    let accept_fut = listener.accept();
    let (connect_res, accept_res) = tokio::join!(connect_fut, accept_fut);
    let mut client_side = connect_res.unwrap();
    let (server_side, _) = accept_res.unwrap();

    let target = TargetAddr::IpV4("1.2.3.4".parse().unwrap(), 80);
    reject_tcp_connection(server_side, &target).await.unwrap();

    // SOCKS5 reply: VER REP RSV ATYP(IPv4) ADDR(4) PORT(2) = 10 bytes
    let mut reply = [0u8; 10];
    client_side.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 5, "VER must be 5");
    assert_eq!(reply[1], SOCKS_REP_NOT_ALLOWED, "REP must be 0x02 (not allowed)");
    assert_eq!(reply[2], 0, "RSV must be 0");
    assert_eq!(reply[3], 1, "ATYP must be 1 (IPv4)");
}
