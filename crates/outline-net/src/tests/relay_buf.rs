//! Read-buffer policy: a relay loop must reuse one allocation while the flow is
//! busy, hand it back while the flow is idle, cover a full-size datagram on
//! every datagram read, and never size a small stream read at the protocol
//! maximum.

use std::net::SocketAddr;
use std::time::Duration;

use socket2::{Domain, Protocol as SocketProtocol, SockAddr, Socket, Type};
use tokio::net::UdpSocket;

use super::{RelayReadBuf, STREAM_INITIAL_READ_CAPACITY};

/// Largest datagram an IPv4 UDP socket can deliver (65_535 - 20 IP - 8 UDP).
const MAX_DATAGRAM: usize = 65_507;
const STREAM_MAX: usize = 64 * 1024;

/// Loopback UDP socket with socket buffers wide enough for a max-size datagram.
/// macOS defaults both to 9216 bytes and rejects anything larger with
/// `EMSGSIZE`, so the sizing has to be explicit for the truncation test to
/// exercise the real wire path on every platform.
fn bind_wide_udp() -> UdpSocket {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(SocketProtocol::UDP)).expect("socket");
    socket.set_send_buffer_size(1 << 20).expect("sndbuf");
    socket.set_recv_buffer_size(1 << 20).expect("rcvbuf");
    let addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
    socket.bind(&SockAddr::from(addr)).expect("bind");
    socket.set_nonblocking(true).expect("nonblocking");
    UdpSocket::from_std(std::net::UdpSocket::from(socket)).expect("tokio socket")
}

async fn recv_once(socket: &UdpSocket, buf: &mut RelayReadBuf) -> usize {
    loop {
        buf.park(socket.readable()).await.expect("readable");
        match socket.try_recv_buf_from(buf.ready()) {
            Ok((len, _)) => return len,
            Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(error) => panic!("recv failed: {error}"),
        }
    }
}

#[tokio::test]
async fn fixed_buffer_carries_a_max_size_datagram_after_reuse() {
    let receiver = bind_wide_udp();
    let sender = bind_wide_udp();
    let recv_addr = receiver.local_addr().expect("receiver addr");

    let mut buf = RelayReadBuf::fixed(MAX_DATAGRAM);

    // A small datagram first, so the max-size one below lands in a buffer that
    // is being REUSED — the case where a naive `clear()` could leave a short
    // window behind and truncate the datagram.
    sender.send_to(b"small", recv_addr).await.expect("send small");
    let len = recv_once(&receiver, &mut buf).await;
    assert_eq!(&buf.filled()[..len], b"small");
    let reused = buf.filled().as_ptr();

    let big = vec![0xa5u8; MAX_DATAGRAM];
    let sent = sender.send_to(&big, recv_addr).await.expect("send max-size datagram");
    assert_eq!(sent, MAX_DATAGRAM);

    let len = recv_once(&receiver, &mut buf).await;
    assert_eq!(len, MAX_DATAGRAM, "max-size datagram was truncated");
    assert_eq!(buf.filled(), &big[..]);
    assert_eq!(buf.filled().as_ptr(), reused, "the busy loop must reuse one allocation");
}

#[tokio::test]
async fn fixed_buffer_keeps_the_full_window_after_a_small_read() {
    let mut buf = RelayReadBuf::fixed(MAX_DATAGRAM);

    let slot = buf.ready();
    assert!(slot.capacity() >= MAX_DATAGRAM);
    slot.extend_from_slice(&[7u8; 100]);
    let first = buf.filled().as_ptr();

    // Next datagram must still see room for the maximum, from the same
    // allocation.
    let slot = buf.ready();
    assert!(slot.capacity() >= MAX_DATAGRAM);
    assert_eq!(slot.as_ptr(), first);
    assert_eq!(buf.read_capacity(), MAX_DATAGRAM);
}

#[tokio::test]
async fn adaptive_buffer_starts_small_and_grows_only_on_saturated_reads() {
    let mut buf = RelayReadBuf::adaptive(STREAM_INITIAL_READ_CAPACITY, STREAM_MAX);
    assert_eq!(buf.read_capacity(), STREAM_INITIAL_READ_CAPACITY);

    // A small read neither grows the window nor allocates the protocol maximum.
    buf.ready().extend_from_slice(&[1u8; 120]);
    assert_eq!(buf.read_capacity(), STREAM_INITIAL_READ_CAPACITY);
    assert!(buf.allocated() < STREAM_MAX);

    // A read that fills the window doubles it for the next iteration, and keeps
    // doubling up to the ceiling.
    let mut expected = STREAM_INITIAL_READ_CAPACITY;
    while expected < STREAM_MAX {
        let window = buf.read_capacity();
        let slot = buf.ready();
        slot.resize(window, 0);
        expected = (window * 2).min(STREAM_MAX);
        assert_eq!(buf.read_capacity(), window, "growth applies on the next ready()");
        assert_eq!(buf.ready().capacity(), expected);
    }

    // At the ceiling a saturated read no longer grows the window.
    let slot = buf.ready();
    slot.resize(STREAM_MAX, 0);
    assert_eq!(buf.ready().capacity(), STREAM_MAX);
    assert_eq!(buf.read_capacity(), STREAM_MAX);
}

#[tokio::test]
async fn idle_park_releases_the_buffer_and_still_completes() {
    let mut buf = RelayReadBuf::adaptive(STREAM_INITIAL_READ_CAPACITY, STREAM_MAX)
        .with_idle_grace(Duration::from_millis(20));

    // Grow the window past its initial size, then hold a live allocation.
    let slot = buf.ready();
    slot.resize(STREAM_INITIAL_READ_CAPACITY, 0);
    buf.ready().extend_from_slice(b"x");
    assert!(buf.allocated() > 0);
    assert!(buf.read_capacity() > STREAM_INITIAL_READ_CAPACITY);

    let ready = async {
        tokio::time::sleep(Duration::from_millis(80)).await;
        Ok::<(), std::io::Error>(())
    };
    buf.park(ready).await.expect("readiness must survive the release");

    assert_eq!(buf.allocated(), 0, "an idle park must hand the buffer back");
    assert_eq!(
        buf.read_capacity(),
        STREAM_INITIAL_READ_CAPACITY,
        "a released buffer re-learns its window from the initial size"
    );
    assert!(buf.ready().capacity() >= STREAM_INITIAL_READ_CAPACITY);
}

#[tokio::test]
async fn busy_park_keeps_the_buffer() {
    let mut buf = RelayReadBuf::fixed(4096).with_idle_grace(Duration::from_millis(200));
    buf.ready().extend_from_slice(b"x");
    let allocation = buf.filled().as_ptr();

    let ready = async {
        tokio::time::sleep(Duration::from_millis(5)).await;
        Ok::<(), std::io::Error>(())
    };
    buf.park(ready).await.expect("ready");

    assert_eq!(buf.allocated(), 4096);
    assert_eq!(buf.ready().as_ptr(), allocation, "a busy park must not reallocate");
}
