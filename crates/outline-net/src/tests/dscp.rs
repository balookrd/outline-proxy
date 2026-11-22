#[cfg(unix)]
use std::net::{SocketAddr, TcpListener};
#[cfg(unix)]
use std::os::fd::AsRawFd;

use super::{MAX_DSCP, SocketMark, validate_dscp};
#[cfg(unix)]
use super::{bind_udp_socket, connect_tcp_socket};

#[test]
fn validate_dscp_accepts_valid_range_and_rejects_out_of_range() {
    assert_eq!(MAX_DSCP, 63);
    for valid in [0_u8, 59, 63] {
        assert!(validate_dscp(valid).is_ok(), "DSCP {valid} must be valid");
    }
    for invalid in [64_u8, 128, 255] {
        let err = validate_dscp(invalid).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("0..=63"), "unexpected error for {invalid}: {msg}");
    }
}

#[cfg(unix)]
fn get_sockopt_int(fd: &impl AsRawFd, level: libc::c_int, name: libc::c_int) -> libc::c_int {
    let mut val: libc::c_int = 0;
    let mut len = std::mem::size_of_val(&val) as libc::socklen_t;
    // SAFETY: `fd` borrows a live open socket descriptor for the syscall;
    // `val` and `len` point to valid initialized stack storage, and `len`
    // holds the byte capacity of `val` before the call. Return value is checked.
    let rc = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            level,
            name,
            &mut val as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    assert_eq!(rc, 0, "getsockopt({level}, {name}) failed: {}", std::io::Error::last_os_error());
    if len as usize == std::mem::size_of::<u8>() {
        // SAFETY: `getsockopt` reported writing 1 byte into the prefix of `val`.
        let byte = unsafe { *(&val as *const libc::c_int as *const u8) };
        libc::c_int::from(byte)
    } else {
        val
    }
}

#[cfg(unix)]
#[test]
fn ipv4_tcp_connect_applies_ip_tos_before_connect() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap();
    rt.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_handle = std::thread::spawn(move || listener.accept());

        let stream = connect_tcp_socket(addr, SocketMark::with_dscp(Some(59)))
            .await
            .expect("IPv4 TCP connect with DSCP=59 must succeed");
        let tos = get_sockopt_int(&stream, libc::IPPROTO_IP, libc::IP_TOS);
        assert_eq!(tos & 0xfc, 59 << 2, "expected DSCP 59 (0xec), got {tos:#x}");

        let _ = accept_handle.join().unwrap();
    });
}

#[cfg(unix)]
#[test]
fn ipv6_tcp_connect_applies_ipv6_tclass() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap();
    rt.block_on(async {
        let listener = match TcpListener::bind("[::1]:0") {
            Ok(l) => l,
            Err(_) => return,
        };
        let addr = listener.local_addr().unwrap();
        let accept_handle = std::thread::spawn(move || listener.accept());

        let stream = connect_tcp_socket(addr, SocketMark::with_dscp(Some(59)))
            .await
            .expect("IPv6 TCP connect with DSCP=59 must succeed");
        let tclass = get_sockopt_int(&stream, libc::IPPROTO_IPV6, libc::IPV6_TCLASS);
        assert_eq!(tclass & 0xfc, 59 << 2, "expected TCLASS 59 (0xec), got {tclass:#x}");

        let _ = accept_handle.join().unwrap();
    });
}

#[cfg(unix)]
#[test]
fn ipv4_udp_bind_applies_ip_tos() {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let sock = bind_udp_socket(addr, SocketMark::with_dscp(Some(59)))
        .expect("IPv4 UDP bind with DSCP=59 must succeed");
    let tos = get_sockopt_int(&sock, libc::IPPROTO_IP, libc::IP_TOS);
    assert_eq!(tos & 0xfc, 59 << 2, "expected IP_TOS 0xec, got {tos:#x}");
}

#[cfg(unix)]
#[test]
fn ipv6_dual_stack_udp_bind_applies_tclass_and_linux_v4_tos() {
    let addr: SocketAddr = "[::]:0".parse().unwrap();
    let sock = match bind_udp_socket(addr, SocketMark::with_dscp(Some(59))) {
        Ok(s) => s,
        Err(_) => return,
    };
    let tclass = get_sockopt_int(&sock, libc::IPPROTO_IPV6, libc::IPV6_TCLASS);
    assert_eq!(tclass & 0xfc, 59 << 2, "expected IPV6_TCLASS 0xec, got {tclass:#x}");

    #[cfg(target_os = "linux")]
    {
        let tos = get_sockopt_int(&sock, libc::IPPROTO_IP, libc::IP_TOS);
        assert_eq!(tos & 0xfc, 59 << 2, "expected dual-stack IP_TOS 0xec, got {tos:#x}");
    }
}

#[cfg(unix)]
#[test]
fn dscp_zero_and_none_keep_cs0_bits() {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let sock_zero = bind_udp_socket(addr, SocketMark::with_dscp(Some(0))).unwrap();
    let sock_none = bind_udp_socket(addr, SocketMark::default()).unwrap();
    assert_eq!(get_sockopt_int(&sock_zero, libc::IPPROTO_IP, libc::IP_TOS) & 0xfc, 0);
    assert_eq!(get_sockopt_int(&sock_none, libc::IPPROTO_IP, libc::IP_TOS) & 0xfc, 0);
}

#[cfg(unix)]
#[test]
fn dscp_above_63_is_rejected_before_bind_or_connect() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap();
    rt.block_on(async {
        let err =
            connect_tcp_socket("127.0.0.1:1".parse().unwrap(), SocketMark::with_dscp(Some(64)))
                .await
                .unwrap_err();
        assert!(format!("{err:#}").contains("0..=63"), "unexpected err: {err:#}");
    });

    let err = bind_udp_socket("127.0.0.1:0".parse().unwrap(), SocketMark::with_dscp(Some(64)))
        .unwrap_err();
    assert!(format!("{err:#}").contains("0..=63"), "unexpected err: {err:#}");
}
