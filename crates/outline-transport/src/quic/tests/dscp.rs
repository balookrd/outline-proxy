use std::mem::{self, MaybeUninit};
#[cfg(target_os = "linux")]
use std::net::{IpAddr, Ipv4Addr};
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;

use outline_net::{SocketMark, bind_udp_socket};
use quinn::udp::{EcnCodepoint, Transmit, UdpSocketState};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

#[repr(C)]
struct AlignedCtrl {
    _align: [libc::cmsghdr; 0],
    bytes: [u8; 256],
}

fn set_recv_tos(sock: &UdpSocket, is_ipv4: bool) {
    let on: libc::c_int = 1;
    let (level, name) = if is_ipv4 {
        (libc::IPPROTO_IP, libc::IP_RECVTOS)
    } else {
        (libc::IPPROTO_IPV6, libc::IPV6_RECVTCLASS)
    };
    // SAFETY: `sock` owns an open UDP fd for this call; `on` is a valid
    // initialized `c_int` matching the `int` option expected by `IP_RECVTOS`
    // and `IPV6_RECVTCLASS`. Return value is asserted below.
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            level,
            name,
            &on as *const _ as *const libc::c_void,
            mem::size_of_val(&on) as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "setsockopt({level}, {name}) failed: {}", std::io::Error::last_os_error());
}

fn recv_packet_tos(sock: &UdpSocket) -> (usize, Option<u8>) {
    sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut payload = [0u8; 2048];
    let mut name = MaybeUninit::<libc::sockaddr_storage>::zeroed();
    let mut ctrl = AlignedCtrl { _align: [], bytes: [0u8; 256] };
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    // SAFETY: `libc::msghdr` is a plain C struct of integers and pointers;
    // zeroing initializes any platform-specific padding or extra fields.
    let mut hdr: libc::msghdr = unsafe { mem::zeroed() };
    hdr.msg_name = name.as_mut_ptr() as *mut libc::c_void;
    hdr.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    hdr.msg_iov = &mut iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = ctrl.bytes.as_mut_ptr() as *mut libc::c_void;
    hdr.msg_controllen = ctrl.bytes.len() as _;

    let n = loop {
        // SAFETY: `sock` owns a valid fd; `hdr`, `iov`, `name`, and `ctrl`
        // live on this stack frame with accurate lengths for the syscall.
        let rc = unsafe { libc::recvmsg(sock.as_raw_fd(), &mut hdr, 0) };
        if rc >= 0 {
            break rc as usize;
        }
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        panic!("recvmsg failed: {err}");
    };

    let mut tos: Option<u8> = None;
    let cmsg_hdr_len = mem::size_of::<libc::cmsghdr>();
    // SAFETY: `hdr` was just populated by `recvmsg` using the `AlignedCtrl`
    // buffer, so `CMSG_FIRSTHDR` and `CMSG_NXTHDR` iterate within `ctrl.bytes`.
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&hdr) };
    while !cmsg.is_null() {
        // SAFETY: `cmsg` is non-null and points inside `ctrl.bytes` as
        // validated by `CMSG_FIRSTHDR` / `CMSG_NXTHDR`.
        let header = unsafe { *cmsg };
        let data_len = (header.cmsg_len as usize).saturating_sub(cmsg_hdr_len);
        match (header.cmsg_level, header.cmsg_type) {
            (libc::IPPROTO_IP, libc::IP_TOS) | (libc::IPPROTO_IP, libc::IP_RECVTOS) => {
                // SAFETY: `CMSG_DATA(cmsg)` points to `data_len` initialized
                // payload bytes within the kernel-populated control buffer.
                let data = unsafe { libc::CMSG_DATA(cmsg) };
                if data_len >= mem::size_of::<libc::c_int>() {
                    // SAFETY: `data_len >= size_of::<c_int>()` ensures reading an
                    // unaligned `c_int` stays inside the control message payload.
                    let v = unsafe { std::ptr::read_unaligned(data as *const libc::c_int) };
                    tos = Some(v as u8);
                } else if data_len >= 1 {
                    // SAFETY: `data_len >= 1` ensures reading 1 byte is in bounds.
                    tos = Some(unsafe { *data });
                }
            },
            (libc::IPPROTO_IPV6, libc::IPV6_TCLASS) => {
                // SAFETY: `CMSG_DATA(cmsg)` points to `data_len` initialized
                // payload bytes within the kernel-populated control buffer.
                let data = unsafe { libc::CMSG_DATA(cmsg) };
                if data_len >= mem::size_of::<libc::c_int>() {
                    // SAFETY: `data_len >= size_of::<c_int>()` ensures reading an
                    // unaligned `c_int` stays inside the control message payload.
                    let v = unsafe { std::ptr::read_unaligned(data as *const libc::c_int) };
                    tos = Some(v as u8);
                } else if data_len >= 1 {
                    // SAFETY: `data_len >= 1` ensures reading 1 byte is in bounds.
                    tos = Some(unsafe { *data });
                }
            },
            _ => {},
        }
        // SAFETY: `cmsg` is a valid entry returned by `CMSG_FIRSTHDR`/`CMSG_NXTHDR`
        // for `hdr`, so advancing to the next control header stays bounded by `hdr`.
        cmsg = unsafe { libc::CMSG_NXTHDR(&hdr, cmsg) };
    }
    (n, tos)
}

fn dummy_quic_client_config() -> quinn::ClientConfig {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let _key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let mut client_tls = rustls::ClientConfig::builder()
        .with_root_certificates(Arc::new(roots))
        .with_no_client_auth();
    client_tls.alpn_protocols = vec![b"h3".to_vec()];
    let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap();
    quinn::ClientConfig::new(Arc::new(quic_tls))
}

fn send_quic_initial_and_capture_tos(
    bind_addr: SocketAddr,
    target_addr: SocketAddr,
    mark: SocketMark,
    receiver: &UdpSocket,
) -> u8 {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_io()
        .enable_time()
        .build()
        .unwrap();
    let client_sock = bind_udp_socket(bind_addr, mark).unwrap();
    let endpoint = rt.block_on(async {
        let runtime: Arc<dyn quinn::Runtime> = Arc::new(quinn::TokioRuntime);
        let udp = runtime.wrap_udp_socket(client_sock).unwrap();
        quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            udp,
            runtime,
        )
        .unwrap()
    });
    let client_config = dummy_quic_client_config();
    let connecting = rt
        .block_on(async { endpoint.connect_with(client_config, target_addr, "localhost") })
        .unwrap();
    rt.spawn(async move {
        let _ = connecting.await;
    });

    let (len, tos) = recv_packet_tos(receiver);
    endpoint.close(0u32.into(), b"done");
    drop(endpoint);
    assert!(len > 0, "expected non-empty QUIC Initial datagram");
    tos.expect("expected IP_TOS / IPV6_TCLASS ancillary cmsg from recvmsg")
}

#[test]
fn quic_ipv4_preserves_dscp_in_sendmsg_cmsg() {
    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    set_recv_tos(&receiver, true);
    let server_addr = receiver.local_addr().unwrap();

    let tos_marked = send_quic_initial_and_capture_tos(
        "127.0.0.1:0".parse().unwrap(),
        server_addr,
        SocketMark::with_dscp(Some(59)),
        &receiver,
    );
    assert_eq!(
        tos_marked >> 2,
        59,
        "QUIC Initial packet lost DSCP=59 (got tos={tos_marked:#x}, dscp={})",
        tos_marked >> 2
    );

    let receiver_default = UdpSocket::bind("127.0.0.1:0").unwrap();
    set_recv_tos(&receiver_default, true);
    let tos_default = send_quic_initial_and_capture_tos(
        "127.0.0.1:0".parse().unwrap(),
        receiver_default.local_addr().unwrap(),
        SocketMark::default(),
        &receiver_default,
    );
    assert_eq!(tos_default >> 2, 0, "expected default DSCP 0, got {tos_default:#x}");
}

#[test]
fn quic_ipv6_preserves_dscp_in_sendmsg_cmsg() {
    let receiver = match UdpSocket::bind("[::1]:0") {
        Ok(s) => s,
        Err(_) => return,
    };
    set_recv_tos(&receiver, false);
    let server_addr = receiver.local_addr().unwrap();

    let tos_marked = send_quic_initial_and_capture_tos(
        "[::1]:0".parse().unwrap(),
        server_addr,
        SocketMark::with_dscp(Some(59)),
        &receiver,
    );
    assert_eq!(
        tos_marked >> 2,
        59,
        "IPv6 QUIC Initial packet lost DSCP=59 (got tclass={tos_marked:#x}, dscp={})",
        tos_marked >> 2
    );

    let receiver_default = UdpSocket::bind("[::1]:0").unwrap();
    set_recv_tos(&receiver_default, false);
    let tos_default = send_quic_initial_and_capture_tos(
        "[::1]:0".parse().unwrap(),
        receiver_default.local_addr().unwrap(),
        SocketMark::default(),
        &receiver_default,
    );
    assert_eq!(tos_default >> 2, 0, "expected default TCLASS DSCP 0, got {tos_default:#x}");
}

#[cfg(target_os = "linux")]
#[test]
fn quic_dual_stack_v6_to_v4_mapped_preserves_dscp() {
    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    set_recv_tos(&receiver, true);
    let v4_port = receiver.local_addr().unwrap().port();
    let v4_mapped_target =
        SocketAddr::new(IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()), v4_port);

    let tos = send_quic_initial_and_capture_tos(
        "[::]:0".parse().unwrap(),
        v4_mapped_target,
        SocketMark::with_dscp(Some(59)),
        &receiver,
    );
    assert_eq!(
        tos >> 2,
        59,
        "dual-stack v6->v4-mapped QUIC Initial lost DSCP=59 (got tos={tos:#x})"
    );
}

#[test]
fn quinn_udp_preserves_dscp_and_ecn_bits_together() {
    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    set_recv_tos(&receiver, true);
    let server_addr = receiver.local_addr().unwrap();

    let sender =
        bind_udp_socket("127.0.0.1:0".parse().unwrap(), SocketMark::with_dscp(Some(59))).unwrap();
    let state = UdpSocketState::new((&sender).into()).unwrap();

    for ecn in [EcnCodepoint::Ect0, EcnCodepoint::Ect1] {
        let transmit = Transmit {
            destination: server_addr,
            ecn: Some(ecn),
            contents: b"dscp+ecn",
            segment_size: None,
            src_ip: None,
        };
        state.try_send((&sender).into(), &transmit).unwrap();
        let (len, tos) = recv_packet_tos(&receiver);
        assert_eq!(len, b"dscp+ecn".len());
        let tos = tos.expect("expected IP_TOS cmsg");
        assert_eq!(tos >> 2, 59, "DSCP bits clobbered with ECN {ecn:?}: tos={tos:#x}");
        assert_eq!(
            tos & 0x03,
            ecn as u8,
            "ECN bits clobbered with DSCP 59 for {ecn:?}: tos={tos:#x}"
        );
    }
}
