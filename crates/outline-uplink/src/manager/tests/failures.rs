//! Attribution tests for [`UplinkManager::report_runtime_failure`].
//!
//! Invariant under test: the carrier descends only on evidence about the
//! carrier itself. A payload-integrity error (AEAD open failure, a truncated
//! datagram, an SS2022 replay/reorder rejection) says something about the
//! bytes that arrived, not about the transport that carried them — charging
//! it to the uplink caps `xhttp_h3 → xhttp_h2` and stamps a cooldown, which
//! demotes an otherwise healthy QUIC carrier to UDP-over-TCP for the whole
//! downgrade window.

use std::io::{Error as IoError, ErrorKind};

use outline_wire::ss2022::Ss2022Error;
use shadowsocks_crypto::CryptoError;

use crate::config::TransportMode;
use crate::tests::fallback::{manager_with_uplink, vless_xhttp_primary};
use crate::types::TransportKind;

/// Every payload-integrity shape the UDP downlink can surface, wrapped the way
/// the reader surfaces it: a typed error under an `anyhow` context layer.
fn payload_errors() -> Vec<(&'static str, anyhow::Error)> {
    vec![
        (
            "aead open failure",
            anyhow::Error::new(CryptoError::DecryptFailed { cipher: "aes-256-gcm" })
                .context("failed to read UDP downlink packet"),
        ),
        (
            "truncated datagram",
            anyhow::Error::new(CryptoError::UdpPacketTooShort)
                .context("failed to read UDP downlink packet"),
        ),
        (
            "ss2022 replay / reorder",
            anyhow::Error::new(Ss2022Error::DuplicateOrOutOfOrderUdpPacket)
                .context("failed to read UDP downlink packet"),
        ),
    ]
}

#[tokio::test]
async fn payload_integrity_error_does_not_cap_the_carrier() {
    for (label, error) in payload_errors() {
        // min_failures = 1: a single charged failure would cap immediately,
        // which makes the "no cap" assertion sharp.
        let manager = manager_with_uplink(vless_xhttp_primary(), 1);
        manager.report_runtime_failure(0, TransportKind::Udp, &error).await;

        let status = manager.read_status_for_test(0);
        assert_eq!(
            status.udp.descent.capped_to(),
            None,
            "{label}: a corrupt datagram must not cap the carrier",
        );
    }
}

#[tokio::test]
async fn payload_integrity_error_does_not_stamp_a_cooldown() {
    for (label, error) in payload_errors() {
        let manager = manager_with_uplink(vless_xhttp_primary(), 1);
        manager.report_runtime_failure(0, TransportKind::Udp, &error).await;

        let status = manager.read_status_for_test(0);
        assert!(
            status.udp.cooldown_until.is_none(),
            "{label}: a corrupt datagram must not put the uplink in cooldown",
        );
        assert_eq!(
            status.udp.consecutive_runtime_failures, 0,
            "{label}: a corrupt datagram must not feed the runtime-failure streak",
        );
    }
}

#[tokio::test]
async fn payload_integrity_error_leaves_the_tcp_plane_untouched() {
    // The descent slot is per-transport, so the TCP assertion is a guard
    // against the gate being widened later; the UDP one is the production
    // symptom itself — every new UDP dial reads the capped carrier.
    let manager = manager_with_uplink(vless_xhttp_primary(), 1);
    let error = anyhow::Error::new(CryptoError::DecryptFailed { cipher: "xchacha20-poly1305" });
    manager.report_runtime_failure(0, TransportKind::Udp, &error).await;

    assert_eq!(
        manager.effective_tcp_mode(0).await,
        TransportMode::XhttpH3,
        "a UDP payload error must leave the TCP plane on its configured carrier",
    );
    assert_eq!(
        manager.effective_udp_mode(0).await,
        TransportMode::XhttpH3,
        "a UDP payload error must leave the UDP plane on its configured carrier",
    );
}

#[tokio::test]
async fn carrier_read_failure_still_caps_and_stamps_cooldown() {
    // The control case: a genuine carrier fault (the peer reset the stream
    // under a `websocket read failed` context) must escalate exactly as
    // before — this is what the payload gate must not weaken.
    let manager = manager_with_uplink(vless_xhttp_primary(), 1);
    let error = anyhow::Error::new(IoError::new(ErrorKind::ConnectionReset, "connection reset"))
        .context("websocket read failed");
    manager.report_runtime_failure(0, TransportKind::Udp, &error).await;

    let status = manager.read_status_for_test(0);
    assert_eq!(
        status.udp.descent.capped_to(),
        Some(TransportMode::XhttpH2),
        "a carrier-level read failure must still cap XhttpH3 → XhttpH2",
    );
    assert!(
        status.udp.cooldown_until.is_some(),
        "a carrier-level read failure must still stamp a cooldown",
    );
    assert_eq!(
        status.udp.consecutive_runtime_failures, 1,
        "a carrier-level read failure must still feed the runtime-failure streak",
    );
}

#[tokio::test]
async fn endpoint_unreachable_flips_single_endpoint_uplink_unhealthy_immediately() {
    let mut uplink = vless_xhttp_primary();
    uplink.shuffle_wires = true;
    uplink.fallbacks = vec![crate::config::FallbackTransport {
        transport: crate::config::UplinkTransport::Ss,
        tcp_ws_url: uplink.tcp_xhttp_url.clone(),
        tcp_xhttp_url: None,
        tcp_mode: TransportMode::WsH2,
        udp_ws_url: uplink.udp_xhttp_url.clone(),
        udp_xhttp_url: None,
        udp_mode: TransportMode::WsH2,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH2,
        ss_ws_url: None,
        ss_xhttp_url: None,
        ss_mode: None,
        vless_id: None,
        cipher: uplink.cipher,
        password: uplink.password.clone(),
        fwmark: None,
        dscp: None,
        disable_udp_gso: false,
        ipv6_first: false,
        ipv4_only: false,
        fingerprint_profile: None,
    }];
    let manager = manager_with_uplink(uplink, 3);
    let err = anyhow::anyhow!("L4 dead").context(outline_transport::EndpointUnreachable);

    manager.report_runtime_failure(0, TransportKind::Tcp, &err).await;

    let status = manager.read_status_for_test(0);
    assert_eq!(
        status.tcp.healthy,
        Some(false),
        "EndpointUnreachable on a single-endpoint uplink must immediately mark it unhealthy despite shuffle_wires and min_failures=3"
    );
    assert!(status.tcp.cooldown_until.is_some());
    assert!(status.tcp.consecutive_runtime_failures >= 3);
}

#[tokio::test]
async fn probe_wakeup_min_interval_is_2s_for_desktop_and_15s_for_mobile() {
    use std::time::Duration;

    let desktop_manager = manager_with_uplink(vless_xhttp_primary(), 1);
    assert_eq!(desktop_manager.probe_wakeup_min_interval(), Duration::from_secs(2));

    let mut mobile_probe = crate::tests::fallback::make_probe(1);
    mobile_probe.interval = Duration::from_secs(300);
    let mobile_manager = crate::types::UplinkManager::new_for_test(
        "mobile",
        vec![vless_xhttp_primary()],
        mobile_probe,
        crate::tests::fallback::make_lb(Duration::from_secs(60)),
    )
    .unwrap();
    assert_eq!(mobile_manager.probe_wakeup_min_interval(), Duration::from_secs(15));
}
