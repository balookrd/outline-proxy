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
