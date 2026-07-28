//! Tests for the payload-integrity classifier.
//!
//! The distinction it draws is the one the carrier-descent machinery depends
//! on: "the bytes that arrived were corrupt" (payload) versus "the pipe that
//! carried them broke" (carrier). Only the latter may descend a carrier.

use std::io::{Error as IoError, ErrorKind};

use anyhow::anyhow;
use outline_wire::ss2022::Ss2022Error;
use shadowsocks_crypto::CryptoError;

use super::super::error_classify::payload_integrity_cause;
use crate::{TransportOperation, WsClosed};

#[test]
fn aead_open_failure_is_payload_integrity() {
    let err = anyhow::Error::new(CryptoError::DecryptFailed { cipher: "aes-256-gcm" });
    assert_eq!(payload_integrity_cause(&err), Some("decrypt_failed"));
}

#[test]
fn truncated_udp_datagram_is_payload_integrity() {
    let err = anyhow::Error::new(CryptoError::UdpPacketTooShort);
    assert_eq!(payload_integrity_cause(&err), Some("packet_too_short"));
}

#[test]
fn ss2022_replay_or_reorder_is_payload_integrity() {
    let err = anyhow::Error::new(Ss2022Error::DuplicateOrOutOfOrderUdpPacket);
    assert_eq!(payload_integrity_cause(&err), Some("udp_out_of_order"));
}

#[test]
fn payload_integrity_is_found_under_context_layers() {
    // The reader propagates the decrypt error up through `?`, which layers
    // context on top of the typed error. A classifier that only inspected the
    // outermost error would miss it and charge the carrier.
    let err = anyhow::Error::new(CryptoError::DecryptFailed { cipher: "xchacha20-poly1305" })
        .context("failed to decrypt UDP packet")
        .context("reading UDP downlink packet");
    assert_eq!(payload_integrity_cause(&err), Some("decrypt_failed"));
}

#[test]
fn carrier_reset_is_not_payload_integrity() {
    let err = anyhow::Error::new(IoError::new(ErrorKind::ConnectionReset, "connection reset"))
        .context("websocket read failed");
    assert_eq!(payload_integrity_cause(&err), None);
}

#[test]
fn carrier_close_and_send_failures_are_not_payload_integrity() {
    assert_eq!(payload_integrity_cause(&anyhow::Error::new(WsClosed)), None);
    assert_eq!(
        payload_integrity_cause(&anyhow!("boom").context(TransportOperation::WebSocketSend)),
        None,
    );
    assert_eq!(payload_integrity_cause(&anyhow!("ws upstream read idle for 300s")), None);
}

#[test]
fn unrelated_crypto_failures_are_not_payload_integrity() {
    // An encrypt-side failure is ours, not the peer's: it never describes a
    // datagram that arrived corrupt, so it stays outside the gate.
    let err = anyhow::Error::new(CryptoError::EncryptFailed { cipher: "aes-256-gcm" });
    assert_eq!(payload_integrity_cause(&err), None);
}
