use super::*;

fn classify(err: Ss2022Error) -> &'static str {
    let wrapped = Error::from(err).context("ss2022 framing failed in some outer layer");
    classify_runtime_failure_signature(&wrapped)
}

#[test]
fn context_on_result_preserves_typed_marker() {
    // Canonical call-site shape: `Result<_, StdError>.context(TypedMarker)`.
    // The typed marker is stored as an anyhow context layer — found via
    // `anyhow::Error::downcast_ref` (or `find_typed`), NOT via walking
    // the std `source()` chain.
    use anyhow::Context;
    let tungstenite_like: Result<(), std::io::Error> =
        Err(std::io::Error::other("tungstenite protocol error"));
    let err = tungstenite_like
        .context(TransportOperation::WebSocketRead)
        .unwrap_err();
    assert!(
        find_typed::<TransportOperation>(&err).is_some(),
        "find_typed must locate typed context marker"
    );
    assert_eq!(classify_runtime_failure_signature(&err), "ws_read_failed");
}

#[test]
fn typed_transport_operation_classified_when_no_io_kind() {
    // Construct as root typed error + outer string context (matches the
    // shape produced by `.with_context(|| TransportOperation::…)` at real
    // call-sites, where the typed value becomes the error's root type and
    // the underlying library error becomes a `source()` layer).
    let err = Error::new(TransportOperation::WebSocketRead).context("outer call frame");
    assert_eq!(classify_runtime_failure_signature(&err), "ws_read_failed");

    let err = Error::new(TransportOperation::SocketShutdown).context("outer call frame");
    assert_eq!(classify_runtime_failure_signature(&err), "socket_shutdown_failed");
}

#[test]
fn io_kind_wins_over_transport_operation_marker() {
    // When an io::Error with ConnectionReset is the *source* of a typed
    // TransportOperation, io::ErrorKind classification takes priority
    // over the operation marker (preserves the existing fallback
    // ordering established before the typed marker was added).
    let io_err = std::io::Error::from(std::io::ErrorKind::ConnectionReset);
    let err: Error = anyhow::Error::from(io_err).context(TransportOperation::WebSocketRead);
    assert_eq!(classify_runtime_failure_signature(&err), "connection_reset");
}

#[test]
fn typed_crypto_errors_are_classified() {
    use shadowsocks_crypto::CryptoError;

    let err = Error::new(CryptoError::DecryptFailed { cipher: "aes-256-gcm" });
    assert_eq!(classify_runtime_failure_signature(&err), "decrypt_failed");
    assert_eq!(classify_runtime_failure_cause(&err), "crypto");

    let err = Error::new(CryptoError::EncryptFailed { cipher: "chacha20-poly1305" });
    assert_eq!(classify_runtime_failure_signature(&err), "encrypt_failed");
    assert_eq!(classify_runtime_failure_cause(&err), "crypto");

    let err = Error::new(CryptoError::NonceOverflow);
    assert_eq!(classify_runtime_failure_signature(&err), "encrypt_failed");
    assert_eq!(classify_runtime_failure_cause(&err), "crypto");

    // Protocol variant falls through to string fallback (catch-all design).
    let err = Error::new(CryptoError::Protocol("invalid ss2022 UDP server packet type"));
    assert_eq!(classify_runtime_failure_signature(&err), "invalid_ss2022");
    assert_eq!(classify_runtime_failure_cause(&err), "crypto");
}

#[test]
fn typed_marker_survives_nested_context_wrapping() {
    // If a call-site's .with_context(|| Typed) is later wrapped with an
    // additional .context("outer label") by a caller, the typed marker
    // must still be findable.
    use anyhow::Context;
    let io_err: std::io::Result<()> = Err(std::io::Error::other("x"));
    let err = io_err
        .with_context(|| TransportOperation::Connect { target: "to X".into() })
        .context("outer caller frame")
        .unwrap_err();
    assert!(
        err.downcast_ref::<TransportOperation>().is_some(),
        "typed marker must survive outer .context() wrapping"
    );
}

#[test]
fn connect_with_context_at_call_site_is_classified() {
    use anyhow::Context;
    let io_err: std::io::Result<()> = Err(std::io::Error::other("network unreachable"));
    let err = io_err
        .with_context(|| TransportOperation::Connect {
            target: "TCP socket to 1.2.3.4:443".into(),
        })
        .unwrap_err();
    // anyhow::Error has a direct .downcast_ref() that inspects the context
    // layer (distinct from chain() walking via source()).
    assert!(
        err.downcast_ref::<TransportOperation>().is_some(),
        "anyhow::Error::downcast_ref() must find typed context marker"
    );
    assert_eq!(classify_runtime_failure_signature(&err), "connect_failed");
}

#[test]
fn typed_connect_and_dns_failures_are_classified() {
    let err = Error::new(TransportOperation::Connect { target: "TCP socket to 1.2.3.4:443".into() });
    assert_eq!(classify_runtime_failure_signature(&err), "connect_failed");
    assert_eq!(classify_runtime_failure_cause(&err), "connect");

    let err = Error::new(TransportOperation::DnsResolveNoAddresses { host: "example.com:443".into() });
    assert_eq!(classify_runtime_failure_signature(&err), "dns_no_addresses");
    assert_eq!(classify_runtime_failure_cause(&err), "connect");
}

#[test]
fn typed_connect_survives_outer_context_wrapping() {
    let inner = Error::new(TransportOperation::Connect { target: "to wss://host".into() });
    let wrapped = inner.context("probe_http");
    assert_eq!(classify_runtime_failure_signature(&wrapped), "connect_failed");
}

#[test]
fn typed_ss2022_errors_are_classified_by_variant() {
    assert_eq!(classify(Ss2022Error::InvalidResponseHeaderLength(42)), "invalid_ss2022");
    assert_eq!(classify(Ss2022Error::InvalidResponseHeaderType(9)), "invalid_ss2022");
    assert_eq!(classify(Ss2022Error::InvalidInitialTargetHeader), "invalid_ss2022");
    assert_eq!(classify(Ss2022Error::RequestSaltMismatch), "request_salt_mismatch");
    assert_eq!(classify(Ss2022Error::DuplicateOrOutOfOrderUdpPacket), "udp_out_of_order");
    assert_eq!(classify(Ss2022Error::OversizedUdpUplink), "oversized_udp");
}
