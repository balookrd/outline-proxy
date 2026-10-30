use super::{H2ConnectionKey, H2Dialer};
use crate::dial_plan::DialResumeOptions;
use crate::fingerprint_profile::{TlsFingerprint, with_dial_fingerprint};
use crate::shared_cache::should_reuse_connection;
use crate::shared_dial::WsDialer;

const CHROMIUM: TlsFingerprint = TlsFingerprint::Chromium;

#[test]
fn h2_shared_connection_key_distinguishes_scheme_server_name_port_fwmark_and_family() {
    let base = H2ConnectionKey::new("one.example", 443, true, None, CHROMIUM);

    assert_ne!(base, H2ConnectionKey::new("two.example", 443, true, None, CHROMIUM));
    assert_ne!(base, H2ConnectionKey::new("one.example", 443, false, None, CHROMIUM));
    assert_ne!(base, H2ConnectionKey::new("one.example", 443, true, Some(42), CHROMIUM));
    assert_ne!(base, H2ConnectionKey::new("one.example", 8443, true, None, CHROMIUM));
    assert_ne!(
        base,
        H2ConnectionKey::new("one.example", 443, true, None, TlsFingerprint::Firefox)
    );
    assert_eq!(base, H2ConnectionKey::new("one.example", 443, true, None, CHROMIUM));
}

/// The dialer reads the dial-scoped family, so two dials to the same server
/// as different browsers key two shared connections, while a dial without a
/// profile shares the Chromium one (it sends the Chromium hello and shape).
#[tokio::test]
async fn h2_dialer_keys_connections_by_dial_scoped_family() {
    async fn key_under(fp: Option<TlsFingerprint>) -> H2ConnectionKey {
        with_dial_fingerprint(fp, async {
            H2Dialer::new(true, DialResumeOptions::default(), None).make_key(
                "one.example",
                443,
                None,
            )
        })
        .await
    }
    let chromium = key_under(Some(TlsFingerprint::Chromium)).await;
    let firefox = key_under(Some(TlsFingerprint::Firefox)).await;
    let safari = key_under(Some(TlsFingerprint::Safari)).await;
    let unscoped =
        H2Dialer::new(true, DialResumeOptions::default(), None).make_key("one.example", 443, None);
    assert_ne!(chromium, firefox);
    assert_ne!(chromium, safari);
    assert_ne!(firefox, safari);
    assert_eq!(chromium, key_under(None).await);
    assert_eq!(chromium, unscoped);
}

#[test]
fn probe_sources_do_not_reuse_shared_h2_connections() {
    assert!(should_reuse_connection("direct"));
    assert!(should_reuse_connection("standby_tcp"));
    assert!(!should_reuse_connection("probe_ws"));
    assert!(!should_reuse_connection("probe_http"));
}
