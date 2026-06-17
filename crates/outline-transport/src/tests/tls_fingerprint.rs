//! Tests for the per-family TLS ClientHello cipher / kx ordering.

use std::sync::Arc;

use rustls::{CipherSuite, NamedGroup};

use super::provider_for;
use crate::fingerprint_profile::TlsFingerprint;

/// IANA cipher ids offered, in order, for a family.
fn suites(fp: TlsFingerprint) -> Vec<CipherSuite> {
    provider_for(fp).cipher_suites.iter().map(|s| s.suite()).collect()
}

/// Named kx groups offered, in order, for a family.
fn groups(fp: TlsFingerprint) -> Vec<NamedGroup> {
    provider_for(fp).kx_groups.iter().map(|g| g.name()).collect()
}

#[test]
fn chromium_order_is_aes128_aes256_chacha() {
    assert_eq!(
        suites(TlsFingerprint::Chromium),
        vec![
            CipherSuite::TLS13_AES_128_GCM_SHA256,
            CipherSuite::TLS13_AES_256_GCM_SHA384,
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        ]
    );
}

#[test]
fn firefox_puts_chacha_ahead_of_aes256() {
    let s = suites(TlsFingerprint::Firefox);
    // TLS 1.3 head: AES-128, ChaCha20, AES-256 — ChaCha20 ahead of AES-256.
    assert_eq!(
        &s[..3],
        &[
            CipherSuite::TLS13_AES_128_GCM_SHA256,
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS13_AES_256_GCM_SHA384,
        ]
    );
}

#[test]
fn safari_groups_ecdsa_before_rsa() {
    let s = suites(TlsFingerprint::Safari);
    // Head matches Chromium, but the TLS 1.2 block runs all ECDSA suites
    // before any RSA one — the first ECDHE suite is ECDSA-AES-256.
    assert_eq!(s[3], CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
    assert_eq!(s[6], CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
}

#[test]
fn families_have_distinct_orders() {
    let chromium = suites(TlsFingerprint::Chromium);
    let firefox = suites(TlsFingerprint::Firefox);
    let safari = suites(TlsFingerprint::Safari);
    assert_ne!(chromium, firefox);
    assert_ne!(chromium, safari);
    assert_ne!(firefox, safari);
}

#[test]
fn every_family_offers_the_full_suite_set() {
    // We offer 3 TLS 1.3 AEADs + 6 TLS 1.2 ECDHE suites = 9. Each family is
    // a reordering of the same set, so the count is fixed and the set
    // (sorted) is identical across families — only order moves.
    let mut chromium = suites(TlsFingerprint::Chromium);
    let mut firefox = suites(TlsFingerprint::Firefox);
    let mut safari = suites(TlsFingerprint::Safari);
    assert_eq!(chromium.len(), 9);
    chromium.sort_by_key(|c| u16::from(*c));
    firefox.sort_by_key(|c| u16::from(*c));
    safari.sort_by_key(|c| u16::from(*c));
    assert_eq!(chromium, firefox);
    assert_eq!(chromium, safari);
}

#[test]
fn kx_order_leads_with_post_quantum_then_x25519_uniform() {
    // The post-quantum hybrid leads (as current Chrome / Firefox / Safari
    // offer), so a censor cannot flag the dial on a missing PQ key share.
    let expected = vec![
        NamedGroup::X25519MLKEM768,
        NamedGroup::X25519,
        NamedGroup::secp256r1,
        NamedGroup::secp384r1,
    ];
    assert_eq!(groups(TlsFingerprint::Chromium), expected);
    assert_eq!(groups(TlsFingerprint::Firefox), expected);
    assert_eq!(groups(TlsFingerprint::Safari), expected);
}

#[test]
fn provider_is_cached_per_family() {
    // Same family returns the very same Arc; different families do not.
    assert!(Arc::ptr_eq(
        &provider_for(TlsFingerprint::Chromium),
        &provider_for(TlsFingerprint::Chromium)
    ));
    assert!(!Arc::ptr_eq(
        &provider_for(TlsFingerprint::Chromium),
        &provider_for(TlsFingerprint::Firefox)
    ));
}

/// Diagnostic: emit the raw ClientHello each family produces so an external
/// parser can compute JA3/JA4 and confirm the post-quantum key share is on
/// the wire. `write_tls` serialises the ClientHello without any network I/O.
/// Run with `--nocapture` to see the `CLIENTHELLO <family> <hex>` lines.
#[test]
fn dump_clienthello_wire() {
    for (name, fp) in [
        ("chromium", TlsFingerprint::Chromium),
        ("firefox", TlsFingerprint::Firefox),
        ("safari", TlsFingerprint::Safari),
    ] {
        let mut config = rustls::ClientConfig::builder_with_provider(provider_for(fp))
            .with_safe_default_protocol_versions()
            .expect("aws-lc-rs provider supports TLS 1.2 + 1.3")
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let server_name = rustls::pki_types::ServerName::try_from("www.example.com").unwrap();
        let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
        let mut buf = Vec::new();
        conn.write_tls(&mut buf).unwrap();
        // TLS record: 0x16 = handshake; payload byte 0 (record[5]) = 0x01 ClientHello.
        assert_eq!(buf[0], 0x16, "{name}: expected a TLS handshake record");
        assert_eq!(buf[5], 0x01, "{name}: expected a ClientHello");
        let hex: String = buf.iter().map(|b| format!("{b:02x}")).collect();
        eprintln!("CLIENTHELLO {name} {hex}");
    }
}

/// Diagnostic (QUIC): emit the ClientHello as it rides inside a QUIC Initial —
/// i.e. what a censor sees after deriving Initial keys from the well-known v1
/// salt and decrypting the packet. Unlike the TCP dump above, this ClientHello
/// is TLS 1.3-only and carries the `quic_transport_parameters` extension
/// (0x39), so its JA3/JA4 surface differs from the TCP ClientHello of the same
/// family. `write_hs` serialises the handshake as the bare CRYPTO-frame payload
/// (no TLS record header, no network I/O).
///
/// The transport-parameters bytes are an empty placeholder here: this step
/// measures only the TLS layer. The real quinn-encoded transport-parameter set
/// (ids, values, order, jitter, padding) is dumped by the full-Initial
/// diagnostic that drives a real `quinn` handshake.
///
/// The cases mirror the real dial paths: H3 carriers run under a browser
/// fingerprint and offer `h3`; raw-QUIC (vless/ss) currently dials outside any
/// fingerprint scope (`fp = None` → default provider) and offers the tell-tale
/// `vless` ALPN. Run with `--nocapture` to see the `QUIC-CLIENTHELLO` lines.
///
/// No feature gate: `rustls::quic` is unconditionally available (rustls 0.23
/// has no `quic` feature), so the diagnostic builds in the default test set.
#[test]
fn dump_quic_clienthello_wire() {
    use rustls::RootCertStore;
    use rustls::pki_types::ServerName;
    use rustls::quic::{ClientConnection, Version};

    let cases: &[(&str, Option<TlsFingerprint>, &[&[u8]])] = &[
        ("h3-chromium", Some(TlsFingerprint::Chromium), &[b"h3"]),
        ("h3-firefox", Some(TlsFingerprint::Firefox), &[b"h3"]),
        ("h3-safari", Some(TlsFingerprint::Safari), &[b"h3"]),
        ("rawquic-default-vless", None, &[b"vless-mtu", b"vless"]),
    ];
    for (label, fp, alpn) in cases {
        let provider = match fp {
            Some(fp) => provider_for(*fp),
            None => Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        };
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("aws-lc-rs provider supports TLS 1.2 + 1.3")
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        let name = ServerName::try_from("www.example.com").unwrap();
        let mut conn =
            ClientConnection::new(Arc::new(config), Version::V1, name, Vec::new()).unwrap();
        let mut buf = Vec::new();
        conn.write_hs(&mut buf);
        // QUIC handshake bytes are the bare CRYPTO payload: byte 0 is the
        // handshake type (0x01 = ClientHello), with no 0x16 TLS record wrapper.
        assert_eq!(buf[0], 0x01, "{label}: expected a ClientHello handshake");
        let hex: String = buf.iter().map(|b| format!("{b:02x}")).collect();
        eprintln!("QUIC-CLIENTHELLO {label} {hex}");
    }
}
