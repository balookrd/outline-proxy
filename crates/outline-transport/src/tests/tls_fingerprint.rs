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
