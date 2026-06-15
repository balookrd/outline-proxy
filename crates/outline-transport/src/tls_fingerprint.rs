//! Maps a browser [`TlsFingerprint`] family to a rustls `CryptoProvider`
//! whose ClientHello cipher-suite order matches that browser, so the JA3
//! surface of a dial lines up with the HTTP-layer identity carried by the
//! same [`crate::fingerprint_profile::Profile`].
//!
//! ## What this controls — and what it cannot
//!
//! On rustls + `aws-lc-rs` the ClientHello knobs the public API exposes are
//! the *order* of the offered cipher suites and the *order* of the
//! key-exchange groups (both are emitted verbatim from the `CryptoProvider`
//! vectors). Reordering the cipher list moves JA3 — which hashes the ciphers
//! in offer order — toward the target browser, and leading with the
//! post-quantum group closes the strongest modern tell, but it still cannot
//! reach a byte-exact match:
//!
//! * **Post-quantum key share is offered.** `aws-lc-rs` provides
//!   `X25519MLKEM768`, and it leads the kx-group list as current browsers
//!   do, so a censor can no longer flag the dial on the *absence* of a PQ
//!   key share behind a modern-browser User-Agent — the single strongest
//!   "not a real browser" tell on stock rustls + `ring`.
//! * **No GREASE.** Browsers prepend a random GREASE value to the cipher
//!   list and sprinkle GREASE extensions; rustls emits none, whatever the
//!   provider. This is the remaining byte-level gap.
//! * **Extension set and order are owned by rustls** and are not exposed.
//!   JA4 sorts ciphers/extensions and drops GREASE, so it keys on the
//!   *set*; reordering alone does not move it.
//!
//! The honest payoff is a closer JA3 with a PQ-capable key_share, and
//! removal of the obvious "rustls-default order / no post-quantum group
//! behind a Chrome User-Agent" mismatch. A byte-exact JA3/JA4 still needs a
//! vendored rustls (GREASE + extension control); this module is the seam
//! such a fork extends — callers keep asking for a provider by family and
//! never see the difference.
//!
//! The kx-group order is `[X25519MLKEM768, x25519, secp256r1, secp384r1]`
//! for every family — that matches what current Chrome / Firefox / Safari
//! offer; it is set explicitly to keep the post-quantum group first and the
//! seam in one place.

use std::sync::{Arc, OnceLock};

use rustls::SupportedCipherSuite;
use rustls::crypto::CryptoProvider;
use rustls::crypto::aws_lc_rs::{cipher_suite as cs, default_provider, kx_group};

use crate::fingerprint_profile::TlsFingerprint;

/// Returns a process-wide cached `CryptoProvider` whose cipher / kx order
/// mimics `fp`. Built once per family (there are three) on first use; the
/// `Arc` is cheap to clone into a `ClientConfig` per dial.
pub(crate) fn provider_for(fp: TlsFingerprint) -> Arc<CryptoProvider> {
    static CHROMIUM: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    static FIREFOX: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    static SAFARI: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    let slot = match fp {
        TlsFingerprint::Chromium => &CHROMIUM,
        TlsFingerprint::Firefox => &FIREFOX,
        TlsFingerprint::Safari => &SAFARI,
    };
    Arc::clone(slot.get_or_init(|| Arc::new(build_provider(fp))))
}

/// Clones aws-lc-rs's default provider and swaps in the family-specific
/// cipher / kx ordering (post-quantum group leading), leaving the
/// secure-random source, key provider, and signature-verification
/// algorithms untouched.
fn build_provider(fp: TlsFingerprint) -> CryptoProvider {
    CryptoProvider {
        cipher_suites: cipher_order(fp),
        kx_groups: vec![
            kx_group::X25519MLKEM768,
            kx_group::X25519,
            kx_group::SECP256R1,
            kx_group::SECP384R1,
        ],
        ..default_provider()
    }
}

/// Cipher-suite offer order for a family — a browser-like subset of what
/// aws-lc-rs implements (TLS 1.3 AEADs + TLS 1.2 ECDHE-GCM/ChaCha20). The
/// head — the three TLS 1.3 suites — is what differs most between
/// browsers and is the part a JA3 rule keys on:
///
/// * Chromium / Safari: AES-128-GCM, AES-256-GCM, ChaCha20.
/// * Firefox: AES-128-GCM, ChaCha20, AES-256-GCM.
fn cipher_order(fp: TlsFingerprint) -> Vec<SupportedCipherSuite> {
    match fp {
        // Chrome / Edge (BoringSSL): AES-128 ahead of AES-256, ECDSA and
        // RSA interleaved per key size, ChaCha20 last.
        TlsFingerprint::Chromium => vec![
            cs::TLS13_AES_128_GCM_SHA256,
            cs::TLS13_AES_256_GCM_SHA384,
            cs::TLS13_CHACHA20_POLY1305_SHA256,
            cs::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            cs::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            cs::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            cs::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            cs::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            cs::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        ],
        // Firefox (NSS): ChaCha20 sits ahead of AES-256 in both the TLS 1.3
        // head and the TLS 1.2 ECDHE block.
        TlsFingerprint::Firefox => vec![
            cs::TLS13_AES_128_GCM_SHA256,
            cs::TLS13_CHACHA20_POLY1305_SHA256,
            cs::TLS13_AES_256_GCM_SHA384,
            cs::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            cs::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            cs::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            cs::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            cs::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            cs::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ],
        // Safari (SecureTransport): groups all ECDSA suites ahead of the
        // RSA ones, AES-256 ahead of AES-128 within each auth type.
        TlsFingerprint::Safari => vec![
            cs::TLS13_AES_128_GCM_SHA256,
            cs::TLS13_AES_256_GCM_SHA384,
            cs::TLS13_CHACHA20_POLY1305_SHA256,
            cs::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            cs::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            cs::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            cs::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            cs::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            cs::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        ],
    }
}

#[cfg(test)]
#[path = "tests/tls_fingerprint.rs"]
mod tests;
