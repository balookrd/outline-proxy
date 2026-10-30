//! TCP browser profiles against the captured browser ClientHellos (2026-10-30, host
//! `localtest.me`): Chrome 156 (page = `h2, http/1.1`, WebSocket = `http/1.1`), Apple
//! URLSession on macOS 27 (both ALPN lists) and Firefox 159 (`h2, http/1.1`, its
//! WebSocket hello is the same). The fixtures are the handshake messages with their
//! 4-byte header. Our hellos are written by a sans-IO `rustls::ClientConnection`, for the
//! same SNI, over a config from `build_shaped_client_config` (the builder the dial path
//! uses) or, in `dial_path_sends_the_browser_hello`, from the dial path itself
//! (`crate::tls::build_client_config` under a dial fingerprint).

use std::collections::BTreeSet;
use std::sync::Arc;

use rustls::client::WebPkiServerVerifier;

use super::*;
use crate::fingerprint_profile::TlsFingerprint;
use crate::tests::client_hello::{
    alpn_protocols, capture_tcp_hello, cert_compression_algs, cipher_suites, ech_outer, extension,
    extension_types, handshake, is_grease_u16, ja4, ja4_without_grease_sigalgs, key_share_entries,
    key_share_groups, self_signed, server_config, supported_versions, u16_list_ext,
};
use crate::tls_hello::{BrowserVerifier, build_shaped_client_config, webpki_verifier};

const CHROME_H2: &[u8] = include_bytes!("fixtures/tcp_client_hello/chrome156_h2.bin");
const CHROME_H1: &[u8] = include_bytes!("fixtures/tcp_client_hello/chrome156_h1.bin");
const APPLE_H2: &[u8] = include_bytes!("fixtures/tcp_client_hello/apple_h2.bin");
const APPLE_H1: &[u8] = include_bytes!("fixtures/tcp_client_hello/apple_h1.bin");
const FIREFOX_H2: &[u8] = include_bytes!("fixtures/tcp_client_hello/firefox159_h2.bin");

const ALPN_H2: &[&[u8]] = &[b"h2", b"http/1.1"];
const ALPN_H1: &[&[u8]] = &[b"http/1.1"];

/// The SNI of the captures (its length only changes the hello's length, not JA4).
const SNI: &str = "localtest.me";

/// Our ClientHello for `profile` offering `alpn`.
fn hello(profile: &HelloProfile, alpn: &[&[u8]]) -> Vec<u8> {
    let config = build_shaped_client_config(profile, alpn, webpki_verifier(profile));
    capture_tcp_hello(config, SNI)
}

/// GREASE values collapse to one marker: the tests check "a GREASE value here".
fn mask(v: &[u16]) -> Vec<u16> {
    v.iter()
        .map(|x| if is_grease_u16(*x) { 0x0a0a } else { *x })
        .collect()
}

/// Every profile with its ALPN lists and the fixture each one is compared with.
fn cases() -> [(&'static HelloProfile, &'static [&'static [u8]], &'static [u8]); 6] {
    [
        (&CHROMIUM, ALPN_H2, CHROME_H2),
        (&CHROMIUM, ALPN_H1, CHROME_H1),
        (&SAFARI, ALPN_H2, APPLE_H2),
        (&SAFARI, ALPN_H1, APPLE_H1),
        (&FIREFOX, ALPN_H2, FIREFOX_H2),
        // Firefox sends `h2, http/1.1` for WebSocket too: only the ALPN differs.
        (&FIREFOX, ALPN_H1, FIREFOX_H2),
    ]
}

fn alpn_name(alpn: &[&[u8]]) -> &'static str {
    if alpn.len() == 2 { "h2" } else { "h1" }
}

// ---------------------------------------------------------------------------
// JA4
// ---------------------------------------------------------------------------

#[test]
fn ja4_helper_reproduces_fixtures() {
    // tshark's JA4 of the Apple and Firefox captures.
    assert_eq!(ja4(APPLE_H2), "t13d2013h2_a09f3c656075_7f0f34a4126d");
    assert_eq!(ja4(FIREFOX_H2), "t13d1517h2_8daaf6152771_3cbfd9057e0d");
    assert!(ja4(APPLE_H1).starts_with("t13d2013h1_a09f3c656075_"), "{}", ja4(APPLE_H1));

    // Chrome puts a GREASE value in its signature algorithms, which tshark hashes, so
    // the plain c-part changes per hello; without it each capture has a stable JA4.
    for (fixture, prefix) in
        [(CHROME_H2, "t13d1517h2_8daaf6152771_"), (CHROME_H1, "t13d1516h1_8daaf6152771_")]
    {
        let stable = ja4_without_grease_sigalgs(fixture);
        println!("chrome {prefix}: ja4 {} / without GREASE sigalgs {stable}", ja4(fixture));
        assert!(stable.starts_with(prefix), "{stable}");
        assert_eq!(stable, ja4_without_grease_sigalgs(fixture));
        assert!(is_grease_u16(u16_list_ext(fixture, 13)[0]));
        assert_ne!(ja4(fixture), stable, "the GREASE signature algorithm is hashed");
    }
    // tshark on these two captures (GREASE signature algorithm hashed).
    assert_eq!(ja4(CHROME_H2), "t13d1517h2_8daaf6152771_63ff51340b64");
    assert_eq!(ja4(CHROME_H1), "t13d1516h1_8daaf6152771_92b19d3f31ad");
    assert_eq!(ja4_without_grease_sigalgs(CHROME_H2), "t13d1517h2_8daaf6152771_cb7bf5808d99");
    assert_eq!(ja4_without_grease_sigalgs(CHROME_H1), "t13d1516h1_8daaf6152771_5b37b36a67c0");
}

/// JA4 of our hello vs the fixture's: Chrome without GREASE signature algorithms on
/// both sides.
fn assert_ja4_matches(profile: &HelloProfile, alpn: &[&[u8]], fixture: &[u8]) {
    let ours = hello(profile, alpn);
    let (ours, theirs) = if profile.grease_signature_algorithms {
        (ja4_without_grease_sigalgs(&ours), ja4_without_grease_sigalgs(fixture))
    } else {
        (ja4(&ours), ja4(fixture))
    };
    println!("{} {}: {ours}", profile.name, alpn_name(alpn));
    assert_eq!(ours, theirs, "{} {}", profile.name, alpn_name(alpn));
}

#[test]
fn chromium_h2_matches_the_browser() {
    assert_ja4_matches(&CHROMIUM, ALPN_H2, CHROME_H2);
}

#[test]
fn safari_h2_matches_the_browser() {
    assert_ja4_matches(&SAFARI, ALPN_H2, APPLE_H2);
}

#[test]
fn firefox_h2_matches_the_browser() {
    assert_ja4_matches(&FIREFOX, ALPN_H2, FIREFOX_H2);
}

#[test]
fn chromium_h1_matches_the_browser() {
    assert_ja4_matches(&CHROMIUM, ALPN_H1, CHROME_H1);
}

#[test]
fn safari_h1_matches_the_browser() {
    assert_ja4_matches(&SAFARI, ALPN_H1, APPLE_H1);
}

#[test]
fn firefox_h1_differs_only_in_alpn() {
    let ours = ja4(&hello(&FIREFOX, ALPN_H1));
    println!("firefox h1: {ours}");
    assert_eq!(ours, ja4(FIREFOX_H2).replacen("h2_", "h1_", 1));
    assert_eq!(ours, "t13d1517h1_8daaf6152771_3cbfd9057e0d");
}

// ---------------------------------------------------------------------------
// Wire lists and extension bodies
// ---------------------------------------------------------------------------

#[test]
fn wire_lists_match_the_fixture() {
    for (profile, alpn, fixture) in cases() {
        let ours = hello(profile, alpn);
        let what = format!("{} {}", profile.name, alpn_name(alpn));
        assert_eq!(mask(&cipher_suites(&ours)), mask(&cipher_suites(fixture)), "{what}: ciphers");
        assert_eq!(
            mask(&u16_list_ext(&ours, 10)),
            mask(&u16_list_ext(fixture, 10)),
            "{what}: groups"
        );
        let shares = |ch: &[u8]| -> Vec<(u16, usize)> {
            key_share_entries(ch)
                .into_iter()
                .map(|(g, len)| (mask(&[g])[0], len))
                .collect()
        };
        assert_eq!(shares(&ours), shares(fixture), "{what}: key shares");
        assert_eq!(
            mask(&key_share_groups(&ours)),
            mask(&key_share_groups(fixture)),
            "{what}: key share groups"
        );
        assert_eq!(
            mask(&supported_versions(&ours)),
            mask(&supported_versions(fixture)),
            "{what}: versions"
        );
        assert_eq!(
            mask(&u16_list_ext(&ours, 13)),
            mask(&u16_list_ext(fixture, 13)),
            "{what}: sigs"
        );
        assert_eq!(
            cert_compression_algs(&ours),
            cert_compression_algs(fixture),
            "{what}: compress_certificate"
        );
        assert_eq!(extension(&ours, 45), extension(fixture, 45), "{what}: psk_ke_modes");

        // ALPN is ours; for Firefox on h1 it is the one deliberate difference.
        let want_alpn: Vec<Vec<u8>> = alpn.iter().map(|p| p.to_vec()).collect();
        assert_eq!(alpn_protocols(&ours), want_alpn, "{what}: ALPN");
        if !(profile.name == "firefox" && alpn == ALPN_H1) {
            assert_eq!(alpn_protocols(&ours), alpn_protocols(fixture), "{what}: ALPN");
        }

        for typ in [5, 11, 18, 23, 28, 34, 35, 65281, 17613, 51764] {
            assert_eq!(extension(&ours, typ), extension(fixture, typ), "{what}: extension {typ}");
        }

        let set = |ch: &[u8]| -> BTreeSet<u16> { mask(&extension_types(ch)).into_iter().collect() };
        assert_eq!(set(&ours), set(fixture), "{what}: extension set");
    }
}

#[test]
fn fixed_orders_match() {
    for (profile, alpn, fixture) in cases() {
        if !matches!(profile.order, ShapeOrder::Fixed(_)) {
            continue;
        }
        // Fixed order: every hello is the same, GREASE as a marker.
        for _ in 0..4 {
            let ours = mask(&extension_types(&hello(profile, alpn)));
            println!("{} {}: {ours:?}", profile.name, alpn_name(alpn));
            assert_eq!(
                ours,
                mask(&extension_types(fixture)),
                "{} {}",
                profile.name,
                alpn_name(alpn)
            );
        }
    }
}

#[test]
fn chromium_order_is_shuffled() {
    let mut orders = BTreeSet::new();
    for _ in 0..8 {
        let types = extension_types(&hello(&CHROMIUM, ALPN_H2));
        assert!(is_grease_u16(types[0]), "{types:?}");
        assert!(is_grease_u16(types[types.len() - 1]), "{types:?}");
        orders.insert(types[1..types.len() - 1].to_vec());
    }
    assert!(orders.len() >= 2, "8 Chromium hellos share one extension order");
}

/// HPKE `(kdf, aead)` ids of the outer GREASE ECH extension, as raw bytes.
fn ech_suite_bytes(ch: &[u8]) -> [u8; 4] {
    let body = extension(ch, 0xfe0d).expect("no encrypted_client_hello");
    assert_eq!(body[0], 0, "outer ECH");
    body[1..5].try_into().unwrap()
}

#[test]
fn ech_grease_lengths() {
    let (_, _, enc, _) = ech_outer(CHROME_H2);
    let mut seen = BTreeSet::new();
    for _ in 0..32 {
        let (_, _, e, payload) = ech_outer(&hello(&CHROMIUM, ALPN_H2));
        assert_eq!(e, enc, "chromium ECH enc");
        assert!([144, 176, 208, 240].contains(&payload), "chromium payload {payload}");
        seen.insert(payload);
    }
    println!("chromium ECH payloads: {seen:?}");
    assert!(seen.len() >= 2, "one Chromium ECH payload length in 32 hellos");

    let (_, _, enc, payload) = ech_outer(FIREFOX_H2);
    assert_eq!(payload, 240);
    for alpn in [ALPN_H2, ALPN_H1] {
        let ours = hello(&FIREFOX, alpn);
        let (_, _, e, p) = ech_outer(&ours);
        assert_eq!((e, p), (enc, 240), "firefox");
        assert_eq!(
            extension(&ours, 0xfe0d).map(<[u8]>::len),
            extension(FIREFOX_H2, 0xfe0d).map(<[u8]>::len),
            "firefox ECH length"
        );
    }

    for alpn in [ALPN_H2, ALPN_H1] {
        assert_eq!(extension(&hello(&SAFARI, alpn), 0xfe0d), None, "safari");
    }
}

/// The GREASE ECH cipher suite (KDF and AEAD ids) is the browser's: HKDF-SHA256 with
/// AES-128-GCM for Chrome, with ChaCha20-Poly1305 for Firefox.
#[test]
fn ech_grease_suite_matches_the_fixture() {
    assert_eq!(ech_suite_bytes(CHROME_H2), [0x00, 0x01, 0x00, 0x01]);
    assert_eq!(ech_suite_bytes(CHROME_H1), [0x00, 0x01, 0x00, 0x01]);
    assert_eq!(ech_suite_bytes(FIREFOX_H2), [0x00, 0x01, 0x00, 0x03]);
    for (profile, alpn, fixture) in cases() {
        if !profile.ech_grease {
            continue;
        }
        for _ in 0..4 {
            assert_eq!(
                ech_suite_bytes(&hello(profile, alpn)),
                ech_suite_bytes(fixture),
                "{} {}",
                profile.name,
                alpn_name(alpn)
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Profiles and handshakes
// ---------------------------------------------------------------------------

#[test]
fn profiles_offer_their_suites_and_groups() {
    for p in [&CHROMIUM, &SAFARI, &FIREFOX] {
        p.check_wire_cipher_suites()
            .unwrap_or_else(|missing| panic!("{}: {missing:?} not on the wire", p.name));
        let provider = p.provider();
        let suites: Vec<_> = provider.cipher_suites.iter().map(|s| s.suite()).collect();
        assert_eq!(suites, p.cipher_suites, "{}", p.name);
        let groups: Vec<_> = provider.kx_groups.iter().map(|g| g.name()).collect();
        assert_eq!(groups, p.kx_groups, "{}", p.name);
        let algs: Vec<_> = p.cert_decompressors().iter().map(|d| d.algorithm()).collect();
        assert_eq!(algs, p.cert_compression, "{}", p.name);
    }
}

#[test]
fn handshake_completes_over_tcp_profiles() {
    let (cert, key) = self_signed(&rcgen::PKCS_ECDSA_P256_SHA256);
    for (profile, alpn, _) in cases() {
        let what = format!("{} {}", profile.name, alpn_name(alpn));
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.clone()).unwrap();
        let inner = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(profile.provider()),
        )
        .build()
        .unwrap();
        let verifier = Arc::new(BrowserVerifier::new(inner, profile.sig_schemes));
        let client = build_shaped_client_config(profile, alpn, verifier);

        let mut server = server_config(&[&rustls::version::TLS13], None, cert.clone(), key.clone());
        server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let (client, _) = handshake(client, server).unwrap_or_else(|e| panic!("{what}: {e:?}"));
        assert_eq!(client.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_3), "{what}");
        assert_eq!(client.alpn_protocol(), Some(alpn[0]), "{what}");
    }
}

#[test]
fn none_fingerprint_is_chromium() {
    assert_eq!(for_fingerprint(None), &CHROMIUM);
    assert_eq!(for_fingerprint(Some(TlsFingerprint::Chromium)), &CHROMIUM);
    assert_eq!(for_fingerprint(Some(TlsFingerprint::Safari)), &SAFARI);
    assert_eq!(for_fingerprint(Some(TlsFingerprint::Firefox)), &FIREFOX);
}

/// The dial path (`tls::build_client_config` under the dial fingerprint) sends the
/// browser's hello, `None` included (Chromium).
#[tokio::test]
async fn dial_path_sends_the_browser_hello() {
    use crate::fingerprint_profile::with_dial_fingerprint;
    for (fp, fixture) in [
        (None, CHROME_H2),
        (Some(TlsFingerprint::Chromium), CHROME_H2),
        (Some(TlsFingerprint::Safari), APPLE_H2),
        (Some(TlsFingerprint::Firefox), FIREFOX_H2),
    ] {
        let config =
            with_dial_fingerprint(fp, async { crate::tls::build_client_config(ALPN_H2) }).await;
        let ours = capture_tcp_hello(config, SNI);
        let (ours, theirs) = if for_fingerprint(fp).grease_signature_algorithms {
            (ja4_without_grease_sigalgs(&ours), ja4_without_grease_sigalgs(fixture))
        } else {
            (ja4(&ours), ja4(fixture))
        };
        println!("dial path {fp:?}: {ours}");
        assert_eq!(ours, theirs, "{fp:?}");
    }
}

#[test]
fn probe_config_follows_the_url_profile() {
    let alpn = ALPN_H2;
    // No fingerprint (the default strategy) = Chromium.
    let default =
        capture_tcp_hello(crate::tls::build_https_probe_client_config_for(None, alpn), SNI);
    let stable = ja4_without_grease_sigalgs(&default);
    println!("probe default: ja4 {} / without GREASE sigalgs {stable}", ja4(&default));
    assert_eq!(stable, "t13d1517h2_8daaf6152771_cb7bf5808d99");
    assert_eq!(alpn_protocols(&default), vec![b"h2".to_vec(), b"http/1.1".to_vec()]);

    for (fp, expected) in [
        (TlsFingerprint::Firefox, "t13d1517h2_8daaf6152771_3cbfd9057e0d"),
        (TlsFingerprint::Safari, "t13d2013h2_a09f3c656075_7f0f34a4126d"),
    ] {
        let hello =
            capture_tcp_hello(crate::tls::build_https_probe_client_config_for(Some(fp), alpn), SNI);
        println!("probe {fp:?}: ja4 {}", ja4(&hello));
        assert_eq!(ja4(&hello), expected, "{fp:?}");
    }
}

#[test]
fn probe_target_that_is_not_a_url_falls_back_to_chromium() {
    let alpn = ALPN_H2;
    let default =
        capture_tcp_hello(crate::tls::build_https_probe_client_config_for(None, alpn), SNI);
    // A space makes `https://{host}:{port}/` unparsable; the probe must still get a config.
    assert!(crate::tls::https_url("bad host", 443).is_err());
    let config = crate::tls::build_https_probe_client_config_for_target("bad host", 443, alpn);
    let got = capture_tcp_hello(config, SNI);
    assert_eq!(ja4_without_grease_sigalgs(&got), ja4_without_grease_sigalgs(&default));
}
