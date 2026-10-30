//! TCP-side knobs of the rustls patch "client-hello-shape" (`wire_cipher_suites`,
//! `advertise_tls12`, `grease_signature_algorithms`), checked on the ClientHello a
//! sans-IO `rustls::ClientConnection` writes and on in-memory handshakes.

use std::sync::Arc;

use rustls::CipherSuite;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::{CryptoProvider, aws_lc_rs};
use rustls::pki_types::CertificateDer;

use super::{ClientHelloShape, ExtensionOrder, set_client_hello_shape};
use crate::tests::client_hello::{
    Failed, capture_tcp_hello, cipher_suites, extension, extension_types, handshake, is_grease_u16,
    self_signed, server_config, supported_versions, u16_list_ext,
};

// ---------------------------------------------------------------------------
// Configs and capture
// ---------------------------------------------------------------------------

/// aws-lc-rs with `TLS13_AES_128_GCM_SHA256` and `X25519` only.
fn narrow_provider() -> Arc<CryptoProvider> {
    Arc::new(CryptoProvider {
        cipher_suites: vec![aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256],
        kx_groups: vec![aws_lc_rs::kx_group::X25519],
        ..aws_lc_rs::default_provider()
    })
}

fn verifier(
    provider: &Arc<CryptoProvider>,
    cert: &CertificateDer<'static>,
) -> Arc<WebPkiServerVerifier> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .unwrap()
}

/// TLS 1.3-only client config over [`narrow_provider`], trusting `cert`.
fn tls13_config(cert: &CertificateDer<'static>) -> rustls::ClientConfig {
    let provider = narrow_provider();
    let verifier = verifier(&provider, cert);
    rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_webpki_verifier(verifier)
        .with_no_client_auth()
}

fn shaped(mut config: rustls::ClientConfig, shape: ClientHelloShape) -> rustls::ClientConfig {
    set_client_hello_shape(&mut config, shape);
    config
}

/// The first ClientHello `config` writes (handshake message, record header stripped).
fn capture(config: rustls::ClientConfig) -> Vec<u8> {
    capture_tcp_hello(Arc::new(config), "localhost")
}

fn suites(list: &[u16]) -> Vec<CipherSuite> {
    list.iter().map(|&v| CipherSuite::from(v)).collect()
}

/// Schemes the client's verifier accepts (what upstream rustls sends in 13).
fn verifier_schemes(cert: &CertificateDer<'static>) -> Vec<u16> {
    verifier(&narrow_provider(), cert)
        .supported_verify_schemes()
        .into_iter()
        .map(u16::from)
        .collect()
}

fn test_cert() -> CertificateDer<'static> {
    self_signed(&rcgen::PKCS_ECDSA_P256_SHA256).0
}

// ---------------------------------------------------------------------------
// Wire lists
// ---------------------------------------------------------------------------

#[test]
fn wire_cipher_suites_replace_the_offered_list() {
    let cert = test_cert();
    let ch = capture(shaped(
        tls13_config(&cert),
        ClientHelloShape {
            wire_cipher_suites: suites(&[0x1301, 0xc02b, 0x002f, 0x000a]),
            ..ClientHelloShape::default()
        },
    ));
    let wire = cipher_suites(&ch);
    println!("wire_cipher_suites only: {wire:04x?}");
    assert_eq!(wire, [0x1301, 0xc02b, 0x002f, 0x000a]);
    assert!(!wire.contains(&0x00ff));
}

#[test]
fn wire_cipher_suites_follow_grease() {
    let cert = test_cert();
    let ch = capture(shaped(
        tls13_config(&cert),
        ClientHelloShape {
            grease: true,
            wire_cipher_suites: suites(&[0x1301, 0xc02b, 0x002f, 0x000a]),
            ..ClientHelloShape::default()
        },
    ));
    let wire = cipher_suites(&ch);
    println!("wire_cipher_suites + grease: {wire:04x?}");
    assert!(is_grease_u16(wire[0]), "{wire:04x?}");
    assert_eq!(wire[1..], [0x1301, 0xc02b, 0x002f, 0x000a]);
}

#[test]
fn empty_wire_list_keeps_the_provider_list() {
    let cert = test_cert();
    let provider = Arc::new(CryptoProvider {
        kx_groups: vec![aws_lc_rs::kx_group::X25519],
        ..aws_lc_rs::default_provider()
    });
    let verifier = verifier(&provider, &cert);
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
        .unwrap()
        .with_webpki_verifier(verifier)
        .with_no_client_auth();
    let ch = capture(shaped(config, ClientHelloShape::default()));
    let wire = cipher_suites(&ch);
    println!("provider list (TLS 1.2+1.3): {wire:04x?}");
    let mut expected: Vec<u16> =
        provider.cipher_suites.iter().map(|s| u16::from(s.suite())).collect();
    assert!(expected.contains(&0xc02b), "provider has TLS 1.2 suites");
    expected.push(0x00ff);
    assert_eq!(wire, expected);
}

#[test]
fn advertise_tls12_appends_0303() {
    let cert = test_cert();
    let hello = |grease: bool, advertise_tls12: bool| {
        capture(shaped(
            tls13_config(&cert),
            ClientHelloShape {
                grease,
                advertise_tls12,
                ..ClientHelloShape::default()
            },
        ))
    };

    let ch = hello(false, true);
    let versions = supported_versions(&ch);
    println!("advertise_tls12: {versions:04x?}");
    assert_eq!(versions, [0x0304, 0x0303]);
    // Internal logic still sees TLS 1.3 only: no SCSV, no session_ticket (35).
    assert_eq!(cipher_suites(&ch), [0x1301]);
    assert!(!extension_types(&ch).contains(&35));

    let ch = hello(true, true);
    let versions = supported_versions(&ch);
    println!("advertise_tls12 + grease: {versions:04x?}");
    assert!(is_grease_u16(versions[0]), "{versions:04x?}");
    assert_eq!(versions[1..], [0x0304, 0x0303]);

    let versions = supported_versions(&hello(false, false));
    println!("without advertise_tls12: {versions:04x?}");
    assert_eq!(versions, [0x0304]);
}

#[test]
fn grease_signature_algorithms_prepends_one_value() {
    let cert = test_cert();
    let expected = verifier_schemes(&cert);
    let hello = |grease: bool| {
        capture(shaped(
            tls13_config(&cert),
            ClientHelloShape {
                grease,
                grease_signature_algorithms: true,
                ..ClientHelloShape::default()
            },
        ))
    };

    let sigs = u16_list_ext(&hello(true), 13);
    println!("grease_signature_algorithms + grease: {sigs:04x?}");
    assert!(is_grease_u16(sigs[0]), "{sigs:04x?}");
    assert_eq!(sigs[1..], expected[..]);

    let sigs = u16_list_ext(&hello(false), 13);
    println!("grease_signature_algorithms without grease: {sigs:04x?}");
    assert_eq!(sigs, expected);
}

/// A QUIC-profile-like shape (Apple: GREASE, omissions, a raw extension, a fixed
/// order) with the three new fields at their defaults offers what it offered before
/// they existed.
#[test]
fn defaults_keep_the_offered_lists() {
    let cert = test_cert();
    let shape = ClientHelloShape {
        omit_extended_master_secret: true,
        omit_ec_point_formats: true,
        omit_status_request: false,
        extra_extensions: vec![(18, vec![])],
        grease: true,
        extension_order: ExtensionOrder::Fixed(vec![0, 10, 16, 5, 13, 18, 51, 45, 43, 27]),
        ..ClientHelloShape::default()
    };
    assert!(shape.wire_cipher_suites.is_empty());
    assert!(!shape.advertise_tls12 && !shape.grease_signature_algorithms);
    let ch = capture(shaped(tls13_config(&cert), shape));

    let ciphers = cipher_suites(&ch);
    assert!(is_grease_u16(ciphers[0]), "{ciphers:04x?}");
    assert_eq!(ciphers[1..], [0x1301]);

    let versions = supported_versions(&ch);
    assert!(is_grease_u16(versions[0]), "{versions:04x?}");
    assert_eq!(versions[1..], [0x0304]);

    let groups = u16_list_ext(&ch, 10);
    assert!(is_grease_u16(groups[0]), "{groups:04x?}");
    assert_eq!(groups[1..], [0x001d]);

    // Exactly the verifier's schemes, no GREASE: the aws-lc-rs webpki defaults.
    let sigs = u16_list_ext(&ch, 13);
    assert_eq!(sigs, verifier_schemes(&cert));
    assert_eq!(
        sigs,
        [0x0503, 0x0403, 0x0603, 0x0807, 0x0806, 0x0805, 0x0804, 0x0601, 0x0501, 0x0401]
    );

    let types = extension_types(&ch);
    assert!(is_grease_u16(types[0]) && is_grease_u16(types[types.len() - 1]), "{types:?}");
    assert_eq!(types[1..types.len() - 1], [0, 10, 5, 13, 18, 51, 45, 43]);
}

// ---------------------------------------------------------------------------
// In-memory handshakes
// ---------------------------------------------------------------------------

#[test]
fn server_selecting_tls12_fails_cleanly() {
    let (cert, key) = self_signed(&rcgen::PKCS_ECDSA_P256_SHA256);
    let client = shaped(
        tls13_config(&cert),
        ClientHelloShape {
            advertise_tls12: true,
            wire_cipher_suites: suites(&[0x1301, 0xc02b, 0xc02f]),
            ..ClientHelloShape::default()
        },
    );
    let server = server_config(&[&rustls::version::TLS12], None, cert, key);
    let err = handshake(Arc::new(client), server).expect_err("handshake must fail");
    println!("TLS 1.2 server: {err:?}");
    // The server did pick TLS 1.2 (c02b); the client refuses the version.
    assert_eq!(
        err,
        Failed::Client(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::ServerTlsVersionIsDisabledByOurConfig
        ))
    );
}

/// Pins decision 1's contract: a server choosing a wire-only (unimplemented) suite makes
/// the handshake fail cleanly on the client. The failure surfaces at the version check,
/// not at the suite check (rustls checks the version first), so this does not exercise
/// the "suite not in the provider" path itself.
#[test]
fn server_selecting_an_unimplemented_suite_fails_cleanly() {
    let (cert, key) = self_signed(&rcgen::PKCS_RSA_SHA256);
    let client = shaped(
        tls13_config(&cert),
        ClientHelloShape {
            advertise_tls12: true,
            wire_cipher_suites: suites(&[0x1301, 0xc02f]),
            ..ClientHelloShape::default()
        },
    );
    let server = server_config(
        &[&rustls::version::TLS12],
        Some(vec![aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256]),
        cert,
        key,
    );
    let err = handshake(Arc::new(client), server).expect_err("handshake must fail");
    println!("TLS 1.2 server with c02f only: {err:?}");
    // rustls checks the version before the suite, so this lands on the same
    // error as a TLS 1.2 server; the contract is a clean client-side error.
    assert_eq!(
        err,
        Failed::Client(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::ServerTlsVersionIsDisabledByOurConfig
        ))
    );
}

#[test]
fn handshake_completes_with_all_three_fields() {
    let (cert, key) = self_signed(&rcgen::PKCS_ECDSA_P256_SHA256);
    let client = shaped(
        tls13_config(&cert),
        ClientHelloShape {
            grease: true,
            wire_cipher_suites: suites(&[0x1301, 0xc02b, 0xc02f, 0x002f, 0x000a]),
            advertise_tls12: true,
            grease_signature_algorithms: true,
            ..ClientHelloShape::default()
        },
    );
    let server = server_config(&[&rustls::version::TLS13], None, cert, key);
    let (client, _) = handshake(Arc::new(client), server).expect("handshake");
    assert_eq!(
        client.negotiated_cipher_suite().map(|s| s.suite()),
        Some(CipherSuite::TLS13_AES_128_GCM_SHA256)
    );
    assert_eq!(client.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_3));
}

// ---------------------------------------------------------------------------
// ALPS (`alps`)
// ---------------------------------------------------------------------------

const ALPS: u16 = 17613;

fn alps_shape(alps: &[(&[u8], &[u8])]) -> ClientHelloShape {
    ClientHelloShape {
        alps: alps.iter().map(|(p, s)| (p.to_vec(), s.to_vec())).collect(),
        ..ClientHelloShape::default()
    }
}

fn with_alpn(mut config: rustls::ClientConfig, alpn: &[&[u8]]) -> rustls::ClientConfig {
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config
}

#[test]
fn alps_lists_the_offered_protocols_in_alpn_order() {
    let cert = test_cert();
    let hello = |alpn: &[&[u8]], alps: &[(&[u8], &[u8])]| {
        capture(shaped(with_alpn(tls13_config(&cert), alpn), alps_shape(alps)))
    };

    // Chrome over TCP: `h2, http/1.1` offered, ALPS for h2 only.
    let ch = hello(&[b"h2", b"http/1.1"], &[(b"h2", b"")]);
    assert_eq!(extension(&ch, ALPS), Some(&[0x00, 0x03, 0x02, b'h', b'2'][..]));

    // ALPN order, not the `alps` order; protocols without settings are left out.
    let ch = hello(&[b"h2", b"x", b"h3"], &[(b"h3", b"3"), (b"h2", b"2"), (b"y", b"")]);
    assert_eq!(
        extension(&ch, ALPS),
        Some(&[0x00, 0x06, 0x02, b'h', b'2', 0x02, b'h', b'3'][..])
    );

    // No offered protocol has settings, or no ALPN at all: no extension.
    assert_eq!(extension(&hello(&[b"http/1.1"], &[(b"h2", b"")]), ALPS), None);
    assert_eq!(extension(&hello(&[], &[(b"h2", b"")]), ALPS), None);
    // Empty `alps` (the default): no extension.
    assert_eq!(extension(&hello(&[b"h2"], &[]), ALPS), None);
}

/// A raw `extra_extensions` entry of type 17613 replaces the built-in encoding.
#[test]
fn raw_alps_extension_overrides_the_field() {
    let cert = test_cert();
    let mut shape = alps_shape(&[(b"h2", b"")]);
    shape.extra_extensions = vec![(ALPS, vec![0x00, 0x03, 0x02, b'h', b'3'])];
    let ch = capture(shaped(with_alpn(tls13_config(&cert), &[b"h2"]), shape));
    let types = extension_types(&ch);
    assert_eq!(types.iter().filter(|t| **t == ALPS).count(), 1, "{types:?}");
    assert_eq!(extension(&ch, ALPS), Some(&[0x00, 0x03, 0x02, b'h', b'3'][..]));
}

/// The field encodes exactly what the raw extension did (same body, same place in a
/// fixed order).
#[test]
fn alps_field_matches_the_raw_extension() {
    let cert = test_cert();
    let order = ExtensionOrder::Fixed(vec![0, 16, ALPS, 10, 13, 51, 45, 43, 5, 23, 11]);
    let field = ClientHelloShape {
        extension_order: order.clone(),
        ..alps_shape(&[(b"h2", b"")])
    };
    let raw = ClientHelloShape {
        extension_order: order,
        extra_extensions: vec![(ALPS, vec![0x00, 0x03, 0x02, b'h', b'2'])],
        ..ClientHelloShape::default()
    };
    let config = || with_alpn(tls13_config(&cert), &[b"h2", b"http/1.1"]);
    let a = capture(shaped(config(), field));
    let b = capture(shaped(config(), raw));
    assert_eq!(extension_types(&a), extension_types(&b));
    assert_eq!(extensions_of(&a), extensions_of(&b));
}

fn extensions_of(ch: &[u8]) -> Vec<(u16, Vec<u8>)> {
    crate::tests::client_hello::parse_client_hello(ch)
        .extensions
        .into_iter()
        // random-valued extensions differ per connection
        .filter(|(t, _)| *t != 51)
        .map(|(t, b)| (t, b.to_vec()))
        .collect()
}

/// A rustls server does not speak ALPS: it ignores the offer, and the client sends no
/// EncryptedExtensions of its own (the rustls server would reject it as unexpected).
#[test]
fn alps_offer_to_a_server_without_alps_completes() {
    let (cert, key) = self_signed(&rcgen::PKCS_ECDSA_P256_SHA256);
    let client = shaped(
        with_alpn(tls13_config(&cert), &[b"h2", b"http/1.1"]),
        alps_shape(&[(b"h2", b"settings")]),
    );
    let mut server = server_config(&[&rustls::version::TLS13], None, cert, key);
    server.alpn_protocols = vec![b"h2".to_vec()];
    let (mut client, mut server) = handshake(Arc::new(client), server).expect("handshake");
    assert_eq!(client.alpn_protocol(), Some(&b"h2"[..]));

    // Application data flows both ways after the handshake.
    use std::io::{Read, Write};
    client.writer().write_all(b"ping").unwrap();
    let mut buf = Vec::new();
    client.write_tls(&mut buf).unwrap();
    server.read_tls(&mut &buf[..]).unwrap();
    server
        .process_new_packets()
        .expect("server accepts the client's records");
    let mut got = [0u8; 4];
    server.reader().read_exact(&mut got).unwrap();
    assert_eq!(&got, b"ping");
}

// --- Scripted TLS 1.3 server answering ALPS --------------------------------
//
// rustls' server cannot answer ALPS, so these tests play the server by hand:
// ServerHello, then EncryptedExtensions (optionally with `application_settings`),
// Certificate, CertificateVerify and Finished under the server handshake key, and they
// decrypt the client's flight with the client handshake key. The client trusts any
// certificate and signature, so the Certificate / CertificateVerify bodies are
// placeholders; everything else (key schedule, transcript, both Finished MACs) is
// real TLS 1.3 with TLS_CHACHA20_POLY1305_SHA256 / X25519.

mod scripted {
    use std::sync::Arc;

    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::crypto::cipher::{
        AeadKey, InboundOpaqueMessage, Iv, MessageDecrypter, MessageEncrypter, OutboundPlainMessage,
    };
    use rustls::crypto::tls13::{HkdfExpander, OkmBlock};
    use rustls::crypto::{CryptoProvider, aws_lc_rs};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{ContentType, DigitallySignedStruct, ProtocolVersion, SignatureScheme};

    use crate::tests::client_hello::{Reader, extension};

    #[derive(Debug)]
    struct AcceptAll;

    impl ServerCertVerifier for AcceptAll {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::ECDSA_NISTP256_SHA256]
        }
    }

    fn suite() -> &'static rustls::Tls13CipherSuite {
        aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256
            .tls13()
            .unwrap()
    }

    /// TLS 1.3-only client (ChaCha20-Poly1305, X25519) trusting anything.
    pub(super) fn client_config(alpn: &[&[u8]]) -> rustls::ClientConfig {
        let provider = Arc::new(CryptoProvider {
            cipher_suites: vec![aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256],
            kx_groups: vec![aws_lc_rs::kx_group::X25519],
            ..aws_lc_rs::default_provider()
        });
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAll))
            .with_no_client_auth();
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        config
    }

    fn hash(data: &[u8]) -> Vec<u8> {
        suite().common.hash_provider.hash(data).as_ref().to_vec()
    }

    fn expand_label(prk: &[u8], label: &str, context: &[u8], len: usize) -> Vec<u8> {
        let expander = suite().hkdf_provider.expander_for_okm(&OkmBlock::new(prk));
        expand_label_with(expander.as_ref(), label, context, len)
    }

    fn expand_label_with(
        expander: &dyn HkdfExpander,
        label: &str,
        context: &[u8],
        len: usize,
    ) -> Vec<u8> {
        let mut out = vec![0u8; len];
        let len_be = (len as u16).to_be_bytes();
        let label_len = [(6 + label.len()) as u8];
        let context_len = [context.len() as u8];
        expander
            .expand_slice(
                &[&len_be, &label_len, b"tls13 ", label.as_bytes(), &context_len, context],
                &mut out,
            )
            .unwrap();
        out
    }

    fn key_iv(secret: &[u8]) -> (AeadKey, Iv) {
        let key: [u8; 32] = expand_label(secret, "key", &[], 32).try_into().unwrap();
        (AeadKey::from(key), Iv::copy(&expand_label(secret, "iv", &[], 12)))
    }

    fn finished_mac(secret: &[u8], transcript: &[u8]) -> Vec<u8> {
        let key = expand_label(secret, "finished", &[], 32);
        suite()
            .hkdf_provider
            .hmac_sign(&OkmBlock::new(&key), &hash(transcript))
            .as_ref()
            .to_vec()
    }

    fn handshake_msg(typ: u8, body: &[u8]) -> Vec<u8> {
        let len = body.len() as u32;
        let mut out = vec![typ, (len >> 16) as u8, (len >> 8) as u8, len as u8];
        out.extend_from_slice(body);
        out
    }

    fn ext(typ: u16, body: &[u8]) -> Vec<u8> {
        let mut out = typ.to_be_bytes().to_vec();
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    fn records(mut data: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut out = Vec::new();
        while !data.is_empty() {
            let len = usize::from(u16::from_be_bytes([data[3], data[4]]));
            out.push((data[0], data[5..5 + len].to_vec()));
            data = &data[5 + len..];
        }
        out
    }

    fn handshake_msgs(mut data: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut out = Vec::new();
        while !data.is_empty() {
            let len =
                (usize::from(data[1]) << 16) | (usize::from(data[2]) << 8) | usize::from(data[3]);
            out.push((data[0], data[4..4 + len].to_vec()));
            data = &data[4 + len..];
        }
        out
    }

    /// What the scripted server sends in EncryptedExtensions.
    pub(super) struct ServerAnswer<'a> {
        /// ALPN protocol to select (`None`: no ALPN extension).
        pub(super) alpn: Option<&'a [u8]>,
        /// `application_settings` body (`None`: no ALPS extension).
        pub(super) alps: Option<&'a [u8]>,
    }

    /// The client's flight after the server's: handshake messages `(type, body)`, and
    /// whether its Finished MAC covers the transcript including those messages.
    pub(super) struct ClientFlight {
        pub(super) messages: Vec<(u8, Vec<u8>)>,
        pub(super) finished_ok: bool,
        pub(super) alpn: Option<Vec<u8>>,
        pub(super) handshaking: bool,
    }

    /// The client connection under test: TLS over TCP, or QUIC (handshake bytes in
    /// the clear, as CRYPTO frames carry them).
    enum Client {
        Tcp(rustls::ClientConnection),
        Quic(rustls::quic::ClientConnection),
    }

    /// Runs one TCP handshake of `config` against the scripted server.
    pub(super) fn run(
        config: rustls::ClientConfig,
        answer: ServerAnswer<'_>,
    ) -> Result<ClientFlight, rustls::Error> {
        let client = rustls::ClientConnection::new(
            Arc::new(config),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        run_client(Client::Tcp(client), answer)
    }

    /// Runs one QUIC (v1) handshake of `config` against the scripted server.
    pub(super) fn run_quic(
        config: rustls::ClientConfig,
        answer: ServerAnswer<'_>,
    ) -> Result<ClientFlight, rustls::Error> {
        let client = rustls::quic::ClientConnection::new(
            Arc::new(config),
            rustls::quic::Version::V1,
            ServerName::try_from("localhost").unwrap(),
            vec![0x01, 0x01, 0x00],
        )
        .unwrap();
        run_client(Client::Quic(client), answer)
    }

    fn run_client(
        mut client: Client,
        answer: ServerAnswer<'_>,
    ) -> Result<ClientFlight, rustls::Error> {
        let ch = match &mut client {
            Client::Tcp(client) => {
                let mut out = Vec::new();
                client.write_tls(&mut out).unwrap();
                records(&out).remove(0).1
            },
            Client::Quic(client) => {
                let mut out = Vec::new();
                client.write_hs(&mut out);
                out
            },
        };

        // ServerHello: echo the session id, X25519 share.
        let sid = &ch[39..39 + usize::from(ch[38])];
        let mut shares = Reader::new(extension(&ch, 51).expect("key_share"));
        shares.u16();
        let client_pub = loop {
            let group = shares.u16();
            let len = usize::from(shares.u16());
            let key = shares.take(len);
            if group == 0x001d {
                break key.to_vec();
            }
        };
        let kx = aws_lc_rs::kx_group::X25519.start().unwrap();
        let mut key_share = 0x001du16.to_be_bytes().to_vec();
        key_share.extend_from_slice(&(kx.pub_key().len() as u16).to_be_bytes());
        key_share.extend_from_slice(kx.pub_key());
        let shared = kx.complete(&client_pub).unwrap();

        let mut sh = vec![0x03, 0x03];
        sh.extend_from_slice(&[0x5a; 32]);
        sh.push(sid.len() as u8);
        sh.extend_from_slice(sid);
        sh.extend_from_slice(&[0x13, 0x03, 0x00]);
        let exts = [ext(43, &[0x03, 0x04]), ext(51, &key_share)].concat();
        sh.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        sh.extend_from_slice(&exts);
        let sh = handshake_msg(2, &sh);
        let mut transcript = [&ch[..], &sh[..]].concat();

        // Key schedule up to the handshake traffic secrets.
        let hkdf = suite().hkdf_provider;
        let early = hkdf.extract_from_zero_ikm(None);
        let derived = expand_label_with(early.as_ref(), "derived", &hash(&[]), 32);
        let hs = hkdf.extract_from_secret(Some(&derived), shared.secret_bytes());
        let th = hash(&transcript);
        let s_hs = expand_label_with(hs.as_ref(), "s hs traffic", &th, 32);
        let c_hs = expand_label_with(hs.as_ref(), "c hs traffic", &th, 32);

        // EncryptedExtensions, Certificate, CertificateVerify, Finished.
        let mut ee = Vec::new();
        if let Some(alpn) = answer.alpn {
            let mut list = ((alpn.len() + 1) as u16).to_be_bytes().to_vec();
            list.push(alpn.len() as u8);
            list.extend_from_slice(alpn);
            ee.extend(ext(16, &list));
        }
        if let Some(alps) = answer.alps {
            ee.extend(ext(super::ALPS, alps));
        }
        if matches!(client, Client::Quic(_)) {
            // quic_transport_parameters, opaque to rustls.
            ee.extend(ext(57, &[0x01, 0x01, 0x00]));
        }
        let mut ee_body = (ee.len() as u16).to_be_bytes().to_vec();
        ee_body.extend(ee);
        transcript.extend(handshake_msg(8, &ee_body));
        // One placeholder "certificate" (the client verifies nothing).
        let cert = [0x30, 0x03, 0x02, 0x01, 0x01];
        let mut cert_msg = vec![0x00, 0x00, 0x00, (cert.len() + 5) as u8, 0x00, 0x00];
        cert_msg.push(cert.len() as u8);
        cert_msg.extend_from_slice(&cert);
        cert_msg.extend_from_slice(&[0x00, 0x00]);
        transcript.extend(handshake_msg(11, &cert_msg));
        transcript.extend(handshake_msg(15, &[0x04, 0x03, 0x00, 0x02, 0x30, 0x00]));
        let server_fin = finished_mac(&s_hs, &transcript);
        transcript.extend(handshake_msg(20, &server_fin));
        let server_flight = &transcript[ch.len() + sh.len()..];

        let mut client = match client {
            Client::Tcp(client) => client,
            Client::Quic(mut client) => {
                client.read_hs(&sh)?;
                client.read_hs(server_flight)?;
                let mut plain = Vec::new();
                // The client's Handshake-epoch flight, then the 1-RTT key change.
                for _ in 0..4 {
                    client.write_hs(&mut plain);
                }
                return Ok(client_flight(
                    &c_hs,
                    transcript,
                    &plain,
                    client.alpn_protocol(),
                    client.is_handshaking(),
                ));
            },
        };
        let (key, iv) = key_iv(&s_hs);
        let mut enc: Box<dyn MessageEncrypter> = suite().aead_alg.encrypter(key, iv);
        let record = enc
            .encrypt(
                OutboundPlainMessage {
                    typ: ContentType::Handshake,
                    version: ProtocolVersion::TLSv1_2,
                    payload: server_flight.into(),
                },
                0,
            )
            .unwrap()
            .encode();
        let mut sh_record = vec![0x16, 0x03, 0x03];
        sh_record.extend_from_slice(&(sh.len() as u16).to_be_bytes());
        sh_record.extend_from_slice(&sh);
        let input = [sh_record, record].concat();
        client.read_tls(&mut &input[..]).unwrap();
        client.process_new_packets()?;

        // The client's flight under the client handshake key (a fake CCS first).
        let mut out = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut out).unwrap();
        }
        let (key, iv) = key_iv(&c_hs);
        let mut dec: Box<dyn MessageDecrypter> = suite().aead_alg.decrypter(key, iv);
        let mut plain = Vec::new();
        let mut seq = 0;
        for (typ, mut payload) in records(&out) {
            if typ == 0x14 {
                continue;
            }
            assert_eq!(typ, 0x17, "encrypted record");
            let msg = dec
                .decrypt(
                    InboundOpaqueMessage::new(
                        ContentType::ApplicationData,
                        ProtocolVersion::TLSv1_2,
                        &mut payload,
                    ),
                    seq,
                )
                .unwrap();
            seq += 1;
            assert_eq!(msg.typ, ContentType::Handshake);
            plain.extend_from_slice(msg.payload);
        }
        Ok(client_flight(
            &c_hs,
            transcript,
            &plain,
            client.alpn_protocol(),
            client.is_handshaking(),
        ))
    }

    fn client_flight(
        c_hs: &[u8],
        mut transcript: Vec<u8>,
        plain: &[u8],
        alpn: Option<&[u8]>,
        handshaking: bool,
    ) -> ClientFlight {
        let messages = handshake_msgs(plain);
        let (fin_typ, fin) = messages.last().expect("client Finished");
        assert_eq!(*fin_typ, 20, "client flight ends with Finished");
        let before_fin = plain.len() - fin.len() - 4;
        transcript.extend_from_slice(&plain[..before_fin]);
        ClientFlight {
            finished_ok: finished_mac(c_hs, &transcript) == *fin,
            messages,
            alpn: alpn.map(|p| p.to_vec()),
            handshaking,
        }
    }
}

/// The server answers ALPS for the negotiated protocol: the client sends its own
/// EncryptedExtensions (only `application_settings`, its settings for that protocol)
/// before Finished, and its Finished covers that message.
#[test]
fn alps_answer_gets_the_client_settings() {
    for settings in [&b""[..], &b"\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00"[..]] {
        let client = shaped(
            scripted::client_config(&[b"h2", b"http/1.1"]),
            alps_shape(&[(b"h2", settings), (b"http/1.1", b"unused")]),
        );
        let flight = scripted::run(
            client,
            scripted::ServerAnswer {
                alpn: Some(b"h2"),
                alps: Some(b"server settings"),
            },
        )
        .expect("handshake");
        assert!(!flight.handshaking);
        assert_eq!(flight.alpn.as_deref(), Some(&b"h2"[..]));
        let mut ee = (settings.len() as u16 + 4).to_be_bytes().to_vec();
        ee.extend_from_slice(&ALPS.to_be_bytes());
        ee.extend_from_slice(&(settings.len() as u16).to_be_bytes());
        ee.extend_from_slice(settings);
        assert_eq!(flight.messages.len(), 2, "EncryptedExtensions, Finished");
        assert_eq!(flight.messages[0], (8, ee));
        assert!(flight.finished_ok, "client Finished covers its EncryptedExtensions");
    }
}

/// Without an ALPS answer the client's flight is Finished alone.
#[test]
fn no_alps_answer_no_client_encrypted_extensions() {
    let client = shaped(scripted::client_config(&[b"h2"]), alps_shape(&[(b"h2", b"s")]));
    let flight = scripted::run(client, scripted::ServerAnswer { alpn: Some(b"h2"), alps: None })
        .expect("handshake");
    assert_eq!(flight.messages.iter().map(|(t, _)| *t).collect::<Vec<_>>(), [20]);
    assert!(flight.finished_ok);

    // The same server against an unshaped client: upstream behaviour.
    let flight = scripted::run(
        scripted::client_config(&[b"h2"]),
        scripted::ServerAnswer { alpn: Some(b"h2"), alps: None },
    )
    .expect("handshake");
    assert_eq!(flight.messages.iter().map(|(t, _)| *t).collect::<Vec<_>>(), [20]);
    assert!(flight.finished_ok);
}

/// An ALPS answer the client did not ask for fails the handshake with an error.
#[test]
fn unsolicited_alps_answer_fails() {
    let unsolicited =
        rustls::Error::PeerMisbehaved(rustls::PeerMisbehaved::UnsolicitedEncryptedExtension);
    let run = |config: rustls::ClientConfig, alpn: Option<&[u8]>| {
        scripted::run(config, scripted::ServerAnswer { alpn, alps: Some(b"x") }).err()
    };
    // Negotiated protocol without settings (ALPS offered for h2 only).
    let config =
        || shaped(scripted::client_config(&[b"h2", b"http/1.1"]), alps_shape(&[(b"h2", b"")]));
    assert_eq!(run(config(), Some(b"http/1.1")), Some(unsolicited.clone()));
    // No ALPN negotiated.
    assert_eq!(run(config(), None), Some(unsolicited.clone()));
    // ALPS not offered at all (no shape, or a shape without `alps`).
    assert_eq!(run(scripted::client_config(&[b"h2"]), Some(b"h2")), Some(unsolicited.clone()));
    let config = shaped(scripted::client_config(&[b"h2"]), ClientHelloShape::default());
    assert_eq!(run(config, Some(b"h2")), Some(unsolicited));
}

/// QUIC carries the same messages in CRYPTO frames: the client's EncryptedExtensions
/// comes out of `write_hs` in the Handshake epoch, before Finished (QUIC Chromium: h3,
/// empty settings).
#[test]
fn quic_alps_answer_gets_the_client_settings() {
    let client = shaped(scripted::client_config(&[b"h3"]), alps_shape(&[(b"h3", b"")]));
    let flight = scripted::run_quic(
        client,
        scripted::ServerAnswer {
            alpn: Some(b"h3"),
            alps: Some(b"\x00\x04\x00"),
        },
    )
    .expect("handshake");
    assert!(!flight.handshaking);
    assert_eq!(flight.alpn.as_deref(), Some(&b"h3"[..]));
    assert_eq!(flight.messages.len(), 2, "EncryptedExtensions, Finished");
    assert_eq!(flight.messages[0], (8, vec![0x00, 0x04, 0x44, 0xcd, 0x00, 0x00]));
    assert!(flight.finished_ok);

    // No answer: Finished alone.
    let client = shaped(scripted::client_config(&[b"h3"]), alps_shape(&[(b"h3", b"")]));
    let flight =
        scripted::run_quic(client, scripted::ServerAnswer { alpn: Some(b"h3"), alps: None })
            .expect("handshake");
    assert_eq!(flight.messages.iter().map(|(t, _)| *t).collect::<Vec<_>>(), [20]);
    assert!(flight.finished_ok);
}

// ---------------------------------------------------------------------------
// ALPS settings size
// ---------------------------------------------------------------------------

fn profile_with_alps_settings(len: usize) -> crate::tls_hello::HelloProfile {
    let settings: &'static [u8] = Box::leak(vec![0u8; len].into_boxed_slice());
    let alps: &'static [(&'static [u8], &'static [u8])] =
        Box::leak(vec![(&b"h2"[..], settings)].into_boxed_slice());
    crate::tls_hello::HelloProfile { alps, ..crate::tcp_tls_profile::CHROMIUM }
}

#[test]
fn alps_settings_at_the_u16_limit_are_accepted() {
    let cert = test_cert();
    let mut config = tls13_config(&cert);
    super::apply_tls_hello_profile(&mut config, &profile_with_alps_settings(65531));
}

#[test]
#[should_panic(expected = "do not fit the u16 length fields")]
fn alps_settings_longer_than_the_u16_fields_are_rejected() {
    let cert = test_cert();
    let mut config = tls13_config(&cert);
    super::apply_tls_hello_profile(&mut config, &profile_with_alps_settings(65532));
}
