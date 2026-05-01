use std::{path::PathBuf, sync::Arc};

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use rustls::{
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer},
    sign::CertifiedKey,
};

use super::{
    MultiCertResolver, build_listener_tls_config, ensure_rustls_provider_installed,
    extract_sni_names,
};
use crate::config::TlsCertEntry;

fn install_provider() {
    ensure_rustls_provider_installed();
}

fn signing_key(key: PrivateKeyDer<'static>) -> Arc<dyn rustls::sign::SigningKey> {
    let provider = CryptoProvider::get_default().expect("rustls provider installed");
    provider.key_provider.load_private_key(key).expect("load private key")
}

/// Generate a self-signed cert covering the given DNS SANs and return
/// the in-memory `CertifiedKey` ready for the resolver.
fn gen_cert(sans: &[&str]) -> CertifiedKey {
    install_provider();
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, sans.first().copied().unwrap_or("self-signed"));
    params.subject_alt_names = sans
        .iter()
        .map(|s| SanType::DnsName(s.to_string().try_into().unwrap()))
        .collect();
    let key_pair = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(key_pair.serialize_der()).unwrap();
    CertifiedKey::new(vec![cert_der], signing_key(key_der))
}

/// Write a fresh cert+key PEM pair into a temp dir under `target/`,
/// return their paths so a `TlsCertEntry` can point at them on disk.
fn cert_files(name: &str, sans: &[&str]) -> (PathBuf, PathBuf) {
    install_provider();
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, sans.first().copied().unwrap_or("self-signed"));
    params.subject_alt_names = sans
        .iter()
        .map(|s| SanType::DnsName(s.to_string().try_into().unwrap()))
        .collect();
    let key_pair = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();

    let dir = std::env::temp_dir().join(format!("outline-ss-tls-{}-{}", name, std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cert_path = dir.join(format!("{name}.cert.pem"));
    let key_path = dir.join(format!("{name}.key.pem"));
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();
    (cert_path, key_path)
}

#[test]
fn extract_sni_names_returns_dns_sans() {
    let ck = gen_cert(&["api.example.com", "www.example.com"]);
    let names = extract_sni_names(&ck.cert);
    assert_eq!(names, vec!["api.example.com", "www.example.com"]);
}

#[test]
fn extract_sni_names_lowercases() {
    let ck = gen_cert(&["MIXED.Example.COM"]);
    let names = extract_sni_names(&ck.cert);
    assert_eq!(names, vec!["mixed.example.com"]);
}

#[test]
fn resolver_picks_cert_by_sni() {
    let api = gen_cert(&["api.example.com"]);
    let www = gen_cert(&["www.example.com"]);
    let resolver = MultiCertResolver::from_entries(
        vec![(api, vec![]), (www, vec![])],
        None,
        "server",
    )
    .unwrap();

    let api_pick = resolver.pick(Some("api.example.com")).expect("api hit");
    let www_pick = resolver.pick(Some("www.example.com")).expect("www hit");
    assert!(!Arc::ptr_eq(&api_pick, &www_pick));
    assert!(resolver.pick(Some("other.example.com")).is_none());
    assert!(resolver.pick(None).is_none());
}

#[test]
fn resolver_falls_back_to_default_when_sni_missing_or_unmatched() {
    let api = gen_cert(&["api.example.com"]);
    let default = gen_cert(&["default.example.com"]);
    let resolver = MultiCertResolver::from_entries(
        vec![(api, vec![])],
        Some(default),
        "server",
    )
    .unwrap();

    let unknown = resolver.pick(Some("nope.example.com")).expect("falls back");
    let no_sni = resolver.pick(None).expect("falls back without SNI");
    assert!(Arc::ptr_eq(&unknown, &no_sni));
    let api_hit = resolver.pick(Some("api.example.com")).expect("api hit");
    assert!(!Arc::ptr_eq(&api_hit, &unknown));
}

#[test]
fn resolver_explicit_sni_overrides_san() {
    // Cert has SAN `internal.local` but operator wants to expose it as
    // `public.example.com` via explicit `sni = [...]`.
    let internal = gen_cert(&["internal.local"]);
    let resolver = MultiCertResolver::from_entries(
        vec![(internal, vec!["public.example.com".into()])],
        None,
        "server",
    )
    .unwrap();

    assert!(resolver.pick(Some("public.example.com")).is_some());
    // The SAN itself is NOT auto-registered when `sni` is set.
    assert!(resolver.pick(Some("internal.local")).is_none());
}

#[test]
fn resolver_rejects_duplicate_sni_across_entries() {
    let a = gen_cert(&["dup.example.com"]);
    let b = gen_cert(&["dup.example.com"]);
    let err = MultiCertResolver::from_entries(
        vec![(a, vec![]), (b, vec![])],
        None,
        "server",
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("dup.example.com"), "unexpected error: {err}");
}

#[test]
fn resolver_skips_wildcard_san() {
    let wild = gen_cert(&["*.example.com"]);
    let err = MultiCertResolver::from_entries(
        vec![(wild, vec![])],
        None,
        "server",
    )
    .unwrap_err()
    .to_string();
    // The cert has only a wildcard SAN, none of which the resolver can
    // register as an exact key — so we surface a "no SNI to derive"
    // error rather than silently building an empty resolver.
    assert!(err.contains("no DNS SAN/CN"), "unexpected error: {err}");
}

#[test]
fn build_listener_tls_config_single_cert_path() {
    install_provider();
    let (cert, key) = cert_files("single", &["solo.example.com"]);
    let cfg = build_listener_tls_config(
        Some(&cert),
        Some(&key),
        &[],
        &[b"http/1.1".as_slice()],
        "server",
    )
    .expect("single cert builds");
    assert_eq!(cfg.alpn_protocols, vec![b"http/1.1".to_vec()]);
}

#[test]
fn build_listener_tls_config_array_with_default() {
    install_provider();
    let (default_cert, default_key) = cert_files("def", &["default.example.com"]);
    let (api_cert, api_key) = cert_files("api", &["api.example.com"]);
    let entries = vec![TlsCertEntry {
        cert_path: api_cert,
        key_path: api_key,
        sni: vec![],
    }];
    let cfg = build_listener_tls_config(
        Some(&default_cert),
        Some(&default_key),
        &entries,
        &[b"h2".as_slice()],
        "server",
    )
    .expect("multi-cert + default builds");
    assert_eq!(cfg.alpn_protocols, vec![b"h2".to_vec()]);
}

/// End-to-end: stand up a real TLS listener with two SNI-selected
/// certs plus a default fallback, dial it three times with different
/// SNIs, and verify the leaf cert returned matches the expected one
/// each time.
#[tokio::test]
async fn end_to_end_handshake_selects_cert_per_sni() {
    use std::io::Cursor;

    use rustls::{
        ClientConfig, RootCertStore,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{ServerName, UnixTime},
    };
    use tokio::{io::AsyncWriteExt, net::TcpListener};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    install_provider();

    let (default_cert, default_key) = cert_files("e2e-def", &["default.example.com"]);
    let (api_cert, api_key) = cert_files("e2e-api", &["api.example.com"]);
    let (www_cert, www_key) = cert_files("e2e-www", &["www.example.com"]);

    let entries = vec![
        TlsCertEntry { cert_path: api_cert.clone(), key_path: api_key, sni: vec![] },
        TlsCertEntry { cert_path: www_cert.clone(), key_path: www_key, sni: vec![] },
    ];
    let server_cfg = build_listener_tls_config(
        Some(&default_cert),
        Some(&default_key),
        &entries,
        &[b"http/1.1".as_slice()],
        "server",
    )
    .expect("build server config");
    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        for _ in 0..3 {
            let (sock, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut stream = match acceptor.accept(sock).await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let _ = stream.shutdown().await;
            });
        }
    });

    fn pem_to_der(pem: &str) -> CertificateDer<'static> {
        let parsed = rustls_pemfile::certs(&mut Cursor::new(pem))
            .next()
            .expect("at least one cert")
            .expect("cert parses");
        parsed
    }

    fn read_cert_der(path: &std::path::Path) -> CertificateDer<'static> {
        pem_to_der(&std::fs::read_to_string(path).unwrap())
    }

    let api_der = read_cert_der(&api_cert);
    let www_der = read_cert_der(&www_cert);
    let default_der = read_cert_der(&default_cert);

    #[derive(Debug)]
    struct CapturingVerifier {
        captured: parking_lot::Mutex<Option<CertificateDer<'static>>>,
    }
    impl ServerCertVerifier for CapturingVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            *self.captured.lock() = Some(end_entity.clone().into_owned());
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::ED25519,
            ]
        }
    }

    async fn dial(addr: std::net::SocketAddr, sni: &str) -> CertificateDer<'static> {
        let verifier = Arc::new(CapturingVerifier { captured: parking_lot::Mutex::new(None) });
        let mut client_cfg = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth();
        client_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let _ = RootCertStore::empty();
        let connector = TlsConnector::from(Arc::new(client_cfg));
        let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        let server_name = ServerName::try_from(sni.to_owned()).unwrap();
        let mut stream = connector.connect(server_name, sock).await.unwrap();
        let _ = stream.shutdown().await;
        verifier.captured.lock().take().expect("verifier captured cert")
    }

    let got_api = dial(addr, "api.example.com").await;
    assert_eq!(got_api.as_ref(), api_der.as_ref(), "SNI api → api cert");
    let got_www = dial(addr, "www.example.com").await;
    assert_eq!(got_www.as_ref(), www_der.as_ref(), "SNI www → www cert");
    let got_unknown = dial(addr, "unmatched.example.com").await;
    assert_eq!(
        got_unknown.as_ref(),
        default_der.as_ref(),
        "unmatched SNI → default cert"
    );

    server.abort();
}

#[test]
fn build_listener_tls_config_array_only() {
    install_provider();
    let (api_cert, api_key) = cert_files("only", &["only.example.com"]);
    let entries = vec![TlsCertEntry {
        cert_path: api_cert,
        key_path: api_key,
        sni: vec![],
    }];
    let cfg = build_listener_tls_config(
        None,
        None,
        &entries,
        &[b"h2".as_slice()],
        "server",
    )
    .expect("multi-cert only builds");
    assert_eq!(cfg.alpn_protocols, vec![b"h2".to_vec()]);
}
