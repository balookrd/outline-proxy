//! ClientHello parsing, JA4 and in-memory handshakes shared by the TLS tests: the rustls
//! patch knobs (`tls_vendored`), the TCP browser profiles (`tcp_tls_profile`) and the
//! QUIC ClientHello decoded from Initial packets (`quic/tests/tls_config.rs`).
//!
//! A ClientHello here is the handshake message with its 4-byte header (type `0x01` and
//! 24-bit length), without the TLS record header.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Minimal cursor over a byte slice.
pub(crate) struct Reader<'a> {
    pub(crate) b: &'a [u8],
    pub(crate) i: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Self {
        Self { b, i: 0 }
    }
    pub(crate) fn u8(&mut self) -> u8 {
        let v = self.b[self.i];
        self.i += 1;
        v
    }
    pub(crate) fn u16(&mut self) -> u16 {
        let v = u16::from_be_bytes([self.b[self.i], self.b[self.i + 1]]);
        self.i += 2;
        v
    }
    pub(crate) fn take(&mut self, n: usize) -> &'a [u8] {
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        s
    }
    pub(crate) fn remaining(&self) -> usize {
        self.b.len() - self.i
    }
}

/// RFC 8701 GREASE value `0x?A?A`.
pub(crate) fn is_grease_u16(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && (v >> 8) == (v & 0xff)
}

/// The parts of a ClientHello the tests look at, borrowed from the message.
pub(crate) struct ClientHello<'a> {
    /// Cipher suites in offer order.
    pub(crate) cipher_suites: Vec<u16>,
    /// `(type, body)` of every extension, in wire order.
    pub(crate) extensions: Vec<(u16, &'a [u8])>,
}

/// Parses a ClientHello handshake message (see the module docs).
pub(crate) fn parse_client_hello(ch: &[u8]) -> ClientHello<'_> {
    let mut r = Reader::new(ch);
    assert_eq!(r.u8(), 0x01, "expected ClientHello handshake");
    let len = (usize::from(r.u8()) << 16) | usize::from(r.u16());
    assert_eq!(len, r.remaining(), "ClientHello length");
    r.take(2 + 32); // legacy_version, random
    let sid_len = r.u8() as usize;
    r.take(sid_len);
    let cs_len = r.u16() as usize;
    let mut cs = Reader::new(r.take(cs_len));
    let mut cipher_suites = Vec::new();
    while cs.remaining() > 0 {
        cipher_suites.push(cs.u16());
    }
    let comp_len = r.u8() as usize;
    r.take(comp_len);
    let ext_end = r.u16() as usize + r.i;
    assert_eq!(ext_end, ch.len(), "extensions length");
    let mut extensions = Vec::new();
    while r.i < ext_end {
        let ext_type = r.u16();
        let ext_len = r.u16() as usize;
        extensions.push((ext_type, r.take(ext_len)));
    }
    ClientHello { cipher_suites, extensions }
}

/// `(type, body)` of every ClientHello extension, in wire order.
#[cfg_attr(not(feature = "quic"), allow(dead_code))] // only the QUIC tests use it
pub(crate) fn extensions(ch: &[u8]) -> Vec<(u16, Vec<u8>)> {
    parse_client_hello(ch)
        .extensions
        .into_iter()
        .map(|(t, b)| (t, b.to_vec()))
        .collect()
}

/// Extension types of a ClientHello in wire order.
pub(crate) fn extension_types(ch: &[u8]) -> Vec<u16> {
    parse_client_hello(ch)
        .extensions
        .into_iter()
        .map(|(t, _)| t)
        .collect()
}

/// The body of extension `typ`, if present.
pub(crate) fn extension(ch: &[u8], typ: u16) -> Option<&[u8]> {
    parse_client_hello(ch)
        .extensions
        .into_iter()
        .find(|(t, _)| *t == typ)
        .map(|(_, b)| b)
}

/// Cipher suites in offer order.
pub(crate) fn cipher_suites(ch: &[u8]) -> Vec<u16> {
    parse_client_hello(ch).cipher_suites
}

/// u16 list inside an extension whose body is `<u16 len><u16...>` (groups 10, sig algs 13).
pub(crate) fn u16_list_ext(ch: &[u8], ext: u16) -> Vec<u16> {
    let Some(body) = extension(ch, ext) else {
        return Vec::new();
    };
    let mut r = Reader::new(body);
    let len = r.u16() as usize;
    assert_eq!(len, r.remaining(), "extension {ext:#06x} list length");
    let mut out = Vec::new();
    while r.remaining() > 0 {
        out.push(r.u16());
    }
    out
}

/// u16 list inside an extension whose body is `<u8 len><u16...>`.
fn u8_len_u16_list_ext(ch: &[u8], ext: u16) -> Vec<u16> {
    let body = extension(ch, ext).unwrap_or_else(|| panic!("no extension {ext}"));
    let mut r = Reader::new(body);
    let len = r.u8() as usize;
    assert_eq!(len, r.remaining(), "extension {ext} list length");
    let mut out = Vec::new();
    while r.remaining() > 0 {
        out.push(r.u16());
    }
    out
}

/// `supported_versions` (43).
pub(crate) fn supported_versions(ch: &[u8]) -> Vec<u16> {
    u8_len_u16_list_ext(ch, 43)
}

/// `compress_certificate` (27) algorithms.
pub(crate) fn cert_compression_algs(ch: &[u8]) -> Vec<u16> {
    u8_len_u16_list_ext(ch, 27)
}

/// `(group, key length)` of every `key_share` entry, in order.
pub(crate) fn key_share_entries(ch: &[u8]) -> Vec<(u16, usize)> {
    let data = extension(ch, 51).expect("no key_share");
    let mut r = Reader::new(data);
    let end = r.u16() as usize + r.i;
    let mut out = Vec::new();
    while r.i < end {
        let group = r.u16();
        let len = r.u16() as usize;
        r.take(len);
        out.push((group, len));
    }
    out
}

/// Named groups offered in `key_share`, in order; empty without the extension.
pub(crate) fn key_share_groups(ch: &[u8]) -> Vec<u16> {
    if extension(ch, 51).is_none() {
        return Vec::new();
    }
    key_share_entries(ch).into_iter().map(|(g, _)| g).collect()
}

/// ALPN (16) protocol names, in order; empty without the extension.
pub(crate) fn alpn_protocols(ch: &[u8]) -> Vec<Vec<u8>> {
    let Some(body) = extension(ch, 16) else {
        return Vec::new();
    };
    let mut r = Reader::new(body);
    let len = r.u16() as usize;
    assert_eq!(len, r.remaining(), "ALPN list length");
    let mut out = Vec::new();
    while r.remaining() > 0 {
        let n = r.u8() as usize;
        out.push(r.take(n).to_vec());
    }
    out
}

/// `(kdf, aead, enc length, payload length)` of an outer GREASE ECH extension (0xfe0d).
pub(crate) fn ech_outer(ch: &[u8]) -> (u16, u16, usize, usize) {
    let body = extension(ch, 0xfe0d).expect("no encrypted_client_hello");
    let mut r = Reader::new(body);
    assert_eq!(r.u8(), 0, "outer ECH");
    let kdf = r.u16();
    let aead = r.u16();
    r.take(1); // config_id
    let enc = r.u16() as usize;
    r.take(enc);
    let payload = r.u16() as usize;
    r.take(payload);
    assert_eq!(r.remaining(), 0, "trailing bytes after ECH payload");
    (kdf, aead, enc, payload)
}

// ---------------------------------------------------------------------------
// JA4
// ---------------------------------------------------------------------------

pub(crate) fn sha256_hex12(s: &str) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, s.as_bytes());
    d.as_ref()[..6].iter().map(|b| format!("{b:02x}")).collect()
}

/// JA4 (FoxIO spec, as tshark computes it): `q` for a QUIC ClientHello (one carrying
/// `quic_transport_parameters`), else `t`, + "13" + d/i + 2-digit ciphers + 2-digit
/// extensions (GREASE excluded, SNI and ALPN counted) + ALPN first/last char, then
/// sha256[..12] of sorted ciphers, then sha256[..12] of sorted extensions without
/// SNI/ALPN joined with "_" and the signature algorithms in offer order (a GREASE
/// signature algorithm included, as tshark does).
pub(crate) fn ja4(ch: &[u8]) -> String {
    ja4_impl(ch, false)
}

/// [`ja4`] with GREASE values dropped from the signature algorithms, so a hello with a
/// GREASE signature algorithm (Chrome over TCP) has a stable JA4.
pub(crate) fn ja4_without_grease_sigalgs(ch: &[u8]) -> String {
    ja4_impl(ch, true)
}

fn ja4_impl(ch: &[u8], drop_grease_sigalgs: bool) -> String {
    let hex = |v: &[u16]| v.iter().map(|x| format!("{x:04x}")).collect::<Vec<_>>().join(",");
    let ciphers: Vec<u16> = cipher_suites(ch).into_iter().filter(|c| !is_grease_u16(*c)).collect();
    let exts: Vec<u16> = extension_types(ch)
        .into_iter()
        .filter(|e| !is_grease_u16(*e))
        .collect();
    let transport = if exts.contains(&57) { 'q' } else { 't' };
    let version = match extension(ch, 43) {
        Some(_) => supported_versions(ch)
            .into_iter()
            .filter(|v| !is_grease_u16(*v))
            .max(),
        None => None,
    };
    let version = match version {
        Some(0x0304) => "13",
        Some(0x0303) => "12",
        other => panic!("unexpected TLS version {other:?}"),
    };
    let sni = if exts.contains(&0) { 'd' } else { 'i' };
    let alpn = match alpn_protocols(ch).first() {
        Some(first) => format!("{}{}", first[0] as char, first[first.len() - 1] as char),
        None => "00".into(),
    };
    let mut sorted_ciphers = ciphers.clone();
    sorted_ciphers.sort_unstable();
    let mut sorted_exts: Vec<u16> = exts.iter().copied().filter(|e| *e != 0 && *e != 16).collect();
    sorted_exts.sort_unstable();
    let sigs: Vec<u16> = u16_list_ext(ch, 13)
        .into_iter()
        .filter(|s| !(drop_grease_sigalgs && is_grease_u16(*s)))
        .collect();
    let c = if sigs.is_empty() {
        hex(&sorted_exts)
    } else {
        format!("{}_{}", hex(&sorted_exts), hex(&sigs))
    };
    format!(
        "{transport}{version}{sni}{:02}{:02}{alpn}_{}_{}",
        ciphers.len().min(99),
        exts.len().min(99),
        sha256_hex12(&hex(&sorted_ciphers)),
        sha256_hex12(&c)
    )
}

// ---------------------------------------------------------------------------
// TCP capture and in-memory handshakes
// ---------------------------------------------------------------------------

/// The first ClientHello `config` writes for `server_name` (record header stripped).
pub(crate) fn capture_tcp_hello(config: Arc<rustls::ClientConfig>, server_name: &str) -> Vec<u8> {
    let mut conn = rustls::ClientConnection::new(
        config,
        ServerName::try_from(server_name.to_owned()).unwrap(),
    )
    .unwrap();
    let mut out = Vec::new();
    conn.write_tls(&mut out).unwrap();
    assert_eq!(out[0], 0x16, "expected a handshake record");
    let len = usize::from(u16::from_be_bytes([out[3], out[4]]));
    assert_eq!(out.len(), 5 + len, "ClientHello spans one record");
    out[5..].to_vec()
}

/// Self-signed `localhost` certificate and its PKCS#8 key.
pub(crate) fn self_signed(
    alg: &'static rcgen::SignatureAlgorithm,
) -> (CertificateDer<'static>, Vec<u8>) {
    let key = rcgen::KeyPair::generate_for(alg).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    (cert.der().clone(), key.serialize_der())
}

/// A rustls server config (aws-lc-rs, `cipher_suites` or the provider's) with one
/// certificate.
pub(crate) fn server_config(
    versions: &[&'static rustls::SupportedProtocolVersion],
    cipher_suites: Option<Vec<rustls::SupportedCipherSuite>>,
    cert: CertificateDer<'static>,
    key: Vec<u8>,
) -> rustls::ServerConfig {
    use rustls::crypto::{CryptoProvider, aws_lc_rs};
    let default = aws_lc_rs::default_provider();
    let provider = CryptoProvider {
        cipher_suites: cipher_suites.unwrap_or(default.cipher_suites.clone()),
        ..default
    };
    rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(versions)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)))
        .unwrap()
}

/// Which side failed a handshake.
#[derive(Debug, PartialEq)]
pub(crate) enum Failed {
    Client(rustls::Error),
    Server(rustls::Error),
}

fn feed(
    from: &mut impl std::ops::DerefMut<Target = rustls::ConnectionCommon<impl Sized>>,
    to: &mut impl std::ops::DerefMut<Target = rustls::ConnectionCommon<impl Sized>>,
) {
    let mut buf = Vec::new();
    while from.wants_write() {
        from.write_tls(&mut buf).unwrap();
    }
    let mut rd = &buf[..];
    while !rd.is_empty() {
        to.read_tls(&mut rd).unwrap();
    }
}

/// Runs the handshake with `localhost` in memory until both sides finish or one fails.
pub(crate) fn handshake(
    client: Arc<rustls::ClientConfig>,
    server: rustls::ServerConfig,
) -> Result<(rustls::ClientConnection, rustls::ServerConnection), Failed> {
    let mut client =
        rustls::ClientConnection::new(client, ServerName::try_from("localhost").unwrap()).unwrap();
    let mut server = rustls::ServerConnection::new(Arc::new(server)).unwrap();
    for _ in 0..16 {
        feed(&mut client, &mut server);
        if let Err(e) = server.process_new_packets() {
            return Err(Failed::Server(e));
        }
        feed(&mut server, &mut client);
        if let Err(e) = client.process_new_packets() {
            return Err(Failed::Client(e));
        }
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok((client, server));
        }
    }
    panic!("handshake did not finish");
}
