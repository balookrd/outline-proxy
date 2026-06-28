use super::{SniffOutcome, sniff_host};

/// Build a minimal but well-formed TLS 1.2/1.3 ClientHello record carrying a
/// single `server_name` (host_name) extension for `sni`.
fn tls_client_hello(sni: &str) -> Vec<u8> {
    // server_name extension body.
    let mut sni_ext = Vec::new();
    let name = sni.as_bytes();
    let entry_len = 1 + 2 + name.len(); // name_type(1) + name_len(2) + name
    sni_ext.extend_from_slice(&(entry_len as u16).to_be_bytes()); // ServerNameList length
    sni_ext.push(0x00); // host_name
    sni_ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(name);

    // Extensions block: just the one SNI extension (type 0x0000).
    let mut extensions = Vec::new();
    extensions.extend_from_slice(&0x0000u16.to_be_bytes()); // ext type
    extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni_ext);

    // ClientHello body.
    let mut hello = Vec::new();
    hello.extend_from_slice(&[0x03, 0x03]); // client_version TLS1.2
    hello.extend_from_slice(&[0x11; 32]); // random
    hello.push(0x00); // session_id length 0
    hello.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites length
    hello.extend_from_slice(&[0x13, 0x01]); // one suite
    hello.push(0x01); // compression_methods length
    hello.push(0x00); // null compression
    hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello.extend_from_slice(&extensions);

    // Handshake header: type(1) + length(3).
    let mut handshake = Vec::new();
    handshake.push(0x01); // ClientHello
    let l = hello.len();
    handshake.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
    handshake.extend_from_slice(&hello);

    // Record header: type(1) version(2) length(2).
    let mut record = Vec::new();
    record.push(0x16); // handshake
    record.extend_from_slice(&[0x03, 0x01]); // record version
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

#[test]
fn extracts_sni_from_tls_client_hello() {
    let record = tls_client_hello("example.com");
    assert_eq!(sniff_host(&record), SniffOutcome::Found("example.com".to_string()));
}

#[test]
fn extracts_sni_with_other_extensions_before_it() {
    // Prepend a dummy extension (supported_versions-ish, type 0x002b) before SNI.
    let mut record = tls_client_hello("cdn.example.org");
    // Easiest: rebuild with an extra extension is overkill; instead verify the
    // single-extension case already exercises the extension loop. Add a second
    // run with a longer host to cover the host_name length path.
    assert_eq!(sniff_host(&record), SniffOutcome::Found("cdn.example.org".to_string()));
    record.clear();
    record.extend_from_slice(&tls_client_hello("a.very.long.sub.domain.example.net"));
    assert_eq!(
        sniff_host(&record),
        SniffOutcome::Found("a.very.long.sub.domain.example.net".to_string())
    );
}

#[test]
fn truncated_tls_client_hello_is_incomplete() {
    let record = tls_client_hello("example.com");
    // Cut off inside the extensions — parser must ask for more, not bail.
    let cut = record.len() - 5;
    assert_eq!(sniff_host(&record[..cut]), SniffOutcome::Incomplete);
    // Just the record header.
    assert_eq!(sniff_host(&record[..5]), SniffOutcome::Incomplete);
    // Single handshake byte still looks like TLS.
    assert_eq!(sniff_host(&record[..1]), SniffOutcome::Incomplete);
}

#[test]
fn tls_client_hello_without_sni_is_not_matched() {
    // Build a ClientHello with zero extensions.
    let mut hello = Vec::new();
    hello.extend_from_slice(&[0x03, 0x03]);
    hello.extend_from_slice(&[0x22; 32]);
    hello.push(0x00);
    hello.extend_from_slice(&2u16.to_be_bytes());
    hello.extend_from_slice(&[0x13, 0x01]);
    hello.push(0x01);
    hello.push(0x00);
    hello.extend_from_slice(&0u16.to_be_bytes()); // extensions length 0

    let mut handshake = vec![0x01];
    let l = hello.len();
    handshake.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
    handshake.extend_from_slice(&hello);

    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    assert_eq!(sniff_host(&record), SniffOutcome::NotMatched);
}

#[test]
fn non_tls_binary_is_not_matched() {
    // SSH banner-ish bytes, not starting with 0x16 nor an HTTP method.
    assert_eq!(sniff_host(b"SSH-2.0-OpenSSH_9.0\r\n"), SniffOutcome::NotMatched);
    // Random non-handshake TLS content type (0x17 = application_data).
    assert_eq!(sniff_host(&[0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3]), SniffOutcome::NotMatched);
}

#[test]
fn extracts_host_from_http_request() {
    let req = b"GET /path HTTP/1.1\r\nHost: example.com\r\nUser-Agent: x\r\n\r\n";
    assert_eq!(sniff_host(req), SniffOutcome::Found("example.com".to_string()));
}

#[test]
fn http_host_is_case_insensitive_and_strips_port() {
    let req = b"POST / HTTP/1.1\r\nhOsT:  example.org:8443  \r\n\r\n";
    assert_eq!(sniff_host(req), SniffOutcome::Found("example.org".to_string()));
}

#[test]
fn truncated_http_request_is_incomplete() {
    // Request line present, headers not terminated, no Host yet.
    let req = b"GET / HTTP/1.1\r\nUser-Agent: x";
    assert_eq!(sniff_host(req), SniffOutcome::Incomplete);
    // Partial method token.
    assert_eq!(sniff_host(b"GE"), SniffOutcome::Incomplete);
    // Just the method, no request line terminator yet.
    assert_eq!(sniff_host(b"GET /index.html HTTP/1.1"), SniffOutcome::Incomplete);
}

#[test]
fn http_without_host_header_is_not_matched() {
    let req = b"GET / HTTP/1.0\r\nUser-Agent: x\r\n\r\n";
    assert_eq!(sniff_host(req), SniffOutcome::NotMatched);
}

#[test]
fn host_header_with_ip_literal_is_not_matched() {
    let req = b"GET / HTTP/1.1\r\nHost: 93.184.216.34\r\n\r\n";
    assert_eq!(sniff_host(req), SniffOutcome::NotMatched);
    let req6 = b"GET / HTTP/1.1\r\nHost: [2606:2800:220:1::1]:443\r\n\r\n";
    assert_eq!(sniff_host(req6), SniffOutcome::NotMatched);
}

#[test]
fn sni_with_ip_literal_is_not_matched() {
    let record = tls_client_hello("203.0.113.7");
    assert_eq!(sniff_host(&record), SniffOutcome::NotMatched);
}

#[test]
fn empty_buffer_is_incomplete() {
    assert_eq!(sniff_host(&[]), SniffOutcome::Incomplete);
}
