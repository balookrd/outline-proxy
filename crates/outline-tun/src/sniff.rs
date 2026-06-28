//! Connection sniffing: extract the destination host name from the first
//! client bytes of a TCP flow.
//!
//! Mirrors Xray's `sniffing` + `destOverride` behaviour for the two
//! cleartext-metadata protocols that ride TCP: TLS (ClientHello SNI) and
//! HTTP/1.x (`Host` header). When a host is recovered the TUN engine rewrites
//! the flow's destination from the literal IP the client dialled into a
//! `TargetAddr::Domain`, so the request leaves over VLESS/Shadowsocks carrying
//! the *domain* and the exit node resolves it (split-horizon / geo-correct
//! resolution, and routing rules can match on the real host).
//!
//! Everything here is pure: it inspects a byte slice and never blocks, so it
//! is cheap to unit-test exhaustively. QUIC (UDP) sniffing is intentionally
//! out of scope for this module — its Initial packet is encrypted and lives on
//! the UDP path.

/// Largest prefix of the client byte stream we are willing to buffer while
/// waiting for a parseable ClientHello / request line. The SNI extension and
/// the `Host` header sit near the front of real requests, so this is generous;
/// anything past it is treated as "not sniffable" and the flow dials by IP.
pub(crate) const SNIFF_PEEK_CAP: usize = 4096;

/// Outcome of inspecting the buffered client prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SniffOutcome {
    /// A usable host name was extracted.
    Found(String),
    /// The bytes look like the start of a TLS ClientHello / HTTP request but
    /// the structure is truncated — more client data may complete it.
    Incomplete,
    /// The bytes are definitely not a sniffable TLS ClientHello or HTTP
    /// request (or they carry no host): give up and dial by IP.
    NotMatched,
}

/// Try to recover the destination host from `data`, the in-order prefix of the
/// client byte stream.
pub(crate) fn sniff_host(data: &[u8]) -> SniffOutcome {
    match data.first() {
        None => SniffOutcome::Incomplete,
        // TLS record, content type = handshake (0x16).
        Some(0x16) => sniff_tls_sni(data),
        _ => match http_method_prefix(data) {
            HttpPrefix::Method => sniff_http_host(data),
            HttpPrefix::Maybe => SniffOutcome::Incomplete,
            HttpPrefix::No => SniffOutcome::NotMatched,
        },
    }
}

// ---------------------------------------------------------------------------
// TLS ClientHello SNI
// ---------------------------------------------------------------------------

fn sniff_tls_sni(data: &[u8]) -> SniffOutcome {
    // Record header: type(1) version(2) length(2).
    if data.len() < 5 {
        return SniffOutcome::Incomplete;
    }
    if data[0] != 0x16 || data[1] != 0x03 {
        // Not a TLS handshake record (major version is 3 for SSL3..TLS1.3).
        return SniffOutcome::NotMatched;
    }
    let record_len = usize::from(u16::from_be_bytes([data[3], data[4]]));
    // The handshake almost always fits in this first record. Bound the body to
    // the record length we have so a following record's header is never parsed
    // as handshake bytes; if the record has not fully arrived, parse what we
    // hold and let the cursor report `Incomplete`.
    let avail = (data.len() - 5).min(record_len);
    parse_client_hello(&data[5..5 + avail])
}

fn parse_client_hello(body: &[u8]) -> SniffOutcome {
    let mut c = Cursor::new(body);
    match c.u8() {
        Some(0x01) => {},                           // ClientHello
        Some(_) => return SniffOutcome::NotMatched, // some other handshake msg
        None => return SniffOutcome::Incomplete,
    }
    if c.skip(3).is_none() {
        return SniffOutcome::Incomplete; // handshake length (u24)
    }
    // client_version (2) + random (32).
    if c.skip(2 + 32).is_none() {
        return SniffOutcome::Incomplete;
    }
    // legacy_session_id <0..32>.
    match c.u8() {
        Some(len) if c.skip(usize::from(len)).is_some() => {},
        Some(_) => return SniffOutcome::Incomplete,
        None => return SniffOutcome::Incomplete,
    }
    // cipher_suites <2..2^16-2>.
    match c.u16() {
        Some(len) if c.skip(usize::from(len)).is_some() => {},
        Some(_) => return SniffOutcome::Incomplete,
        None => return SniffOutcome::Incomplete,
    }
    // legacy_compression_methods <1..2^8-1>.
    match c.u8() {
        Some(len) if c.skip(usize::from(len)).is_some() => {},
        Some(_) => return SniffOutcome::Incomplete,
        None => return SniffOutcome::Incomplete,
    }
    // extensions <8..2^16-1>.
    let ext_total = match c.u16() {
        Some(len) => usize::from(len),
        None => return SniffOutcome::Incomplete,
    };
    let ext_end = c.pos + ext_total;
    while c.pos < ext_end {
        let etype = match c.u16() {
            Some(v) => v,
            None => return SniffOutcome::Incomplete,
        };
        let elen = match c.u16() {
            Some(v) => usize::from(v),
            None => return SniffOutcome::Incomplete,
        };
        if etype == 0x0000 {
            // server_name extension.
            return match c.take(elen) {
                Some(ext) => parse_sni_extension(ext),
                None => SniffOutcome::Incomplete,
            };
        }
        if c.skip(elen).is_none() {
            return SniffOutcome::Incomplete;
        }
    }
    // Extensions block fully present and parsed, no SNI found.
    SniffOutcome::NotMatched
}

fn parse_sni_extension(ext: &[u8]) -> SniffOutcome {
    // ServerNameList: list_length(2) then ServerName entries.
    if ext.len() < 2 {
        return SniffOutcome::Incomplete;
    }
    let list_len = usize::from(u16::from_be_bytes([ext[0], ext[1]]));
    let list = &ext[2..];
    if list.len() < list_len {
        return SniffOutcome::Incomplete;
    }
    let list = &list[..list_len];
    let mut i = 0;
    while i + 3 <= list.len() {
        let name_type = list[i];
        let name_len = usize::from(u16::from_be_bytes([list[i + 1], list[i + 2]]));
        i += 3;
        if i + name_len > list.len() {
            return SniffOutcome::Incomplete;
        }
        if name_type == 0x00 {
            // host_name.
            let name = &list[i..i + name_len];
            return match std::str::from_utf8(name) {
                Ok(host) if is_valid_sniffed_host(host) => SniffOutcome::Found(host.to_string()),
                _ => SniffOutcome::NotMatched,
            };
        }
        i += name_len;
    }
    SniffOutcome::NotMatched
}

// ---------------------------------------------------------------------------
// HTTP/1.x Host
// ---------------------------------------------------------------------------

/// Longest request line / header line we tolerate before declaring the stream
/// non-HTTP. Guards against waiting forever on a binary protocol that happens
/// to start with method-like bytes but never emits a CRLF.
const MAX_HTTP_LINE: usize = 8 * 1024;

enum HttpPrefix {
    /// A full `METHOD ` token is present.
    Method,
    /// A strict prefix of some `METHOD ` token — wait for more bytes.
    Maybe,
    /// Definitely not the start of an HTTP/1.x request.
    No,
}

const HTTP_METHODS: [&[u8]; 9] = [
    b"GET ",
    b"POST ",
    b"PUT ",
    b"HEAD ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
];

fn http_method_prefix(data: &[u8]) -> HttpPrefix {
    let mut maybe = false;
    for method in HTTP_METHODS {
        if data.len() >= method.len() {
            if &data[..method.len()] == method {
                return HttpPrefix::Method;
            }
        } else if data == &method[..data.len()] {
            maybe = true;
        }
    }
    if maybe { HttpPrefix::Maybe } else { HttpPrefix::No }
}

fn sniff_http_host(data: &[u8]) -> SniffOutcome {
    // Skip the request line.
    let mut pos = match find_crlf(data, 0) {
        Some(eol) => eol + 2,
        None => {
            return if data.len() > MAX_HTTP_LINE {
                SniffOutcome::NotMatched
            } else {
                SniffOutcome::Incomplete
            };
        },
    };
    loop {
        match find_crlf(data, pos) {
            Some(eol) => {
                let line = &data[pos..eol];
                if line.is_empty() {
                    // End of headers, no Host seen.
                    return SniffOutcome::NotMatched;
                }
                if let Some(outcome) = parse_host_line(line) {
                    return outcome;
                }
                pos = eol + 2;
            },
            None => {
                return if data.len().saturating_sub(pos) > MAX_HTTP_LINE {
                    SniffOutcome::NotMatched
                } else {
                    SniffOutcome::Incomplete
                };
            },
        }
    }
}

/// If `line` is a `Host:` header, return the sniff outcome for its value;
/// otherwise `None` (keep scanning).
fn parse_host_line(line: &[u8]) -> Option<SniffOutcome> {
    const HOST: &[u8] = b"host:";
    if line.len() < HOST.len() || !line[..HOST.len()].eq_ignore_ascii_case(HOST) {
        return None;
    }
    let value = &line[HOST.len()..];
    let value = std::str::from_utf8(value).ok()?.trim();
    let host = strip_host_port(value);
    if is_valid_sniffed_host(host) {
        Some(SniffOutcome::Found(host.to_string()))
    } else {
        Some(SniffOutcome::NotMatched)
    }
}

/// Strip a trailing `:port` from a `Host` header value, leaving the host. The
/// flow already knows the real port, so the sniffed port is irrelevant.
/// Bracketed IPv6 literals (`[::1]:443`) are left untouched — they are not
/// valid override targets anyway and `is_valid_sniffed_host` rejects them.
fn strip_host_port(value: &str) -> &str {
    if value.starts_with('[') {
        return value;
    }
    match value.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => value,
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// A sniffed host is usable only if it is a real domain name: non-empty,
/// length-bounded, made of host-legal characters, and not an IP literal
/// (overriding an IP target with the same IP buys nothing).
fn is_valid_sniffed_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    let mut has_alpha = false;
    for &b in host.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' => has_alpha = true,
            b'0'..=b'9' | b'.' | b'-' | b'_' => {},
            _ => return false,
        }
    }
    // Require at least one letter so bare numeric strings (not IPs, but not
    // hostnames either) are not treated as domains.
    has_alpha
}

fn find_crlf(data: &[u8], from: usize) -> Option<usize> {
    if from >= data.len() {
        return None;
    }
    data[from..].windows(2).position(|w| w == b"\r\n").map(|p| from + p)
}

/// Minimal big-endian byte-stream cursor with bounds-checked reads. A read
/// past the end returns `None` (the caller maps that to `Incomplete`).
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn u16(&mut self) -> Option<u16> {
        let hi = u16::from(*self.buf.get(self.pos)?);
        let lo = u16::from(*self.buf.get(self.pos + 1)?);
        self.pos += 2;
        Some((hi << 8) | lo)
    }

    fn skip(&mut self, n: usize) -> Option<()> {
        let end = self.pos.checked_add(n)?;
        if end > self.buf.len() {
            return None;
        }
        self.pos = end;
        Some(())
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }
}

#[cfg(test)]
#[path = "tests/sniff.rs"]
mod tests;
