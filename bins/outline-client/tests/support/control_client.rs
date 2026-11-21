#![allow(dead_code)]
//! Minimal blocking HTTP/1.1 client for the proxy's `/control/topology`
//! (Bearer-authenticated JSON snapshot) and `/metrics` (Prometheus text)
//! planes. No reqwest dependency — a raw `GET ... Connection: close` over
//! `std::net::TcpStream`, parsed with `serde_json` + a tiny Prometheus line
//! matcher. These are the signals the failover tests assert on, proving a
//! switch actually happened rather than just "traffic kept flowing".

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

type BoxError = Box<dyn std::error::Error>;

fn http_get(addr: SocketAddr, path: &str, bearer: Option<&str>) -> Result<String, BoxError> {
    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    if let Some(token) = bearer {
        req.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes())?;

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    let text = String::from_utf8_lossy(&raw).into_owned();

    let split = text
        .find("\r\n\r\n")
        .ok_or_else(|| format!("malformed HTTP response: {text}"))?;
    let headers = &text[..split];
    let status_ok = headers.lines().next().map(|l| l.contains(" 200 ")).unwrap_or(false);
    if !status_ok {
        return Err(format!("non-200 response for {path}: {headers}").into());
    }
    let body = &text[split + 4..];
    if headers.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        Ok(dechunk(body))
    } else {
        Ok(body.to_string())
    }
}

/// Decode an HTTP/1.1 chunked body (size-in-hex CRLF, data CRLF, … 0 CRLF).
fn dechunk(body: &str) -> String {
    let bytes = body.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let Some(eol) = find(&bytes[i..], b"\r\n") else { break };
        let size_line = &body[i..i + eol];
        let size = usize::from_str_radix(size_line.trim(), 16).unwrap_or(0);
        i += eol + 2;
        if size == 0 || i + size > bytes.len() {
            break;
        }
        out.extend_from_slice(&bytes[i..i + size]);
        i += size + 2; // skip data + trailing CRLF
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ── Topology ─────────────────────────────────────────────────────────────────

pub struct Topology(serde_json::Value);

pub fn get_topology(addr: SocketAddr, token: &str) -> Result<Topology, BoxError> {
    let body = http_get(addr, "/control/topology", Some(token))?;
    let v: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| format!("topology JSON parse error: {e}; body={body}"))?;
    Ok(Topology(v))
}

impl Topology {
    fn group<'a>(&'a self, group: &str) -> Option<&'a serde_json::Value> {
        self.0
            .get("instance")?
            .get("groups")?
            .as_array()?
            .iter()
            .find(|g| g.get("name").and_then(|n| n.as_str()) == Some(group))
    }

    fn uplink<'a>(&'a self, group: &str, uplink: &str) -> Option<&'a serde_json::Value> {
        self.group(group)?
            .get("uplinks")?
            .as_array()?
            .iter()
            .find(|u| u.get("name").and_then(|n| n.as_str()) == Some(uplink))
    }

    pub fn global_active_uplink(&self, group: &str) -> Option<String> {
        self.group(group)?
            .get("global_active_uplink")?
            .as_str()
            .map(String::from)
    }

    pub fn tcp_active_uplink(&self, group: &str) -> Option<String> {
        self.group(group)?
            .get("tcp_active_uplink")?
            .as_str()
            .map(String::from)
    }

    pub fn udp_active_uplink(&self, group: &str) -> Option<String> {
        self.group(group)?
            .get("udp_active_uplink")?
            .as_str()
            .map(String::from)
    }

    pub fn tcp_active_wire(&self, group: &str, uplink: &str) -> Option<u64> {
        self.uplink(group, uplink)?.get("tcp_active_wire")?.as_u64()
    }

    pub fn udp_active_wire(&self, group: &str, uplink: &str) -> Option<u64> {
        self.uplink(group, uplink)?.get("udp_active_wire")?.as_u64()
    }

    pub fn tcp_health_effective(&self, group: &str, uplink: &str) -> Option<bool> {
        self.uplink(group, uplink)?.get("tcp_health_effective")?.as_bool()
    }

    pub fn active_tcp(&self, group: &str, uplink: &str) -> Option<bool> {
        self.uplink(group, uplink)?.get("active_tcp")?.as_bool()
    }

    /// Raw JSON, for ad-hoc assertions / debug printing.
    pub fn raw(&self) -> &serde_json::Value {
        &self.0
    }
}

// ── Metrics ──────────────────────────────────────────────────────────────────

pub struct Metrics(String);

pub fn metrics_scrape(addr: SocketAddr) -> Result<Metrics, BoxError> {
    Ok(Metrics(http_get(addr, "/metrics", None)?))
}

impl Metrics {
    /// Sum the values of every sample line whose metric name matches and whose
    /// label set is a superset of `labels` (Prometheus counters here carry more
    /// labels than a test usually wants to pin, e.g. `failovers_total` has 4).
    pub fn sum(&self, name: &str, labels: &[(&str, &str)]) -> f64 {
        let mut total = 0.0;
        for line in self.0.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((sample_name, sample_labels, value)) = parse_sample(line) else {
                continue;
            };
            if sample_name != name {
                continue;
            }
            if labels
                .iter()
                .all(|(k, v)| sample_labels.iter().any(|(lk, lv)| lk == k && lv == v))
            {
                total += value;
            }
        }
        total
    }

    pub fn raw(&self) -> &str {
        &self.0
    }
}

/// Parse `name{k="v",k2="v2"} 123.0` or `name 123.0` → (name, labels, value).
fn parse_sample(line: &str) -> Option<(&str, Vec<(&str, &str)>, f64)> {
    if let Some(brace) = line.find('{') {
        let name = &line[..brace];
        let close = line.find('}')?;
        let labels_str = &line[brace + 1..close];
        let value: f64 = line[close + 1..].trim().parse().ok()?;
        let labels = labels_str
            .split(',')
            .filter_map(|kv| {
                let (k, v) = kv.split_once('=')?;
                Some((k.trim(), v.trim().trim_matches('"')))
            })
            .collect();
        Some((name, labels, value))
    } else {
        let (name, value) = line.split_once(char::is_whitespace)?;
        Some((name, Vec::new(), value.trim().parse().ok()?))
    }
}
