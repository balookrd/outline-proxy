#![allow(dead_code)]
//! Programmatic TOML generation for the server (`outline-ss-rust`) and the
//! grouped client (`outline-ws-rust`). Field names are taken verbatim from the
//! serde schemas (`bins/outline-ss-rust/src/config/file.rs` +
//! `user_entry.rs`, and `bins/outline-ws-rust/src/config/schema.rs`); every
//! section is `deny_unknown_fields`, so a typo here is a parse error at start.
//!
//! Conventions shared by all e2e tests:
//! * SS1 cipher (`chacha20-ietf-poly1305`) — plain string password, no PSK.
//! * One server (with [`ServerConfig::all_paths`]) multiplexes SS / VLESS over
//!   WS / XHTTP on a single TCP port (+ an optional H3 UDP port).
//! * A single client group named `"default"`, so no `[[route]]` is needed.
//! * Host `127.0.0.1` for both cleartext and TLS — the test leaf cert carries
//!   `127.0.0.1` as an IP SAN alongside `localhost`.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::Path;

pub const TEST_METHOD: &str = "chacha20-ietf-poly1305";
pub const TEST_PASSWORD: &str = "e2e-test-password";
pub const TEST_VLESS_ID: &str = "11111111-2222-3333-4444-555555555555";

pub const PATH_SS_TCP: &str = "/tcp";
pub const PATH_SS_UDP: &str = "/udp";
pub const PATH_SS_XHTTP: &str = "/ssx";
pub const PATH_VLESS_WS: &str = "/vlessws";
pub const PATH_VLESS_XHTTP: &str = "/vlessx";

// ── Server config ────────────────────────────────────────────────────────────

pub struct ServerConfig {
    listen: SocketAddr,
    method: String,
    ws_path_tcp: Option<String>,
    ws_path_udp: Option<String>,
    ws_path_vless: Option<String>,
    xhttp_path_tcp: Option<String>,
    xhttp_path_vless: Option<String>,
    user_password: Option<String>,
    user_vless_id: Option<String>,
    session_resumption: bool,
    downlink_buffer_bytes: Option<usize>,
    /// `(paths, cover)` for the `[padding]` block when carrier padding is on.
    padding: Option<(Vec<String>, bool)>,
    tls: Option<(String, String)>,
    h3: Option<(SocketAddr, Vec<String>)>,
}

impl ServerConfig {
    pub fn new(listen: SocketAddr) -> Self {
        Self {
            listen,
            method: TEST_METHOD.to_string(),
            ws_path_tcp: None,
            ws_path_udp: None,
            ws_path_vless: None,
            xhttp_path_tcp: None,
            xhttp_path_vless: None,
            user_password: None,
            user_vless_id: None,
            session_resumption: false,
            downlink_buffer_bytes: None,
            padding: None,
            tls: None,
            h3: None,
        }
    }

    /// Enable every cleartext path + a user that carries both an SS password
    /// and a VLESS id, so one server serves all four protocol×carrier shapes.
    pub fn all_paths(mut self) -> Self {
        self.ws_path_tcp = Some(PATH_SS_TCP.into());
        self.ws_path_udp = Some(PATH_SS_UDP.into());
        self.ws_path_vless = Some(PATH_VLESS_WS.into());
        self.xhttp_path_tcp = Some(PATH_SS_XHTTP.into());
        self.xhttp_path_vless = Some(PATH_VLESS_XHTTP.into());
        self.user_password = Some(TEST_PASSWORD.into());
        self.user_vless_id = Some(TEST_VLESS_ID.into());
        self
    }

    pub fn with_tls(mut self, cert_path: &Path, key_path: &Path) -> Self {
        self.tls = Some((path_str(cert_path), path_str(key_path)));
        self
    }

    /// Add an H3/QUIC listener. ALPN typically `["h3", "vless", "ss"]`
    /// (HTTP/3+WS, raw-VLESS-over-QUIC, raw-SS-over-QUIC). Requires TLS.
    pub fn with_h3(mut self, listen: SocketAddr, alpn: &[&str]) -> Self {
        self.h3 = Some((listen, alpn.iter().map(|s| s.to_string()).collect()));
        self
    }

    pub fn with_session_resumption(mut self, downlink_buffer_bytes: usize) -> Self {
        self.session_resumption = true;
        self.downlink_buffer_bytes = Some(downlink_buffer_bytes);
        self
    }

    /// Enable carrier padding on the given carrier paths. `cover` toggles idle
    /// cover frames (with a fast 50–100 ms jitter so tests do not wait long).
    pub fn with_padding(mut self, paths: &[&str], cover: bool) -> Self {
        self.padding = Some((paths.iter().map(|p| p.to_string()).collect(), cover));
        self
    }

    pub fn render(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "[server]");
        let _ = writeln!(s, "listen = \"{}\"", self.listen);
        if let Some((cert, key)) = &self.tls {
            let _ = writeln!(s, "cert_path = \"{cert}\"");
            let _ = writeln!(s, "key_path = \"{key}\"");
        }
        if let Some((h3_listen, alpn)) = &self.h3 {
            let _ = writeln!(s, "\n[server.h3]");
            let _ = writeln!(s, "listen = \"{h3_listen}\"");
            let alpn_list = alpn.iter().map(|a| format!("\"{a}\"")).collect::<Vec<_>>().join(", ");
            let _ = writeln!(s, "alpn = [{alpn_list}]");
        }

        let _ = writeln!(s, "\n[websocket]");
        for (key, val) in [
            ("ws_path_tcp", &self.ws_path_tcp),
            ("ws_path_udp", &self.ws_path_udp),
            ("ws_path_vless", &self.ws_path_vless),
            ("xhttp_path_tcp", &self.xhttp_path_tcp),
            ("xhttp_path_vless", &self.xhttp_path_vless),
        ] {
            if let Some(v) = val {
                let _ = writeln!(s, "{key} = \"{v}\"");
            }
        }

        let _ = writeln!(s, "\n[shadowsocks]");
        let _ = writeln!(s, "method = \"{}\"", self.method);

        if self.session_resumption {
            let _ = writeln!(s, "\n[session_resumption]");
            let _ = writeln!(s, "enabled = true");
            if let Some(n) = self.downlink_buffer_bytes {
                let _ = writeln!(s, "downlink_buffer_bytes = {n}");
            }
        }

        if let Some((paths, cover)) = &self.padding {
            let list = paths
                .iter()
                .map(|p| format!("\"{p}\""))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(s, "\n[padding]");
            let _ = writeln!(s, "enabled = true");
            let _ = writeln!(s, "paths = [{list}]");
            let _ = writeln!(s, "min_bytes = 16");
            let _ = writeln!(s, "max_bytes = 256");
            let _ = writeln!(s, "cover = {cover}");
            let _ = writeln!(s, "cover_jitter_min_ms = 50");
            let _ = writeln!(s, "cover_jitter_max_ms = 100");
        }

        let _ = writeln!(s, "\n[[users]]");
        let _ = writeln!(s, "id = \"e2e-user\"");
        if let Some(pw) = &self.user_password {
            let _ = writeln!(s, "password = \"{pw}\"");
        }
        if let Some(id) = &self.user_vless_id {
            let _ = writeln!(s, "vless_id = \"{id}\"");
        }
        s
    }
}

// ── Wire shapes ──────────────────────────────────────────────────────────────

/// One carrier shape: dial URL(s) + `*_mode`. `transport()` and the rendered
/// keys follow the client validator's gating (`wire_shape.rs`): SS-WS uses
/// `tcp_ws_url`, SS-XHTTP uses `tcp_xhttp_url`, VLESS uses a single
/// `vless_ws_url` / `vless_xhttp_url`.
#[derive(Clone)]
pub enum Wire {
    SsWs {
        tcp_url: String,
        udp_url: Option<String>,
        mode: String,
    },
    SsXhttp {
        tcp_url: String,
        mode: String,
    },
    VlessWs {
        url: String,
        mode: String,
    },
    VlessXhttp {
        url: String,
        mode: String,
    },
}

impl Wire {
    pub fn transport(&self) -> &'static str {
        match self {
            Wire::SsWs { .. } | Wire::SsXhttp { .. } => "ss",
            Wire::VlessWs { .. } | Wire::VlessXhttp { .. } => "vless",
        }
    }

    fn render_fields(&self, out: &mut String) {
        match self {
            Wire::SsWs { tcp_url, udp_url, mode } => {
                let _ = writeln!(out, "tcp_ws_url = \"{tcp_url}\"");
                let _ = writeln!(out, "tcp_mode = \"{mode}\"");
                if let Some(u) = udp_url {
                    let _ = writeln!(out, "udp_ws_url = \"{u}\"");
                    let _ = writeln!(out, "udp_mode = \"{mode}\"");
                }
            },
            Wire::SsXhttp { tcp_url, mode } => {
                let _ = writeln!(out, "tcp_xhttp_url = \"{tcp_url}\"");
                let _ = writeln!(out, "tcp_mode = \"{mode}\"");
            },
            Wire::VlessWs { url, mode } => {
                let _ = writeln!(out, "vless_ws_url = \"{url}\"");
                let _ = writeln!(out, "vless_mode = \"{mode}\"");
            },
            Wire::VlessXhttp { url, mode } => {
                let _ = writeln!(out, "vless_xhttp_url = \"{url}\"");
                let _ = writeln!(out, "vless_mode = \"{mode}\"");
            },
        }
    }
}

/// Per-wire credentials. Must match the wire's transport. For cross-protocol
/// fallbacks these are rendered explicitly (a VLESS fallback's id is never
/// inherited; an SS fallback under a VLESS parent needs its own password).
#[derive(Clone)]
pub enum Creds {
    Ss { method: String, password: String },
    Vless { id: String },
}

impl Creds {
    pub fn ss() -> Self {
        Creds::Ss {
            method: TEST_METHOD.into(),
            password: TEST_PASSWORD.into(),
        }
    }

    pub fn vless() -> Self {
        Creds::Vless { id: TEST_VLESS_ID.into() }
    }

    fn render_fields(&self, out: &mut String) {
        match self {
            Creds::Ss { method, password } => {
                let _ = writeln!(out, "method = \"{method}\"");
                let _ = writeln!(out, "password = \"{password}\"");
            },
            Creds::Vless { id } => {
                let _ = writeln!(out, "vless_id = \"{id}\"");
            },
        }
    }
}

// ── Client uplink / group ────────────────────────────────────────────────────

pub struct UplinkSpec {
    pub name: String,
    pub primary: Wire,
    pub creds: Creds,
    pub fallbacks: Vec<(Wire, Creds)>,
    pub weight: f64,
    pub shuffle_wires: Option<bool>,
    pub carrier_downgrade: Option<bool>,
}

impl UplinkSpec {
    pub fn new(name: &str, primary: Wire, creds: Creds) -> Self {
        Self {
            name: name.to_string(),
            primary,
            creds,
            fallbacks: Vec::new(),
            weight: 1.0,
            shuffle_wires: None,
            carrier_downgrade: None,
        }
    }

    pub fn with_fallback(mut self, wire: Wire, creds: Creds) -> Self {
        self.fallbacks.push((wire, creds));
        self
    }

    fn render(&self, out: &mut String, group: &str) {
        let _ = writeln!(out, "\n[[outline.uplinks]]");
        let _ = writeln!(out, "name = \"{}\"", self.name);
        let _ = writeln!(out, "group = \"{group}\"");
        let _ = writeln!(out, "transport = \"{}\"", self.primary.transport());
        self.primary.render_fields(out);
        self.creds.render_fields(out);
        let _ = writeln!(out, "weight = {:?}", self.weight);
        if let Some(b) = self.shuffle_wires {
            let _ = writeln!(out, "shuffle_wires = {b}");
        }
        if let Some(b) = self.carrier_downgrade {
            let _ = writeln!(out, "carrier_downgrade = {b}");
        }
        for (wire, creds) in &self.fallbacks {
            let _ = writeln!(out, "\n[[outline.uplinks.fallbacks]]");
            let _ = writeln!(out, "transport = \"{}\"", wire.transport());
            wire.render_fields(out);
            creds.render_fields(out);
        }
    }
}

pub struct GroupSpec {
    pub name: String,
    pub mode: String,
    pub routing_scope: String,
    pub failure_cooldown_secs: u64,
    pub tcp_chunk0_failover_timeout_secs: u64,
    pub mode_downgrade_secs: u64,
    pub hysteresis_ms: u64,
    pub auto_failback: bool,
    pub mid_session_retry_buffer_bytes: Option<usize>,
    pub mid_session_retry_budget: Option<u8>,
    pub uplinks: Vec<UplinkSpec>,
}

impl GroupSpec {
    /// Defaults tuned for fast, deterministic failover tests: 1 s chunk-0
    /// timeout, 1 s cooldown / downgrade pin, no auto-failback (so an advanced
    /// active wire/uplink stays put for the assertion).
    pub fn new(mode: &str, routing_scope: &str) -> Self {
        Self {
            name: "default".to_string(),
            mode: mode.to_string(),
            routing_scope: routing_scope.to_string(),
            failure_cooldown_secs: 1,
            tcp_chunk0_failover_timeout_secs: 1,
            mode_downgrade_secs: 1,
            hysteresis_ms: 50,
            auto_failback: false,
            mid_session_retry_buffer_bytes: None,
            mid_session_retry_budget: None,
            uplinks: Vec::new(),
        }
    }

    pub fn uplink(mut self, u: UplinkSpec) -> Self {
        self.uplinks.push(u);
        self
    }

    pub fn with_mid_session_retry(mut self, buffer_bytes: usize, budget: u8) -> Self {
        self.mid_session_retry_buffer_bytes = Some(buffer_bytes);
        self.mid_session_retry_budget = Some(budget);
        self
    }

    fn render(&self, out: &mut String) {
        let _ = writeln!(out, "\n[[uplink_group]]");
        let _ = writeln!(out, "name = \"{}\"", self.name);
        let _ = writeln!(out, "mode = \"{}\"", self.mode);
        let _ = writeln!(out, "routing_scope = \"{}\"", self.routing_scope);
        let _ = writeln!(out, "failure_cooldown_secs = {}", self.failure_cooldown_secs);
        let _ = writeln!(
            out,
            "tcp_chunk0_failover_timeout_secs = {}",
            self.tcp_chunk0_failover_timeout_secs
        );
        let _ = writeln!(out, "mode_downgrade_secs = {}", self.mode_downgrade_secs);
        let _ = writeln!(out, "hysteresis_ms = {}", self.hysteresis_ms);
        let _ = writeln!(out, "auto_failback = {}", self.auto_failback);
        if let Some(n) = self.mid_session_retry_buffer_bytes {
            let _ = writeln!(out, "tcp_mid_session_retry_buffer_bytes = {n}");
        }
        if let Some(n) = self.mid_session_retry_budget {
            let _ = writeln!(out, "tcp_mid_session_retry_budget = {n}");
        }
        for u in &self.uplinks {
            u.render(out, &self.name);
        }
    }
}

pub struct ProbeSpec {
    pub enabled: bool,
    pub interval_secs: u64,
    pub timeout_secs: u64,
    pub min_failures: usize,
}

impl ProbeSpec {
    /// Probe enabled with a fast cycle (1 s interval / 2 s timeout / 1 failure
    /// to flip), so inter-uplink health flips quickly in the global tests.
    pub fn fast() -> Self {
        Self {
            enabled: true,
            interval_secs: 1,
            timeout_secs: 2,
            min_failures: 1,
        }
    }

    /// Probe disabled — wire / uplink advance is driven purely by dial outcomes
    /// of new SOCKS sessions (used by the wire-failover tests).
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            interval_secs: 120,
            timeout_secs: 10,
            min_failures: 1,
        }
    }
}

pub struct ClientConfig {
    socks5: SocketAddr,
    control: Option<(SocketAddr, String)>,
    metrics: Option<SocketAddr>,
    state_path: String,
    probe: ProbeSpec,
    /// `Some(cover)` when carrier padding is on (global on the client side).
    padding: Option<bool>,
    groups: Vec<GroupSpec>,
}

impl ClientConfig {
    pub fn new(socks5: SocketAddr, state_path: &Path, probe: ProbeSpec) -> Self {
        Self {
            socks5,
            control: None,
            metrics: None,
            state_path: path_str(state_path),
            probe,
            padding: None,
            groups: Vec::new(),
        }
    }

    /// Enable carrier padding (global). `cover` toggles idle cover frames with
    /// a fast 50–100 ms jitter to keep tests quick.
    pub fn with_padding(mut self, cover: bool) -> Self {
        self.padding = Some(cover);
        self
    }

    pub fn with_control(mut self, listen: SocketAddr, token: &str) -> Self {
        self.control = Some((listen, token.to_string()));
        self
    }

    pub fn with_metrics(mut self, listen: SocketAddr) -> Self {
        self.metrics = Some(listen);
        self
    }

    pub fn group(mut self, g: GroupSpec) -> Self {
        self.groups.push(g);
        self
    }

    pub fn render(&self) -> String {
        let mut s = String::new();
        // Top-level keys must precede every [table] header in TOML.
        let _ = writeln!(s, "state_path = \"{}\"", self.state_path);

        if let Some(cover) = self.padding {
            let _ = writeln!(s, "\n[padding]");
            let _ = writeln!(s, "enabled = true");
            let _ = writeln!(s, "min_bytes = 16");
            let _ = writeln!(s, "max_bytes = 256");
            let _ = writeln!(s, "cover = {cover}");
            let _ = writeln!(s, "cover_jitter_min_ms = 50");
            let _ = writeln!(s, "cover_jitter_max_ms = 100");
        }

        let _ = writeln!(s, "\n[socks5]");
        let _ = writeln!(s, "listen = \"{}\"", self.socks5);

        if let Some(m) = &self.metrics {
            let _ = writeln!(s, "\n[metrics]");
            let _ = writeln!(s, "listen = \"{m}\"");
        }
        if let Some((listen, token)) = &self.control {
            let _ = writeln!(s, "\n[control]");
            let _ = writeln!(s, "listen = \"{listen}\"");
            let _ = writeln!(s, "token = \"{token}\"");
        }

        // Top-level probe template; groups inherit it.
        let _ = writeln!(s, "\n[outline.probe]");
        let _ = writeln!(s, "interval_secs = {}", self.probe.interval_secs);
        let _ = writeln!(s, "timeout_secs = {}", self.probe.timeout_secs);
        let _ = writeln!(s, "min_failures = {}", self.probe.min_failures);
        let _ = writeln!(s, "\n[outline.probe.ws]");
        let _ = writeln!(s, "enabled = {}", self.probe.enabled);

        for g in &self.groups {
            g.render(&mut s);
        }
        s
    }
}

fn path_str(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}
