#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
pub enum Transport {
    Tcp,
    Udp,
}

impl Transport {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// Application-layer protocol carried over the websocket/QUIC transport.
/// Distinguishes the Shadowsocks and VLESS data paths so per-protocol
/// throughput, frame-size and session metrics can be compared on the
/// same dashboard.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
pub enum AppProtocol {
    Shadowsocks,
    Vless,
}

impl AppProtocol {
    pub const VARIANTS_COUNT: usize = 2;

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Shadowsocks => "shadowsocks",
            Self::Vless => "vless",
        }
    }

    pub const fn as_index(self) -> usize {
        match self {
            Self::Shadowsocks => 0,
            Self::Vless => 1,
        }
    }

    pub const fn from_index(index: usize) -> Self {
        match index {
            0 => Self::Shadowsocks,
            _ => Self::Vless,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
pub enum Protocol {
    Http1,
    Http2,
    Http3,
    Socket,
    QuicRaw,
    /// VLESS over XHTTP packet-up carried on HTTP/1.1. Each packet
    /// is its own short request/response, so h1 is fine for this
    /// mode (stream-one returns 505 on h1 and never lands here).
    /// Distinct from `Http1` so the metric splits XHTTP packet-up
    /// from WebSocket-Upgrade traffic on the same h1 listener.
    XhttpH1,
    /// VLESS over XHTTP packet-up / stream-one carried on HTTP/2
    /// (RFC 7540). Distinct from `Http2` so dashboards can split
    /// XHTTP traffic from WebSocket-Upgrade traffic on the same
    /// h2 listener — they share Tcp+TLS+h2 wire shape but have
    /// very different framing and resumption behaviour.
    XhttpH2,
    /// VLESS over XHTTP carried on HTTP/3 (RFC 9114).
    XhttpH3,
}

impl Protocol {
    pub const VARIANTS_COUNT: usize = 8;

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http1 => "http1",
            Self::Http2 => "http2",
            Self::Http3 => "http3",
            Self::Socket => "socket",
            Self::QuicRaw => "quic",
            Self::XhttpH1 => "xhttp_h1",
            Self::XhttpH2 => "xhttp_h2",
            Self::XhttpH3 => "xhttp_h3",
        }
    }

    pub const fn as_index(self) -> usize {
        match self {
            Self::Http1 => 0,
            Self::Http2 => 1,
            Self::Http3 => 2,
            Self::Socket => 3,
            Self::QuicRaw => 4,
            Self::XhttpH1 => 5,
            Self::XhttpH2 => 6,
            Self::XhttpH3 => 7,
        }
    }

    pub const fn from_index(index: usize) -> Self {
        match index {
            0 => Self::Http1,
            1 => Self::Http2,
            2 => Self::Http3,
            3 => Self::Socket,
            4 => Self::QuicRaw,
            5 => Self::XhttpH1,
            6 => Self::XhttpH2,
            _ => Self::XhttpH3,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
pub enum DisconnectReason {
    Normal,
    ClientDisconnect,
    Error,
    /// Handshake rejected by the protocol parser or auth check, the
    /// session was held open in the probe-resistance sink until the
    /// handshake-equivalent timeout (or byte cap) before closing. Split
    /// out from `Error` so probe activity is visible separately from
    /// genuine relay errors and so the long sink-mode session lifetime
    /// does not skew p99 session-duration histograms for real errors.
    HandshakeRejected,
}

impl DisconnectReason {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::ClientDisconnect => "client_disconnect",
            Self::Error => "error",
            Self::HandshakeRejected => "handshake_rejected",
        }
    }
}
