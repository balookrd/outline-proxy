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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
pub enum Protocol {
    Http1,
    Http2,
    Http3,
    Socket,
    QuicRaw,
}

impl Protocol {
    pub const VARIANTS_COUNT: usize = 5;

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http1 => "http1",
            Self::Http2 => "http2",
            Self::Http3 => "http3",
            Self::Socket => "socket",
            Self::QuicRaw => "quic",
        }
    }

    pub const fn as_index(self) -> usize {
        match self {
            Self::Http1 => 0,
            Self::Http2 => 1,
            Self::Http3 => 2,
            Self::Socket => 3,
            Self::QuicRaw => 4,
        }
    }

    pub const fn from_index(index: usize) -> Self {
        match index {
            0 => Self::Http1,
            1 => Self::Http2,
            2 => Self::Http3,
            3 => Self::Socket,
            _ => Self::QuicRaw,
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
