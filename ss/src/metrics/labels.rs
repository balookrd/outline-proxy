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
}

impl DisconnectReason {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::ClientDisconnect => "client_disconnect",
            Self::Error => "error",
        }
    }
}
