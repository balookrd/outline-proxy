use std::time::Duration;

pub const SOCKS_VERSION: u8 = 0x05;
pub const SOCKS_CMD_CONNECT: u8 = 0x01;
pub const SOCKS_CMD_UDP_ASSOCIATE: u8 = 0x03;
pub const SOCKS_CMD_UDP_IN_TCP: u8 = 0x05;
pub const SOCKS_METHOD_NO_AUTH: u8 = 0x00;
pub const SOCKS_METHOD_USERNAME_PASSWORD: u8 = 0x02;
pub const SOCKS_METHOD_NO_ACCEPTABLE: u8 = 0xff;
pub const SOCKS_REP_SUCCESS: u8 = 0x00;
/// RFC 1928 REP=0x02 — connection not allowed by ruleset (policy drop).
pub const SOCKS_REP_NOT_ALLOWED: u8 = 0x02;
pub const SOCKS_REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
pub const SOCKS_REP_ADDRESS_NOT_SUPPORTED: u8 = 0x08;

pub const SOCKS5_UDP_FRAGMENT_END: u8 = 0x80;
pub const SOCKS5_UDP_FRAGMENT_MASK: u8 = 0x7f;
pub const SOCKS5_UDP_REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(5);
/// Upper bound on the cumulative payload a single SOCKS5 UDP fragment
/// sequence may accumulate before the final (END-flagged) fragment arrives.
/// Protects the proxy from a client that holds memory hostage by sending up
/// to 127 × 64 KiB fragments without ever terminating the sequence.
pub const SOCKS5_UDP_REASSEMBLY_MAX_BYTES: usize = 256 * 1024;
