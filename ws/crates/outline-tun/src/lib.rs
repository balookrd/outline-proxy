//! TUN device engine for transparent proxying.
//!
//! Reads raw IP packets from a TUN interface, reassembles IPv6 fragments, and
//! dispatches traffic to two relay engines: a stateful userspace TCP stack
//! (`tun2tcp`) and a stateless UDP forwarder (`tun2udp`).

mod atomic_counter;
mod classify;
pub mod config;
pub(crate) mod defrag;
mod device;
mod engine;
pub(crate) mod error_classify;
mod frag;
mod icmp;
mod routing;
pub mod tcp;
pub mod udp;
mod utils;
pub(crate) mod wire;
mod writer;

#[cfg(test)]
mod tests;

pub use config::{TunConfig, TunTcpConfig};
pub use engine::spawn_tun_loop;
pub use routing::{TunRoute, TunRouting};
pub use tcp::TunTcpEngine;

pub(crate) use writer::SharedTunWriter;

#[cfg(test)]
pub(crate) use classify::{PacketDisposition, classify_packet};
#[cfg(test)]
pub(crate) use device::{EBUSY_OS_ERROR, is_tun_device_busy_error};
#[cfg(test)]
pub(crate) use icmp::{
    IPV4_MIN_PATH_MTU, IPV6_MIN_PATH_MTU, build_icmp_echo_reply, build_icmp_echo_reply_packets,
    build_icmpv4_frag_needed, build_icmpv6_packet_too_big, icmpv6_checksum,
};
#[cfg(test)]
pub(crate) use udp::should_emit_ptb_now;
#[cfg(test)]
pub(crate) use wire::{IPV4_HEADER_LEN, IPV6_HEADER_LEN, IPV6_NEXT_HEADER_FRAGMENT, checksum16};
