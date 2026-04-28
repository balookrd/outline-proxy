//! Process-wide UDP NAT table for sharing socket state across client sessions.
//!
//! Instead of creating a new ephemeral UDP socket per incoming datagram, the NAT
//! table maintains a persistent socket per `(user_id, fwmark, target_addr)` triple.
//! This gives:
//!
//! - A stable source port for the lifetime of the NAT entry, which is required by
//!   stateful UDP protocols (QUIC, DTLS, some game protocols).
//! - Delivery of unsolicited upstream responses (server-initiated pushes) to the
//!   currently active client session.
//! - Transparent reconnect: a new client session for the same user immediately
//!   receives responses from the existing upstream socket without re-establishing
//!   the upstream association.
//!
//! Entries are evicted after `idle_timeout` with no outbound traffic.  A background
//! cleanup task calls [`NatTable::evict_idle`] on a regular interval.

mod entry;
mod reader;
mod table;

pub(crate) use entry::{NatKey, ResponseSender, UdpResponseSender};
pub(crate) use table::{NatTable, bind_nat_udp_socket};

#[cfg(test)]
mod tests;
