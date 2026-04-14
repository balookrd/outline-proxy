use super::super::{TCP_FLAG_FIN, TCP_FLAG_SYN, ParsedTcpPacket};

pub(in crate::tun_tcp) fn seq_lt(lhs: u32, rhs: u32) -> bool {
    (lhs.wrapping_sub(rhs) as i32) < 0
}

pub(in crate::tun_tcp) fn seq_gt(lhs: u32, rhs: u32) -> bool {
    (lhs.wrapping_sub(rhs) as i32) > 0
}

pub(in crate::tun_tcp) fn seq_ge(lhs: u32, rhs: u32) -> bool {
    !seq_lt(lhs, rhs)
}

pub(in crate::tun_tcp) fn timestamp_lt(lhs: u32, rhs: u32) -> bool {
    (lhs.wrapping_sub(rhs) as i32) < 0
}

pub(in crate::tun_tcp) fn packet_sequence_len(packet: &ParsedTcpPacket) -> u32 {
    packet.payload.len() as u32
        + u32::from((packet.flags & TCP_FLAG_SYN) != 0)
        + u32::from((packet.flags & TCP_FLAG_FIN) != 0)
}
