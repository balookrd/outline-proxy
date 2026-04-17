use super::state_machine::{TcpFlowState, packet_overlaps_receive_window, seq_gt, timestamp_lt};
use super::wire::ParsedTcpPacket;
use super::{TCP_FLAG_ACK, TCP_FLAG_RST, TCP_FLAG_SYN};

pub(super) enum PacketValidation {
    Accept,
    Ignore,
    ChallengeAck(&'static str),
    CloseFlow(&'static str),
}

fn validate_packet_timestamps(state: &TcpFlowState, packet: &ParsedTcpPacket) -> PacketValidation {
    if !state.timestamps_enabled || (packet.flags & TCP_FLAG_RST) != 0 {
        return PacketValidation::Accept;
    }

    let Some(timestamp_value) = packet.timestamp_value else {
        return if packet_overlaps_receive_window(state, packet) {
            PacketValidation::ChallengeAck("missing_timestamp")
        } else {
            PacketValidation::Ignore
        };
    };

    if state
        .recent_client_timestamp
        .is_some_and(|recent| timestamp_lt(timestamp_value, recent))
    {
        return if packet_overlaps_receive_window(state, packet) {
            PacketValidation::ChallengeAck("paws_reject")
        } else {
            PacketValidation::Ignore
        };
    }

    PacketValidation::Accept
}

pub(super) fn validate_existing_packet(
    state: &TcpFlowState,
    packet: &ParsedTcpPacket,
) -> PacketValidation {
    if (packet.flags & TCP_FLAG_RST) != 0 {
        if packet.sequence_number == state.client_next_seq {
            return PacketValidation::CloseFlow("client_rst");
        }
        return if packet_overlaps_receive_window(state, packet) {
            PacketValidation::ChallengeAck("invalid_rst")
        } else {
            PacketValidation::Ignore
        };
    }

    match validate_packet_timestamps(state, packet) {
        PacketValidation::Accept => {},
        other => return other,
    }

    if (packet.flags & TCP_FLAG_SYN) != 0 {
        return if packet_overlaps_receive_window(state, packet) {
            PacketValidation::ChallengeAck("unexpected_syn")
        } else {
            PacketValidation::Ignore
        };
    }

    if (packet.flags & TCP_FLAG_ACK) != 0 && seq_gt(packet.acknowledgement_number, state.server_seq)
    {
        return if packet_overlaps_receive_window(state, packet) {
            PacketValidation::ChallengeAck("ack_above_snd_nxt")
        } else {
            PacketValidation::Ignore
        };
    }

    PacketValidation::Accept
}
