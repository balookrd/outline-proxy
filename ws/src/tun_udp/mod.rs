use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::sync::Mutex;
use tracing::debug;

use crate::atomic_counter::CounterU64;
use crate::metrics;
use crate::transport::{UdpWsTransport, is_dropped_oversized_udp_error};
use crate::tun::SharedTunWriter;
use crate::tun_wire::IpVersion;
use crate::types::TargetAddr;
use crate::uplink::{TransportKind, UplinkManager};

const TUN_FLOW_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
mod lifecycle;
mod wire;

use self::wire::ParsedUdpPacket;
#[cfg(test)]
pub(crate) use self::wire::build_ipv4_udp_packet;
pub(crate) use self::wire::parse_udp_packet;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct UdpFlowKey {
    version: IpVersion,
    local_ip: IpAddr,
    local_port: u16,
    remote_ip: IpAddr,
    remote_port: u16,
}

#[derive(Clone)]
struct UdpFlowState {
    id: u64,
    transport: Arc<UdpWsTransport>,
    uplink_index: usize,
    uplink_name: String,
    created_at: Instant,
    last_seen: Instant,
}

type FlowTable = Arc<Mutex<HashMap<UdpFlowKey, UdpFlowState>>>;

#[derive(Clone)]
pub struct TunUdpEngine {
    inner: Arc<TunUdpEngineInner>,
}

struct TunUdpEngineInner {
    writer: SharedTunWriter,
    uplinks: UplinkManager,
    flows: FlowTable,
    next_flow_id: CounterU64,
    max_flows: usize,
    idle_timeout: Duration,
}

impl TunUdpEngine {
    pub(crate) fn new(
        writer: SharedTunWriter,
        uplinks: UplinkManager,
        max_flows: usize,
        idle_timeout: Duration,
    ) -> Self {
        let engine = Self {
            inner: Arc::new(TunUdpEngineInner {
                writer,
                uplinks,
                flows: Arc::new(Mutex::new(HashMap::new())),
                next_flow_id: CounterU64::new(1),
                max_flows,
                idle_timeout,
            }),
        };
        engine.spawn_cleanup_loop();
        engine
    }

    pub(crate) async fn handle_packet(&self, packet: ParsedUdpPacket) -> Result<()> {
        let remote_target = ip_to_target(packet.destination_ip, packet.destination_port);
        let key = UdpFlowKey {
            version: packet.version,
            local_ip: packet.source_ip,
            local_port: packet.source_port,
            remote_ip: packet.destination_ip,
            remote_port: packet.destination_port,
        };

        let active_uplink = if self
            .inner
            .uplinks
            .strict_active_uplink_for(TransportKind::Udp)
        {
            self.inner
                .uplinks
                .active_uplink_index_for_transport(TransportKind::Udp)
                .await
        } else {
            None
        };

        let (existing, stale_flow) = {
            let mut guard = self.inner.flows.lock().await;
            match guard.get(&key) {
                Some(flow) if active_uplink.is_some_and(|active| active != flow.uplink_index) => {
                    let stale = guard.remove(&key).expect("stale TUN UDP flow must exist");
                    (None, Some(stale))
                }
                Some(_) => {
                    let flow = guard.get_mut(&key).expect("TUN UDP flow must still exist");
                    flow.last_seen = Instant::now();
                    (
                        Some((
                            flow.id,
                            Arc::clone(&flow.transport),
                            flow.uplink_index,
                            flow.uplink_name.clone(),
                        )),
                        None,
                    )
                }
                None => (None, None),
            }
        };

        if let Some(stale_flow) = stale_flow {
            self::lifecycle::close_udp_flow(stale_flow, "global_switch").await;
        }

        let (flow_id, transport, uplink_index, uplink_name) = match existing {
            Some(existing) => existing,
            None => self.create_flow(key.clone()).await?,
        };

        let payload = build_udp_payload(&remote_target, &packet.payload)?;
        if let Err(error) = transport.send_packet(&payload).await {
            if is_dropped_oversized_udp_error(&error) {
                return Ok(());
            }
            let (replacement_flow_id, replacement_transport, replacement_index, replacement_name) =
                self.recreate_flow_after_send_error(
                    &key,
                    flow_id,
                    uplink_index,
                    &uplink_name,
                    &error,
                )
                .await?;
            if let Err(error) = replacement_transport.send_packet(&payload).await {
                if is_dropped_oversized_udp_error(&error) {
                    return Ok(());
                }
                return Err(error);
            }
            metrics::add_udp_datagram("client_to_upstream", &replacement_name);
            metrics::add_bytes(
                "udp",
                "client_to_upstream",
                &replacement_name,
                payload.len(),
            );
            debug!(
                flow_id = replacement_flow_id,
                uplink = %replacement_name,
                "recreated TUN UDP flow after send failure"
            );
            let _ = replacement_index;
        } else {
            metrics::add_udp_datagram("client_to_upstream", &uplink_name);
            metrics::add_bytes("udp", "client_to_upstream", &uplink_name, payload.len());
        }

        Ok(())
    }
}

pub(crate) fn classify_tun_udp_forward_error(error: &anyhow::Error) -> &'static str {
    crate::error_text::classify_tun_udp_forward_error(error)
}

fn build_udp_payload(target: &TargetAddr, payload: &[u8]) -> Result<Vec<u8>> {
    let mut out = target.to_wire_bytes()?;
    out.extend_from_slice(payload);
    Ok(out)
}

fn ip_to_target(ip: IpAddr, port: u16) -> TargetAddr {
    match ip {
        IpAddr::V4(ip) => TargetAddr::IpV4(ip, port),
        IpAddr::V6(ip) => TargetAddr::IpV6(ip, port),
    }
}

fn ip_family_from_version(version: IpVersion) -> &'static str {
    match version {
        IpVersion::V4 => "ipv4",
        IpVersion::V6 => "ipv6",
    }
}

#[cfg(test)]
mod tests {
    use super::wire::{build_ipv4_udp_packet, build_ipv6_udp_packet};
    use super::{IpVersion, parse_udp_packet};
    use crate::tun_wire::test_utils::{
        IP_PROTOCOL_UDP, assert_ipv4_header_checksum_valid, assert_transport_checksum_valid,
        corrupt_ip_length_field, corrupt_udp_length_field, random_payload, seeded_rng,
    };
    use rand::Rng;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn ipv4_udp_roundtrip() {
        let packet = build_ipv4_udp_packet(
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(10, 0, 0, 2),
            53,
            40000,
            b"hello",
        )
        .unwrap();

        let parsed = parse_udp_packet(&packet).unwrap();
        assert_eq!(parsed.version, IpVersion::V4);
        assert_eq!(parsed.source_ip, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(
            parsed.destination_ip,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
        assert_eq!(parsed.source_port, 53);
        assert_eq!(parsed.destination_port, 40000);
        assert_eq!(parsed.payload, b"hello");
    }

    #[test]
    fn ipv6_udp_roundtrip() {
        let packet = build_ipv6_udp_packet(
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
            5353,
            41000,
            b"world",
        )
        .unwrap();

        let parsed = parse_udp_packet(&packet).unwrap();
        assert_eq!(parsed.version, IpVersion::V6);
        assert_eq!(parsed.source_ip, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(
            parsed.destination_ip,
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2))
        );
        assert_eq!(parsed.source_port, 5353);
        assert_eq!(parsed.destination_port, 41000);
        assert_eq!(parsed.payload, b"world");
    }

    #[test]
    fn ipv6_udp_roundtrip_with_destination_options() {
        let source_ip = Ipv6Addr::LOCALHOST;
        let destination_ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
        let payload = b"world";
        let udp_len = 8 + payload.len();
        let extension_len = 8usize;
        let total_len = crate::tun_wire::IPV6_HEADER_LEN + extension_len + udp_len;
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&((extension_len + udp_len) as u16).to_be_bytes());
        packet[6] = crate::tun_wire::IPV6_NEXT_HEADER_DESTINATION_OPTIONS;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source_ip.octets());
        packet[24..40].copy_from_slice(&destination_ip.octets());
        packet[40] = IP_PROTOCOL_UDP;
        packet[48..50].copy_from_slice(&5353u16.to_be_bytes());
        packet[50..52].copy_from_slice(&41000u16.to_be_bytes());
        packet[52..54].copy_from_slice(&(udp_len as u16).to_be_bytes());
        packet[56..].copy_from_slice(payload);
        let checksum = crate::tun_wire::ipv6_payload_checksum(
            source_ip,
            destination_ip,
            IP_PROTOCOL_UDP,
            &packet[48..],
        );
        packet[54..56].copy_from_slice(&checksum.to_be_bytes());

        let parsed = parse_udp_packet(&packet).unwrap();
        assert_eq!(parsed.version, IpVersion::V6);
        assert_eq!(parsed.source_ip, IpAddr::V6(source_ip));
        assert_eq!(parsed.destination_ip, IpAddr::V6(destination_ip));
        assert_eq!(parsed.source_port, 5353);
        assert_eq!(parsed.destination_port, 41000);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn randomized_udp_packet_roundtrip_and_mutation_smoke() {
        let mut rng = seeded_rng(0x5eed_4eed);
        for _ in 0..128 {
            let payload = random_payload(&mut rng, 63);
            let source_port = rng.gen_range(1..=65000);
            let destination_port = rng.gen_range(1..=65000);

            if rng.gen_bool(0.5) {
                let source_ip = Ipv4Addr::new(8, 8, 4, rng.gen_range(1..=250));
                let destination_ip = Ipv4Addr::new(10, 0, 0, rng.gen_range(2..=250));
                let packet = build_ipv4_udp_packet(
                    source_ip,
                    destination_ip,
                    source_port,
                    destination_port,
                    &payload,
                )
                .unwrap();

                assert_ipv4_header_checksum_valid(&packet);
                assert_transport_checksum_valid(&packet, IP_PROTOCOL_UDP);

                let parsed = parse_udp_packet(&packet).unwrap();
                assert_eq!(parsed.version, IpVersion::V4);
                assert_eq!(parsed.source_ip, IpAddr::V4(source_ip));
                assert_eq!(parsed.destination_ip, IpAddr::V4(destination_ip));
                assert_eq!(parsed.source_port, source_port);
                assert_eq!(parsed.destination_port, destination_port);
                assert_eq!(parsed.payload, payload);

                assert!(parse_udp_packet(&corrupt_ip_length_field(&packet)).is_err());
                assert!(parse_udp_packet(&corrupt_udp_length_field(&packet)).is_err());
            } else {
                let source_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, rng.gen_range(2..=250));
                let destination_ip =
                    Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, rng.gen_range(2..=250));
                let packet = build_ipv6_udp_packet(
                    source_ip,
                    destination_ip,
                    source_port,
                    destination_port,
                    &payload,
                )
                .unwrap();

                assert_transport_checksum_valid(&packet, IP_PROTOCOL_UDP);

                let parsed = parse_udp_packet(&packet).unwrap();
                assert_eq!(parsed.version, IpVersion::V6);
                assert_eq!(parsed.source_ip, IpAddr::V6(source_ip));
                assert_eq!(parsed.destination_ip, IpAddr::V6(destination_ip));
                assert_eq!(parsed.source_port, source_port);
                assert_eq!(parsed.destination_port, destination_port);
                assert_eq!(parsed.payload, payload);

                assert!(parse_udp_packet(&corrupt_ip_length_field(&packet)).is_err());
                assert!(parse_udp_packet(&corrupt_udp_length_field(&packet)).is_err());
            }
        }
    }
}
