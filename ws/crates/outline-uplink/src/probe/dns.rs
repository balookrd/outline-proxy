//! DNS data-path probe.  Sends a single A query through the Shadowsocks UDP
//! tunnel and verifies the response transaction id and rcode — enough to
//! detect that the far side is reachable, addressed correctly, and returning
//! well-formed DNS packets.

use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use tokio::sync::Semaphore;
use tracing::debug;

use outline_transport::{
    DnsCache, TransportOperation, UdpWsTransport, VlessUdpWsTransport,
    connect_shadowsocks_udp_with_source,
};
#[cfg(feature = "quic")]
use outline_transport::{connect_ss_udp_quic, connect_vless_udp_session_quic};

use crate::config::{DnsProbeConfig, TargetAddr, UplinkConfig, UplinkTransport, WsTransportMode};

use super::metrics::BytesRecorder;

pub(super) async fn run_dns_probe(
    cache: &DnsCache,
    group: &str,
    uplink: &UplinkConfig,
    probe: &DnsProbeConfig,
    dial_limit: Arc<Semaphore>,
    effective_udp_mode: WsTransportMode,
) -> Result<bool> {
    let dns_server = probe.target_addr()?;
    let query = build_dns_query(&probe.name);

    let bytes = BytesRecorder { group, uplink: &uplink.name, transport: "udp", probe: "dns" };

    match uplink.transport {
        UplinkTransport::Ws | UplinkTransport::Shadowsocks => {
            let mut payload = dns_server.to_wire_bytes()?;
            payload.extend_from_slice(&query);

            let transport = {
                let _permit =
                    dial_limit.acquire_owned().await.expect("probe dial semaphore closed");
                match uplink.transport {
                    UplinkTransport::Ws => {
                        let udp_ws_url = uplink.udp_ws_url.as_ref().ok_or_else(|| {
                            anyhow!("uplink {} has no udp_ws_url for DNS probe", uplink.name)
                        })?;
                        if effective_udp_mode == WsTransportMode::Quic {
                            #[cfg(feature = "quic")]
                            {
                                connect_ss_udp_quic(
                                    cache,
                                    udp_ws_url,
                                    uplink.fwmark,
                                    uplink.ipv6_first,
                                    "probe_dns",
                                    uplink.cipher,
                                    &uplink.password,
                                )
                                .await
                                .with_context(|| TransportOperation::Connect {
                                    target: format!(
                                        "DNS probe raw-QUIC for uplink {}",
                                        uplink.name
                                    ),
                                })?
                            }
                            #[cfg(not(feature = "quic"))]
                            {
                                let _ = udp_ws_url;
                                return Err(anyhow!(
                                    "WsTransportMode::Quic requested but binary was built without the `quic` feature"
                                ));
                            }
                        } else {
                            UdpWsTransport::connect(
                                cache,
                                udp_ws_url,
                                effective_udp_mode,
                                uplink.cipher,
                                &uplink.password,
                                uplink.fwmark,
                                uplink.ipv6_first,
                                "probe_dns",
                                None,
                            )
                            .await
                            .with_context(|| TransportOperation::Connect {
                                target: format!("DNS probe websocket for uplink {}", uplink.name),
                            })?
                        }
                    },
                    UplinkTransport::Shadowsocks => {
                        let socket = connect_shadowsocks_udp_with_source(
                            cache,
                            uplink.udp_addr.as_ref().ok_or_else(|| {
                                anyhow!("uplink {} has no udp_addr for DNS probe", uplink.name)
                            })?,
                            uplink.fwmark,
                            uplink.ipv6_first,
                            "probe_dns",
                        )
                        .await
                        .with_context(|| TransportOperation::Connect {
                            target: format!(
                                "DNS probe shadowsocks socket for uplink {}",
                                uplink.name
                            ),
                        })?;
                        UdpWsTransport::from_socket(
                            socket,
                            uplink.cipher,
                            &uplink.password,
                            "probe_dns",
                        )?
                    },
                    UplinkTransport::Vless => unreachable!(),
                }
            };

            let result = async {
                transport
                    .send_packet(&payload)
                    .await
                    .context("failed to send DNS probe packet")?;
                bytes.outgoing(payload.len());
                let response = transport
                    .read_packet()
                    .await
                    .context("failed to read DNS probe response")?;
                bytes.incoming(response.len());
                let (_, consumed) = TargetAddr::from_wire_bytes(&response)?;
                validate_dns_response(&response[consumed..], &query)?;
                Ok::<bool, anyhow::Error>(true)
            }
            .await;

            debug!(
                uplink = %uplink.name,
                transport = "udp",
                probe = "dns",
                "closing probe transport after DNS probe"
            );
            if let Err(error) = transport.close().await {
                debug!(
                    uplink = %uplink.name,
                    transport = "udp",
                    probe = "dns",
                    error = %format!("{error:#}"),
                    "probe transport close returned error during teardown"
                );
            }
            result
        },
        UplinkTransport::Vless => {
            let udp_ws_url = uplink.udp_ws_url.as_ref().ok_or_else(|| {
                anyhow!("uplink {} has no udp_ws_url for DNS probe", uplink.name)
            })?;
            let uuid = uplink.vless_id.as_ref().ok_or_else(|| {
                anyhow!("uplink {} has no vless_id for DNS probe", uplink.name)
            })?;

            if effective_udp_mode == WsTransportMode::Quic {
                #[cfg(feature = "quic")]
                {
                    let session = {
                        let _permit = dial_limit
                            .acquire_owned()
                            .await
                            .expect("probe dial semaphore closed");
                        connect_vless_udp_session_quic(
                            cache,
                            udp_ws_url,
                            uplink.fwmark,
                            uplink.ipv6_first,
                            "probe_dns",
                            uuid,
                            &dns_server,
                        )
                        .await
                        .with_context(|| TransportOperation::Connect {
                            target: format!(
                                "DNS probe VLESS raw-QUIC for uplink {}",
                                uplink.name
                            ),
                        })?
                    };
                    let result = async {
                        session
                            .send_packet(&query)
                            .await
                            .context("failed to send DNS probe packet")?;
                        bytes.outgoing(query.len());
                        let response = session
                            .read_packet()
                            .await
                            .context("failed to read DNS probe response")?;
                        bytes.incoming(response.len());
                        validate_dns_response(&response, &query)?;
                        Ok::<bool, anyhow::Error>(true)
                    }
                    .await;
                    debug!(
                        uplink = %uplink.name,
                        transport = "udp",
                        probe = "dns",
                        "closing probe transport after DNS probe"
                    );
                    if let Err(error) = session.close().await {
                        debug!(
                            uplink = %uplink.name,
                            transport = "udp",
                            probe = "dns",
                            error = %format!("{error:#}"),
                            "probe transport close returned error during teardown"
                        );
                    }
                    return result;
                }
                #[cfg(not(feature = "quic"))]
                {
                    let _ = (udp_ws_url, uuid);
                    return Err(anyhow!(
                        "WsTransportMode::Quic requested but binary was built without the `quic` feature"
                    ));
                }
            }

            let transport = {
                let _permit =
                    dial_limit.acquire_owned().await.expect("probe dial semaphore closed");
                VlessUdpWsTransport::connect(
                    cache,
                    udp_ws_url,
                    effective_udp_mode,
                    uuid,
                    &dns_server,
                    uplink.fwmark,
                    uplink.ipv6_first,
                    "probe_dns",
                    None,
                )
                .await
                .with_context(|| TransportOperation::Connect {
                    target: format!("DNS probe VLESS websocket for uplink {}", uplink.name),
                })?
            };

            let result = async {
                transport
                    .send_packet(&query)
                    .await
                    .context("failed to send DNS probe packet")?;
                bytes.outgoing(query.len());
                let response = transport
                    .read_packet()
                    .await
                    .context("failed to read DNS probe response")?;
                bytes.incoming(response.len());
                validate_dns_response(&response, &query)?;
                Ok::<bool, anyhow::Error>(true)
            }
            .await;

            debug!(
                uplink = %uplink.name,
                transport = "udp",
                probe = "dns",
                "closing probe transport after DNS probe"
            );
            if let Err(error) = transport.close().await {
                debug!(
                    uplink = %uplink.name,
                    transport = "udp",
                    probe = "dns",
                    error = %format!("{error:#}"),
                    "probe transport close returned error during teardown"
                );
            }
            result
        },
    }
}

fn validate_dns_response(dns: &[u8], query: &[u8]) -> Result<()> {
    if dns.len() < 12 {
        bail!("DNS probe response is too short");
    }
    if dns[..2] != query[..2] {
        bail!("DNS probe transaction id mismatch");
    }
    if dns[3] & 0x0f != 0 {
        bail!("DNS probe returned non-zero rcode");
    }
    Ok(())
}

fn build_dns_query(name: &str) -> Vec<u8> {
    let txid = 0x5353u16.to_be_bytes();
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&txid);
    out.extend_from_slice(&[0x01, 0x00]);
    out.extend_from_slice(&[0x00, 0x01]);
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    out
}

