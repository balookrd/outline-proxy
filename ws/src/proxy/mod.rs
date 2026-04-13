mod tcp;
mod udp;

use std::net::SocketAddr;

use anyhow::Result;
use tokio::net::TcpStream;
use tracing::debug;

use crate::config::AppConfig;
use crate::metrics;
use crate::socks5::{negotiate, SocksRequest};
use crate::uplink::UplinkManager;

pub async fn handle_client(
    mut client: TcpStream,
    peer: SocketAddr,
    config: AppConfig,
    uplinks: UplinkManager,
) -> Result<()> {
    let request = negotiate(&mut client, config.socks5_auth.as_ref()).await?;
    debug!(%peer, ?request, "accepted SOCKS5 request");
    metrics::record_request(match &request {
        SocksRequest::Connect(_) => "connect",
        SocksRequest::UdpAssociate(_) => "udp_associate",
        SocksRequest::UdpInTcp(_) => "udp_in_tcp",
    });

    match request {
        SocksRequest::Connect(target) => {
            tcp::handle_tcp_connect(client, config, uplinks, target).await
        },
        SocksRequest::UdpAssociate(client_hint) => {
            udp::handle_udp_associate(client, config, uplinks, client_hint).await
        },
        SocksRequest::UdpInTcp(client_hint) => {
            udp::handle_udp_in_tcp(client, config, uplinks, client_hint).await
        },
    }
}
