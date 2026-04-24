//! Initialises all process-wide services from the parsed config.

use std::{collections::BTreeMap, sync::Arc};

use anyhow::{Context, Result};
use tokio::{sync::Semaphore, time::Duration};

use crate::{
    config::Config,
    crypto::UserKey,
    metrics::{Metrics, Transport},
    outbound::{InterfaceSource, OutboundIpv6},
};

use super::{
    constants::UDP_DNS_CACHE_TTL_SECS,
    dns_cache::DnsCache,
    nat::NatTable,
    replay::ReplayStore,
    setup::{build_transport_route_map, build_users},
    state::{AuthPolicy, RouteRegistry, Services, TransportRoute, UdpServices},
};

pub(super) struct Built {
    pub(super) metrics: Arc<Metrics>,
    pub(super) users: Arc<[UserKey]>,
    pub(super) tcp_routes: Arc<BTreeMap<String, Arc<TransportRoute>>>,
    pub(super) udp_routes: Arc<BTreeMap<String, Arc<TransportRoute>>>,
    pub(super) routes: Arc<RouteRegistry>,
    pub(super) services: Arc<Services>,
    pub(super) auth: Arc<AuthPolicy>,
    pub(super) nat_table: Arc<NatTable>,
    pub(super) replay_store: Arc<ReplayStore>,
    pub(super) dns_cache: Arc<DnsCache>,
    pub(super) outbound_ipv6: Option<Arc<OutboundIpv6>>,
}

pub(super) fn build(config: &Arc<Config>) -> Result<Built> {
    let metrics = Metrics::new(config.as_ref());
    metrics.start_process_memory_sampler();
    let users = build_users(config)?;
    let tcp_routes = Arc::new(build_transport_route_map(users.as_ref(), Transport::Tcp));
    let udp_routes = Arc::new(build_transport_route_map(users.as_ref(), Transport::Udp));
    let outbound_ipv6: Option<Arc<OutboundIpv6>> =
        if let Some(prefix) = config.outbound_ipv6_prefix {
            Some(Arc::new(OutboundIpv6::Prefix(prefix)))
        } else if let Some(iface) = config.outbound_ipv6_interface.clone() {
            let iface_for_err = iface.clone();
            let source = InterfaceSource::bind(iface).with_context(|| {
                format!(
                    "failed to enumerate IPv6 addresses on outbound interface {iface_for_err:?} \
                     (getifaddrs(3) uses AF_NETLINK on Linux — if running under systemd, \
                     ensure RestrictAddressFamilies includes AF_NETLINK)"
                )
            })?;
            Some(Arc::new(OutboundIpv6::Interface(source)))
        } else {
            None
        };
    let nat_table = NatTable::with_outbound_ipv6(
        Duration::from_secs(config.tuning.udp_nat_idle_timeout_secs),
        outbound_ipv6.clone(),
    );
    // Replay TTL is intentionally tied to NAT idle timeout: both bound the window of
    // a single client session's activity, so a replayed handshake is rejected for at
    // least as long as its NAT entry could still be live. Keep these two in sync.
    let replay_store =
        ReplayStore::new(Duration::from_secs(config.tuning.udp_nat_idle_timeout_secs));
    let dns_cache = DnsCache::new(Duration::from_secs(UDP_DNS_CACHE_TTL_SECS));
    let routes = Arc::new(RouteRegistry {
        tcp: Arc::clone(&tcp_routes),
        udp: Arc::clone(&udp_routes),
    });
    let udp_relay_semaphore = if config.tuning.udp_max_concurrent_relay_tasks == 0 {
        None
    } else {
        Some(Arc::new(Semaphore::new(
            config.tuning.udp_max_concurrent_relay_tasks,
        )))
    };
    let services = Arc::new(Services {
        metrics: metrics.clone(),
        dns_cache: Arc::clone(&dns_cache),
        prefer_ipv4_upstream: config.prefer_ipv4_upstream,
        outbound_ipv6: outbound_ipv6.clone(),
        udp: UdpServices {
            nat_table: Arc::clone(&nat_table),
            replay_store: Arc::clone(&replay_store),
            relay_semaphore: udp_relay_semaphore,
        },
    });
    let auth = Arc::new(AuthPolicy {
        users: users.clone(),
        http_root_auth: config.http_root_auth,
        http_root_realm: Arc::from(config.http_root_realm.clone()),
    });
    Ok(Built {
        metrics,
        users,
        tcp_routes,
        udp_routes,
        routes,
        services,
        auth,
        nat_table,
        replay_store,
        dns_cache,
        outbound_ipv6,
    })
}
