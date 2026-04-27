//! Initialises all process-wide services from the parsed config.

use std::{collections::BTreeMap, sync::Arc};

use anyhow::{Context, Result};
use tokio::{sync::Semaphore, time::Duration};

use crate::{
    config::Config,
    crypto::UserKey,
    metrics::{Metrics, Transport},
    outbound::{self, InterfaceSource, OutboundIpv6},
};

use super::{
    constants::UDP_DNS_CACHE_TTL_SECS,
    dns_cache::DnsCache,
    nat::NatTable,
    replay::ReplayStore,
    resumption::{OrphanRegistry, ResumptionConfig},
    setup::{
        UserRoute, VlessUserRoute, build_transport_route_map, build_user_routes,
        build_vless_transport_route_map, build_vless_user_routes, user_keys,
    },
    state::{
        AuthPolicy, AuthUsersSnapshot, RouteRegistry, RoutesSnapshot, Services, TransportRoute,
        UdpServices, UserKeySlice, VlessTransportRoute,
    },
};
use arc_swap::ArcSwap;

pub(super) struct Built {
    pub(super) users: Arc<[UserKey]>,
    pub(super) user_routes: Arc<[UserRoute]>,
    pub(super) vless_user_routes: Arc<[VlessUserRoute]>,
    pub(super) tcp_routes: Arc<BTreeMap<String, Arc<TransportRoute>>>,
    pub(super) udp_routes: Arc<BTreeMap<String, Arc<TransportRoute>>>,
    pub(super) vless_routes: Arc<BTreeMap<String, Arc<VlessTransportRoute>>>,
    pub(super) routes: RoutesSnapshot,
    #[cfg_attr(not(feature = "control"), allow(dead_code))]
    pub(super) auth_users: AuthUsersSnapshot,
    pub(super) services: Arc<Services>,
    pub(super) auth: Arc<AuthPolicy>,
}

pub(super) fn build(config: &Arc<Config>) -> Result<Built> {
    let metrics = Metrics::new(config.as_ref());
    metrics.start_process_memory_sampler();
    let user_routes = build_user_routes(config)?;
    let vless_user_routes = build_vless_user_routes(config)?;
    let users = user_keys(user_routes.as_ref());
    let tcp_routes = Arc::new(build_transport_route_map(user_routes.as_ref(), Transport::Tcp));
    let udp_routes = Arc::new(build_transport_route_map(user_routes.as_ref(), Transport::Udp));
    let vless_routes = Arc::new(build_vless_transport_route_map(vless_user_routes.as_ref()));
    let outbound_ipv6: Option<Arc<OutboundIpv6>> = if let Some(prefix) = config.outbound_ipv6_prefix
    {
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
    let outbound_ipv6 = outbound_ipv6.and_then(probe_or_disable);
    let nat_table = NatTable::with_outbound_ipv6(
        Duration::from_secs(config.tuning.udp_nat_idle_timeout_secs),
        outbound_ipv6.clone(),
    );
    // Replay TTL is intentionally tied to NAT idle timeout: both bound the window of
    // a single client session's activity, so a replayed handshake is rejected for at
    // least as long as its NAT entry could still be live. Keep these two in sync.
    let replay_store = ReplayStore::new(
        Duration::from_secs(config.tuning.udp_nat_idle_timeout_secs),
        config.tuning.udp_replay_max_sessions,
    );
    let dns_cache = DnsCache::new(Duration::from_secs(UDP_DNS_CACHE_TTL_SECS));
    let routes: RoutesSnapshot = Arc::new(ArcSwap::from_pointee(RouteRegistry {
        tcp: Arc::clone(&tcp_routes),
        udp: Arc::clone(&udp_routes),
        vless: Arc::clone(&vless_routes),
    }));
    let auth_users: AuthUsersSnapshot =
        Arc::new(ArcSwap::from_pointee(UserKeySlice(Arc::clone(&users))));
    let udp_relay_semaphore = if config.tuning.udp_max_concurrent_relay_tasks == 0 {
        None
    } else {
        Some(Arc::new(Semaphore::new(config.tuning.udp_max_concurrent_relay_tasks)))
    };
    let resumption_cfg = ResumptionConfig::from(&config.session_resumption);
    let orphan_registry = Arc::new(OrphanRegistry::new(resumption_cfg, Arc::clone(&metrics)));
    let services = Arc::new(Services::new(
        metrics,
        dns_cache,
        config.prefer_ipv4_upstream,
        outbound_ipv6,
        UdpServices {
            nat_table,
            replay_store,
            relay_semaphore: udp_relay_semaphore,
        },
        Some(orphan_registry),
        config.tuning.ws_data_channel_capacity,
    ));
    let auth = Arc::new(AuthPolicy {
        users: Arc::clone(&auth_users),
        http_root_auth: config.http_root_auth,
        http_root_realm: Arc::from(config.http_root_realm.clone()),
    });
    Ok(Built {
        users,
        user_routes,
        vless_user_routes,
        tcp_routes,
        udp_routes,
        vless_routes,
        routes,
        auth_users,
        services,
        auth,
    })
}

/// Verify outbound IPv6 actually works by probing the configured source. On
/// success returns the input unchanged; on failure logs a `WARN` and returns
/// `None` so the rest of the process runs as if no outbound IPv6 were
/// configured. An empty interface pool is treated as transient (e.g. SLAAC
/// not yet up): we keep the source wired and let the periodic refresh pick
/// addresses up later.
fn probe_or_disable(out: Arc<OutboundIpv6>) -> Option<Arc<OutboundIpv6>> {
    const ATTEMPTS: u32 = 3;
    const TIMEOUT: Duration = Duration::from_secs(3);

    match outbound::probe(&out, outbound::DEFAULT_PROBE_TARGET, ATTEMPTS, TIMEOUT) {
        outbound::ProbeOutcome::Ok { source } => {
            tracing::info!(
                outbound = %out,
                %source,
                target = %outbound::DEFAULT_PROBE_TARGET,
                "outbound IPv6 startup probe succeeded",
            );
            Some(out)
        },
        outbound::ProbeOutcome::EmptyPool => {
            tracing::warn!(
                outbound = %out,
                "outbound IPv6 source has no addresses yet; keeping it enabled, \
                 the periodic refresh will pick addresses up when they appear",
            );
            Some(out)
        },
        outbound::ProbeOutcome::AllFailed(errors) => {
            let summary: Vec<String> = errors
                .iter()
                .map(|(src, e)| match src {
                    Some(s) => format!("{s} -> {e}"),
                    None => format!("(no source) -> {e}"),
                })
                .collect();
            tracing::warn!(
                outbound = %out,
                target = %outbound::DEFAULT_PROBE_TARGET,
                attempts = errors.len(),
                failures = ?summary,
                "outbound IPv6 startup probe failed for all attempts; disabling \
                 random outbound IPv6 source — upstream connections will use the \
                 kernel default source",
            );
            None
        },
    }
}
