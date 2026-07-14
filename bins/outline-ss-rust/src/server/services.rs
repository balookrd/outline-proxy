//! Initialises all process-wide services from the parsed config.

use std::{collections::BTreeMap, sync::Arc};

use anyhow::{Context, Result};
use tokio::{sync::Semaphore, time::Duration};

use outline_wire::cluster::ObfuscationKey;

use crate::{
    config::Config,
    crypto::UserKey,
    metrics::{Metrics, Transport},
    outbound::{
        self, InterfacePrefixSource, InterfaceSource, OutboundIpv6, OutboundIpv6Source,
        StickyIpv6Cache,
    },
};

use super::{
    constants::UDP_DNS_CACHE_TTL_SECS,
    dns_cache::DnsCache,
    nat::NatTable,
    replay::ReplayStore,
    resumption::{OrphanRegistry, ResumptionConfig},
    setup::{
        SsXhttpUserRoute, UserRoute, VlessUserRoute, VlessXhttpUserRoute,
        build_ss_xhttp_udp_user_routes, build_ss_xhttp_user_routes, build_transport_route_map,
        build_user_routes, build_vless_transport_route_map, build_vless_user_routes,
        build_vless_xhttp_user_routes, build_xhttp_ss_route_map, build_xhttp_vless_route_map,
        user_keys,
    },
    state::{
        AuthPolicy, AuthUsersSnapshot, RouteRegistry, RoutesSnapshot, Services, TransportRoute,
        UdpServices, UserKeySlice, VlessTransportRoute,
    },
    transport::{HttpFallbackContext, XhttpRegistryLimits, sni_fallback::SniFallbackContext},
};
use arc_swap::ArcSwap;

pub(super) struct Built {
    pub(super) users: Arc<[UserKey]>,
    pub(super) user_routes: Arc<[UserRoute]>,
    pub(super) vless_user_routes: Arc<[VlessUserRoute]>,
    pub(super) vless_xhttp_user_routes: Arc<[VlessXhttpUserRoute]>,
    pub(super) ss_xhttp_user_routes: Arc<[SsXhttpUserRoute]>,
    pub(super) ss_xhttp_udp_user_routes: Arc<[SsXhttpUserRoute]>,
    pub(super) tcp_routes: Arc<BTreeMap<String, Arc<TransportRoute>>>,
    pub(super) udp_routes: Arc<BTreeMap<String, Arc<TransportRoute>>>,
    pub(super) vless_routes: Arc<BTreeMap<String, Arc<VlessTransportRoute>>>,
    pub(super) xhttp_vless_routes: Arc<BTreeMap<String, Arc<VlessTransportRoute>>>,
    pub(super) xhttp_ss_routes: Arc<BTreeMap<String, Arc<TransportRoute>>>,
    pub(super) xhttp_ss_udp_routes: Arc<BTreeMap<String, Arc<TransportRoute>>>,
    pub(super) routes: RoutesSnapshot,
    #[cfg_attr(not(feature = "control"), allow(dead_code))]
    pub(super) auth_users: AuthUsersSnapshot,
    pub(super) services: Arc<Services>,
    pub(super) auth: Arc<AuthPolicy>,
    /// Per-process state for the HTTP fallback reverse-proxy. `None`
    /// when `[http_fallback]` is not configured.
    pub(super) http_fallback: Option<Arc<HttpFallbackContext>>,
    /// Per-process state for the SNI-routed L4 fallback. `None` when
    /// `[sni_fallback]` is not configured.
    pub(super) sni_fallback: Option<Arc<SniFallbackContext>>,
    /// Mesh cluster runtime (endpoint + peer pool). `None` when `[cluster]`
    /// is not configured. Drives the mesh listener and the edge relay.
    pub(super) cluster: Option<Arc<super::cluster::ClusterCtx>>,
}

pub(super) fn build(config: &Arc<Config>) -> Result<Built> {
    let metrics = Metrics::new(config.as_ref());
    metrics.start_process_memory_sampler();
    // Wire the process-wide carrier-padding policy (per-path; default disabled
    // keeps the wire byte-for-byte identical for unlisted paths and for
    // deployments that never opt in). Config-synchronised with the client.
    super::transport::carrier_padding::init(config.padding.clone());
    let user_routes = build_user_routes(config)?;
    let vless_user_routes = build_vless_user_routes(config)?;
    let vless_xhttp_user_routes = build_vless_xhttp_user_routes(config)?;
    let ss_xhttp_user_routes = build_ss_xhttp_user_routes(config)?;
    let ss_xhttp_udp_user_routes = build_ss_xhttp_udp_user_routes(config)?;
    // Raw VLESS-over-QUIC and the reverse-tunnel dialer were removed, so a
    // vless_id user with neither a ws_path_vless nor an xhttp_path_vless now
    // has no forward transport. Rather than hard-fail an otherwise-valid
    // config, warn and skip such users — they are already absent from every
    // route table built above.
    for entry in &config.users {
        if entry.is_enabled()
            && entry.vless_id.is_some()
            && entry
                .effective_ws_path_vless(config.ws_path_vless.as_deref())
                .is_none()
            && entry
                .effective_xhttp_path_vless(config.xhttp_path_vless.as_deref())
                .is_none()
        {
            tracing::warn!(
                user = %entry.id,
                "vless_id user has no forward transport (ws_path_vless / xhttp_path_vless); \
                 skipping — raw VLESS-over-QUIC was removed"
            );
        }
    }
    let users = user_keys(user_routes.as_ref());
    let tcp_routes = Arc::new(build_transport_route_map(user_routes.as_ref(), Transport::Tcp));
    let udp_routes = Arc::new(build_transport_route_map(user_routes.as_ref(), Transport::Udp));
    let vless_routes = Arc::new(build_vless_transport_route_map(vless_user_routes.as_ref()));
    let xhttp_vless_routes =
        Arc::new(build_xhttp_vless_route_map(vless_xhttp_user_routes.as_ref()));
    let xhttp_ss_routes = Arc::new(build_xhttp_ss_route_map(ss_xhttp_user_routes.as_ref()));
    let xhttp_ss_udp_routes = Arc::new(build_xhttp_ss_route_map(ss_xhttp_udp_user_routes.as_ref()));
    let outbound_ipv6_source: Option<OutboundIpv6Source> =
        if let Some(prefix) = config.outbound_ipv6_prefix {
            Some(OutboundIpv6Source::Prefix(prefix))
        } else if let Some(iface) = config.outbound_ipv6_interface.clone() {
            let iface_for_err = iface.clone();
            let source = InterfaceSource::bind(iface).with_context(|| {
                format!(
                    "failed to enumerate IPv6 addresses on outbound interface {iface_for_err:?} \
                     (getifaddrs(3) uses AF_NETLINK on Linux — if running under systemd, \
                     ensure RestrictAddressFamilies includes AF_NETLINK)"
                )
            })?;
            Some(OutboundIpv6Source::Interface(source))
        } else if let Some(iface) = config.outbound_ipv6_prefix_interface.clone() {
            let iface_for_err = iface.clone();
            // /64 is the universal SLAAC prefix length; derive it from the
            // interface's current global address and refresh it periodically.
            let source = InterfacePrefixSource::bind(iface, 64).with_context(|| {
                format!(
                    "failed to derive outbound IPv6 prefix from interface {iface_for_err:?} \
                     (reads /proc/net/if_inet6 on Linux)"
                )
            })?;
            Some(OutboundIpv6Source::PrefixFromInterface(source))
        } else {
            None
        };
    let outbound_ipv6: Option<Arc<OutboundIpv6>> = outbound_ipv6_source.map(|source| {
        let sticky = config
            .outbound_ipv6_sticky
            .then(|| StickyIpv6Cache::new(config.outbound_ipv6_sticky_ttl_secs));
        Arc::new(OutboundIpv6::new(source, sticky))
    });
    let outbound_ipv6 = outbound_ipv6.and_then(probe_or_disable);
    let nat_table = NatTable::with_outbound_ipv6(
        Duration::from_secs(config.tuning.udp_nat_idle_timeout_secs),
        config.tuning.udp_nat_max_entries,
        outbound_ipv6.clone(),
    );
    // Replay TTL is intentionally tied to NAT idle timeout: both bound the window of
    // a single client session's activity, so a replayed handshake is rejected for at
    // least as long as its NAT entry could still be live. Keep these two in sync.
    let replay_store = ReplayStore::new(
        Duration::from_secs(config.tuning.udp_nat_idle_timeout_secs),
        config.tuning.udp_replay_max_sessions,
    );
    // Bounded: the cache key carries the client-supplied destination host, so
    // an unbounded map would grow for the whole TTL + stale-grace window on a
    // client that resolves unique names. `0` opts out (unbounded, sweep-only).
    let dns_cache = DnsCache::with_capacity(
        Duration::from_secs(UDP_DNS_CACHE_TTL_SECS),
        config.tuning.dns_cache_max_entries,
    );
    let routes: RoutesSnapshot = Arc::new(ArcSwap::from_pointee(RouteRegistry {
        tcp: Arc::clone(&tcp_routes),
        udp: Arc::clone(&udp_routes),
        vless: Arc::clone(&vless_routes),
        xhttp_vless: Arc::clone(&xhttp_vless_routes),
        xhttp_ss: Arc::clone(&xhttp_ss_routes),
        xhttp_ss_udp: Arc::clone(&xhttp_ss_udp_routes),
    }));
    let auth_users: AuthUsersSnapshot =
        Arc::new(ArcSwap::from_pointee(UserKeySlice(Arc::clone(&users))));
    let udp_relay_semaphore = if config.tuning.udp_max_concurrent_relay_tasks == 0 {
        None
    } else {
        Some(Arc::new(Semaphore::new(config.tuning.udp_max_concurrent_relay_tasks)))
    };
    let resumption_cfg = ResumptionConfig::from(&config.session_resumption);
    // When clustered, the registry mints session ids carrying this server's
    // shard (obfuscated under the PSK) so a resuming client's edge can route
    // back to this home. Standalone servers keep plain random ids.
    let orphan_registry = {
        let registry = OrphanRegistry::new(resumption_cfg, Arc::clone(&metrics));
        match &config.cluster {
            Some(cluster) => {
                let key = ObfuscationKey::derive_from_psk(cluster.psk.as_bytes());
                registry.with_cluster(key, cluster.shard)
            },
            None => registry,
        }
    };
    let orphan_registry = Arc::new(orphan_registry);
    let services = Arc::new(Services::new(
        metrics.clone(),
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
        XhttpRegistryLimits {
            max_sessions: config.tuning.xhttp_max_sessions,
            max_relay_tasks: config.tuning.xhttp_max_concurrent_relay_tasks,
        },
    ));
    let auth = Arc::new(AuthPolicy {
        users: Arc::clone(&auth_users),
        http_root_auth: config.http_root_auth,
        http_root_realm: Arc::from(config.http_root_realm.clone()),
    });
    let http_fallback = config.http_fallback.as_ref().map(|cfg| {
        // `validate()` already enforces that the listener required by
        // each `apply_to_*` flag is set; we simply gate the bind addr
        // on the flag so an h3-only deployment with `apply_to_h1 =
        // false` does not pull a non-existent TCP listen addr.
        let tcp_inbound_listen = if cfg.apply_to_h1 { config.listen } else { None };
        let h3_inbound_listen = if cfg.apply_to_h3 { config.h3_listen } else { None };
        Arc::new(HttpFallbackContext {
            config: Arc::new(cfg.clone()),
            tcp_inbound_listen,
            h3_inbound_listen,
            inbound_tls: config.tcp_tls_enabled(),
        })
    });
    let sni_fallback = config.sni_fallback.as_ref().map(|cfg| {
        let inbound_listen = config.listen.expect("listen required when sni_fallback is set");
        Arc::new(SniFallbackContext::new(Arc::new(cfg.clone()), inbound_listen))
    });
    // Bind the mesh endpoint + build the peer pool when clustered. Fails fast
    // (aborting startup) on a bad identity or listen bind.
    let cluster = config
        .cluster
        .as_ref()
        .map(|c| super::cluster::ClusterCtx::build(c, metrics.clone()))
        .transpose()?;
    Ok(Built {
        users,
        user_routes,
        vless_user_routes,
        vless_xhttp_user_routes,
        ss_xhttp_user_routes,
        ss_xhttp_udp_user_routes,
        tcp_routes,
        udp_routes,
        vless_routes,
        xhttp_vless_routes,
        xhttp_ss_routes,
        xhttp_ss_udp_routes,
        routes,
        auth_users,
        services,
        auth,
        http_fallback,
        sni_fallback,
        cluster,
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
