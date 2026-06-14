//! Helpers for bootstrapping application state from the parsed config.

use std::{collections::BTreeMap, sync::Arc};

use anyhow::Result;
use axum::http::Version;

use crate::{
    config::Config,
    crypto::UserKey,
    metrics::{Protocol, Transport},
    protocol::vless::VlessUser,
};

use super::constants::TCP_PEER_USER_CACHE_CAPACITY;
use super::peer_user_cache::PeerUserCache;
use super::state::TransportRoute;

/// A user along with the WebSocket paths it is reachable on.
///
/// Routing is a server-side concern, separate from the crypto identity in
/// [`UserKey`]; keeping the paths beside the key (and out of it) preserves
/// that separation.
#[derive(Clone)]
pub(super) struct UserRoute {
    pub user: UserKey,
    pub ws_path_tcp: Arc<str>,
    pub ws_path_udp: Arc<str>,
}

#[derive(Clone)]
pub(super) struct VlessUserRoute {
    pub user: VlessUser,
    pub ws_path: Arc<str>,
}

pub(super) fn protocol_from_http_version(version: Version) -> Protocol {
    match version {
        Version::HTTP_2 => Protocol::Http2,
        _ => Protocol::Http1,
    }
}

pub(super) fn build_vless_transport_route_map(
    routes: &[VlessUserRoute],
) -> BTreeMap<String, Arc<super::state::VlessTransportRoute>> {
    let mut grouped = BTreeMap::<String, Vec<VlessUser>>::new();
    for route in routes {
        grouped
            .entry(route.ws_path.to_string())
            .or_default()
            .push(route.user.clone());
    }

    grouped
        .into_iter()
        .map(|(path, path_users)| {
            let candidate_users =
                path_users.iter().map(|user| user.label_arc()).collect::<Vec<_>>();
            (
                path,
                Arc::new(super::state::VlessTransportRoute {
                    users: Arc::from(path_users.into_boxed_slice()),
                    candidate_users: Arc::from(candidate_users.into_boxed_slice()),
                }),
            )
        })
        .collect()
}

pub(super) fn build_transport_route_map(
    routes: &[UserRoute],
    transport: Transport,
) -> BTreeMap<String, Arc<TransportRoute>> {
    let mut grouped = BTreeMap::<String, Vec<UserKey>>::new();
    for route in routes {
        let path: &str = match transport {
            Transport::Tcp => &route.ws_path_tcp,
            Transport::Udp => &route.ws_path_udp,
        };
        grouped.entry(path.to_owned()).or_default().push(route.user.clone());
    }

    grouped
        .into_iter()
        .map(|(path, path_users)| {
            let candidate_users =
                path_users.iter().map(|user| user.log_label()).collect::<Vec<_>>();
            (
                path,
                Arc::new(TransportRoute {
                    users: Arc::from(path_users.into_boxed_slice()),
                    candidate_users: Arc::from(candidate_users.into_boxed_slice()),
                    peer_user_cache: Arc::new(PeerUserCache::with_capacity(
                        TCP_PEER_USER_CACHE_CAPACITY,
                    )),
                }),
            )
        })
        .collect()
}

pub(super) fn describe_user_routes(routes: &[UserRoute]) -> Vec<String> {
    routes
        .iter()
        .map(|route| {
            format!(
                "{}:{} tcp={} udp={}",
                route.user.id(),
                route.user.cipher().as_str(),
                route.ws_path_tcp,
                route.ws_path_udp,
            )
        })
        .collect()
}

pub(super) fn describe_vless_user_routes(routes: &[VlessUserRoute]) -> Vec<String> {
    routes
        .iter()
        .map(|route| format!("{} vless={}", route.user.label(), route.ws_path))
        .collect()
}

pub(super) fn describe_vless_xhttp_user_routes(routes: &[VlessXhttpUserRoute]) -> Vec<String> {
    routes
        .iter()
        .map(|route| format!("{} xhttp={}", route.user.label(), route.xhttp_path))
        .collect()
}

pub(super) fn build_user_routes(config: &Config) -> Result<Arc<[UserRoute]>> {
    Ok(Arc::from(
        config
            .user_entries()?
            .into_iter()
            .map(|entry| {
                let method = entry.effective_method(config.method);
                // A combined `ws_path_ss` puts both legs on one path: tcp and
                // udp resolve to the same base, so it lands in both WS route
                // tables and the bootstrap registers a combined
                // `<base>/{token}` upgrade. Split users keep distinct paths.
                let (ws_path_tcp, ws_path_udp): (Arc<str>, Arc<str>) =
                    match entry.effective_ws_path_ss(config.ws_path_ss.as_deref()) {
                        Some(ss) => (Arc::from(ss), Arc::from(ss)),
                        None => (
                            Arc::from(entry.effective_ws_path_tcp(&config.ws_path_tcp)),
                            Arc::from(entry.effective_ws_path_udp(&config.ws_path_udp)),
                        ),
                    };
                let password = entry.password.expect("user_entries filters passwordless users");
                UserKey::new(entry.id, &password, entry.fwmark, method).map(|user| UserRoute {
                    user,
                    ws_path_tcp,
                    ws_path_udp,
                })
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_boxed_slice(),
    ))
}

/// All VLESS users (by `vless_id`), regardless of any WS path. This is the
/// authentication set for the raw-QUIC `vless` ALPN — both the forward H3
/// listener and the reverse-tunnel dialer match an incoming UUID against it.
/// Unlike [`build_vless_user_routes`], it does NOT require a `ws_path_vless`:
/// a raw-QUIC-only or reverse-only VLESS user has no WS path, and config
/// validation already accepts that when raw VLESS-over-QUIC (or a vless
/// reverse endpoint) is configured.
pub(super) fn build_raw_vless_users(config: &Config) -> Result<Arc<[VlessUser]>> {
    Ok(Arc::from(
        config
            .users
            .iter()
            .filter_map(|entry| entry.vless_id.as_ref().map(|vless_id| (entry, vless_id)))
            .map(|(entry, vless_id)| {
                VlessUser::new(vless_id.clone(), Arc::from(entry.id.as_str()), entry.fwmark)
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_boxed_slice(),
    ))
}

pub(super) fn build_vless_user_routes(config: &Config) -> Result<Arc<[VlessUserRoute]>> {
    Ok(Arc::from(
        config
            .users
            .iter()
            .filter_map(|entry| entry.vless_id.as_ref().map(|vless_id| (entry, vless_id)))
            // Skip users that only ride raw-quic VLESS or XHTTP and have no
            // WS path — they belong to those routing tables, not this one.
            .filter_map(|(entry, vless_id)| {
                entry
                    .effective_ws_path_vless(config.ws_path_vless.as_deref())
                    .map(|path| (entry, vless_id, path))
            })
            .map(|(entry, vless_id, ws_path)| {
                VlessUser::new(vless_id.clone(), Arc::from(entry.id.as_str()), entry.fwmark)
                    .map(|user| VlessUserRoute { user, ws_path: Arc::from(ws_path) })
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_boxed_slice(),
    ))
}

#[derive(Clone)]
pub(super) struct VlessXhttpUserRoute {
    pub user: VlessUser,
    pub xhttp_path: Arc<str>,
}

pub(super) fn build_vless_xhttp_user_routes(config: &Config) -> Result<Arc<[VlessXhttpUserRoute]>> {
    Ok(Arc::from(
        config
            .users
            .iter()
            .filter_map(|entry| entry.vless_id.as_ref().map(|vless_id| (entry, vless_id)))
            .filter_map(|(entry, vless_id)| {
                entry
                    .effective_xhttp_path_vless(config.xhttp_path_vless.as_deref())
                    .map(|path| (entry, vless_id, path))
            })
            .map(|(entry, vless_id, xhttp_path)| {
                VlessUser::new(vless_id.clone(), Arc::from(entry.id.as_str()), entry.fwmark)
                    .map(|user| VlessXhttpUserRoute { user, xhttp_path: Arc::from(xhttp_path) })
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_boxed_slice(),
    ))
}

pub(super) fn build_xhttp_vless_route_map(
    routes: &[VlessXhttpUserRoute],
) -> BTreeMap<String, Arc<super::state::VlessTransportRoute>> {
    let mut grouped = BTreeMap::<String, Vec<VlessUser>>::new();
    for route in routes {
        grouped
            .entry(route.xhttp_path.to_string())
            .or_default()
            .push(route.user.clone());
    }
    grouped
        .into_iter()
        .map(|(path, path_users)| {
            let candidate_users =
                path_users.iter().map(|user| user.label_arc()).collect::<Vec<_>>();
            (
                path,
                Arc::new(super::state::VlessTransportRoute {
                    users: Arc::from(path_users.into_boxed_slice()),
                    candidate_users: Arc::from(candidate_users.into_boxed_slice()),
                }),
            )
        })
        .collect()
}

/// A Shadowsocks user reachable over an XHTTP base path. The SS payload is
/// authenticated by the same [`UserKey`] as SS-over-WS; only the carrier
/// differs, so the route record is a plain [`TransportRoute`].
#[derive(Clone)]
pub(super) struct SsXhttpUserRoute {
    pub user: UserKey,
    pub xhttp_path: Arc<str>,
}

pub(super) fn describe_ss_xhttp_user_routes(routes: &[SsXhttpUserRoute]) -> Vec<String> {
    routes
        .iter()
        .map(|route| {
            format!(
                "{}:{} ss-xhttp={}",
                route.user.id(),
                route.user.cipher().as_str(),
                route.xhttp_path,
            )
        })
        .collect()
}

pub(super) fn build_ss_xhttp_user_routes(config: &Config) -> Result<Arc<[SsXhttpUserRoute]>> {
    Ok(Arc::from(
        config
            .user_entries()?
            .into_iter()
            // Keep only users that resolve to an SS-over-XHTTP base path
            // (per-user override or the global `xhttp_path_tcp`). Others
            // belong to the WS tables, not this one.
            .filter_map(|entry| {
                // A combined `xhttp_path_ss` feeds BOTH the tcp and udp maps,
                // so the base path lands in both tables and the bootstrap tags
                // it `SsCombined`. The split `xhttp_path_tcp` is the fallback
                // for non-combined users.
                let path = entry
                    .effective_xhttp_path_ss(config.xhttp_path_ss.as_deref())
                    .or_else(|| entry.effective_xhttp_path_tcp(config.xhttp_path_tcp.as_deref()))?
                    .to_owned();
                Some((entry, path))
            })
            .map(|(entry, xhttp_path)| {
                let method = entry.effective_method(config.method);
                let password = entry.password.expect("user_entries filters passwordless users");
                UserKey::new(entry.id, &password, entry.fwmark, method).map(|user| {
                    SsXhttpUserRoute {
                        user,
                        xhttp_path: Arc::from(xhttp_path.as_str()),
                    }
                })
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_boxed_slice(),
    ))
}

/// Same as [`build_ss_xhttp_user_routes`] but for the SS-UDP-over-XHTTP
/// base path (`xhttp_path_udp`). Reuses `SsXhttpUserRoute` /
/// `build_xhttp_ss_route_map` — the route record is identical; only the
/// base path resolved per user differs.
pub(super) fn build_ss_xhttp_udp_user_routes(config: &Config) -> Result<Arc<[SsXhttpUserRoute]>> {
    Ok(Arc::from(
        config
            .user_entries()?
            .into_iter()
            .filter_map(|entry| {
                // Combined `xhttp_path_ss` also feeds the udp map (see the tcp
                // builder); the split `xhttp_path_udp` is the fallback.
                let path = entry
                    .effective_xhttp_path_ss(config.xhttp_path_ss.as_deref())
                    .or_else(|| entry.effective_xhttp_path_udp(config.xhttp_path_udp.as_deref()))?
                    .to_owned();
                Some((entry, path))
            })
            .map(|(entry, xhttp_path)| {
                let method = entry.effective_method(config.method);
                let password = entry.password.expect("user_entries filters passwordless users");
                UserKey::new(entry.id, &password, entry.fwmark, method).map(|user| {
                    SsXhttpUserRoute {
                        user,
                        xhttp_path: Arc::from(xhttp_path.as_str()),
                    }
                })
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_boxed_slice(),
    ))
}

pub(super) fn build_xhttp_ss_route_map(
    routes: &[SsXhttpUserRoute],
) -> BTreeMap<String, Arc<TransportRoute>> {
    let mut grouped = BTreeMap::<String, Vec<UserKey>>::new();
    for route in routes {
        grouped
            .entry(route.xhttp_path.to_string())
            .or_default()
            .push(route.user.clone());
    }
    grouped
        .into_iter()
        .map(|(path, path_users)| {
            let candidate_users =
                path_users.iter().map(|user| user.log_label()).collect::<Vec<_>>();
            (
                path,
                Arc::new(TransportRoute {
                    users: Arc::from(path_users.into_boxed_slice()),
                    candidate_users: Arc::from(candidate_users.into_boxed_slice()),
                    peer_user_cache: Arc::new(PeerUserCache::with_capacity(
                        TCP_PEER_USER_CACHE_CAPACITY,
                    )),
                }),
            )
        })
        .collect()
}

#[cfg(test)]
pub(super) fn build_users(config: &Config) -> Result<Arc<[UserKey]>> {
    Ok(user_keys(build_user_routes(config)?.as_ref()))
}

pub(super) fn user_keys(routes: &[UserRoute]) -> Arc<[UserKey]> {
    Arc::from(
        routes
            .iter()
            .map(|route| route.user.clone())
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    )
}
