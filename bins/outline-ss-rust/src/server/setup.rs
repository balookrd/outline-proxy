//! Helpers for bootstrapping application state from the parsed config.

use std::{collections::BTreeMap, sync::Arc};

use axum::http::Version;

use crate::{
    crypto::UserKey,
    metrics::{Protocol, Transport},
    protocol::vless::VlessUser,
};
// `build_user_routes` below is the only consumer of `Config`/`Result` left in
// this module — the rest of the stage-1 builders (which needed them too) are
// gone now that `services::build` sources routes from `endpoint_routes`
// instead. It survives only as a test helper (see its own doc comment), so
// these go with it.
#[cfg(test)]
use crate::config::Config;
#[cfg(test)]
use anyhow::Result;

use super::constants::TCP_PEER_USER_CACHE_CAPACITY;
use super::peer_user_cache::PeerUserCache;
use super::state::TransportRoute;

/// A user along with the WebSocket paths it is reachable on.
///
/// Routing is a server-side concern, separate from the crypto identity in
/// [`UserKey`]; keeping the paths beside the key (and out of it) preserves
/// that separation.
// Test-only now that `control::manager::rebuild_snapshots` routes through
// `endpoint_routes` instead of these per-user-path records: every remaining
// caller of this struct and the route builders below is `#[cfg(test)]`. Kept
// (not deleted) because a large body of integration tests still hand-assembles
// route tables through them; the whole set is retired in Task 6. The `allow`
// is scoped to `not(test)` so a genuinely unused helper still warns in the
// test build.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone)]
pub(super) struct UserRoute {
    pub user: UserKey,
    pub ws_path_tcp: Arc<str>,
    pub ws_path_udp: Arc<str>,
}

#[cfg_attr(not(test), allow(dead_code))]
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

#[cfg_attr(not(test), allow(dead_code))]
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

#[cfg_attr(not(test), allow(dead_code))]
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

/// Builds the same per-user, per-path `UserRoute` records `services::build`
/// used to derive before the endpoint-driven route builder replaced it in
/// production. Kept as a test-only helper: a lot of narrow integration tests
/// (`websocket.rs`, `h3.rs`, `fallback.rs`, resumption tests, ...) still want
/// to hand-assemble a small route table without going through
/// `services::build`, and several of them exercise the still-live per-user
/// `ws_path_*` override fields (removed only in Task 6) directly.
#[cfg(test)]
pub(super) fn build_user_routes(config: &Config) -> Result<Arc<[UserRoute]>> {
    Ok(Arc::from(
        config
            .user_entries()?
            .into_iter()
            .map(|entry| -> Result<UserRoute> {
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
                let aliases = entry.build_ip_aliases()?;
                let password = entry.password.expect("user_entries filters passwordless users");
                let user = UserKey::new(entry.id, &password, entry.fwmark, method, aliases)?;
                Ok(UserRoute { user, ws_path_tcp, ws_path_udp })
            })
            .collect::<Result<Vec<_>>>()?
            .into_boxed_slice(),
    ))
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone)]
pub(super) struct VlessXhttpUserRoute {
    pub user: VlessUser,
    pub xhttp_path: Arc<str>,
}

#[cfg_attr(not(test), allow(dead_code))]
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
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone)]
pub(super) struct SsXhttpUserRoute {
    pub user: UserKey,
    pub xhttp_path: Arc<str>,
}

#[cfg_attr(not(test), allow(dead_code))]
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

/// Same situation as [`build_user_routes`]: `control::manager::rebuild_snapshots`
/// builds its `auth_keys` by hand (it already has the `UserKey`s from
/// assembling `UserRoute`s) rather than calling this, so it survives only as
/// a shared test helper.
#[cfg(test)]
pub(super) fn user_keys(routes: &[UserRoute]) -> Arc<[UserKey]> {
    Arc::from(
        routes
            .iter()
            .map(|route| route.user.clone())
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    )
}
