//! Helpers for bootstrapping application state from the parsed config.

use std::{collections::BTreeMap, sync::Arc};

use anyhow::Result;
use axum::http::Version;

use crate::{
    config::Config,
    crypto::UserKey,
    metrics::{Protocol, Transport},
};

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

pub(super) fn protocol_from_http_version(version: Version) -> Protocol {
    match version {
        Version::HTTP_2 => Protocol::Http2,
        _ => Protocol::Http1,
    }
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
        grouped
            .entry(path.to_owned())
            .or_default()
            .push(route.user.clone());
    }

    grouped
        .into_iter()
        .map(|(path, path_users)| {
            let candidate_users = path_users
                .iter()
                .map(|user| user.log_label())
                .collect::<Vec<_>>();
            (
                path,
                Arc::new(TransportRoute {
                    users: Arc::from(path_users.into_boxed_slice()),
                    candidate_users: Arc::from(candidate_users.into_boxed_slice()),
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

pub(super) fn build_user_routes(config: &Config) -> Result<Arc<[UserRoute]>> {
    Ok(Arc::from(
        config
            .user_entries()?
            .into_iter()
            .map(|entry| {
                let method = entry.effective_method(config.method);
                let ws_path_tcp: Arc<str> =
                    Arc::from(entry.effective_ws_path_tcp(&config.ws_path_tcp));
                let ws_path_udp: Arc<str> =
                    Arc::from(entry.effective_ws_path_udp(&config.ws_path_udp));
                UserKey::new(entry.id, &entry.password, entry.fwmark, method).map(|user| {
                    UserRoute {
                        user,
                        ws_path_tcp,
                        ws_path_udp,
                    }
                })
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_boxed_slice(),
    ))
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
