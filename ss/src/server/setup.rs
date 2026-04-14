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

pub(super) fn protocol_from_http_version(version: Version) -> Protocol {
    match version {
        Version::HTTP_2 => Protocol::Http2,
        _ => Protocol::Http1,
    }
}

pub(super) fn build_transport_route_map(
    users: &[UserKey],
    transport: Transport,
) -> BTreeMap<String, TransportRoute> {
    let mut grouped = BTreeMap::<String, Vec<UserKey>>::new();
    for user in users {
        let path = match transport {
            Transport::Tcp => user.ws_path_tcp(),
            Transport::Udp => user.ws_path_udp(),
        };
        grouped.entry(path.to_owned()).or_default().push(user.clone());
    }

    grouped
        .into_iter()
        .map(|(path, path_users)| {
            let candidate_users = path_users
                .iter()
                .map(|user| format!("{}:{}", user.id(), user.cipher().as_str()))
                .collect::<Vec<_>>();
            (
                path,
                TransportRoute {
                    users: Arc::from(path_users.into_boxed_slice()),
                    candidate_users: Arc::from(candidate_users.into_boxed_slice()),
                },
            )
        })
        .collect()
}

pub(super) fn describe_user_routes(users: &[UserKey]) -> Vec<String> {
    users
        .iter()
        .map(|user| {
            format!(
                "{}:{} tcp={} udp={}",
                user.id(),
                user.cipher().as_str(),
                user.ws_path_tcp(),
                user.ws_path_udp()
            )
        })
        .collect()
}

pub(super) fn build_users(config: &Config) -> Result<Arc<[UserKey]>> {
    Ok(Arc::from(
        config
            .user_entries()?
            .into_iter()
            .map(|entry| {
                let method = entry.effective_method(config.method);
                let ws_path_tcp = entry.effective_ws_path_tcp(&config.ws_path_tcp).to_owned();
                let ws_path_udp = entry.effective_ws_path_udp(&config.ws_path_udp).to_owned();
                UserKey::new(
                    entry.id,
                    &entry.password,
                    entry.fwmark,
                    method,
                    ws_path_tcp,
                    ws_path_udp,
                )
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_boxed_slice(),
    ))
}
