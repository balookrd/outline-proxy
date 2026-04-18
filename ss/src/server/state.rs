//! Shared application state used by the websocket/H3 server.

use std::{collections::BTreeMap, sync::Arc};

use crate::{crypto::UserKey, metrics::Metrics, nat::NatTable};

use super::dns_cache::DnsCache;

#[derive(Clone)]
pub(super) struct AppState {
    pub(super) users: Arc<[UserKey]>,
    pub(super) tcp_routes: Arc<BTreeMap<String, Arc<TransportRoute>>>,
    pub(super) udp_routes: Arc<BTreeMap<String, Arc<TransportRoute>>>,
    pub(super) metrics: Arc<Metrics>,
    pub(super) nat_table: Arc<NatTable>,
    pub(super) dns_cache: Arc<DnsCache>,
    pub(super) prefer_ipv4_upstream: bool,
    pub(super) http_root_auth: bool,
    pub(super) http_root_realm: Arc<str>,
}

#[derive(Clone)]
pub(super) struct TransportRoute {
    pub(super) users: Arc<[UserKey]>,
    pub(super) candidate_users: Arc<[String]>,
}

pub(super) fn empty_transport_route() -> Arc<TransportRoute> {
    Arc::new(TransportRoute {
        users: Arc::from(Vec::<UserKey>::new().into_boxed_slice()),
        candidate_users: Arc::from(Vec::<String>::new().into_boxed_slice()),
    })
}

