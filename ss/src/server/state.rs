//! Shared application state used by the websocket/H3 server.

use std::{collections::BTreeMap, sync::Arc};

use tokio::sync::Semaphore;

use crate::{crypto::UserKey, metrics::Metrics, outbound::OutboundIpv6};

use super::nat::NatTable;

use super::dns_cache::DnsCache;

/// Per-path TCP/UDP route tables.
pub(super) struct RouteRegistry {
    pub(super) tcp: Arc<BTreeMap<String, Arc<TransportRoute>>>,
    pub(super) udp: Arc<BTreeMap<String, Arc<TransportRoute>>>,
}

/// Process-wide services shared by every transport handler.
pub(super) struct Services {
    pub(super) metrics: Arc<Metrics>,
    pub(super) nat_table: Arc<NatTable>,
    pub(super) dns_cache: Arc<DnsCache>,
    pub(super) prefer_ipv4_upstream: bool,
    pub(super) outbound_ipv6: Option<Arc<OutboundIpv6>>,
    /// Process-wide semaphore limiting concurrent UDP relay tasks across all
    /// WebSocket sessions. `None` means no global cap is enforced.
    pub(super) udp_relay_semaphore: Option<Arc<Semaphore>>,
}

/// Credentials and HTTP front-door auth policy.
pub(super) struct AuthPolicy {
    pub(super) users: Arc<[UserKey]>,
    pub(super) http_root_auth: bool,
    pub(super) http_root_realm: Arc<str>,
}

#[derive(Clone)]
pub(super) struct AppState {
    pub(super) routes: Arc<RouteRegistry>,
    pub(super) services: Arc<Services>,
    pub(super) auth: Arc<AuthPolicy>,
}

#[derive(Clone)]
pub(super) struct TransportRoute {
    pub(super) users: Arc<[UserKey]>,
    pub(super) candidate_users: Arc<[Arc<str>]>,
}

pub(super) fn empty_transport_route() -> Arc<TransportRoute> {
    Arc::new(TransportRoute {
        users: Arc::from(Vec::<UserKey>::new().into_boxed_slice()),
        candidate_users: Arc::from(Vec::<Arc<str>>::new().into_boxed_slice()),
    })
}
