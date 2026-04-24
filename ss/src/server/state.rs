//! Shared application state used by the websocket/H3 server.

use std::{collections::BTreeMap, sync::Arc};

use arc_swap::ArcSwap;
use tokio::sync::Semaphore;

use crate::{
    crypto::UserKey, metrics::Metrics, outbound::OutboundIpv6, protocol::vless::VlessUser,
};

use super::nat::NatTable;
use super::replay::ReplayStore;

use super::dns_cache::DnsCache;

/// Per-path TCP/UDP route tables.
pub(super) struct RouteRegistry {
    pub(super) tcp: Arc<BTreeMap<String, Arc<TransportRoute>>>,
    pub(super) udp: Arc<BTreeMap<String, Arc<TransportRoute>>>,
    pub(super) vless: Arc<BTreeMap<String, Arc<VlessTransportRoute>>>,
}

/// Snapshot of live routing state that control-plane mutations swap atomically.
///
/// Handlers do `state.routes.load_full()` once per request to obtain an
/// `Arc<RouteRegistry>`, then look up the path inside. Updates publish a new
/// `RouteRegistry` via `store`, so in-flight requests keep seeing the prior
/// snapshot — no reader ever sees a torn view.
pub(super) type RoutesSnapshot = Arc<ArcSwap<RouteRegistry>>;

/// Snapshot of the HTTP Basic Auth user set. Same atomic-swap pattern as
/// [`RoutesSnapshot`]; mutations rebuild the slice and publish it.
pub(super) type AuthUsersSnapshot = Arc<ArcSwap<UserKeySlice>>;

/// Newtype wrapper so `ArcSwap` can hold what logically is `Arc<[UserKey]>`.
pub(super) struct UserKeySlice(pub Arc<[UserKey]>);

/// UDP-only services. Not touched by the TCP path.
pub(super) struct UdpServices {
    pub(super) nat_table: Arc<NatTable>,
    pub(super) replay_store: Arc<ReplayStore>,
    /// Process-wide semaphore limiting concurrent UDP relay tasks across all
    /// WebSocket sessions. `None` means no global cap is enforced.
    pub(super) relay_semaphore: Option<Arc<Semaphore>>,
}

/// Process-wide services shared by every transport handler.
pub(super) struct Services {
    pub(super) metrics: Arc<Metrics>,
    pub(super) dns_cache: Arc<DnsCache>,
    pub(super) prefer_ipv4_upstream: bool,
    pub(super) outbound_ipv6: Option<Arc<OutboundIpv6>>,
    pub(super) udp: UdpServices,
}

/// Credentials and HTTP front-door auth policy.
pub(super) struct AuthPolicy {
    pub(super) users: AuthUsersSnapshot,
    pub(super) http_root_auth: bool,
    pub(super) http_root_realm: Arc<str>,
}

#[derive(Clone)]
pub(super) struct AppState {
    pub(super) routes: RoutesSnapshot,
    pub(super) services: Arc<Services>,
    pub(super) auth: Arc<AuthPolicy>,
}

#[derive(Clone)]
pub(super) struct TransportRoute {
    pub(super) users: Arc<[UserKey]>,
    pub(super) candidate_users: Arc<[Arc<str>]>,
}

#[derive(Clone)]
pub(super) struct VlessTransportRoute {
    pub(super) users: Arc<[VlessUser]>,
    pub(super) candidate_users: Arc<[Arc<str>]>,
}

pub(super) fn empty_transport_route() -> Arc<TransportRoute> {
    Arc::new(TransportRoute {
        users: Arc::from(Vec::<UserKey>::new().into_boxed_slice()),
        candidate_users: Arc::from(Vec::<Arc<str>>::new().into_boxed_slice()),
    })
}

pub(super) fn empty_vless_transport_route() -> Arc<VlessTransportRoute> {
    Arc::new(VlessTransportRoute {
        users: Arc::from(Vec::<VlessUser>::new().into_boxed_slice()),
        candidate_users: Arc::from(Vec::<Arc<str>>::new().into_boxed_slice()),
    })
}
