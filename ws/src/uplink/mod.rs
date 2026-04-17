mod manager;
mod probe;
mod registry;
mod selection;
pub(crate) mod state;
mod types;
mod utils;

pub use manager::log_uplink_summary;
pub use registry::{UplinkGroup, UplinkRegistry, log_registry_summary};
pub use state::StateStore;
pub use types::{
    StickyRouteSnapshot, TransportKind, UplinkCandidate, UplinkManager, UplinkManagerSnapshot,
    UplinkSnapshot,
};

#[cfg(test)]
use probe::build_http_probe_request;
#[cfg(test)]
use selection::{effective_latency, score_latency};
#[cfg(test)]
use types::{PenaltyState, PerTransportStatus, UplinkStatus};
#[cfg(test)]
use utils::update_rtt_ewma;

#[cfg(test)]
mod tests;
