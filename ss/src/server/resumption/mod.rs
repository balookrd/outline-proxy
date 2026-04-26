//! Cross-transport session resumption.
//!
//! When a client transport stream closes (mid-session, for any reason)
//! the upstream relay state is moved into an in-memory orphan registry
//! instead of being torn down. A subsequent client connect — possibly on
//! a different transport — can present the Session ID it received earlier
//! and reattach to the parked upstream without re-establishing the
//! connection to the destination host.
//!
//! See `docs/SESSION-RESUMPTION.md` for the wire format and the lifecycle
//! contract.

mod config;
mod parked;
mod registry;
mod session_id;

pub(super) use config::ResumptionConfig;
#[allow(unused_imports)]
pub(super) use parked::{
    Parked, ParkedMuxSubConn, ParkedMuxSubKind, ParkedTcp, ParkedVlessMux, TcpProtocolContext,
};
#[allow(unused_imports)]
pub(super) use registry::{OrphanRegistry, ResumeMiss, ResumeOutcome};
#[allow(unused_imports)]
pub(super) use session_id::SessionId;
