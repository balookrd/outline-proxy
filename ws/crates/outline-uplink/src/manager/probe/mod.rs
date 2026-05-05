//! Manager-side probe loop.  Split into three submodules:
//!
//! * [`scheduler`] — spawn loop, fan-out of per-uplink probe tasks with
//!   timeouts/retries, and the policy for skipping probes on active healthy
//!   uplinks.
//! * [`outcome`] — applies a probe result to `UplinkStatus` (health, penalty,
//!   EWMA, H3 downgrade bookkeeping).
//! * [`h3_recovery`] — explicit H3 re-probe that confirms recovery and clears
//!   (or extends) the downgrade window.

mod h3_recovery;
pub(crate) mod outcome;
mod scheduler;
pub(crate) mod warm_tcp;
pub(crate) mod warm_udp;
