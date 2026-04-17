//! Policy routing lives in the `outline-routing` workspace crate. This
//! module is a thin facade so the rest of the binary can keep using
//! `crate::routing::*` paths without churn.

pub use outline_routing::*;
