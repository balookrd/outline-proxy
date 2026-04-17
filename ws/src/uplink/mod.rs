// The uplink module has been extracted to the `outline-uplink` workspace crate.
// All public items are re-exported here so that existing `crate::uplink::*`
// imports throughout the binary keep working without change.
pub use outline_uplink::*;
