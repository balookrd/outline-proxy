mod list;
mod mutate;
mod payload;

// TODO(task-7): not yet wired into `server.rs`'s request dispatch. Remove this
// `allow` once that lands.
#[allow(unused_imports)]
pub(crate) use mutate::{handle_routes, handle_routes_reorder};
