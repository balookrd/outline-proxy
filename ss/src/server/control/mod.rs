//! Control-plane HTTP endpoint for runtime user management.
//!
//! Exposes CRUD over `[[users]]` entries: list, create, delete, block, unblock.
//! Mutations atomically swap the route/auth snapshots consumed by the WebSocket
//! data plane (see [`super::state`]) so in-flight requests keep their previous
//! view and no reader observes a torn state. Changes also persist back to the
//! config file the server was loaded from, so they survive restart.
//!
//! Known v1 limitations:
//! - New per-user `ws_path_tcp`/`ws_path_udp`/`vless_ws_path` values must
//!   already exist in the startup config (the Axum/H3 routers only register
//!   paths known at startup). Creating a user on a brand-new path requires a
//!   restart.
//! - Plain shadowsocks listeners (`ss_listen`) use a startup snapshot of user
//!   keys; they are not updated at runtime. WebSocket transports are.
//! - The implicit user synthesized from the top-level `password` field cannot
//!   be mutated via the control plane.

mod dashboard;
mod handlers;
mod manager;
mod persist;
mod server;
mod ui;

pub(in crate::server) use dashboard::spawn_dashboard_server;
pub(in crate::server) use manager::UserManager;
pub(in crate::server) use server::spawn_control_server;
