pub mod config;
mod dispatcher;
pub mod router;
mod tcp;
mod udp;

pub use config::{ProxyConfig, TcpTimeouts};
pub use dispatcher::handle_client;
pub(crate) use dispatcher::Route;
pub use router::Router;
