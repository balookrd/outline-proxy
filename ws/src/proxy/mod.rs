pub mod config;
mod dispatcher;
pub mod router;
mod tcp;
mod udp;

pub use config::{ProxyConfig, TcpTimeouts};
pub use dispatcher::handle_client;
pub(crate) use dispatcher::DispatchTarget;
pub use router::Router;
