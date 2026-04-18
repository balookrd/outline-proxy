pub mod config;
mod dispatcher;
mod tcp;
mod udp;

pub use config::ProxyConfig;
pub use dispatcher::handle_client;
pub(crate) use dispatcher::DispatchTarget;
