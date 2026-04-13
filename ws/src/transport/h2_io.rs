use anyhow::{Context, Result, anyhow};
use pin_project_lite::pin_project;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use webpki_roots::TLS_SERVER_ROOTS;

use super::connect_tcp_socket;

static H2_CLIENT_TLS_CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();

pub(super) fn h2_client_tls_config() -> Arc<ClientConfig> {
    Arc::clone(H2_CLIENT_TLS_CONFIG.get_or_init(|| {
        let mut roots = RootCertStore::empty();
        roots.extend(TLS_SERVER_ROOTS.iter().cloned());
        let mut config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec()];
        Arc::new(config)
    }))
}

pub(super) async fn connect_tls_h2(
    addr: SocketAddr,
    host: &str,
    fwmark: Option<u32>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = connect_tcp_socket(addr, fwmark).await?;
    let connector = TlsConnector::from(h2_client_tls_config());
    let server_name = if let Ok(ip) = host.parse::<IpAddr>() {
        ServerName::IpAddress(ip.into())
    } else {
        ServerName::try_from(host.to_string())
            .map_err(|_| anyhow!("invalid TLS server name: {host}"))?
    };
    connector
        .connect(server_name, tcp)
        .await
        .context("TLS handshake for h2 websocket failed")
}

pin_project! {
    #[project = H2IoProj]
    pub(super) enum H2Io {
        Plain { #[pin] inner: TcpStream },
        Tls { #[pin] inner: tokio_rustls::client::TlsStream<TcpStream> },
    }
}

impl tokio::io::AsyncRead for H2Io {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.project() {
            H2IoProj::Plain { inner } => inner.poll_read(cx, buf),
            H2IoProj::Tls { inner } => inner.poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for H2Io {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.project() {
            H2IoProj::Plain { inner } => inner.poll_write(cx, buf),
            H2IoProj::Tls { inner } => inner.poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.project() {
            H2IoProj::Plain { inner } => inner.poll_flush(cx),
            H2IoProj::Tls { inner } => inner.poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.project() {
            H2IoProj::Plain { inner } => inner.poll_shutdown(cx),
            H2IoProj::Tls { inner } => inner.poll_shutdown(cx),
        }
    }
}
