//! Loopback QUIC server shared by the `quic` tests.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

pub(super) struct Loopback {
    pub(super) server: quinn::Endpoint,
    pub(super) addr: SocketAddr,
    client_tls: Arc<quinn::crypto::rustls::QuicClientConfig>,
    roots: Arc<rustls::RootCertStore>,
}

impl Loopback {
    pub(super) fn new() -> Self {
        Self::with_server_tls(rustls::ServerConfig::builder())
    }

    /// Like [`Loopback::new`], with the server's rustls config started from `server_tls`
    /// (e.g. a builder over a provider restricted to some key-exchange groups).
    pub(super) fn with_server_tls(
        server_tls: rustls::ConfigBuilder<rustls::ServerConfig, rustls::WantsVerifier>,
    ) -> Self {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
        Self::with_identity(server_tls, cert_der, key)
    }

    /// Like [`Loopback::with_server_tls`], serving `cert_der` (valid for `localhost`)
    /// with `key` instead of a fresh self-signed certificate.
    pub(super) fn with_identity(
        server_tls: rustls::ConfigBuilder<rustls::ServerConfig, rustls::WantsVerifier>,
        cert_der: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
    ) -> Self {
        let mut server_tls = server_tls
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key)
            .unwrap();
        server_tls.alpn_protocols = vec![b"h3".to_vec()];
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_tls).unwrap(),
        ));
        // A large send window keeps the growth tests bounded by the client's flow-control
        // credit, not by the server's own send window or debug-build throughput.
        let mut server_transport = quinn::TransportConfig::default();
        server_transport.send_window(256 * 1024 * 1024);
        server_config.transport_config(Arc::new(server_transport));
        let server = quinn::Endpoint::server(server_config, loopback()).unwrap();
        let addr = server.local_addr().unwrap();

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der).unwrap();
        let roots = Arc::new(roots);
        let mut client_tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots.clone())
            .with_no_client_auth();
        client_tls.alpn_protocols = vec![b"h3".to_vec()];
        let client_tls =
            Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap());

        Self { server, addr, client_tls, roots }
    }

    /// Roots that trust this server's certificate.
    pub(super) fn roots(&self) -> Arc<rustls::RootCertStore> {
        self.roots.clone()
    }

    /// Connects a fresh client endpoint (with `endpoint_config`) using `transport`.
    pub(super) async fn connect(
        &self,
        endpoint_config: quinn::EndpointConfig,
        transport: quinn::TransportConfig,
    ) -> (quinn::Endpoint, quinn::Connection) {
        self.connect_with_tls(self.client_tls.clone(), endpoint_config, transport)
            .await
    }

    /// Like [`Loopback::connect`], with the client's QUIC TLS config `client_tls`.
    pub(super) async fn connect_with_tls(
        &self,
        client_tls: Arc<quinn::crypto::rustls::QuicClientConfig>,
        endpoint_config: quinn::EndpointConfig,
        transport: quinn::TransportConfig,
    ) -> (quinn::Endpoint, quinn::Connection) {
        self.dial(client_tls, endpoint_config, transport, self.addr).await
    }

    /// Like [`Loopback::connect`], dialling `via` (a relay in front of this server)
    /// instead of the server's own address.
    pub(super) async fn connect_via(
        &self,
        via: SocketAddr,
        endpoint_config: quinn::EndpointConfig,
        transport: quinn::TransportConfig,
    ) -> (quinn::Endpoint, quinn::Connection) {
        self.dial(self.client_tls.clone(), endpoint_config, transport, via)
            .await
    }

    async fn dial(
        &self,
        client_tls: Arc<quinn::crypto::rustls::QuicClientConfig>,
        endpoint_config: quinn::EndpointConfig,
        transport: quinn::TransportConfig,
        target: SocketAddr,
    ) -> (quinn::Endpoint, quinn::Connection) {
        let mut client_config = quinn::ClientConfig::new(client_tls);
        client_config.transport_config(Arc::new(transport));
        let socket = UdpSocket::bind(loopback()).unwrap();
        let endpoint =
            quinn::Endpoint::new(endpoint_config, None, socket, Arc::new(quinn::TokioRuntime))
                .unwrap();
        let conn = endpoint
            .connect_with(client_config, target, "localhost")
            .unwrap()
            .await
            .unwrap();
        (endpoint, conn)
    }
}

pub(super) fn loopback() -> SocketAddr {
    (Ipv4Addr::LOCALHOST, 0).into()
}

/// UDP relay standing in for a path narrower than both hosts: it forwards
/// datagrams both ways and drops every client→server datagram larger than `limit`.
pub(super) async fn narrow_uplink(
    server: SocketAddr,
    limit: usize,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let front = tokio::net::UdpSocket::bind(loopback()).await.unwrap();
    let back = tokio::net::UdpSocket::bind(loopback()).await.unwrap();
    back.connect(server).await.unwrap();
    let addr = front.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut client = None;
        let mut up = vec![0u8; 65_536];
        let mut down = vec![0u8; 65_536];
        loop {
            tokio::select! {
                Ok((n, from)) = front.recv_from(&mut up) => {
                    client = Some(from);
                    if n <= limit {
                        let _ = back.send(&up[..n]).await;
                    }
                }
                Ok(n) = back.recv(&mut down) => {
                    if let Some(to) = client {
                        let _ = front.send_to(&down[..n], to).await;
                    }
                }
            }
        }
    });
    (addr, task)
}
