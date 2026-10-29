//! Loopback QUIC server shared by the `quic` tests.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

pub(super) struct Loopback {
    pub(super) server: quinn::Endpoint,
    pub(super) addr: SocketAddr,
    client_tls: Arc<quinn::crypto::rustls::QuicClientConfig>,
}

impl Loopback {
    pub(super) fn new() -> Self {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

        let mut server_tls = rustls::ServerConfig::builder()
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
        let mut client_tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_tls.alpn_protocols = vec![b"h3".to_vec()];
        let client_tls =
            Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap());

        Self { server, addr, client_tls }
    }

    /// Connects a fresh client endpoint (with `endpoint_config`) using `transport`.
    pub(super) async fn connect(
        &self,
        endpoint_config: quinn::EndpointConfig,
        transport: quinn::TransportConfig,
    ) -> (quinn::Endpoint, quinn::Connection) {
        let mut client_config = quinn::ClientConfig::new(self.client_tls.clone());
        client_config.transport_config(Arc::new(transport));
        let socket = UdpSocket::bind(loopback()).unwrap();
        let endpoint =
            quinn::Endpoint::new(endpoint_config, None, socket, Arc::new(quinn::TokioRuntime))
                .unwrap();
        let conn = endpoint
            .connect_with(client_config, self.addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        (endpoint, conn)
    }
}

pub(super) fn loopback() -> SocketAddr {
    (Ipv4Addr::LOCALHOST, 0).into()
}
