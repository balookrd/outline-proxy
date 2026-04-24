//! Process-wide UDP NAT table for sharing socket state across client sessions.
//!
//! Instead of creating a new ephemeral UDP socket per incoming datagram, the NAT
//! table maintains a persistent socket per `(user_id, fwmark, target_addr)` triple.
//! This gives:
//!
//! - A stable source port for the lifetime of the NAT entry, which is required by
//!   stateful UDP protocols (QUIC, DTLS, some game protocols).
//! - Delivery of unsolicited upstream responses (server-initiated pushes) to the
//!   currently active client session.
//! - Transparent reconnect: a new client session for the same user immediately
//!   receives responses from the existing upstream socket without re-establishing
//!   the upstream association.
//!
//! Entries are evicted after `idle_timeout` with no outbound traffic.  A background
//! cleanup task calls [`NatTable::evict_idle`] on a regular interval.

mod entry;
mod reader;
mod socket;
mod table;

pub(crate) use entry::{NatKey, ResponseSender, UdpResponseSender};
pub(crate) use table::NatTable;

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddr},
        sync::Arc,
        time::Duration,
    };

    use anyhow::Result;
    use bytes::Bytes;
    use futures_util::future::BoxFuture;

    use super::{NatKey, NatTable, ResponseSender, UdpResponseSender};
    use super::reader::{MAX_UDP_PAYLOAD_SIZE, record_oversized_socket_response_drop};
    use crate::{
        config::{CipherKind, Config},
        crypto::{UdpSession, UserKey},
        metrics::{Metrics, Protocol},
    };

    /// Minimal `ResponseSender` double used to exercise the NAT layer without
    /// pulling in the WebSocket/H3 transport crates.
    struct TestResponseSender {
        protocol: Protocol,
    }

    impl ResponseSender for TestResponseSender {
        fn send_bytes(&self, _data: Bytes) -> BoxFuture<'_, bool> {
            Box::pin(async { true })
        }

        fn protocol(&self) -> Protocol {
            self.protocol
        }
    }

    fn test_sender(protocol: Protocol) -> UdpResponseSender {
        UdpResponseSender::new(Arc::new(TestResponseSender { protocol }))
    }

    #[tokio::test]
    async fn drops_oversized_socket_udp_response_and_records_metric() -> Result<()> {
        let config = Config {
            listen: Some("127.0.0.1:3000".parse().unwrap()),
            ss_listen: None,
            tls_cert_path: None,
            tls_key_path: None,
            h3_listen: None,
            h3_cert_path: None,
            h3_key_path: None,
            metrics_listen: None,
            metrics_path: "/metrics".into(),
            prefer_ipv4_upstream: false,
            outbound_ipv6_prefix: None,
            outbound_ipv6_interface: None,
            outbound_ipv6_refresh_secs: 30,
            ws_path_tcp: "/tcp".into(),
            ws_path_udp: "/udp".into(),
            http_root_auth: false,
            http_root_realm: "Authorization required".into(),
            password: None,
            fwmark: None,
            users: vec![],
            method: CipherKind::Chacha20IetfPoly1305,
            tuning: Default::default(),
        };
        let metrics = Metrics::new(&config);
        let user = UserKey::new(
            "bob",
            "secret-b",
            None,
            CipherKind::Chacha20IetfPoly1305,
            "/tcp",
            "/udp",
        )?;
        let sender = test_sender(Protocol::Socket);

        assert!(record_oversized_socket_response_drop(
            Some(&sender),
            metrics.as_ref(),
            &user,
            SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 53)),
            MAX_UDP_PAYLOAD_SIZE + 1,
        ));

        let rendered = metrics.render_prometheus();
        assert!(rendered.contains(
            "outline_ss_udp_oversized_datagrams_dropped_total{user=\"bob\",protocol=\"socket\",direction=\"target_to_client\"} 1"
        ));
        Ok(())
    }

    #[test]
    fn ignores_non_socket_or_in_range_udp_response_sizes() -> Result<()> {
        let config = Config {
            listen: Some("127.0.0.1:3000".parse().unwrap()),
            ss_listen: None,
            tls_cert_path: None,
            tls_key_path: None,
            h3_listen: None,
            h3_cert_path: None,
            h3_key_path: None,
            metrics_listen: None,
            metrics_path: "/metrics".into(),
            prefer_ipv4_upstream: false,
            outbound_ipv6_prefix: None,
            outbound_ipv6_interface: None,
            outbound_ipv6_refresh_secs: 30,
            ws_path_tcp: "/tcp".into(),
            ws_path_udp: "/udp".into(),
            http_root_auth: false,
            http_root_realm: "Authorization required".into(),
            password: None,
            fwmark: None,
            users: vec![],
            method: CipherKind::Chacha20IetfPoly1305,
            tuning: Default::default(),
        };
        let metrics = Metrics::new(&config);
        let user = UserKey::new(
            "bob",
            "secret-b",
            None,
            CipherKind::Chacha20IetfPoly1305,
            "/tcp",
            "/udp",
        )?;
        let ws_sender = test_sender(Protocol::Http2);

        assert!(!record_oversized_socket_response_drop(
            Some(&ws_sender),
            metrics.as_ref(),
            &user,
            SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53)),
            MAX_UDP_PAYLOAD_SIZE + 1,
        ));
        assert!(!record_oversized_socket_response_drop(
            Some(&ws_sender),
            metrics.as_ref(),
            &user,
            SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53)),
            MAX_UDP_PAYLOAD_SIZE,
        ));
        Ok(())
    }

    #[tokio::test]
    async fn deduplicates_concurrent_nat_entry_creation() -> Result<()> {
        let config = Config {
            listen: Some("127.0.0.1:3000".parse().unwrap()),
            ss_listen: None,
            tls_cert_path: None,
            tls_key_path: None,
            h3_listen: None,
            h3_cert_path: None,
            h3_key_path: None,
            metrics_listen: None,
            metrics_path: "/metrics".into(),
            prefer_ipv4_upstream: false,
            outbound_ipv6_prefix: None,
            outbound_ipv6_interface: None,
            outbound_ipv6_refresh_secs: 30,
            ws_path_tcp: "/tcp".into(),
            ws_path_udp: "/udp".into(),
            http_root_auth: false,
            http_root_realm: "Authorization required".into(),
            password: None,
            fwmark: None,
            users: vec![],
            method: CipherKind::Chacha20IetfPoly1305,
            tuning: Default::default(),
        };
        let metrics = Metrics::new(&config);
        let nat_table = NatTable::new(Duration::from_secs(300));
        let user = UserKey::new(
            "bob",
            "secret-b",
            None,
            CipherKind::Chacha20IetfPoly1305,
            "/tcp",
            "/udp",
        )?;
        let key = NatKey {
            user_id: user.id_arc(),
            fwmark: None,
            target: SocketAddr::from((Ipv4Addr::LOCALHOST, 5300)),
        };

        let mut tasks = Vec::new();
        for _ in 0..8 {
            let nat_table = Arc::clone(&nat_table);
            let user = user.clone();
            let key = key.clone();
            let metrics = Arc::clone(&metrics);
            tasks.push(tokio::spawn(async move {
                nat_table.get_or_create(key, &user, UdpSession::Legacy, metrics).await
            }));
        }

        let mut entries = Vec::new();
        for task in tasks {
            entries.push(task.await??);
        }

        assert_eq!(nat_table.len(), 1);
        for entry in entries.iter().skip(1) {
            assert!(Arc::ptr_eq(&entries[0], entry));
        }

        let rendered = metrics.render_prometheus();
        assert!(rendered.contains("outline_ss_udp_nat_entries_created_total 1"));
        assert!(rendered.contains("outline_ss_udp_nat_active_entries 1"));
        Ok(())
    }
}
