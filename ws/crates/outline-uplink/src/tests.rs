use anyhow::anyhow;
use futures_util::StreamExt;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::{accept_async, tungstenite::protocol::Message};
use url::Url;

use crate::config::{
    CipherKind, LoadBalancingConfig, LoadBalancingMode, ProbeConfig, RoutingScope, TargetAddr,
    UplinkConfig, UplinkTransport, WsProbeConfig, WsTransportMode,
};
use crate::probe::build_http_probe_request;
use crate::selection::{effective_latency, score_latency};
use crate::types::{PenaltyState, PerTransportStatus, TransportKind, UplinkManager, UplinkStatus};
use crate::utils::update_rtt_ewma;
use outline_transport::connect_websocket_with_source;
use tokio::time::Instant;

fn lb() -> LoadBalancingConfig {
    LoadBalancingConfig {
        mode: LoadBalancingMode::ActiveActive,
        routing_scope: RoutingScope::PerFlow,
        sticky_ttl: Duration::from_secs(300),
        hysteresis: Duration::from_millis(50),
        failure_cooldown: Duration::from_secs(10),
        tcp_chunk0_failover_timeout: Duration::from_secs(10),
        warm_standby_tcp: 0,
        warm_standby_udp: 0,
        rtt_ewma_alpha: 0.25,
        failure_penalty: Duration::from_millis(500),
        failure_penalty_max: Duration::from_secs(30),
        failure_penalty_halflife: Duration::from_secs(60),
        h3_downgrade_duration: Duration::from_secs(60),
        udp_ws_keepalive_interval: None,
        tcp_ws_standby_keepalive_interval: None,
        tcp_active_keepalive_interval: None,
        auto_failback: false,
    }
}

#[test]
fn rtt_ewma_smooths_new_samples() {
    let mut current = Some(Duration::from_millis(100));
    update_rtt_ewma(&mut current, Some(Duration::from_millis(300)), 0.25);
    assert_eq!(current, Some(Duration::from_millis(150)));
}

#[test]
fn weighted_score_prefers_higher_weight_for_same_latency() {
    let now = Instant::now();
    let status = UplinkStatus {
        tcp: PerTransportStatus {
            latency: Some(Duration::from_millis(100)),
            rtt_ewma: Some(Duration::from_millis(100)),
            ..PerTransportStatus::default()
        },
        ..UplinkStatus::default()
    };
    let light = score_latency(&status, 1.0, TransportKind::Tcp, now, &lb()).unwrap();
    let heavy = score_latency(&status, 2.0, TransportKind::Tcp, now, &lb()).unwrap();
    assert!(heavy < light);
    assert_eq!(
        effective_latency(&status, TransportKind::Tcp, now, &lb()),
        Some(Duration::from_millis(100))
    );
}

fn probe_disabled() -> ProbeConfig {
    ProbeConfig {
        interval: Duration::from_secs(30),
        timeout: Duration::from_secs(5),
        max_concurrent: 1,
        max_dials: 1,
        min_failures: 1,
        attempts: 1,
        ws: WsProbeConfig { enabled: false },
        http: None,
        dns: None,
        tcp: None,
    }
}

#[test]
fn http_probe_uses_head_request() {
    let request = build_http_probe_request("example.com", 80, "/healthz?full=1");
    assert!(request.starts_with("HEAD /healthz?full=1 HTTP/1.1\r\n"));
    assert!(request.contains("\r\nHost: example.com\r\n"));
    assert!(request.ends_with("\r\nConnection: close\r\n\r\n"));
}

#[test]
fn http_probe_formats_ipv6_host_header() {
    let request = build_http_probe_request("2001:db8::1", 8080, "/");
    assert!(request.contains("\r\nHost: [2001:db8::1]:8080\r\n"));
}

fn make_uplink(name: &str, url: &str) -> UplinkConfig {
    UplinkConfig {
        name: name.to_string(),
        transport: UplinkTransport::Ws,
        tcp_ws_url: Some(Url::parse(url).unwrap()),
        tcp_ws_mode: WsTransportMode::Http1,
        udp_ws_url: Some(Url::parse(&(url.to_string() + "/udp")).unwrap()),
        udp_ws_mode: WsTransportMode::Http1,
        tcp_addr: None,
        udp_addr: None,
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "secret".to_string(),
        weight: 1.0,
        fwmark: None,
        ipv6_first: false,
    }
}

async fn start_keepalive_observer() -> (
    Url,
    mpsc::UnboundedReceiver<Message>,
    oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (message_tx, message_rx) = mpsc::unbounded_channel();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = accept_async(stream).await.unwrap();
        if let Some(Ok(message)) = ws.next().await {
            message_tx.send(message).unwrap();
        }
        let _ = shutdown_rx.await;
    });
    (Url::parse(&format!("ws://{addr}/tcp")).unwrap(), message_rx, shutdown_tx, task)
}

async fn set_tcp_status(manager: &UplinkManager, index: usize, healthy: bool, rtt_ms: u64) {
    manager.inner.with_status_mut(index, |status| {
        status.tcp.healthy = Some(healthy);
        status.tcp.latency = Some(Duration::from_millis(rtt_ms));
        status.tcp.rtt_ewma = Some(Duration::from_millis(rtt_ms));
    });
}

async fn set_udp_status(manager: &UplinkManager, index: usize, healthy: bool, rtt_ms: u64) {
    manager.inner.with_status_mut(index, |status| {
        status.udp.healthy = Some(healthy);
        status.udp.latency = Some(Duration::from_millis(rtt_ms));
        status.udp.rtt_ewma = Some(Duration::from_millis(rtt_ms));
    });
}

#[tokio::test]
async fn active_passive_keeps_current_healthy_uplink() {
    let mut config = lb();
    config.mode = LoadBalancingMode::ActivePassive;
    let manager = UplinkManager::new_for_test(
        "test",
        vec![
            make_uplink("primary", "wss://primary.example.com/tcp"),
            make_uplink("backup", "wss://backup.example.com/tcp"),
        ],
        probe_disabled(),
        config,
    )
    .unwrap();

    set_tcp_status(&manager, 0, true, 50).await;
    set_tcp_status(&manager, 1, true, 100).await;
    let target = TargetAddr::Domain("example.com".to_string(), 443);
    let first = manager.tcp_candidates(&target).await;
    assert_eq!(first[0].uplink.name, "primary");

    set_tcp_status(&manager, 0, true, 150).await;
    set_tcp_status(&manager, 1, true, 10).await;
    let second = manager.tcp_candidates(&target).await;
    assert_eq!(second[0].uplink.name, "primary");
}

#[tokio::test]
async fn cold_start_active_active_prefers_higher_weight_without_probe_data() {
    let manager = UplinkManager::new_for_test(
        "test",
        vec![
            make_uplink("light", "wss://light.example.com/tcp"),
            UplinkConfig {
                weight: 2.0,
                ..make_uplink("heavy", "wss://heavy.example.com/tcp")
            },
        ],
        probe_disabled(),
        lb(),
    )
    .unwrap();

    let target = TargetAddr::Domain("example.com".to_string(), 443);
    let first = manager.tcp_candidates(&target).await;
    assert_eq!(first[0].uplink.name, "heavy");
}

#[tokio::test]
async fn cold_start_active_passive_prefers_higher_weight_without_probe_data() {
    let mut config = lb();
    config.mode = LoadBalancingMode::ActivePassive;
    config.routing_scope = RoutingScope::Global;
    let manager = UplinkManager::new_for_test(
        "test",
        vec![
            make_uplink("light", "wss://light.example.com/tcp"),
            UplinkConfig {
                weight: 2.0,
                ..make_uplink("heavy", "wss://heavy.example.com/tcp")
            },
        ],
        probe_disabled(),
        config,
    )
    .unwrap();

    let target = TargetAddr::Domain("example.com".to_string(), 443);
    let first = manager.tcp_candidates(&target).await;
    assert_eq!(first[0].uplink.name, "heavy");
    assert_eq!(manager.global_active_uplink_index().await, Some(1));
}

#[tokio::test]
async fn cold_start_active_passive_prefers_higher_weight_over_better_rtt() {
    let mut config = lb();
    config.mode = LoadBalancingMode::ActivePassive;
    config.routing_scope = RoutingScope::Global;
    let manager = UplinkManager::new_for_test(
        "test",
        vec![
            make_uplink("light", "wss://light.example.com/tcp"),
            UplinkConfig {
                weight: 2.0,
                ..make_uplink("heavy", "wss://heavy.example.com/tcp")
            },
        ],
        probe_disabled(),
        config,
    )
    .unwrap();

    set_tcp_status(&manager, 0, true, 10).await;
    set_tcp_status(&manager, 1, true, 50).await;
    let target = TargetAddr::Domain("example.com".to_string(), 443);
    let first = manager.tcp_candidates(&target).await;
    assert_eq!(first[0].uplink.name, "heavy");
    assert_eq!(manager.global_active_uplink_index().await, Some(1));
}

#[tokio::test]
async fn per_uplink_scope_shares_selected_uplink_across_targets() {
    let mut config = lb();
    config.mode = LoadBalancingMode::ActivePassive;
    config.routing_scope = RoutingScope::PerUplink;
    let manager = UplinkManager::new_for_test(
        "test",
        vec![
            make_uplink("primary", "wss://primary.example.com/tcp"),
            make_uplink("backup", "wss://backup.example.com/tcp"),
        ],
        probe_disabled(),
        config,
    )
    .unwrap();

    set_tcp_status(&manager, 0, true, 50).await;
    set_tcp_status(&manager, 1, true, 100).await;
    let target_one = TargetAddr::Domain("example.com".to_string(), 443);
    let first = manager.tcp_candidates(&target_one).await;
    assert_eq!(first[0].uplink.name, "primary");

    set_tcp_status(&manager, 0, true, 200).await;
    set_tcp_status(&manager, 1, true, 10).await;
    let target_two = TargetAddr::Domain("github.com".to_string(), 443);
    let second = manager.tcp_candidates(&target_two).await;
    assert_eq!(second[0].uplink.name, "primary");
}

#[tokio::test]
async fn strict_tcp_failover_candidates_include_backup_before_failure_is_recorded() {
    let mut config = lb();
    config.mode = LoadBalancingMode::ActivePassive;
    config.routing_scope = RoutingScope::Global;
    let manager = UplinkManager::new_for_test(
        "test",
        vec![
            make_uplink("primary", "wss://primary.example.com/tcp"),
            make_uplink("backup", "wss://backup.example.com/tcp"),
        ],
        probe_disabled(),
        config,
    )
    .unwrap();

    set_tcp_status(&manager, 0, true, 20).await;
    set_tcp_status(&manager, 1, true, 40).await;
    let target = TargetAddr::Domain("example.com".to_string(), 443);

    let first = manager.tcp_candidates(&target).await;
    assert_eq!(first[0].uplink.name, "primary");
    assert_eq!(manager.active_uplink_index_for_transport(TransportKind::Tcp).await, Some(0));

    let failover_candidates = manager.tcp_failover_candidates(&target, 0).await;
    let backup = failover_candidates
        .into_iter()
        .find(|candidate| candidate.index != 0)
        .expect("backup candidate should be available for failover");

    assert_eq!(backup.uplink.name, "backup");
    assert_eq!(
        manager.active_uplink_index_for_transport(TransportKind::Tcp).await,
        Some(0),
        "candidate discovery for failover must not switch the active uplink before reconnect succeeds"
    );
}

#[tokio::test]
async fn per_uplink_scope_does_not_expire_with_sticky_ttl() {
    let mut config = lb();
    config.mode = LoadBalancingMode::ActivePassive;
    config.routing_scope = RoutingScope::PerUplink;
    config.sticky_ttl = Duration::ZERO;
    let manager = UplinkManager::new_for_test(
        "test",
        vec![
            make_uplink("primary", "wss://primary.example.com/tcp"),
            make_uplink("backup", "wss://backup.example.com/tcp"),
        ],
        probe_disabled(),
        config,
    )
    .unwrap();

    set_tcp_status(&manager, 0, true, 60).await;
    set_tcp_status(&manager, 1, true, 10).await;
    set_udp_status(&manager, 0, true, 10).await;
    set_udp_status(&manager, 1, true, 60).await;

    let tcp_target = TargetAddr::Domain("example.com".to_string(), 443);
    let udp_target = TargetAddr::IpV4("1.1.1.1".parse().unwrap(), 53);

    let first_tcp = manager.tcp_candidates(&tcp_target).await;
    let first_udp = manager.udp_candidates(Some(&udp_target)).await;
    assert_eq!(first_tcp[0].uplink.name, "backup");
    assert_eq!(first_udp[0].uplink.name, "primary");

    set_tcp_status(&manager, 0, true, 1).await;
    set_tcp_status(&manager, 1, true, 100).await;
    set_udp_status(&manager, 0, true, 100).await;
    set_udp_status(&manager, 1, true, 1).await;

    let second_tcp = manager.tcp_candidates(&tcp_target).await;
    let second_udp = manager.udp_candidates(Some(&udp_target)).await;
    assert_eq!(second_tcp[0].uplink.name, "backup");
    assert_eq!(second_udp[0].uplink.name, "primary");
    assert_eq!(manager.active_uplink_index_for_transport(TransportKind::Tcp).await, Some(1));
    assert_eq!(manager.active_uplink_index_for_transport(TransportKind::Udp).await, Some(0));
}

#[tokio::test]
async fn per_uplink_scope_ignores_penalty_in_selection_score() {
    let mut config = lb();
    config.mode = LoadBalancingMode::ActivePassive;
    config.routing_scope = RoutingScope::PerUplink;
    let manager = UplinkManager::new_for_test(
        "test",
        vec![
            make_uplink("primary", "wss://primary.example.com/tcp"),
            make_uplink("backup", "wss://backup.example.com/tcp"),
        ],
        probe_disabled(),
        config,
    )
    .unwrap();

    set_tcp_status(&manager, 0, true, 20).await;
    set_tcp_status(&manager, 1, true, 30).await;
    manager.inner.with_status_mut(0, |status| {
        status.tcp.penalty = PenaltyState {
            value_secs: 20.0,
            updated_at: Some(Instant::now()),
        };
    });

    let target = TargetAddr::Domain("example.com".to_string(), 443);
    let candidates = manager.tcp_candidates(&target).await;
    assert_eq!(candidates[0].uplink.name, "primary");
}

#[tokio::test]
async fn global_scope_shares_selected_uplink_across_tcp_and_udp() {
    let mut config = lb();
    config.mode = LoadBalancingMode::ActivePassive;
    config.routing_scope = RoutingScope::Global;
    let manager = UplinkManager::new_for_test(
        "test",
        vec![
            make_uplink("primary", "wss://primary.example.com/tcp"),
            make_uplink("backup", "wss://backup.example.com/tcp"),
        ],
        probe_disabled(),
        config,
    )
    .unwrap();

    set_tcp_status(&manager, 0, true, 50).await;
    set_tcp_status(&manager, 1, true, 10).await;
    set_udp_status(&manager, 0, true, 200).await;
    set_udp_status(&manager, 1, true, 20).await;

    let tcp_target = TargetAddr::Domain("example.com".to_string(), 443);
    let tcp_candidates = manager.tcp_candidates(&tcp_target).await;
    assert_eq!(tcp_candidates[0].uplink.name, "backup");

    let udp_target = TargetAddr::IpV4("1.1.1.1".parse().unwrap(), 53);
    let udp_candidates = manager.udp_candidates(Some(&udp_target)).await;
    assert_eq!(udp_candidates[0].uplink.name, "backup");
}

#[tokio::test]
async fn global_scope_keeps_tcp_available_when_udp_is_down() {
    let mut config = lb();
    config.mode = LoadBalancingMode::ActivePassive;
    config.routing_scope = RoutingScope::Global;
    let manager = UplinkManager::new_for_test(
        "test",
        vec![
            make_uplink("primary", "wss://primary.example.com/tcp"),
            make_uplink("backup", "wss://backup.example.com/tcp"),
        ],
        probe_disabled(),
        config,
    )
    .unwrap();

    set_tcp_status(&manager, 0, true, 20).await;
    set_tcp_status(&manager, 1, true, 50).await;
    set_udp_status(&manager, 0, false, 0).await;
    set_udp_status(&manager, 1, false, 0).await;

    let tcp_target = TargetAddr::Domain("example.com".to_string(), 443);
    let tcp_candidates = manager.tcp_candidates(&tcp_target).await;
    assert!(!tcp_candidates.is_empty());
    assert_eq!(tcp_candidates[0].uplink.name, "primary");
}

#[tokio::test]
async fn global_scope_prioritizes_tcp_quality_over_udp_quality() {
    let mut config = lb();
    config.mode = LoadBalancingMode::ActivePassive;
    config.routing_scope = RoutingScope::Global;
    let manager = UplinkManager::new_for_test(
        "test",
        vec![
            make_uplink("primary", "wss://primary.example.com/tcp"),
            make_uplink("backup", "wss://backup.example.com/tcp"),
        ],
        probe_disabled(),
        config,
    )
    .unwrap();

    set_tcp_status(&manager, 0, true, 20).await;
    set_tcp_status(&manager, 1, true, 60).await;
    set_udp_status(&manager, 0, true, 200).await;
    set_udp_status(&manager, 1, true, 10).await;

    let udp_target = TargetAddr::IpV4("1.1.1.1".parse().unwrap(), 53);
    let udp_candidates = manager.udp_candidates(Some(&udp_target)).await;
    assert_eq!(udp_candidates[0].uplink.name, "primary");

    let tcp_target = TargetAddr::Domain("example.com".to_string(), 443);
    let tcp_candidates = manager.tcp_candidates(&tcp_target).await;
    assert_eq!(tcp_candidates[0].uplink.name, "primary");
}

#[tokio::test]
async fn global_scope_keeps_udp_on_tcp_selected_uplink() {
    let mut config = lb();
    config.mode = LoadBalancingMode::ActivePassive;
    config.routing_scope = RoutingScope::Global;
    let manager = UplinkManager::new_for_test(
        "test",
        vec![
            make_uplink("primary", "wss://primary.example.com/tcp"),
            make_uplink("backup", "wss://backup.example.com/tcp"),
        ],
        probe_disabled(),
        config,
    )
    .unwrap();

    set_tcp_status(&manager, 0, true, 20).await;
    set_tcp_status(&manager, 1, true, 60).await;
    set_udp_status(&manager, 0, false, 500).await;
    set_udp_status(&manager, 1, true, 10).await;

    let udp_target = TargetAddr::IpV4("1.1.1.1".parse().unwrap(), 53);
    let udp_candidates = manager.udp_candidates(Some(&udp_target)).await;
    assert_eq!(udp_candidates[0].uplink.name, "primary");
}

// When probe is disabled, the global scope falls back to cooldown-based gating:
// the active uplink is kept even if tcp_healthy flips to false, as long as no
// cooldown has been set by a runtime failure.
#[tokio::test]
async fn global_scope_keeps_current_active_uplink_until_cooldown_when_probe_disabled() {
    let mut config = lb();
    config.mode = LoadBalancingMode::ActivePassive;
    config.routing_scope = RoutingScope::Global;
    let manager = UplinkManager::new_for_test(
        "test",
        vec![
            make_uplink("primary", "wss://primary.example.com/tcp"),
            make_uplink("backup", "wss://backup.example.com/tcp"),
        ],
        probe_disabled(),
        config,
    )
    .unwrap();

    set_tcp_status(&manager, 0, true, 20).await;
    set_tcp_status(&manager, 1, true, 60).await;

    let target = TargetAddr::Domain("example.com".to_string(), 443);
    let first = manager.tcp_candidates(&target).await;
    assert_eq!(first[0].uplink.name, "primary");

    set_tcp_status(&manager, 0, false, 20).await;
    set_tcp_status(&manager, 1, true, 5).await;

    let second = manager.tcp_candidates(&target).await;
    assert_eq!(second[0].uplink.name, "primary");
}

// When probe is enabled, the global scope switches only when the probe confirms
// the active uplink is down (tcp_healthy == Some(false)).  A transient runtime
// cooldown alone must not trigger a failover.
#[tokio::test]
async fn global_scope_switches_only_on_probe_confirmed_failure_when_probe_enabled() {
    let mut config = lb();
    config.mode = LoadBalancingMode::ActivePassive;
    config.routing_scope = RoutingScope::Global;
    let manager = UplinkManager::new_for_test(
        "test",
        vec![
            make_uplink("primary", "wss://primary.example.com/tcp"),
            make_uplink("backup", "wss://backup.example.com/tcp"),
        ],
        ProbeConfig {
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(5),
            max_concurrent: 1,
            max_dials: 1,
            min_failures: 1,
            attempts: 1,
            ws: WsProbeConfig { enabled: true },
            http: None,
            dns: None,
            tcp: None,
        },
        config.clone(),
    )
    .unwrap();

    set_tcp_status(&manager, 0, true, 20).await;
    set_tcp_status(&manager, 1, true, 60).await;

    let target = TargetAddr::Domain("example.com".to_string(), 443);
    let first = manager.tcp_candidates(&target).await;
    assert_eq!(first[0].uplink.name, "primary");

    // Runtime failure sets cooldown but probe has not confirmed the server is down.
    // Simulate: cooldown set but tcp_healthy still Some(true).
    manager.inner.with_status_mut(0, |status| {
        status.tcp.cooldown_until = Some(Instant::now() + Duration::from_secs(10));
        // tcp_healthy is still Some(true) — probe has not fired yet
    });

    // Must keep primary: probe hasn't confirmed it is down.
    let second = manager.tcp_candidates(&target).await;
    assert_eq!(second[0].uplink.name, "primary", "should not switch on cooldown alone");

    // Now the probe confirms primary is down.
    set_tcp_status(&manager, 0, false, 20).await;

    // Must switch to backup.
    let third = manager.tcp_candidates(&target).await;
    assert_eq!(third[0].uplink.name, "backup", "should switch when probe confirms failure");
}

#[tokio::test]
async fn global_scope_ignores_penalty_in_selection_score() {
    let mut config = lb();
    config.mode = LoadBalancingMode::ActivePassive;
    config.routing_scope = RoutingScope::Global;
    let manager = UplinkManager::new_for_test(
        "test",
        vec![
            make_uplink("primary", "wss://primary.example.com/tcp"),
            make_uplink("backup", "wss://backup.example.com/tcp"),
        ],
        probe_disabled(),
        config,
    )
    .unwrap();

    set_tcp_status(&manager, 0, true, 20).await;
    set_tcp_status(&manager, 1, true, 30).await;
    set_udp_status(&manager, 0, true, 40).await;
    set_udp_status(&manager, 1, true, 50).await;
    manager.inner.with_status_mut(0, |status| {
        status.tcp.penalty = PenaltyState {
            value_secs: 20.0,
            updated_at: Some(Instant::now()),
        };
        status.udp.penalty = PenaltyState {
            value_secs: 20.0,
            updated_at: Some(Instant::now()),
        };
    });

    let target = TargetAddr::Domain("example.com".to_string(), 443);
    let candidates = manager.tcp_candidates(&target).await;
    assert_eq!(candidates[0].uplink.name, "primary");
}

#[tokio::test]
async fn global_scope_does_not_expire_with_sticky_ttl() {
    let mut config = lb();
    config.mode = LoadBalancingMode::ActivePassive;
    config.routing_scope = RoutingScope::Global;
    config.sticky_ttl = Duration::ZERO;
    let manager = UplinkManager::new_for_test(
        "test",
        vec![
            make_uplink("primary", "wss://primary.example.com/tcp"),
            make_uplink("backup", "wss://backup.example.com/tcp"),
        ],
        probe_disabled(),
        config,
    )
    .unwrap();

    set_tcp_status(&manager, 0, true, 50).await;
    set_tcp_status(&manager, 1, true, 10).await;
    let tcp_target = TargetAddr::Domain("example.com".to_string(), 443);
    let first = manager.tcp_candidates(&tcp_target).await;
    assert_eq!(first[0].uplink.name, "backup");

    set_tcp_status(&manager, 0, true, 1).await;
    set_tcp_status(&manager, 1, true, 100).await;
    let second = manager.tcp_candidates(&tcp_target).await;
    assert_eq!(second[0].uplink.name, "backup");
    assert_eq!(manager.global_active_uplink_index().await, Some(1));
}

#[tokio::test]
async fn confirm_selected_uplink_updates_global_sticky_route() {
    let mut config = lb();
    config.mode = LoadBalancingMode::ActivePassive;
    config.routing_scope = RoutingScope::Global;
    let manager = UplinkManager::new_for_test(
        "test",
        vec![
            make_uplink("primary", "wss://primary.example.com/tcp"),
            make_uplink("backup", "wss://backup.example.com/tcp"),
        ],
        probe_disabled(),
        config,
    )
    .unwrap();

    let tcp_target = TargetAddr::Domain("example.com".to_string(), 443);
    manager
        .confirm_selected_uplink(TransportKind::Tcp, Some(&tcp_target), 1)
        .await;

    let snapshot = manager.snapshot().await;
    assert_eq!(snapshot.global_active_uplink.as_deref(), Some("backup"));
}

#[tokio::test]
async fn runtime_failover_does_not_promote_global_active_when_probe_enabled() {
    let mut config = lb();
    config.mode = LoadBalancingMode::ActivePassive;
    config.routing_scope = RoutingScope::Global;
    let manager = UplinkManager::new_for_test(
        "test",
        vec![
            make_uplink("primary", "wss://primary.example.com/tcp"),
            make_uplink("backup", "wss://backup.example.com/tcp"),
        ],
        ProbeConfig {
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(5),
            max_concurrent: 1,
            max_dials: 1,
            min_failures: 1,
            attempts: 1,
            ws: WsProbeConfig { enabled: true },
            http: None,
            dns: None,
            tcp: None,
        },
        config,
    )
    .unwrap();

    let target = TargetAddr::Domain("example.com".to_string(), 443);
    manager
        .confirm_selected_uplink(TransportKind::Tcp, Some(&target), 0)
        .await;
    manager
        .confirm_runtime_failover_uplink(TransportKind::Tcp, Some(&target), 1)
        .await;

    assert_eq!(
        manager.global_active_uplink_index().await,
        Some(0),
        "runtime failover should stay session-local while probe remains authoritative for the global active uplink"
    );
}

#[tokio::test]
async fn runtime_failover_promotes_global_active_when_probe_disabled() {
    let mut config = lb();
    config.mode = LoadBalancingMode::ActivePassive;
    config.routing_scope = RoutingScope::Global;
    let manager = UplinkManager::new_for_test(
        "test",
        vec![
            make_uplink("primary", "wss://primary.example.com/tcp"),
            make_uplink("backup", "wss://backup.example.com/tcp"),
        ],
        probe_disabled(),
        config,
    )
    .unwrap();

    let target = TargetAddr::Domain("example.com".to_string(), 443);
    manager
        .confirm_selected_uplink(TransportKind::Tcp, Some(&target), 0)
        .await;
    manager
        .confirm_runtime_failover_uplink(TransportKind::Tcp, Some(&target), 1)
        .await;

    assert_eq!(manager.global_active_uplink_index().await, Some(1));
}

#[tokio::test]
async fn initialize_strict_global_active_selection_sets_initial_active_before_traffic() {
    let mut config = lb();
    config.mode = LoadBalancingMode::ActivePassive;
    config.routing_scope = RoutingScope::Global;
    let manager = UplinkManager::new_for_test(
        "test",
        vec![
            make_uplink("primary", "wss://primary.example.com/tcp"),
            make_uplink("backup", "wss://backup.example.com/tcp"),
        ],
        probe_disabled(),
        config,
    )
    .unwrap();

    set_tcp_status(&manager, 0, true, 80).await;
    set_udp_status(&manager, 0, true, 80).await;
    set_tcp_status(&manager, 1, true, 20).await;
    set_udp_status(&manager, 1, true, 20).await;

    manager.initialize_strict_active_selection().await;

    assert_eq!(
        manager.global_active_uplink_index().await,
        Some(1),
        "strict global mode should choose a deterministic initial active uplink before first traffic"
    );
}

#[tokio::test]
async fn initialize_strict_global_active_selection_does_not_override_existing_active() {
    let mut config = lb();
    config.mode = LoadBalancingMode::ActivePassive;
    config.routing_scope = RoutingScope::Global;
    let manager = UplinkManager::new_for_test(
        "test",
        vec![
            make_uplink("primary", "wss://primary.example.com/tcp"),
            make_uplink("backup", "wss://backup.example.com/tcp"),
        ],
        probe_disabled(),
        config,
    )
    .unwrap();

    let target = TargetAddr::Domain("example.com".to_string(), 443);
    manager
        .confirm_selected_uplink(TransportKind::Tcp, Some(&target), 0)
        .await;
    set_tcp_status(&manager, 0, true, 80).await;
    set_udp_status(&manager, 0, true, 80).await;
    set_tcp_status(&manager, 1, true, 20).await;
    set_udp_status(&manager, 1, true, 20).await;

    manager.initialize_strict_active_selection().await;

    assert_eq!(manager.global_active_uplink_index().await, Some(0));
}

#[tokio::test]
async fn repeated_runtime_failure_during_cooldown_does_not_extend_penalty_or_cooldown() {
    let manager = UplinkManager::new_for_test(
        "test",
        vec![make_uplink("primary", "wss://primary.example.com/tcp")],
        probe_disabled(),
        lb(),
    )
    .unwrap();

    let first_error = anyhow!("first failure");
    manager
        .report_runtime_failure(0, TransportKind::Udp, &first_error)
        .await;
    let (cooldown_first, penalty_first) =
        manager.runtime_failure_debug_state(0, TransportKind::Udp).await;

    tokio::time::sleep(Duration::from_millis(20)).await;

    let second_error = anyhow!("second failure");
    manager
        .report_runtime_failure(0, TransportKind::Udp, &second_error)
        .await;
    let (cooldown_second, penalty_second) =
        manager.runtime_failure_debug_state(0, TransportKind::Udp).await;

    assert_eq!(penalty_second, penalty_first);
    assert!(cooldown_second <= cooldown_first);
}

#[tokio::test]
async fn probe_wakeup_is_rate_limited_across_fresh_cooldowns() {
    let mut probe = probe_disabled();
    probe.ws.enabled = true;
    let manager = UplinkManager::new_for_test(
        "test",
        vec![make_uplink("primary", "wss://primary.example.com/tcp")],
        probe,
        lb(),
    )
    .unwrap();

    let first_error = anyhow!("first failure");
    manager
        .report_runtime_failure(0, TransportKind::Udp, &first_error)
        .await;
    let first_wakeup_age = manager
        .runtime_failure_probe_wakeup_debug_state(0, TransportKind::Udp)
        .await;
    assert!(first_wakeup_age.is_some());

    manager.inner.with_status_mut(0, |status| {
        status.udp.cooldown_until = None;
    });

    let second_error = anyhow!("second failure");
    manager
        .report_runtime_failure(0, TransportKind::Udp, &second_error)
        .await;
    let second_wakeup_age = manager
        .runtime_failure_probe_wakeup_debug_state(0, TransportKind::Udp)
        .await;

    // Rate limit means the timestamp wasn't refreshed, so the age can only
    // grow.  An age that DROPS would imply the wakeup re-fired and the
    // timestamp was reset to a more recent instant.
    let first = first_wakeup_age.expect("first wakeup recorded");
    let second = second_wakeup_age.expect("second wakeup observed");
    assert!(
        second >= first,
        "fresh cooldown should not refresh the wakeup timestamp inside the rate-limit window (first={first}, second={second})"
    );
}

// Regression: Global+ActiveActive must not switch back to primary the moment the
// cooldown expires. global_selection_score_latency ignores penalty, so without the
// fix in preferred_sticky_index the system would immediately re-select primary on
// base latency alone, causing oscillation every ~failure_cooldown seconds.
#[tokio::test]
async fn global_active_active_does_not_switch_back_during_penalty_window() {
    let mut config = lb();
    config.routing_scope = RoutingScope::Global;
    // Keep mode as ActiveActive (default in lb()).
    let manager = UplinkManager::new_for_test(
        "test",
        vec![
            make_uplink("primary", "wss://primary.example.com/tcp"),
            make_uplink("backup", "wss://backup.example.com/tcp"),
        ],
        probe_disabled(),
        config,
    )
    .unwrap();

    // Primary is faster (20 ms), backup is slower (80 ms).
    set_tcp_status(&manager, 0, true, 20).await;
    set_tcp_status(&manager, 1, true, 80).await;
    set_udp_status(&manager, 0, true, 20).await;
    set_udp_status(&manager, 1, true, 80).await;

    let target = TargetAddr::Domain("example.com".to_string(), 443);
    let first = manager.tcp_candidates(&target).await;
    assert_eq!(first[0].uplink.name, "primary");

    // Runtime failure on primary: sets cooldown + penalty.
    let err = anyhow!("connection reset");
    manager.report_runtime_failure(0, TransportKind::Tcp, &err).await;

    // Cooldown makes primary unhealthy → switch to backup.
    let second = manager.tcp_candidates(&target).await;
    assert_eq!(second[0].uplink.name, "backup", "should switch to backup on failure");

    // Simulate cooldown expiry (probe cleared it) while penalty is still large.
    // Before the fix, global_selection_score_latency ignored the penalty so
    // primary (20ms base) would beat backup (80ms base) + hysteresis and switch back.
    manager.inner.with_status_mut(0, |status| {
        status.tcp.cooldown_until = None;
        status.tcp.healthy = Some(true); // probe confirmed it is up again
        // penalty remains high (500 ms, just added)
    });

    // Must stay on backup: penalty on primary is still 500 ms, much larger than
    // the 60 ms gap that would be needed to beat backup + hysteresis.
    let third = manager.tcp_candidates(&target).await;
    assert_eq!(
        third[0].uplink.name, "backup",
        "must not switch back to primary while failure penalty is elevated"
    );
}

// Regression test: in global mode with 3+ uplinks, when the current active
// enters cooldown the penalty-aware fallback must prefer a fresh uplink over
// the one that recently failed, even if the recently-failed uplink has a
// marginally better raw EWMA. With only 2 uplinks the recently-failed one is
// the only healthy option, so this only matters with 3 or more uplinks.
#[tokio::test]
async fn global_scope_avoids_oscillation_via_penalty_aware_fallback() {
    let mut config = lb();
    config.mode = LoadBalancingMode::ActivePassive;
    config.routing_scope = RoutingScope::Global;
    let manager = UplinkManager::new_for_test(
        "test",
        vec![
            make_uplink("primary", "wss://primary.example.com/tcp"),
            make_uplink("backup1", "wss://backup1.example.com/tcp"),
            make_uplink("backup2", "wss://backup2.example.com/tcp"),
        ],
        probe_disabled(),
        config,
    )
    .unwrap();

    let tcp_target = TargetAddr::Domain("example.com".to_string(), 443);

    // Initial state: primary fastest (no active set yet), backup1 middle, backup2 slowest.
    set_tcp_status(&manager, 0, true, 15).await;
    set_tcp_status(&manager, 1, true, 20).await;
    set_tcp_status(&manager, 2, true, 30).await;
    set_udp_status(&manager, 0, true, 15).await;
    set_udp_status(&manager, 1, true, 20).await;
    set_udp_status(&manager, 2, true, 30).await;

    let first = manager.tcp_candidates(&tcp_target).await;
    assert_eq!(first[0].uplink.name, "primary");

    // Primary fails → switch to backup1 (next best by EWMA).
    let err = anyhow!("connection refused");
    manager.report_runtime_failure(0, TransportKind::Tcp, &err).await;
    let second = manager.tcp_candidates(&tcp_target).await;
    assert_eq!(second[0].uplink.name, "backup1", "should switch to backup1");

    // Probe clears primary's cooldown but leaves the penalty intact.
    // Primary now looks like: healthy, EWMA=15ms (best), but tcp_penalty≈500ms.
    manager.inner.with_status_mut(0, |status| {
        status.tcp.cooldown_until = None;
        status.tcp.healthy = Some(true);
    });

    // Backup1 (current active) enters cooldown due to runtime failure.
    manager.report_runtime_failure(1, TransportKind::Tcp, &err).await;

    // Without penalty-aware fallback the sort is by EWMA alone:
    //   primary 15ms < backup2 30ms → primary selected (oscillation back).
    // With penalty-aware fallback the sort includes tcp_penalty:
    //   primary effective ≈ 515ms > backup2 30ms → backup2 selected.
    let third = manager.tcp_candidates(&tcp_target).await;
    assert_eq!(
        third[0].uplink.name, "backup2",
        "penalty-aware fallback must prefer fresh backup2 over recently-failed primary"
    );
}

#[tokio::test]
async fn standby_tcp_keepalive_sends_ping_and_preserves_pool_entry() {
    let mut config = lb();
    config.warm_standby_tcp = 1;
    let (url, mut message_rx, shutdown_tx, observer_task) = start_keepalive_observer().await;
    let manager = UplinkManager::new_for_test(
        "test",
        vec![make_uplink("primary", url.as_str())],
        probe_disabled(),
        config,
    )
    .unwrap();

    let ws = connect_websocket_with_source(
        manager.dns_cache(),
        &url,
        WsTransportMode::Http1,
        None,
        false,
        "test_standby",
    )
    .await
    .unwrap();
    manager.inner.standby_pools[0].tcp.lock().await.push_back(ws);

    manager.run_tcp_standby_keepalive(0).await;

    let message = tokio::time::timeout(Duration::from_secs(2), message_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(message, Message::Ping(_)));
    assert_eq!(manager.inner.standby_pools[0].tcp.lock().await.len(), 1);

    let _ = shutdown_tx.send(());
    observer_task.await.unwrap();
}

#[test]
fn deduplicate_attempted_uplink_names_preserves_order_without_duplicates() {
    use crate::manager::deduplicate_attempted_uplink_names;

    let result = deduplicate_attempted_uplink_names(
        ["nuxt", "aeza", "nuxt"].iter().copied(),
        "aeza",
    );
    assert_eq!(result, vec!["nuxt", "aeza"]);
}

#[test]
fn deduplicate_attempted_uplink_names_includes_current_when_not_seen() {
    use crate::manager::deduplicate_attempted_uplink_names;

    let result = deduplicate_attempted_uplink_names(
        ["nuxt"].iter().copied(),
        "aeza",
    );
    assert_eq!(result, vec!["nuxt", "aeza"]);
}
