use super::super::file::ClusterPeerSection;
use super::*;

fn valid_section() -> ClusterSection {
    ClusterSection {
        enabled: Some(true),
        shard_id: Some(7),
        cluster_psk: Some(STANDARD.encode(b"cluster-secret")),
        mesh_listen: Some("127.0.0.1:9443".to_string()),
        mesh_relay_budget_ms: None,
        peers: Some(vec![
            ClusterPeerSection {
                shard: 1,
                addr: "10.0.0.1:9443".to_string(),
            },
            // This server's own shard: ignored (served locally, not relayed).
            ClusterPeerSection { shard: 7, addr: "whatever:1".to_string() },
        ]),
    }
}

#[test]
fn absent_or_disabled_is_none() {
    assert!(resolve_cluster(None).unwrap().is_none());
    let disabled = ClusterSection { enabled: Some(false), ..valid_section() };
    assert!(resolve_cluster(Some(disabled)).unwrap().is_none());
}

#[test]
fn resolves_a_valid_section() {
    let c = resolve_cluster(Some(valid_section())).unwrap().unwrap();
    assert_eq!(c.shard.get(), 7);
    assert_eq!(c.psk.as_bytes(), b"cluster-secret");
    assert_eq!(c.mesh_listen.to_string(), "127.0.0.1:9443");
    assert_eq!(c.mesh_relay_budget, Duration::from_millis(4000));
    // The self-shard peer is dropped; only the foreign peer remains.
    assert_eq!(c.peers.len(), 1);
    assert_eq!(c.peers[&ShardId::new(1).unwrap()].to_string(), "10.0.0.1:9443");
}

#[test]
fn custom_budget_is_honoured() {
    let s = ClusterSection {
        mesh_relay_budget_ms: Some(2500),
        ..valid_section()
    };
    let c = resolve_cluster(Some(s)).unwrap().unwrap();
    assert_eq!(c.mesh_relay_budget, Duration::from_millis(2500));
}

#[test]
fn missing_required_fields_error() {
    for mutate in [
        |s: &mut ClusterSection| s.shard_id = None,
        |s: &mut ClusterSection| s.cluster_psk = None,
        |s: &mut ClusterSection| s.mesh_listen = None,
    ] {
        let mut s = valid_section();
        mutate(&mut s);
        assert!(resolve_cluster(Some(s)).is_err());
    }
}

#[test]
fn rejects_out_of_range_shard() {
    let s = ClusterSection { shard_id: Some(16), ..valid_section() };
    assert!(resolve_cluster(Some(s)).is_err());
}

#[test]
fn rejects_bad_psk_and_addr() {
    let bad_psk = ClusterSection {
        cluster_psk: Some("!!! not base64".to_string()),
        ..valid_section()
    };
    assert!(resolve_cluster(Some(bad_psk)).is_err());

    let empty_psk = ClusterSection {
        cluster_psk: Some(String::new()),
        ..valid_section()
    };
    assert!(resolve_cluster(Some(empty_psk)).is_err());

    let bad_listen = ClusterSection {
        mesh_listen: Some("nonsense".to_string()),
        ..valid_section()
    };
    assert!(resolve_cluster(Some(bad_listen)).is_err());

    let bad_peer = ClusterSection {
        peers: Some(vec![ClusterPeerSection { shard: 2, addr: "nonsense".to_string() }]),
        ..valid_section()
    };
    assert!(resolve_cluster(Some(bad_peer)).is_err());
}

#[test]
fn rejects_duplicate_peer_shard() {
    let s = ClusterSection {
        peers: Some(vec![
            ClusterPeerSection {
                shard: 2,
                addr: "10.0.0.2:9443".to_string(),
            },
            ClusterPeerSection {
                shard: 2,
                addr: "10.0.0.3:9443".to_string(),
            },
        ]),
        ..valid_section()
    };
    assert!(resolve_cluster(Some(s)).is_err());
}
