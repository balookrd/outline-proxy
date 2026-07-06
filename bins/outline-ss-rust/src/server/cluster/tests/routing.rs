use outline_wire::cluster::{ObfuscationKey, ShardId};
use ring::rand::SystemRandom;

use super::*;

const PSK: &[u8] = b"cluster-routing-test-psk";

fn identity(shard: u8) -> ClusterIdentity {
    ClusterIdentity {
        key: ObfuscationKey::derive_from_psk(PSK),
        shard: ShardId::new(shard).unwrap(),
    }
}

/// Mints a session id carrying `shard` under the shared test PSK.
fn id_for(shard: u8) -> SessionId {
    let rng = SystemRandom::new();
    let key = ObfuscationKey::derive_from_psk(PSK);
    SessionId::random_with_shard(&rng, &key, ShardId::new(shard).unwrap()).unwrap()
}

#[test]
fn no_identity_is_local() {
    // Not clustered: even a resume id routes locally.
    assert_eq!(decide(None, Some(id_for(3))), RouteDecision::Local);
    assert_eq!(decide(None, None), RouteDecision::Local);
}

#[test]
fn no_resume_id_is_local() {
    // First connect (no resume id): this edge becomes the home.
    let me = identity(7);
    assert_eq!(decide(Some(&me), None), RouteDecision::Local);
}

#[test]
fn own_shard_is_local() {
    let me = identity(7);
    assert_eq!(decide(Some(&me), Some(id_for(7))), RouteDecision::Local);
}

#[test]
fn foreign_shard_relays() {
    let me = identity(7);
    assert_eq!(
        decide(Some(&me), Some(id_for(3))),
        RouteDecision::Relay(ShardId::new(3).unwrap())
    );
}

#[test]
fn every_foreign_shard_relays_to_itself() {
    let me = identity(0);
    for shard in 1..outline_wire::cluster::MAX_SHARDS {
        assert_eq!(
            decide(Some(&me), Some(id_for(shard))),
            RouteDecision::Relay(ShardId::new(shard).unwrap()),
            "shard {shard} must relay to itself",
        );
    }
}
