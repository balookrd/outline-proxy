//! Edge-routing tests for the cluster accept path. The shard-decode routing is
//! covered exhaustively in `cluster/tests/routing.rs`; here we check that
//! `edge_route` pairs that decision with the raw advertisement the edge must
//! forward to the home over the mesh.

use axum::http::{HeaderMap, HeaderValue};
use outline_wire::cluster::{ObfuscationKey, ShardId};
use ring::rand::SystemRandom;

use super::*;

const PSK: &[u8] = b"edge-route-test-psk";

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

fn headers_with_resume(id: SessionId) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(RESUME_REQUEST_HEADER, HeaderValue::from_str(&id.to_hex()).unwrap());
    headers
}

#[test]
fn no_identity_never_relays() {
    // Not clustered: even a resume id is served locally, no advert.
    let headers = headers_with_resume(id_for(3));
    let (decision, advert) = edge_route(&headers, None);
    assert_eq!(decision, RouteDecision::Local);
    assert!(advert.is_none());
}

#[test]
fn own_shard_stays_local() {
    let me = identity(7);
    let headers = headers_with_resume(id_for(7));
    let (decision, advert) = edge_route(&headers, Some(&me));
    assert_eq!(decision, RouteDecision::Local);
    assert!(advert.is_none());
}

#[test]
fn no_resume_header_is_local() {
    let me = identity(7);
    let (decision, advert) = edge_route(&HeaderMap::new(), Some(&me));
    assert_eq!(decision, RouteDecision::Local);
    assert!(advert.is_none());
}

#[test]
fn foreign_shard_relays_and_carries_the_id() {
    let me = identity(7);
    let id = id_for(3);
    let headers = headers_with_resume(id);
    let (decision, advert) = edge_route(&headers, Some(&me));
    assert_eq!(decision, RouteDecision::Relay(ShardId::new(3).unwrap()));
    let advert = advert.expect("a relay decision yields the advert to forward");
    assert_eq!(advert.session_id.as_bytes(), id.as_bytes());
    // No capability headers present → everything defaults off / zero.
    assert!(!advert.resume_capable);
    assert!(!advert.ack_prefix);
    assert!(!advert.symmetric_replay);
    assert_eq!(advert.down_acked, 0);
}

#[test]
fn advert_forwards_raw_capability_flags() {
    let me = identity(1);
    let id = id_for(9);
    let mut headers = headers_with_resume(id);
    headers.insert(RESUME_CAPABLE_HEADER, HeaderValue::from_static("1"));
    headers.insert(ACK_PREFIX_HEADER, HeaderValue::from_static("1"));
    headers.insert(SYMMETRIC_REPLAY_HEADER, HeaderValue::from_static("1"));
    headers.insert(DOWN_ACKED_HEADER, HeaderValue::from_static("4096"));

    let (decision, advert) = edge_route(&headers, Some(&me));
    assert_eq!(decision, RouteDecision::Relay(ShardId::new(9).unwrap()));
    let advert = advert.unwrap();
    // The edge forwards the client's raw advertisement verbatim; the home
    // re-applies resumption policy from its own registry.
    assert!(advert.resume_capable);
    assert!(advert.ack_prefix);
    assert!(advert.symmetric_replay);
    assert_eq!(advert.down_acked, 4096);
}

#[test]
fn malformed_down_acked_is_zero() {
    let me = identity(2);
    let mut headers = headers_with_resume(id_for(5));
    headers.insert(SYMMETRIC_REPLAY_HEADER, HeaderValue::from_static("1"));
    headers.insert(DOWN_ACKED_HEADER, HeaderValue::from_static("not-a-number"));
    let (_, advert) = edge_route(&headers, Some(&me));
    assert_eq!(advert.unwrap().down_acked, 0);
}

#[test]
fn edge_route_relays_home_affinity_header_and_mints_unique_session_ids_with_home_shard() {
    let me = identity(2);
    let home_shard = ShardId::new(9).unwrap();
    let pinned_home = id_for(9);

    let mut headers = HeaderMap::new();
    headers.insert(RESUME_CAPABLE_HEADER, HeaderValue::from_static("1"));
    headers.insert(ACK_PREFIX_HEADER, HeaderValue::from_static("1"));
    headers.insert(
        outline_wire::resume::HOME_AFFINITY_HEADER,
        HeaderValue::from_str(&pinned_home.to_hex()).unwrap(),
    );

    let (d1, a1) = edge_route(&headers, Some(&me));
    let (d2, a2) = edge_route(&headers, Some(&me));
    assert_eq!(d1, RouteDecision::Relay(home_shard));
    assert_eq!(d2, RouteDecision::Relay(home_shard));
    let a1 = a1.unwrap();
    let a2 = a2.unwrap();
    assert!(a1.home_affinity);
    assert!(a2.home_affinity);
    assert_ne!(a1.session_id, pinned_home);
    assert_ne!(a1.session_id, a2.session_id);
    assert_eq!(a1.session_id.shard(&me.key), home_shard);
    assert_eq!(a2.session_id.shard(&me.key), home_shard);
}
