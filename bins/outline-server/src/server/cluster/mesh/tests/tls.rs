use super::*;

const PSK: &[u8] = b"mesh-tls-test-psk";

#[test]
fn identity_is_deterministic() {
    // Every node derives the same certificate + pin from the same PSK, so the
    // pin needs no distribution.
    let a = MeshIdentity::derive(PSK).unwrap();
    let b = MeshIdentity::derive(PSK).unwrap();
    assert_eq!(a.pin, b.pin, "same PSK must yield the same pinned fingerprint");
    assert_eq!(a.cert_der, b.cert_der, "same PSK must yield a byte-identical cert");
}

#[test]
fn different_psk_yields_different_identity() {
    let a = MeshIdentity::derive(PSK).unwrap();
    let b = MeshIdentity::derive(b"a-different-cluster-psk").unwrap();
    assert_ne!(a.pin, b.pin, "distinct PSKs must yield distinct pins");
}

#[test]
fn builds_server_and_client_configs() {
    let id = MeshIdentity::derive(PSK).unwrap();
    assert!(build_mesh_server_quic_config(&id).is_ok());
    assert!(build_mesh_client_quic_config(&id).is_ok());
}

#[test]
fn pin_matches_own_cert_but_not_a_foreign_one() {
    // This is the trust decision the verifiers make: a peer with the same PSK
    // presents a cert that matches our pin; a peer with a different PSK does
    // not, so it cannot join the mesh.
    let me = MeshIdentity::derive(PSK).unwrap();
    let other = MeshIdentity::derive(b"a-different-cluster-psk").unwrap();
    assert!(pin_matches(&me.cert_der, &me.pin));
    assert!(!pin_matches(&other.cert_der, &me.pin));
}
