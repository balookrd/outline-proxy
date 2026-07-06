use super::*;

/// Deterministic pseudo-entropy for tests — distinct 16-byte blocks per index,
/// no `rand` dependency.
fn entropy(n: u64) -> [u8; SESSION_ID_LEN] {
    let mut out = [0u8; SESSION_ID_LEN];
    blake3::Hasher::new()
        .update(&n.to_le_bytes())
        .finalize_xof()
        .fill(&mut out);
    out
}

fn key(psk: &[u8]) -> ObfuscationKey {
    ObfuscationKey::derive_from_psk(psk)
}

#[test]
fn shard_id_range() {
    assert_eq!(ShardId::new(0).map(ShardId::get), Some(0));
    assert_eq!(ShardId::new(MAX_SHARDS - 1).map(ShardId::get), Some(MAX_SHARDS - 1));
    assert!(ShardId::new(MAX_SHARDS).is_none());
    assert!(ShardId::new(u8::MAX).is_none());
}

#[test]
fn round_trip_all_shards() {
    let k = key(b"cluster-psk-round-trip");
    for shard in 0..MAX_SHARDS {
        let sid = ShardId::new(shard).unwrap();
        for i in 0..64 {
            let id = encode_session_id(&k, sid, &entropy(i));
            assert_eq!(decode_shard(&k, &id).get(), shard, "shard {shard}, entropy {i}");
        }
    }
}

#[test]
fn deterministic() {
    let k = key(b"cluster-psk-deterministic");
    let sid = ShardId::new(9).unwrap();
    let e = entropy(1234);
    assert_eq!(encode_session_id(&k, sid, &e), encode_session_id(&k, sid, &e));
}

#[test]
fn nonce_varies_the_id() {
    // Same shard + key, different entropy → different session ids.
    let k = key(b"cluster-psk-nonce");
    let sid = ShardId::new(3).unwrap();
    let a = encode_session_id(&k, sid, &entropy(1));
    let b = encode_session_id(&k, sid, &entropy(2));
    assert_ne!(a, b);
}

#[test]
fn key_sensitivity() {
    // A different PSK yields a different id for the same (shard, entropy), and
    // decoding under the wrong key never panics and stays in range.
    let k1 = key(b"cluster-psk-one");
    let k2 = key(b"cluster-psk-two");
    let sid = ShardId::new(7).unwrap();
    let e = entropy(42);

    let id1 = encode_session_id(&k1, sid, &e);
    let id2 = encode_session_id(&k2, sid, &e);
    assert_ne!(id1, id2, "distinct keys must produce distinct ids");

    // Wrong-key decode: total function, always a valid shard (< MAX_SHARDS).
    let wrong = decode_shard(&k2, &id1);
    assert!(wrong.get() < MAX_SHARDS);
}

#[test]
fn structure_is_hidden() {
    // For a fixed shard, the obfuscated first payload byte's high nibble must
    // NOT constantly equal the shard — otherwise the routing bit would be
    // readable on the wire without the key.
    let k = key(b"cluster-psk-hidden");
    let shard = 5u8;
    let sid = ShardId::new(shard).unwrap();

    let mut distinct_nibbles = std::collections::BTreeSet::new();
    let mut equals_shard = 0;
    for i in 0..256 {
        let id = encode_session_id(&k, sid, &entropy(i));
        let nibble = id[SEED_LEN] >> SHARD_BITS;
        distinct_nibbles.insert(nibble);
        if nibble == shard {
            equals_shard += 1;
        }
    }
    assert!(distinct_nibbles.len() > 1, "obfuscated nibble must vary across nonces");
    // Roughly 1/16 of samples coincide by chance; nowhere near all 256.
    assert!(equals_shard < 64, "obfuscated nibble leaks the shard too often: {equals_shard}");
}

#[test]
fn output_looks_random() {
    // Bit balance over many ids (varying shard and nonce) should sit near 50%.
    let k = key(b"cluster-psk-random");
    let mut ones = 0u32;
    let mut total_bits = 0u32;
    for i in 0..512u64 {
        let shard = (i % MAX_SHARDS as u64) as u8;
        let sid = ShardId::new(shard).unwrap();
        let id = encode_session_id(&k, sid, &entropy(i));
        for b in id {
            ones += b.count_ones();
            total_bits += 8;
        }
    }
    let ratio = ones as f64 / total_bits as f64;
    assert!((0.45..0.55).contains(&ratio), "bit ratio {ratio} not near 0.5");
}
