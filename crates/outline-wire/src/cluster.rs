//! Cluster shard routing embedded in the 16-byte resumption session id.
//!
//! In a mesh cluster every session is pinned to a **home** server. A client
//! may enter through any server (an **edge**), which routes by a small shard
//! id carried inside the session id and relays to home. The shard is a
//! *routing hint, not a secret*: an attacker who forges it merely gets pointed
//! at the wrong home and receives a resume-miss. But its structure must not be
//! visible on the wire — a session id has to look like uniform random bytes to
//! a DPI/fingerprint observer — so the shard is obfuscated under a key derived
//! from the cluster's shared secret.
//!
//! # Layout (stable wire contract)
//!
//! A session id is [`SESSION_ID_LEN`] bytes, split into an in-the-clear seed
//! and an obfuscated payload:
//!
//! ```text
//! [ seed: 8 bytes (random) | payload: 8 bytes (XOR keystream) ]
//!                                    payload[0] high nibble = shard id
//! ```
//!
//! The seed is fresh random bytes emitted in the clear (they already look
//! random, so they leak nothing). The keystream is `BLAKE3(key, seed)`, so it
//! is fully determined by the *cleartext* seed — this avoids the circular
//! dependency of trying to derive the keystream from the bytes it encrypts.
//! Decoding re-derives the keystream from the seed, XORs the payload back and
//! reads the shard from the high nibble. Total nonce entropy is 64 (seed) + 60
//! (payload minus the 4 shard bits) = 124 bits.
//!
//! # Key derivation
//!
//! The obfuscation key is derived from the cluster PSK via BLAKE3 `derive_key`
//! with a domain-separation context, so the same PSK can also derive an
//! independent mesh-auth key (a different context) without key reuse. Only the
//! shard-obfuscation domain lives here.

/// Number of bits of the session id reserved for the shard id.
pub const SHARD_BITS: u32 = 4;

/// Number of distinct shards (servers) the cluster can address: `2^SHARD_BITS`.
pub const MAX_SHARDS: u8 = 1 << SHARD_BITS;

/// Length of a resumption session id in bytes.
pub const SESSION_ID_LEN: usize = 16;

/// Length of the in-the-clear seed prefix that keys the keystream.
const SEED_LEN: usize = 8;

/// Length of the obfuscated payload suffix (carries the shard nibble).
const PAYLOAD_LEN: usize = SESSION_ID_LEN - SEED_LEN;

/// BLAKE3 `derive_key` context for the shard-obfuscation key. Distinct from
/// the mesh-auth context so one PSK yields independent keys.
const SHARD_OBFUSCATION_CONTEXT: &str = "outline-proxy cluster shard-obfuscation v1";

/// BLAKE3 `derive_key` context for the mesh-auth key seed. Distinct from the
/// shard-obfuscation context so the two derivations never share key material.
const MESH_AUTH_CONTEXT: &str = "outline-proxy cluster mesh-auth v1";

/// Derives the mesh-auth seed from the shared cluster PSK. The interconnect
/// TLS keypair is generated deterministically from this seed, so every cluster
/// member arrives at the same keypair/certificate and can pin its peers by it
/// without any CA or certificate distribution. Domain-separated from the
/// shard-obfuscation key. See `docs/CLUSTER.md`.
pub fn derive_mesh_auth_seed(psk: &[u8]) -> [u8; 32] {
    blake3::derive_key(MESH_AUTH_CONTEXT, psk)
}

/// A cluster shard identifier — the home server a session is pinned to.
///
/// Invariant: the wrapped value is always `< MAX_SHARDS`, so it fits in
/// [`SHARD_BITS`] bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ShardId(u8);

impl ShardId {
    /// Wraps a raw value, returning `None` if it does not fit in
    /// [`SHARD_BITS`] bits.
    pub const fn new(value: u8) -> Option<Self> {
        if value < MAX_SHARDS { Some(Self(value)) } else { None }
    }

    /// The raw shard value, always `< MAX_SHARDS`.
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// Key that obfuscates the shard within a session id. Derived from the cluster
/// PSK; every cluster member derives the same key and can therefore encode and
/// decode any peer's shard.
#[derive(Clone)]
pub struct ObfuscationKey([u8; 32]);

impl ObfuscationKey {
    /// Derives the obfuscation key from the shared cluster PSK. Domain-separated
    /// so the same PSK can derive an independent mesh-auth key elsewhere.
    pub fn derive_from_psk(psk: &[u8]) -> Self {
        Self(blake3::derive_key(SHARD_OBFUSCATION_CONTEXT, psk))
    }

    /// Builds the key directly from raw bytes (test/interop helper).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

// Never expose key material through Debug.
impl std::fmt::Debug for ObfuscationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ObfuscationKey(..)")
    }
}

/// The keystream for a given seed: `BLAKE3(key, seed)` truncated to the payload
/// length. Determined solely by the cleartext seed, so encode and decode agree.
fn keystream(key: &ObfuscationKey, seed: &[u8]) -> [u8; PAYLOAD_LEN] {
    let mut out = [0u8; PAYLOAD_LEN];
    blake3::Hasher::new_keyed(&key.0)
        .update(seed)
        .finalize_xof()
        .fill(&mut out);
    out
}

/// Encodes `shard` into a session id, using `entropy` (16 fresh random bytes,
/// e.g. from the server CSPRNG) for the nonce. The result looks like uniform
/// random bytes to anyone without the key.
pub fn encode_session_id(
    key: &ObfuscationKey,
    shard: ShardId,
    entropy: &[u8; SESSION_ID_LEN],
) -> [u8; SESSION_ID_LEN] {
    let mut id = [0u8; SESSION_ID_LEN];
    // Seed: emitted in the clear.
    id[..SEED_LEN].copy_from_slice(&entropy[..SEED_LEN]);

    // Plaintext payload: shard in the high nibble of the first byte, the rest
    // is nonce entropy.
    let mut payload = [0u8; PAYLOAD_LEN];
    payload.copy_from_slice(&entropy[SEED_LEN..]);
    payload[0] = (shard.get() << SHARD_BITS) | (payload[0] & 0x0F);

    // Obfuscate: XOR with the seed-keyed keystream.
    let ks = keystream(key, &id[..SEED_LEN]);
    for (dst, (p, k)) in id[SEED_LEN..].iter_mut().zip(payload.iter().zip(ks.iter())) {
        *dst = p ^ k;
    }
    id
}

/// Decodes the shard from a session id. Any 16-byte input yields a valid
/// [`ShardId`] (the high nibble is always `< MAX_SHARDS`); a forged id simply
/// decodes to some shard, so callers treat a miss on that shard as a normal
/// resume-miss rather than an error.
pub fn decode_shard(key: &ObfuscationKey, id: &[u8; SESSION_ID_LEN]) -> ShardId {
    let ks = keystream(key, &id[..SEED_LEN]);
    let first_plain = id[SEED_LEN] ^ ks[0];
    let shard = first_plain >> SHARD_BITS;
    // `shard` is a 4-bit value, always < MAX_SHARDS.
    ShardId::new(shard).expect("4-bit shard is always in range")
}

#[cfg(test)]
#[path = "tests/cluster.rs"]
mod tests;
