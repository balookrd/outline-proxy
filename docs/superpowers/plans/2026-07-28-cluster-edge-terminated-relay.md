# Edge-terminated cluster relay — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the cluster mesh relay work with per-node paths and per-node credentials by moving client-crypto termination from the home to the edge.

**Architecture:** Today the edge splices the still-encrypted client carrier to the home, so the home must hold the same path and credentials to decrypt it — which is why an asymmetric fleet produced a black hole. After this change the edge authenticates the client with its own credentials and the mesh carries application **plaintext** inside the QUIC/TLS tunnel it already establishes; the home becomes a pure session owner (real upstream socket, park, replay ring). Because echoing `X-Outline-Resume-Session` in the `101` must be decided before the client can be authenticated, OPEN becomes two-phase: OPEN (no user) → ACK → `101` → authenticate → USER frame → owner check → plaintext stream.

**Tech Stack:** Rust (edition 2024), tokio, quinn/rustls (mesh QUIC), axum (WS/XHTTP), h3. Server crate `bins/outline-ss-rust`.

**Design spec:** `docs/superpowers/specs/2026-07-28-cluster-edge-terminated-relay-design.md` — read it before Task 1.

## Global Constraints

- Tests live in a `tests/` subdirectory next to the module (`<dir>/tests/<basename>.rs`), wired with `#[cfg(test)] #[path = "tests/<basename>.rs"] mod tests;`. Never inline `#[cfg(test)] mod tests {}`.
- User-facing docs are maintained in EN **and** RU in the same change (`*.md` / `*.ru.md`). Never update one side only.
- Commit messages, code comments and PR text in English. Never add `Co-Authored-By: Claude` or any "Generated with Claude Code" footer.
- Never log secrets/PSK/UUID/tokens. Keep metrics labels low-cardinality.
- Every `unsafe` block carries a `// SAFETY:` comment with a concrete invariant. Enforced by `clippy::undocumented_unsafe_blocks`.
- Do not `git push` unless explicitly asked. Committing per task is expected.
- **CI gate — run locally before every commit, in exactly this order** (`fmt` fails first and masks clippy):

```bash
cargo fmt --check -p outline-ss-rust -p outline-ws-rust -p outline-metrics -p outline-net -p outline-routing -p outline-transport -p outline-tun -p outline-uplink -p outline-wire -p shadowsocks-crypto -p socks5-proto
```

```bash
cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
```

```bash
cargo test --workspace --exclude sockudo-ws
```

- Protocol guardrails that must not regress: H3 keepalive rules, bounded resources (every new long-lived task/buffer needs an explicit limit), transport fallback and cross-transport resume.

## File Structure

| File | Responsibility | Task |
|---|---|---|
| `server/cluster/mesh/frame.rs` | T1 adds the `UserFrame` codec + `NoSession`; T3 adds the v5 header beside v4; T7 deletes v4 | 1, 3, 7 |
| `server/cluster/mesh/tests/frame.rs` | Codec roundtrips, bounds rejection (T1); v5 layout and version rejection (T3) | 1, 3 |
| `server/relay.rs` | New `UpstreamRead` trait; `relay_upstream_to_client` generified off `OwnedReadHalf` | 2 |
| `server/tests/relay.rs` | Trait behaviour against a fake upstream | 2 |
| `server/resumption/registry.rs` | Read-only `has_park(id)` probe for the phase-1 ACK | 3 |
| `server/transport/mesh_relay.rs` | T3 adds the v5 two-phase accept + plaintext splice beside v4; T7 deletes the v4 path and its route lookup | 3, 7 |
| `server/transport/tests/mesh_relay.rs` | Home-side hit/miss/owner-mismatch | 3 |
| `server/transport/upstream_source.rs` | `UpstreamSource` enum (`Direct` / `Mesh`) shared by all three carriers | 5 |
| `server/cluster/mesh/frame.rs` (v5 only) | T4 adds the acked-offset and close-intent fields v4 had and v5 lacked | 4 |
| `server/transport/tcp.rs` | Edge SS-TCP: authenticate, send USER, relay over mesh upstream, never park | 5 |
| `server/transport/vless/mod.rs`, `vless/tcp.rs` | Same for VLESS | 6 |
| `server/transport/udp.rs` | Edge SS-UDP (datagram framing) | 8 |
| `server/transport/udp.rs`, `server/nat/` | Identity-supplied UDP entry point so the home routes plaintext datagrams | 7 |
| `server/tests/resumption/cluster.rs` | Cross-node continuity with asymmetric paths and credentials | 10 |
| `server/config/` (validator), `metrics/registry.rs` | Shared-user-namespace validation; `no_session`/`unknown_user` labels registered | 11 |
| `docs/CLUSTER.md` + `.ru.md`, `docs/CLUSTER-DEPLOY.md` + `.ru.md` | Per-node paths/creds documented; §3a symmetry requirement replaced | 11 |

**Milestone:** after Task 5 the feature works end-to-end for SS-TCP — the largest carrier on the fleet. Tasks 6–8 extend it to VLESS and SS-UDP, Task 9 removes the superseded v4 path. The branch is deployable (behind `[cluster] enabled`, currently `false` fleet-wide) after Task 9.

**Why the home speaks two versions for a while:** 24 end-to-end cluster tests exercise the live v4 relay across all three carriers. Switching the home and the edges in one step would leave those red for four consecutive tasks, which no CI gate can pass and which hides a Task 3 defect until Task 6. So Task 3 adds v5 beside v4, Tasks 5–8 move one carrier at a time, and Task 9 deletes v4. Every commit stays green, and version-skew tolerance — which the design promises — ends up genuinely tested.

---

### Task 1: USER frame codec and the NoSession close reason

**Additive only** — no removals, no version bump, so the crate stays green and
the CI gate passes on this commit. The v5 switch (bumping the version, dropping
`path`, narrowing `CarrierKind`, retiring `NoRoute`) happens in Task 3, where the
home rewrite consumes it in the same commit. Expand now, contract there.

**Files:**
- Modify: `bins/outline-ss-rust/src/server/cluster/mesh/frame.rs`
- Test: `bins/outline-ss-rust/src/server/cluster/mesh/tests/frame.rs`

**Interfaces:**
- Consumes: nothing (first task).
- Produces:
  - `const MAX_USER_LEN: usize = 64`
  - `struct UserFrame { user: String }` with `encode(&self) -> Vec<u8>` and `parse(buf: &[u8]) -> Result<Self>`
  - `CloseReason::NoSession` at wire code `5`, added **alongside** the existing variants (`NoRoute` at `4` stays until Task 3)

- [ ] **Step 1: Write the failing tests**

Append to `bins/outline-ss-rust/src/server/cluster/mesh/tests/frame.rs`:

```rust
#[test]
fn user_frame_roundtrips() {
    let frame = UserFrame { user: "beerloga".to_string() };
    let parsed = UserFrame::parse(&frame.encode()).expect("user frame parses");
    assert_eq!(parsed.user, "beerloga");
}

#[test]
fn user_frame_roundtrips_at_the_length_ceiling() {
    let frame = UserFrame { user: "u".repeat(MAX_USER_LEN) };
    let parsed = UserFrame::parse(&frame.encode()).expect("a max-length name is valid");
    assert_eq!(parsed.user.len(), MAX_USER_LEN);
}

#[test]
fn user_frame_rejects_empty_name() {
    let encoded = vec![0u8]; // len = 0
    let err = UserFrame::parse(&encoded).expect_err("an empty user must be refused");
    assert!(err.to_string().contains("empty"), "got: {err}");
}

#[test]
fn user_frame_rejects_over_long_name() {
    let frame = UserFrame { user: "u".repeat(MAX_USER_LEN + 1) };
    let err = UserFrame::parse(&frame.encode()).expect_err("an over-long user must be refused");
    assert!(err.to_string().contains("too long"), "got: {err}");
}

#[test]
fn user_frame_rejects_invalid_utf8() {
    let encoded = vec![2u8, 0xff, 0xfe];
    let err = UserFrame::parse(&encoded).expect_err("invalid UTF-8 must be refused");
    assert!(err.to_string().contains("UTF-8"), "got: {err}");
}

#[test]
fn user_frame_rejects_a_truncated_buffer() {
    let encoded = vec![8u8, b'a', b'b']; // claims 8 bytes, carries 2
    UserFrame::parse(&encoded).expect_err("a truncated frame must be refused");
}

#[test]
fn no_session_close_reason_roundtrips_on_the_wire() {
    assert_eq!(CloseReason::NoSession.code(), 5);
    assert_eq!(CloseReason::from_code(5), CloseReason::NoSession);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p outline-ss-rust --lib cluster::mesh::frame`
Expected: FAIL — `cannot find struct UserFrame`, `MAX_USER_LEN` and
`CloseReason::NoSession` do not exist.

- [ ] **Step 3: Add the length bound and the USER frame codec**

In `frame.rs`, add next to the existing `MAX_PATH_LEN` constant (line ~47):

```rust
/// Upper bound on the user name carried in a [`UserFrame`]. Guards the parser
/// against an oversized allocation from a malformed peer; a single length byte
/// is enough because names are short identifiers.
pub(in crate::server) const MAX_USER_LEN: usize = 64;
```

Then add the codec after `OpenHeader`:

```rust
/// Second-phase frame: the user the edge authenticated, sent after the home's
/// setup ack.
///
/// It is a separate frame rather than an OPEN field because the edge does not
/// know the user when it sends OPEN — it must decide what to echo in its `101`
/// before it can read the client's first encrypted frame. The home trusts this
/// attestation (a peer holding the mesh PSK is already a full cluster member)
/// and checks it against the park's owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::server) struct UserFrame {
    pub(in crate::server) user: String,
}

impl UserFrame {
    /// Layout: `user_len(1) | user`. One length byte suffices: names are bounded
    /// by [`MAX_USER_LEN`].
    pub(in crate::server) fn encode(&self) -> Vec<u8> {
        let user = self.user.as_bytes();
        let mut out = Vec::with_capacity(1 + user.len());
        out.push(user.len() as u8);
        out.extend_from_slice(user);
        out
    }

    /// Parses the frame. Rejects an empty name (it could never match a park
    /// owner), an over-long one, or invalid UTF-8.
    pub(in crate::server) fn parse(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf);
        let len = r.u8()? as usize;
        if len == 0 {
            bail!("mesh USER frame carries an empty user name");
        }
        if len > MAX_USER_LEN {
            bail!("mesh USER frame user name too long: {len}");
        }
        let user = String::from_utf8(r.bytes(len)?.to_vec())
            .map_err(|_| anyhow::anyhow!("mesh USER frame user name is not valid UTF-8"))?;
        Ok(Self { user })
    }
}
```

- [ ] **Step 4: Add the NoSession close reason**

Add the variant to `CloseReason` (enum at line ~95), leaving `NoRoute` in place —
Task 3 retires it together with the route lookup it describes:

```rust
    /// The home refused the stream: it holds no parked session under the
    /// relayed resume id, or the id's owner is not the user the edge
    /// authenticated. An ordinary outcome — parks expire and are evicted — so
    /// the edge simply serves its client a fresh local session. A peer on an
    /// older build maps it to `Abort`, which is the right fallback.
    NoSession,
```

Extend `code()` with `CloseReason::NoSession => 5` and `from_code()` with
`5 => CloseReason::NoSession`.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p outline-ss-rust --lib cluster::mesh::frame`
Expected: PASS — 7 new tests, and every pre-existing frame test still green
(nothing was removed).

- [ ] **Step 6: Run the full gate and commit**

```bash
cargo fmt --check -p outline-ss-rust -p outline-ws-rust -p outline-metrics -p outline-net -p outline-routing -p outline-transport -p outline-tun -p outline-uplink -p outline-wire -p shadowsocks-crypto -p socks5-proto
```

```bash
cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
```

```bash
cargo test --workspace --exclude sockudo-ws
```

```bash
git add bins/outline-ss-rust/src/server/cluster/mesh/frame.rs bins/outline-ss-rust/src/server/cluster/mesh/tests/frame.rs
git commit -m "feat(cluster): add the mesh USER frame codec and the NoSession close reason"
```

---

### Task 2: Upstream abstraction

**Files:**
- Modify: `bins/outline-ss-rust/src/server/relay.rs` (trait at `:57`, `relay_upstream_to_client` at `:74`)
- Test: `bins/outline-ss-rust/src/server/tests/relay.rs`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces:
  - `trait UpstreamRead: Send + Unpin` with `async fn readable(&self) -> std::io::Result<()>` and `fn try_read_buf(&mut self, buf: &mut BytesMut) -> std::io::Result<usize>`
  - `impl UpstreamRead for tokio::net::tcp::OwnedReadHalf`
  - `relay_upstream_to_client<S, U>(upstream_reader: U, ...)` where `U: UpstreamRead` — all other parameters unchanged

- [ ] **Step 1: Write the failing test**

Append to `bins/outline-ss-rust/src/server/tests/relay.rs`. These drive the real
relay loop with a non-TCP upstream — a test that only exercised the fake would
stay green even if the generification were never done:

```rust
/// An upstream that is deliberately not a `TcpStream`: it hands out a scripted
/// sequence of chunks and then EOFs. Standing in for the mesh stream an edge
/// reads its plaintext from.
struct ScriptedUpstream {
    chunks: std::collections::VecDeque<Vec<u8>>,
}

impl UpstreamRead for ScriptedUpstream {
    async fn readable(&self) -> std::io::Result<()> {
        Ok(())
    }

    fn try_read_buf(&mut self, buf: &mut bytes::BytesMut) -> std::io::Result<usize> {
        match self.chunks.pop_front() {
            Some(chunk) => {
                buf.extend_from_slice(&chunk);
                Ok(chunk.len())
            },
            None => Ok(0), // EOF
        }
    }
}

#[tokio::test]
async fn relay_pumps_a_non_tcp_upstream_through_to_the_sink() {
    let upstream = ScriptedUpstream {
        chunks: vec![b"alpha".to_vec(), b"beta".to_vec()].into(),
    };
    let sink = RecordingSink::default();
    let recorded = sink.recorded();
    let mut encryptor = test_encryptor();

    relay_upstream_to_client(
        upstream,
        sink,
        &mut encryptor,
        test_metrics(),
        Protocol::Http11,
        AppProtocol::Shadowsocks,
        Arc::from("beerloga"),
        None,
        None,
    )
    .await
    .expect("the relay completes when the upstream reaches EOF");

    assert_eq!(
        decrypt_all(&recorded.lock().unwrap()),
        b"alphabeta",
        "every upstream chunk must reach the client, in order"
    );
}

#[tokio::test]
async fn relay_captures_plaintext_into_the_ring_before_encrypting() {
    // The ring must hold plaintext: that is the property letting a *different*
    // node re-seal a replay under its own client key, which is what makes
    // cross-node continuity possible at all.
    let upstream = ScriptedUpstream { chunks: vec![b"ring-me".to_vec()].into() };
    let ring = Arc::new(Mutex::new(DownlinkRing::with_capacity(1024)));
    let mut encryptor = test_encryptor();

    relay_upstream_to_client(
        upstream,
        RecordingSink::default(),
        &mut encryptor,
        test_metrics(),
        Protocol::Http11,
        AppProtocol::Shadowsocks,
        Arc::from("beerloga"),
        None,
        Some(Arc::clone(&ring)),
    )
    .await
    .expect("the relay completes");

    assert_eq!(
        ring.lock().replay_from(0).chunks.concat(),
        b"ring-me",
        "the ring holds plaintext, not ciphertext"
    );
}
```

If `RecordingSink`, `test_encryptor`, `test_metrics` or `decrypt_all` do not
already exist in this test module, add them as local helpers — a sink that
appends every ciphertext chunk to a shared `Vec`, and a decrypt helper that
undoes `test_encryptor`'s stream.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p outline-ss-rust --lib relay::tests::relay_pumps_a_non_tcp_upstream`
Expected: FAIL — `cannot find trait UpstreamRead in this scope`, and `relay_upstream_to_client` does not accept a non-`OwnedReadHalf` upstream.

- [ ] **Step 3: Define the trait and implement it for the TCP half**

Add to `relay.rs`, next to `UpstreamSink` (which already uses `async fn` in a trait, so the pattern is established):

```rust
/// The upstream half a relay reads application plaintext from.
///
/// Two shapes exist. On a standalone server or a cluster home it is the real
/// TCP socket to the target. On a cluster **edge** the home owns that socket and
/// the edge reads the same plaintext off a mesh stream — the edge terminates the
/// client's crypto, so what crosses the mesh is already decrypted.
///
/// The two methods mirror `TcpStream`'s readiness API rather than `AsyncRead`
/// deliberately: the relay's hot loop is a greedy drain (`readable().await` then
/// repeated non-blocking `try_read_buf`), and flattening that into `AsyncRead`
/// would cost a syscall per chunk.
pub(in crate::server) trait UpstreamRead: Send + Unpin {
    /// Resolves when at least one byte may be readable.
    async fn readable(&self) -> std::io::Result<()>;

    /// Non-blocking read appending into `buf`. `Ok(0)` is EOF;
    /// `ErrorKind::WouldBlock` means nothing is pending right now.
    fn try_read_buf(&mut self, buf: &mut BytesMut) -> std::io::Result<usize>;
}

impl UpstreamRead for OwnedReadHalf {
    async fn readable(&self) -> std::io::Result<()> {
        OwnedReadHalf::readable(self).await
    }

    fn try_read_buf(&mut self, buf: &mut BytesMut) -> std::io::Result<usize> {
        OwnedReadHalf::try_read_buf(self, buf)
    }
}
```

- [ ] **Step 4: Generify `relay_upstream_to_client`**

Change the signature at `relay.rs:74` from a concrete `OwnedReadHalf` to the trait, leaving every other parameter and the whole body untouched:

```rust
#[allow(clippy::too_many_arguments)]
pub(in crate::server) async fn relay_upstream_to_client<S, U>(
    mut upstream_reader: U,
    mut sink: S,
    encryptor: &mut AeadStreamEncryptor,
    metrics: Arc<Metrics>,
    protocol: Protocol,
    app_protocol: AppProtocol,
    user_id: Arc<str>,
    cancel: Option<Arc<Notify>>,
    downlink_ring: Option<Arc<Mutex<DownlinkRing>>>,
) -> Result<()>
where
    S: UpstreamSink,
    U: UpstreamRead,
```

The existing calls to `upstream_reader.readable()` (`:138` region) and `try_read_buf` now resolve through the trait. The plaintext ring push at `:187-190` stays exactly where it is — before `encrypt_chunk` — so replay semantics are unchanged.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p outline-ss-rust --lib relay`
Expected: PASS — the new test plus every pre-existing relay test, proving the generification is behaviour-preserving.

- [ ] **Step 6: Run the full gate and commit**

```bash
cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
```

```bash
git add bins/outline-ss-rust/src/server/relay.rs bins/outline-ss-rust/src/server/tests/relay.rs
git commit -m "refactor(relay): read the upstream through a trait instead of a concrete TCP half"
```

---

### Task 3: Home learns v5 alongside v4

**Additive at the protocol level.** The home gains a v5 branch while its v4
branch stays byte-identical, dispatching on the OPEN version byte. This matters
because 24 end-to-end cluster relay tests exercise the live v4 relay across all
three carriers; the edges do not speak v5 until Tasks 4–6, so v4 must keep
working. Task 7 retires v4 once every edge has moved.

A second payoff: the design promises that version skew degrades to a loss of
continuity rather than a loss of traffic. Building the home to tolerate both
versions makes that property **tested** instead of merely asserted.

**Files:**
- Modify: `bins/outline-ss-rust/src/server/cluster/mesh/frame.rs` (add v5 alongside v4)
- Modify: `bins/outline-ss-rust/src/server/resumption/registry.rs` (probe next to `symmetric_replay_enabled` at `:150`)
- Modify: `bins/outline-ss-rust/src/metrics/mod.rs` (next to `record_mesh_relay_rejected` at `:582`)
- Modify: `bins/outline-ss-rust/src/server/transport/mesh_relay.rs` (version dispatch + the v5 home path)
- Test: `bins/outline-ss-rust/src/server/cluster/mesh/tests/frame.rs`, `bins/outline-ss-rust/src/server/transport/tests/mesh_relay.rs`

**Interfaces:**
- Consumes: `UserFrame`, `MAX_USER_LEN`, `CloseReason::NoSession` from Task 1.
- Produces:
  - `fn peek_open_version(buf: &[u8]) -> Result<u8>` — reads the leading version byte without consuming the frame
  - `enum MeshFraming { Tcp, Udp }` (`Tcp` = 0, `Udp` = 1) — all a v5 home needs, since crypto is the edge's business
  - `struct OpenHeaderV5 { framing: MeshFraming, session_id: [u8; 16], resume_capable: bool, ack_prefix: bool, symmetric_replay: bool, client_down_acked: u64, peer_addr: Option<SocketAddr> }` with `encode`/`parse`, version byte `5`, **no path field**
  - `OrphanRegistry::has_park(&self, id: SessionId) -> bool`
  - `Metrics::record_mesh_relay_outcome(&self, outcome: &'static str)`
  - Home-side `serve_relayed_v5`: ack on park existence → read `UserFrame` → `take_for_resume(id, &user)` → splice plaintext. **No crypto, no route table.**

**Untouched in this task:** `OPEN_VERSION` (stays `4`), `OpenHeader`, `CarrierKind`, `MAX_PATH_LEN`, `CloseReason::NoRoute`, and the whole existing `serve_relayed`. Task 7 removes them.

- [ ] **Step 1: Write the failing tests**

Add to `bins/outline-ss-rust/src/server/cluster/mesh/tests/frame.rs`:

```rust
#[test]
fn v5_header_roundtrips_without_peer_addr() {
    let header = OpenHeaderV5 {
        framing: MeshFraming::Tcp,
        session_id: [7u8; 16],
        resume_capable: true,
        ack_prefix: true,
        symmetric_replay: false,
        client_down_acked: 4096,
        peer_addr: None,
    };
    let parsed = OpenHeaderV5::parse(&header.encode()).expect("v5 header parses");
    assert_eq!(parsed, header);
}

#[test]
fn v5_header_roundtrips_with_peer_addr() {
    let header = OpenHeaderV5 {
        framing: MeshFraming::Udp,
        session_id: [9u8; 16],
        resume_capable: true,
        ack_prefix: false,
        symmetric_replay: true,
        client_down_acked: u64::MAX,
        peer_addr: Some("198.51.100.7:443".parse().unwrap()),
    };
    let parsed = OpenHeaderV5::parse(&header.encode()).expect("v5 header parses");
    assert_eq!(parsed, header);
}

#[test]
fn v5_parser_refuses_a_v4_frame_and_vice_versa() {
    let v5 = OpenHeaderV5 {
        framing: MeshFraming::Tcp,
        session_id: [1u8; 16],
        resume_capable: false,
        ack_prefix: false,
        symmetric_replay: false,
        client_down_acked: 0,
        peer_addr: None,
    };
    let mut encoded = v5.encode();
    encoded[0] = 4;
    OpenHeaderV5::parse(&encoded).expect_err("a v4 frame is not a v5 frame");
}

#[test]
fn peek_open_version_reads_the_leading_byte_without_consuming() {
    let v5 = OpenHeaderV5 {
        framing: MeshFraming::Udp,
        session_id: [2u8; 16],
        resume_capable: false,
        ack_prefix: false,
        symmetric_replay: false,
        client_down_acked: 0,
        peer_addr: None,
    };
    let encoded = v5.encode();
    assert_eq!(peek_open_version(&encoded).unwrap(), 5);
    // The frame is still fully parseable afterwards.
    assert_eq!(OpenHeaderV5::parse(&encoded).unwrap(), v5);
    assert!(peek_open_version(&[]).is_err(), "an empty buffer has no version");
}

#[test]
fn mesh_framing_covers_only_the_two_shapes() {
    assert_eq!(MeshFraming::from_u8(0).unwrap(), MeshFraming::Tcp);
    assert_eq!(MeshFraming::from_u8(1).unwrap(), MeshFraming::Udp);
    assert!(MeshFraming::from_u8(2).is_err());
}
```

Add to `bins/outline-ss-rust/src/server/transport/tests/mesh_relay.rs`:

```rust
#[tokio::test]
async fn has_park_reports_a_committed_park() {
    let registry = test_registry();
    let id = SessionId::from_bytes([3u8; 16]);
    assert!(!registry.has_park(id), "no park yet");

    park_test_session(&registry, id, "beerloga").await;

    assert!(registry.has_park(id), "a committed park must be visible");
}

#[tokio::test]
async fn has_park_reports_an_in_flight_reservation() {
    // The phase-1 ack must not answer "no session" while a park is still
    // landing — that is the park-miss race `take_for_resume` already guards.
    let registry = test_registry();
    let id = SessionId::from_bytes([4u8; 16]);
    let _reservation = registry.reserve_park(id);

    assert!(registry.has_park(id), "a reserved park must count as present");
}

#[tokio::test]
async fn has_park_does_not_consume_the_park() {
    let registry = test_registry();
    let id = SessionId::from_bytes([5u8; 16]);
    park_test_session(&registry, id, "beerloga").await;

    assert!(registry.has_park(id));
    assert!(registry.has_park(id), "the probe must be read-only");

    let outcome = registry.take_for_resume(id, "beerloga").await;
    assert!(matches!(outcome, ResumeOutcome::Hit(_)), "the park must still be takeable");
}

#[tokio::test]
async fn v5_home_refuses_when_no_park_exists() {
    let harness = MeshHomeHarness::new().await;

    let outcome = harness.serve_v5(v5_header(SessionId::from_bytes([6u8; 16]))).await;

    assert_eq!(outcome.close_reason(), Some(CloseReason::NoSession));
    assert!(!outcome.acked(), "the refusal replaces the ack, before the edge upgrades its client");
}

#[tokio::test]
async fn v5_home_refuses_when_the_user_does_not_own_the_park() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([7u8; 16]);
    park_test_session(harness.registry(), id, "beerloga").await;

    let outcome = harness.serve_v5_with_user(v5_header(id), "cloud").await;

    assert!(outcome.acked(), "phase 1 cannot know the user yet, so it acks");
    assert_eq!(outcome.close_reason(), Some(CloseReason::NoSession));
}

#[tokio::test]
async fn v5_home_splices_plaintext_to_the_parked_upstream() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([8u8; 16]);
    park_test_session(harness.registry(), id, "beerloga").await;

    let mut session = harness.serve_v5_ok(v5_header(id), "beerloga").await;

    // Uplink: what the edge writes as plaintext reaches the parked upstream verbatim.
    session.edge_write(b"GET / HTTP/1.1\r\n\r\n").await;
    assert_eq!(session.upstream_read().await, b"GET / HTTP/1.1\r\n\r\n");

    // Downlink: the home encrypts nothing — the edge seals it under its own key.
    session.upstream_write(b"HTTP/1.1 200 OK\r\n\r\n").await;
    assert_eq!(session.edge_read().await, b"HTTP/1.1 200 OK\r\n\r\n");
}

#[tokio::test]
async fn v5_home_replays_the_ring_suffix_before_new_downlink() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([9u8; 16]);
    // 12 plaintext bytes already sent, client acked the first 5.
    park_test_session_with_ring(harness.registry(), id, "beerloga", b"HELLO-WORLD!", 5).await;

    let mut header = v5_header(id);
    header.symmetric_replay = true;
    header.client_down_acked = 5;

    let mut session = harness.serve_v5_ok(header, "beerloga").await;

    assert_eq!(
        session.edge_read().await,
        b"-WORLD!",
        "the home replays exactly the unacked suffix, as plaintext"
    );
}

#[tokio::test]
async fn a_v4_relay_still_takes_the_untouched_v4_path() {
    // The 24 end-to-end cluster tests depend on this until Task 7 retires v4.
    let harness = MeshHomeHarness::new().await;

    assert!(
        harness.serve_v4_reaches_legacy_path().await,
        "a v4 OPEN must still dispatch into the original serve_relayed"
    );
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p outline-ss-rust --lib cluster::mesh::frame transport::mesh_relay resumption::registry`
Expected: FAIL — `OpenHeaderV5`, `MeshFraming`, `peek_open_version`, `has_park` and the `serve_v5*` harness helpers do not exist.

- [ ] **Step 3: Add the v5 frame types**

In `frame.rs`, leave every existing item alone and add beside them:

```rust
/// Wire-format version of [`OpenHeaderV5`]. Coexists with [`OPEN_VERSION`]
/// (v4) while the edges migrate: the home dispatches on the leading byte via
/// [`peek_open_version`], so a v4 edge and a v5 edge can both be served.
const OPEN_VERSION_V5: u8 = 5;

/// How a relayed v5 stream is framed. The edge owns the client crypto, so
/// SS-vs-VLESS and WS-vs-XHTTP never reach the home — only the framing does:
/// TCP-shaped carriers relay as a byte stream, UDP as length-delimited
/// datagrams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum MeshFraming {
    Tcp,
    Udp,
}
```

Give `MeshFraming` `to_u8`/`from_u8` (`0`/`1`, unknown → `bail!`). Add
`OpenHeaderV5` with the same flag bits and peer-addr encoding as v4 but **no
path**, layout
`version(1) | framing(1) | flags(1) | down_acked(8) | session_id(16) | [peer_addr]`,
and its `parse` rejecting any version byte that is not `5`. Add:

```rust
/// Reads the version byte a mesh OPEN frame starts with, without consuming it,
/// so the accept loop can route the frame to the matching parser.
pub(in crate::server) fn peek_open_version(buf: &[u8]) -> Result<u8> {
    buf.first().copied().ok_or_else(|| anyhow::anyhow!("empty mesh OPEN frame"))
}
```

- [ ] **Step 4: Add the read-only park probe**

In `registry.rs`, next to `symmetric_replay_enabled` (`:150`):

```rust
    /// Whether a park exists under `id`, without consuming it and without
    /// knowing the user yet.
    ///
    /// Used for the mesh phase-1 ack: the edge must decide what to echo in its
    /// `101` before it can authenticate the client, so the home answers the
    /// narrower question "is there a session under this id?" and defers the
    /// owner check to phase 2 ([`Self::take_for_resume`]). An in-flight
    /// reservation counts as present — otherwise a fast redial arriving while
    /// the park is still landing would be told "no session" and would lose
    /// continuity, which is the very race `take_for_resume` already waits out.
    pub(crate) fn has_park(&self, id: SessionId) -> bool {
        self.by_id.contains_key(&id) || self.reservations.contains_key(&id)
    }
```

- [ ] **Step 5: Add the relay-outcome counter**

`serve_relayed_v5` reports its verdict, so this must exist before Step 6
compiles. Add to `metrics/mod.rs` next to `record_mesh_relay_rejected` (`:582`):

```rust
    /// Outcome of a relayed session as the home decided it. `hit` means the
    /// park was found and spliced; `miss` means the edge fell back to a fresh
    /// local session. Low cardinality: two values.
    ///
    /// Exists because a never-working relay went unnoticed in production —
    /// success was only inferrable from byte counters.
    pub fn record_mesh_relay_outcome(&self, outcome: &'static str) {
        if self.enabled {
            counter!("outline_ss_mesh_relay_outcome_total", "outcome" => outcome).increment(1);
        }
    }
```

- [ ] **Step 6: Add the v5 home path and dispatch on the version**

In `mesh_relay.rs`, keep `serve_relayed` exactly as it is and route to it or to
a new `serve_relayed_v5` from wherever the OPEN frame is first parsed, using
`peek_open_version`. An unknown version keeps today's behaviour (refuse).

`serve_relayed_v5` performs, in order: `has_park` → refuse `NoSession` with
`record_mesh_relay_rejected("no_session")` if absent → `write_open_ack` →
read a bounded `UserFrame` (one length byte, then at most `MAX_USER_LEN`) →
`take_for_resume(session_id, &user.user)` → on `ResumeMiss::OwnerMismatch`
refuse with reason `"unknown_user"`, on any other miss `"no_session"` → on hit
`record_mesh_relay_outcome("hit")` and splice.

The splice for `MeshFraming::Tcp` sends the replay suffix first, then pumps
bidirectionally between the mesh stream and the parked upstream's
reader/writer halves under the existing `cluster.relay_budget`:

```rust
/// Splices a relayed plaintext stream onto a parked TCP upstream.
///
/// Simpler than the v4 path beside it: no decryptor, no encryptor, no route
/// context — just the unacked replay suffix followed by a bidirectional pump.
/// The ring already holds **plaintext** keyed by plaintext offsets, so the
/// suffix goes out as-is and the edge seals it under its own client key.
async fn splice_plaintext_tcp(
    mut stream: MeshStream,
    parked: ParkedTcp,
    client_down_acked: u64,
    cluster: &ClusterCtx,
) -> Result<()> {
```

Do the same for `MeshFraming::Udp` over the datagram framing `MeshUdpCarrier`
already provides, leaving NAT and parking on the home. A framing that
disagrees with the parked session's kind is a forged or mismatched peer:
refuse with `CloseReason::Abort` rather than panicking.

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cargo test -p outline-ss-rust --lib cluster::mesh::frame transport::mesh_relay resumption::registry`
Expected: PASS — 13 new tests.

Then confirm the v4 relay is genuinely untouched:

Run: `cargo test -p outline-ss-rust --lib resumption::cluster`
Expected: PASS — all 24 end-to-end cluster tests still green. **If any of them
fail, the v4 path was disturbed; fix that before continuing.**

- [ ] **Step 8: Run the full gate and commit**

```bash
cargo fmt --check -p outline-ss-rust -p outline-ws-rust -p outline-metrics -p outline-net -p outline-routing -p outline-transport -p outline-tun -p outline-uplink -p outline-wire -p shadowsocks-crypto -p socks5-proto
```

```bash
cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
```

```bash
cargo test --workspace --exclude sockudo-ws
```

```bash
git add bins/outline-ss-rust/src/server/cluster/mesh/frame.rs bins/outline-ss-rust/src/server/cluster/mesh/tests/frame.rs bins/outline-ss-rust/src/server/resumption/registry.rs bins/outline-ss-rust/src/metrics/mod.rs bins/outline-ss-rust/src/server/transport/mesh_relay.rs bins/outline-ss-rust/src/server/transport/tests/mesh_relay.rs
git commit -m "feat(cluster): home serves v5 relays alongside v4 during the edge migration"
```

---

### Task 4: v5 resume-continuity fields

v4 carried two things v5 currently does not, and the edge tasks would be written
against an incomplete protocol without them. Both were found by review of Task 3.

- **Acked uplink offset.** `OpenHeaderV5.ack_prefix` is parsed and never used;
  the v4 path uses its equivalent at `mesh_relay.rs:875`. Without it a v5→v5
  resume cannot recover uplink bytes the home consumed from the mesh but had not
  yet written to the upstream when the carrier dropped — a silent hole in the
  request body at the target.
- **"Client gone for good" vs "carrier ended".** A mesh FIN is currently always
  read as a carrier switch, so the home re-parks. A client that finished for
  good therefore leaves a live upstream parked: the target never sees the
  request-body FIN (half-close-then-read protocols hang until `orphan_ttl_tcp`),
  and the dead session occupies one of the user's `orphan_per_user_cap` slots
  (default 4, `config/resolved.rs:219`) where it can evict a real park.

**Files:**
- Modify: `bins/outline-ss-rust/src/server/cluster/mesh/frame.rs` (v5 only — v4 stays frozen)
- Modify: `bins/outline-ss-rust/src/server/transport/mesh_relay.rs`
- Test: `bins/outline-ss-rust/src/server/cluster/mesh/tests/frame.rs`, `bins/outline-ss-rust/src/server/transport/tests/mesh_relay.rs`

**Interfaces:**
- Consumes: the v5 home path from Task 3.
- Produces:
  - A home→edge **acked-offset** signal on the v5 stream, carrying `upstream_bytes_acked` so a later resume knows where the upstream really got to. Follow how v4 conveys the same fact (`mesh_relay.rs:875` and the v1 ORDR payload built in `transport/tcp.rs:782-798`) rather than inventing a second convention.
  - An edge→home **close intent** on the v5 stream distinguishing "the client is done" from "the carrier ended, expect a resume".
  - Home behaviour: on *client done*, half-close the upstream and do **not** re-park; on *carrier ended*, re-park exactly as today.

- [ ] **Step 1: Write the failing tests**

In `tests/mesh_relay.rs`, using the existing `MeshHomeHarness`:

```rust
#[tokio::test]
async fn a_client_done_close_does_not_park_and_finishes_the_upstream() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([21u8; 16]);
    park_test_session(harness.registry(), id, "beerloga").await;
    let mut session = harness.serve_v5_ok(v5_header(id), "beerloga").await;

    session.close_with_client_done().await;

    assert!(
        session.upstream_saw_eof().await,
        "a finished client must let the target see the request-body FIN"
    );
    assert!(
        !harness.registry().has_park(id),
        "a session the client finished must not occupy an orphan slot"
    );
}

#[tokio::test]
async fn a_carrier_ended_close_still_parks() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([22u8; 16]);
    park_test_session(harness.registry(), id, "beerloga").await;
    let mut session = harness.serve_v5_ok(v5_header(id), "beerloga").await;

    session.close_with_carrier_ended().await;

    assert!(harness.registry().has_park(id), "a carrier switch must keep the park");
}

#[tokio::test]
async fn the_home_reports_the_acked_uplink_offset_to_the_edge() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([23u8; 16]);
    park_test_session(harness.registry(), id, "beerloga").await;
    let mut session = harness.serve_v5_ok(v5_header(id), "beerloga").await;

    session.edge_write(b"twelve bytes").await;
    session.await_upstream_read(12).await;

    assert_eq!(
        session.acked_uplink_offset().await,
        12,
        "the edge must learn how far the upstream actually got"
    );
}

#[tokio::test]
async fn a_resume_replays_uplink_from_the_acked_offset_without_duplicating() {
    // The hole this task exists to close: bytes consumed from the mesh but not
    // yet written to the upstream must be recoverable, and already-written
    // bytes must not be sent twice.
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([24u8; 16]);
    park_test_session(harness.registry(), id, "beerloga").await;

    let mut first = harness.serve_v5_ok(v5_header(id), "beerloga").await;
    first.edge_write(b"AAAABBBB").await;
    first.await_upstream_read(8).await;
    let acked = first.acked_uplink_offset().await;
    first.close_with_carrier_ended().await;

    let mut second = harness.serve_v5_ok(v5_header(id), "beerloga").await;
    second.edge_write_from_offset(b"AAAABBBBCCCC", acked).await;

    assert_eq!(
        second.upstream_read_all().await,
        b"AAAABBBBCCCC",
        "the upstream must see each byte exactly once across the switch"
    );
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p outline-ss-rust --lib transport::mesh_relay cluster::mesh::frame`
Expected: FAIL — no close-intent or acked-offset exists on the v5 stream.

- [ ] **Step 3: Extend the v5 wire format**

Add both signals to the v5 protocol in `frame.rs`, leaving every v4 item frozen.
Keep them bounded and explicit; do not overload an existing field's meaning. A
close intent is a small enum (`ClientDone` / `CarrierEnded`) and the acked
offset is a `u64`. Decide deliberately whether each rides the existing frames or
a new one, and record the layout in the module doc the way `OpenHeaderV5`
already documents its own.

- [ ] **Step 4: Use them on the home**

In `mesh_relay.rs`: report the acked offset from `upstream_bytes_acked` (already
exact per write after Task 3), and branch the end-of-splice on the close intent
— `ClientDone` half-closes the upstream and skips the park, `CarrierEnded` keeps
today's re-park. The existing `SpliceEnd::stream_close` decision is the natural
place for the branch; extend it rather than adding a second close path.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p outline-ss-rust --lib transport::mesh_relay cluster::mesh::frame`
Expected: PASS — 4 new tests plus the 37 already there.

Then the v4 evidence:

Run: `cargo test -p outline-ss-rust --lib resumption::cluster`
Expected: PASS — all 24 end-to-end cluster tests. **Any failure means v4 was disturbed.**

- [ ] **Step 6: Run the full gate and commit**

```bash
cargo fmt --check -p outline-ss-rust -p outline-ws-rust -p outline-metrics -p outline-net -p outline-routing -p outline-transport -p outline-tun -p outline-uplink -p outline-wire -p shadowsocks-crypto -p socks5-proto
```

```bash
cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
```

```bash
cargo test --workspace --exclude sockudo-ws
```

```bash
git add bins/outline-ss-rust/src/server/cluster/mesh/ bins/outline-ss-rust/src/server/transport/mesh_relay.rs bins/outline-ss-rust/src/server/transport/tests/mesh_relay.rs
git commit -m "feat(cluster): carry acked uplink offset and close intent on the v5 mesh stream"
```

---

### Task 5: Edge side — SS byte-stream (milestone: end-to-end)

**Scope covers every SS byte-stream entry point**, not just the WS one:
`CarrierKind::SsTcp` from the axum-WS path (`transport/mod.rs:107`) and from the
h3 path (`h3/http.rs:223`), plus `CarrierKind::SsXhttp`
(`xhttp/handlers.rs:953`). In v5 the carrier byte narrows to framing alone
(`MeshFraming::Tcp`) because crypto is the edge's business, so those three are
the same thing; splitting them would leave the carrier half-migrated and leave
`SsXhttp` unowned — Task 6 is VLESS, Task 8 is SS-UDP, and Task 9 cannot retire
v4 while any SS byte-stream entry point still speaks it.

**Two of the 24 end-to-end cluster tests encode v4 behaviour this design
deliberately removes** ("fresh sessions are never created over the mesh any
more") and must be adapted rather than preserved:
`cluster_session_survives_edge_switch` (`cluster.rs:559`) and
`cluster_stalled_relay_tears_down_on_health_budget` (`cluster.rs:778`). Both
currently rely on the *home* minting a fresh session for a carrier that arrives
with no park. Re-point them at the invariant the feature actually claims —
establish the session against the home, then resume it through an edge — so they
prove one upstream surviving a node switch. Do not weaken what they assert.

**Files:**
- Create: `bins/outline-ss-rust/src/server/transport/upstream_source.rs`
- Modify: `bins/outline-ss-rust/src/server/transport/tcp.rs` (auth at `:735`, connect at `:960`, park at `:567`/`:640`, `run_tcp_relay` at `:292`)
- Modify: `bins/outline-ss-rust/src/server/transport/mesh_relay.rs` (`try_relay_edge` at `:507`, `EdgeRelay` at `:479`)
- Test: `bins/outline-ss-rust/src/server/transport/tests/tcp.rs`

**Interfaces:**
- Consumes: `UpstreamRead` (Task 2), `UserFrame` (Task 1), `OpenHeaderV5`/`MeshFraming`/the v5 home path (Task 3).
- The edge's SS-TCP carrier switches from a v4 OPEN to `OpenHeaderV5` with `MeshFraming::Tcp` plus the `UserFrame`. VLESS and SS-UDP edges stay on v4 until Tasks 5–6, and the home still serves both — so the SS-TCP subset of the 24 end-to-end cluster tests now exercises v5 while the rest keep exercising v4. All 24 must stay green.
- Produces:
  - `enum UpstreamSource { Direct, Mesh(MeshStream) }` in `upstream_source.rs`
  - `run_tcp_relay<T: WsSocket>(socket, server, route, resume, peer_addr, injected_monitor, upstream: UpstreamSource)` — one new trailing parameter
  - `MeshUpstream` implementing `UpstreamRead` over a `MeshStream`

- [ ] **Step 1: Write the failing tests**

Append to `bins/outline-ss-rust/src/server/transport/tests/tcp.rs`:

```rust
#[tokio::test]
async fn edge_authenticates_with_its_own_credentials_then_sends_the_user_frame() {
    // The whole point: the edge's key differs from the home's, and the relay
    // still works because the edge — not the home — decrypts the client.
    let harness = EdgeHarness::with_credentials("edge-secret").await;
    let home = harness.fake_home_with_park("beerloga").await;

    let mut client = harness.connect_client("beerloga", "edge-secret").await;
    client.send_plaintext(b"hello upstream").await;

    assert_eq!(
        home.user_frame().await.user,
        "beerloga",
        "the edge must attest the user it authenticated"
    );
    assert_eq!(
        home.upstream_received().await,
        b"hello upstream",
        "the mesh must carry plaintext, not ciphertext"
    );
}

#[tokio::test]
async fn edge_seals_the_downlink_under_its_own_key() {
    let harness = EdgeHarness::with_credentials("edge-secret").await;
    let home = harness.fake_home_with_park("beerloga").await;
    let mut client = harness.connect_client("beerloga", "edge-secret").await;

    home.send_plaintext_downlink(b"payload from upstream").await;

    // The client decrypts with the edge's key and gets the plaintext back.
    assert_eq!(client.recv_plaintext().await, b"payload from upstream");
}

#[tokio::test]
async fn edge_serves_locally_when_the_home_reports_no_session() {
    let harness = EdgeHarness::with_credentials("edge-secret").await;
    let home = harness.fake_home_without_park().await;

    let client = harness.connect_client("beerloga", "edge-secret").await;

    assert!(client.upgraded(), "the client is still served");
    assert!(harness.served_locally(), "a NoSession refusal degrades to a local session");
    assert_ne!(
        client.echoed_session_id(),
        client.requested_session_id(),
        "a fresh local session mints its own id"
    );
    let _ = home;
}

#[tokio::test]
async fn edge_never_parks_a_relayed_session() {
    // Parking is a home concern: the edge holds no upstream socket to park.
    let harness = EdgeHarness::with_credentials("edge-secret").await;
    let _home = harness.fake_home_with_park("beerloga").await;
    let mut client = harness.connect_client("beerloga", "edge-secret").await;

    client.send_plaintext(b"x").await;
    client.disconnect().await;

    assert_eq!(
        harness.local_registry_size(),
        0,
        "the edge must not park a session whose upstream lives on the home"
    );
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p outline-ss-rust --lib transport::tcp::tests::edge_`
Expected: FAIL — `EdgeHarness` does not exist; `run_tcp_relay` takes no upstream parameter.

- [ ] **Step 3: Add `UpstreamSource` and the mesh upstream**

Create `bins/outline-ss-rust/src/server/transport/upstream_source.rs`:

```rust
//! Where a relay's upstream bytes come from.
//!
//! On a standalone server or a cluster home the relay connects out to the target
//! itself. On a cluster **edge** the home already owns that socket: the edge
//! terminates the client's crypto and exchanges plaintext with the home over the
//! mesh, so the mesh stream takes the upstream's place. Keeping the distinction
//! in one enum — rather than branching inside each carrier — is what lets
//! SS-TCP, VLESS and SS-UDP share the same story.

use crate::server::cluster::mesh::MeshStream;

pub(in crate::server::transport) enum UpstreamSource {
    /// Connect out to the target from this node.
    Direct,
    /// Read and write application plaintext over a mesh stream to the home that
    /// owns the parked upstream. The edge must not park such a session.
    Mesh(MeshStream),
}
```

Add `MeshUpstream` implementing `UpstreamRead` (Task 2's trait) over the mesh receive half, mapping `readable`/`try_read_buf` onto the QUIC stream.

- [ ] **Step 4: Thread the source through `run_tcp_relay`**

Add the trailing parameter at `tcp.rs:292` and branch at the two decision points:

- At `:960` (`connect_tcp_target`): on `UpstreamSource::Mesh(stream)` skip the outbound connect entirely and use `MeshUpstream::new(stream)` as the upstream; the parked-target semantics at `:737-739` are unchanged because the home resolved the target when it first connected.
- At `:567`/`:640` (`reserve_park`/`park`): on `UpstreamSource::Mesh`, do not park — the edge owns no upstream socket. Add the guard with a comment saying so.

The authentication at `:735` (`user.effective_label(...)`) is untouched and now also feeds the `UserFrame`.

- [ ] **Step 5: Send the USER frame from the edge**

In `mesh_relay.rs`, split `try_relay_edge` (`:507`) so the OPEN/ACK phase stays before `101` while the USER frame is sent after authentication. `EdgeRelay` (`:479`) loses its `path` field and its `carrier` becomes `CarrierKind::Tcp`/`Udp`.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test -p outline-ss-rust --lib transport::tcp`
Expected: PASS — 4 new tests plus every pre-existing TCP relay test (the `Direct` path must be untouched).

- [ ] **Step 7: Run the full gate and commit**

```bash
cargo test --workspace --exclude sockudo-ws
```

```bash
git add bins/outline-ss-rust/src/server/transport/upstream_source.rs bins/outline-ss-rust/src/server/transport/tcp.rs bins/outline-ss-rust/src/server/transport/mesh_relay.rs bins/outline-ss-rust/src/server/transport/tests/tcp.rs
git commit -m "feat(cluster): edge terminates SS-TCP crypto and relays plaintext to the home"
```

---

### Task 6: Edge side — VLESS (TCP command only)

**Scoped to the VLESS `Tcp` command.** VLESS multiplexes TCP, UDP and mux on one
carrier, and its parks come in three kinds (`Parked::Tcp`,
`Parked::VlessUdpSingle`, `Parked::VlessMux`) while `serve_relayed_v5` serves
only `Parked::Tcp`. On a `Udp`/`Mux` command the edge resets the mesh stream
before sending `UserFrame` and serves the session locally; cross-node migration
for those two degrades to a fresh upstream until Task 7 lands their home paths.

**Also fixes a live defect this task would otherwise expose.** Phase 1
(`has_park`) is kind-agnostic while `take_for_resume` at `mesh_relay.rs:1311`
**consumes** the park before the `Parked::Tcp` check at `:1336` — so a park of
the wrong kind is destroyed before the mismatch is noticed, and the client loops
reconnecting into repeated destruction. Unreachable today because only SS
byte-stream edges speak v5 and they always park `Parked::Tcp`. Phase 1 must
become kind-aware so a foreign kind is refused before anything is consumed.

**Two VLESS-UDP cluster tests assert something that stops being true.**
`cluster_vless_udp_survives_edge_switch` and `cluster_vless_udp_relays_via_vless_tcp`
claim one upstream across an edge switch, which v5 cannot honour for
`VlessUdpSingle` until Task 7. Rewrite them to assert the honest new behaviour
and state in each doc comment exactly which claim was withdrawn and why — this
is a deliberate, temporary narrowing, not an accidental weakening. Add a
VLESS-**TCP** edge-switch test that is strictly stronger for its shape.

**Files:**
- Modify: `bins/outline-ss-rust/src/server/transport/vless/mod.rs` (`run_vless_relay` at `:46`, auth at `:454`), `vless/tcp.rs` (connect at `:404`, resume at `:177`)
- Test: `bins/outline-ss-rust/src/server/transport/vless/tests/mod.rs`

**Interfaces:**
- Consumes: `UpstreamSource`, `MeshUpstream` (Task 4).
- Produces: `run_vless_relay<T: WsSocket>(socket, server, route, resume, injected_monitor, upstream: UpstreamSource)`; the VLESS edge sending `OpenHeaderV5` with `MeshFraming::Tcp` plus the `UserFrame`.
- SS-UDP stays on v4 until Task 6. All 24 end-to-end cluster tests must stay green.

- [ ] **Step 1: Write the failing test**

```rust
#[tokio::test]
async fn vless_edge_relays_plaintext_with_its_own_uuid() {
    // The edge's UUID differs from the home's; the relay works regardless
    // because the edge parses and authenticates the VLESS header itself.
    let harness = VlessEdgeHarness::with_uuid(EDGE_UUID).await;
    let home = harness.fake_home_with_park("cloud").await;

    let mut client = harness.connect_client(EDGE_UUID).await;
    client.send_plaintext(b"vless uplink").await;

    assert_eq!(home.user_frame().await.user, "cloud");
    assert_eq!(home.upstream_received().await, b"vless uplink");
}

#[tokio::test]
async fn vless_edge_serves_locally_on_no_session() {
    let harness = VlessEdgeHarness::with_uuid(EDGE_UUID).await;
    let _home = harness.fake_home_without_park().await;

    let client = harness.connect_client(EDGE_UUID).await;

    assert!(client.upgraded());
    assert!(harness.served_locally());
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p outline-ss-rust --lib transport::vless::tests::vless_edge_`
Expected: FAIL — `run_vless_relay` takes no upstream parameter.

- [ ] **Step 3: Thread `UpstreamSource` through VLESS**

Add the trailing parameter at `vless/mod.rs:46`. At `vless/tcp.rs:404` (`establish_vless_tcp_upstream`), branch on `UpstreamSource::Mesh` to use `MeshUpstream` instead of connecting out. The user label at `vless/mod.rs:454` (`find_user` → `label_arc()`) feeds the `UserFrame`. Suppress parking on the mesh path exactly as in Task 4.

Leave VLESS-mux sub-connections (`vless_mux/tcp_sub.rs:44`) on the `Direct` path for now and assert that with a test — mux sub-connections open their own upstreams and are out of scope for this plan.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p outline-ss-rust --lib transport::vless`
Expected: PASS.

- [ ] **Step 5: Run the full gate and commit**

```bash
cargo test --workspace --exclude sockudo-ws
```

```bash
git add bins/outline-ss-rust/src/server/transport/vless/
git commit -m "feat(cluster): edge terminates VLESS crypto and relays plaintext to the home"
```

---

### Task 7: v5 plaintext SS-UDP home path

**Scoped to `Parked::SsUdpStream`.** It is the one non-TCP park kind the v5 OPEN
can already name: `MeshFraming::Udp` distinguishes it on the wire. The two VLESS
park kinds cannot be admitted from the home alone — `(framing = Tcp,
protocol = Vless)` is the *identical* OPEN for `Parked::Tcp`,
`Parked::VlessUdpSingle` and `Parked::VlessMux`, and the edge must choose it
before it can read the VLESS command — so admitting them here would reintroduce
the repeated-park-destruction defect `probe_park` exists to prevent. They get
their own tasks (9 and 10), each carrying the edge and wire half they need.

**The NAT ownership rule.** A resumed session must reattach the `nat_keys` it
parked with, **and** must still be able to create entries for targets it has not
reached before — a live UDP session meets new targets constantly, so forbidding
creation would black-hole every new destination for the life of the session.
What must be refused is routing to an entry owned by a *different* session or
user. Reattach owned, create unowned, refuse foreign.

Task 3 refuses `MeshFraming::Udp` deliberately, because the UDP home path is not
a splice like TCP's. A parked SS-UDP session holds only NAT keys and an owner
(`resumption/parked.rs:208-215`) — no socket — and the live UDP handler is driven
by `packet.user` / `packet.session` (`transport/udp.rs:328`, `:333`, `:402-415`),
which are products of the decryption v5 moves to the edge. So the home needs a
way to route datagrams it cannot decrypt.

It has everything required: the **identity** (user, session) arrives once per
stream in OPEN/USER, and the **target** rides inside each plaintext datagram,
because what the edge forwards is the SOCKS5-wrapped payload the SS-UDP body
already contains. Routing is therefore possible without any crypto on the home.

**Files:**
- Modify: `bins/outline-ss-rust/src/server/transport/udp.rs`
- Modify: `bins/outline-ss-rust/src/server/transport/mesh_relay.rs` (replace the refusal with the splice)
- Modify: `bins/outline-ss-rust/src/server/nat/` as needed for an identity-supplied entry point
- Test: `bins/outline-ss-rust/src/server/transport/tests/udp.rs`, `bins/outline-ss-rust/src/server/transport/tests/mesh_relay.rs`

**Interfaces:**
- Consumes: the v5 home path (Task 3), the continuity fields (Task 4).
- Produces: a home-side UDP path taking `(user_id, session_id, SOCKS5-wrapped datagram)` instead of a decrypted packet, reattaching the parked `nat_keys`, and a `MeshFraming::Udp` splice that replaces the refusal.

- [ ] **Step 1: Write the failing tests**

```rust
#[tokio::test]
async fn the_home_routes_plaintext_datagrams_without_decrypting() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([31u8; 16]);
    let target = spawn_udp_echo().await;
    park_test_udp_session(harness.registry(), id, "beerloga", &[nat_key_for(target)]).await;

    let mut session = harness.serve_v5_udp_ok(v5_udp_header(id), "beerloga").await;
    session.edge_send_datagram(&socks5_wrap(target, b"ping")).await;

    assert_eq!(
        session.edge_recv_datagram().await,
        socks5_wrap(target, b"ping"),
        "the echo must come back through the same session, still plaintext"
    );
}

#[tokio::test]
async fn datagram_boundaries_survive_the_mesh() {
    // The property whose loss over XHTTP caused the production incident that
    // started this work. Two datagrams in, two out — never one coalesced blob.
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([32u8; 16]);
    let target = spawn_udp_echo().await;
    park_test_udp_session(harness.registry(), id, "beerloga", &[nat_key_for(target)]).await;

    let mut session = harness.serve_v5_udp_ok(v5_udp_header(id), "beerloga").await;
    session.edge_send_datagram(&socks5_wrap(target, b"first")).await;
    session.edge_send_datagram(&socks5_wrap(target, b"second")).await;

    let got = vec![session.edge_recv_datagram().await, session.edge_recv_datagram().await];
    assert_eq!(got, vec![socks5_wrap(target, b"first"), socks5_wrap(target, b"second")]);
}

#[tokio::test]
async fn a_udp_session_reattaches_its_parked_nat_keys() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([33u8; 16]);
    let target = spawn_udp_echo().await;
    let key = nat_key_for(target);
    park_test_udp_session(harness.registry(), id, "beerloga", &[key.clone()]).await;

    let session = harness.serve_v5_udp_ok(v5_udp_header(id), "beerloga").await;

    assert!(
        harness.nat_table().owner_of(&key).is_some_and(|o| o == "beerloga"),
        "the resumed session must own its parked NAT entries, not fresh ones"
    );
    drop(session);
}

#[tokio::test]
async fn a_datagram_for_another_sessions_nat_entry_is_refused() {
    // The home trusts the edge's user attestation, but not an arbitrary target:
    // a session must not reach a NAT entry another session owns. It *must*
    // still be able to create entries for targets it has not met before — a
    // live UDP session meets new destinations constantly, and forbidding
    // creation would black-hole every new target for the life of the session.
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([34u8; 16]);
    let mine = spawn_udp_echo().await;
    let theirs = spawn_udp_echo().await;
    park_test_udp_session(harness.registry(), id, "beerloga", &[nat_key_for(mine)]).await;
    harness.nat_table().claim(nat_key_for(theirs), "someone-else").await;

    let mut session = harness.serve_v5_udp_ok(v5_udp_header(id), "beerloga").await;
    session.edge_send_datagram(&socks5_wrap(theirs, b"nope")).await;

    assert!(
        session.edge_recv_datagram_timeout().await.is_none(),
        "a foreign session's NAT entry must not be reachable"
    );
}

#[tokio::test]
async fn a_resumed_session_may_still_reach_a_brand_new_target() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([35u8; 16]);
    let parked_target = spawn_udp_echo().await;
    let fresh_target = spawn_udp_echo().await;
    park_test_udp_session(harness.registry(), id, "beerloga", &[nat_key_for(parked_target)]).await;

    let mut session = harness.serve_v5_udp_ok(v5_udp_header(id), "beerloga").await;
    session.edge_send_datagram(&socks5_wrap(fresh_target, b"hello")).await;

    assert_eq!(
        session.edge_recv_datagram().await,
        socks5_wrap(fresh_target, b"hello"),
        "a target first reached after the resume must still be routable"
    );
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p outline-ss-rust --lib transport::udp transport::mesh_relay`
Expected: FAIL — `MeshFraming::Udp` is still refused and no identity-supplied UDP entry point exists.

- [ ] **Step 3: Add the identity-supplied UDP entry point**

Factor the existing datagram handling in `transport/udp.rs` so the part after
decryption — target parsing, NAT lookup/creation, send, and the response path —
can be driven from `(user_id, session_id, socks5_datagram)` supplied by the
caller rather than derived from `packet.*`. Reuse `NatTable`/`NatEntry`
(`nat/table.rs:169`, `nat/entry.rs:149`) rather than a parallel table; if their
signatures demand a `UserKey`/`UdpCipherMode` the home no longer has, change the
API to take what it genuinely needs. Keep the existing v4 caller working — it
must keep passing its decrypted values through the same seam.

- [ ] **Step 4: Splice UDP on the mesh**

Replace the refusal in `mesh_relay.rs` with a splice that reattaches
`ParkedSsUdpStream.nat_keys` and pumps datagrams both ways over `MeshUdpCarrier`
(`transport/mesh_carrier.rs:227`), which already preserves per-datagram
boundaries. Apply the same close-intent and bounded-resource rules the TCP
splice follows. Drop datagrams whose target resolves to a NAT entry this session
does not own.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p outline-ss-rust --lib transport::udp transport::mesh_relay`
Expected: PASS — 4 new tests.

Run: `cargo test -p outline-ss-rust --lib resumption::cluster`
Expected: PASS — all 24 end-to-end cluster tests still green on v4.

- [ ] **Step 6: Run the full gate and commit**

```bash
cargo fmt --check -p outline-ss-rust -p outline-ws-rust -p outline-metrics -p outline-net -p outline-routing -p outline-transport -p outline-tun -p outline-uplink -p outline-wire -p shadowsocks-crypto -p socks5-proto
```

```bash
cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
```

```bash
cargo test --workspace --exclude sockudo-ws
```

```bash
git add bins/outline-ss-rust/src/server/transport/udp.rs bins/outline-ss-rust/src/server/transport/mesh_relay.rs bins/outline-ss-rust/src/server/nat/ bins/outline-ss-rust/src/server/transport/tests/
git commit -m "feat(cluster): route relayed plaintext UDP through NAT on the home"
```

---

### Task 8: Edge side — SS-UDP

**Two items inherited from Task 7's review land here, because this task is when
v5 SS-UDP traffic first flows for real:**

- ~~**A latent cancel-safety defect on the shared UDP relay loop.**~~ **Done
  ahead of this task**, in its own commit: `run_udp_relay` now builds its
  `T::recv` once, `tokio::pin!`s it and polls it through `&mut` from an inner
  select whose other arm drains `in_flight` — the shape Task 7's v5 pump uses.
  A 64-datagram burst test over a carrier framed like `MeshUdpCarrier`
  (`a_burst_of_datagrams_stays_framed_under_concurrent_relays` in
  `transport/tests/udp.rs`) fails against the unpinned loop. Nothing is left
  here for this item.
- **No test covers a relayed park later resumed by a *direct* carrier**, in
  either direction. Task 7's `Plaintext → Generate` server-session-id mapping is
  what makes that handover seal correctly; cover it now that both sides exist.

**Files:**
- Modify: `bins/outline-ss-rust/src/server/transport/udp.rs` (`run_udp_relay` at `:489`, auth at `:328`, NAT scope at `:219`)
- Test: `bins/outline-ss-rust/src/server/transport/tests/udp.rs`

**Interfaces:**
- Consumes: `UpstreamSource` (Task 4).
- Produces: `run_udp_relay<T: WsSocket>(socket, server, route, resume, injected_monitor, upstream: UpstreamSource)`; the SS-UDP edge sending `OpenHeaderV5` with `MeshFraming::Udp` plus the `UserFrame`.
- After this task every edge speaks v5, which is what lets Task 7 delete v4. All 24 end-to-end cluster tests must stay green.

- [ ] **Step 1: Write the failing tests**

```rust
#[tokio::test]
async fn udp_edge_relays_plaintext_datagrams_preserving_boundaries() {
    // Datagram boundaries must survive the mesh — the same property whose loss
    // over XHTTP caused the production incident this cluster work followed.
    let harness = UdpEdgeHarness::with_credentials("edge-secret").await;
    let home = harness.fake_home_with_park("beerloga").await;

    let mut client = harness.connect_client("beerloga", "edge-secret").await;
    client.send_datagram(b"first").await;
    client.send_datagram(b"second").await;

    assert_eq!(
        home.datagrams_received().await,
        vec![b"first".to_vec(), b"second".to_vec()],
        "two datagrams in, two datagrams out — never one coalesced blob"
    );
}

#[tokio::test]
async fn udp_edge_keeps_nat_on_the_home() {
    let harness = UdpEdgeHarness::with_credentials("edge-secret").await;
    let _home = harness.fake_home_with_park("beerloga").await;
    let mut client = harness.connect_client("beerloga", "edge-secret").await;

    client.send_datagram(b"x").await;

    assert_eq!(harness.local_nat_entries(), 0, "NAT belongs to the home that owns the socket");
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p outline-ss-rust --lib transport::udp::tests::udp_edge_`
Expected: FAIL — `run_udp_relay` takes no upstream parameter.

- [ ] **Step 3: Thread `UpstreamSource` through SS-UDP**

Add the trailing parameter at `udp.rs:489`. On `UpstreamSource::Mesh`, skip NAT allocation entirely (`resolve_nat_scope` at `:219`) and forward decrypted, SOCKS5-wrapped datagrams over the mesh's length-delimited datagram framing — the framing `MeshUdpCarrier` already provides. The user id at `:328` (`packet.user.id_arc()`) feeds the `UserFrame`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p outline-ss-rust --lib transport::udp`
Expected: PASS.

- [ ] **Step 5: Run the full gate and commit**

```bash
cargo test --workspace --exclude sockudo-ws
```

```bash
git add bins/outline-ss-rust/src/server/transport/udp.rs bins/outline-ss-rust/src/server/transport/tests/udp.rs
git commit -m "feat(cluster): edge terminates SS-UDP crypto and relays plaintext datagrams"
```

---

### Task 9: VLESS-UDP over v5 (home and edge)

`Parked::VlessUdpSingle` (`vless/udp.rs:81`) cannot be admitted from the home
alone: its v5 OPEN is byte-identical to a VLESS-TCP one, because the edge must
send OPEN before the client's first frame reveals the VLESS command. So this
task owns both halves plus whatever wire discriminator they need.

**Files:** `server/cluster/mesh/frame.rs` (v5 only), `server/transport/mesh_relay.rs`, `server/transport/vless/`, `server/transport/vless_udp.rs`, tests alongside each.

**Interfaces:** consumes the v5 home and edge paths (Tasks 3-7). Produces a way for the edge to name the park shape it needs *after* it reads the VLESS command — the constraint that makes this its own task — plus the home-side plaintext path for `VlessUdpSingle`.

- [ ] **Step 1: Decide and document the discriminator.** The edge knows the command only after the `101`, and OPEN precedes it. Either the shape moves to the second phase alongside `UserFrame`, or the edge re-opens once it knows. Write the choice and its cost into the module doc before implementing; `probe_park` must still refuse a shape mismatch **before** anything is consumed.
- [ ] **Step 2: Write the failing tests** — a VLESS-UDP session parked on the home and resumed through an edge with different paths and credentials keeps one upstream; a shape mismatch leaves the park intact; datagram boundaries survive.
- [ ] **Step 3: Run them to verify they fail.**
- [ ] **Step 4: Implement**, reusing `MeshUdpCarrier` for boundaries and the `SpliceEnd`/`stream_close` and cooperative-stop patterns from the TCP splice.
- [ ] **Step 5: Restore the withdrawn claim.** `cluster_vless_udp_survives_edge_switch` had its "one upstream across an edge switch" assertion withdrawn in Task 6 — put it back, and remove the doc-comment note explaining the withdrawal.
- [ ] **Step 6: Run the full gate and commit** (`fmt` → `clippy` → `test`; `resumption::cluster` must not drop).

---

### Task 10: VLESS-mux over v5 (home and edge)

`Parked::VlessMux` (`vless/mod.rs:348`) has the same indistinguishable-OPEN
problem as Task 9, and additionally carries sub-connections
(`ParkedMuxSubKind::{Tcp, Udp}`, `resumption/parked.rs:157-166`) that each hold
their own upstream. Task 6 left mux sub-connections on `Direct` deliberately.

**Files:** `server/cluster/mesh/frame.rs` (v5 only), `server/transport/mesh_relay.rs`, `server/transport/vless/mod.rs`, `server/transport/vless_mux/`, tests alongside each.

**Interfaces:** consumes Task 9's discriminator — do not invent a second one. Produces the home-side plaintext path for `VlessMux`, including how each sub-connection re-attaches.

- [ ] **Step 1: Write the failing tests** — a mux session with both a TCP and a UDP sub-connection, parked on the home and resumed through an edge with different paths and credentials, keeps every sub-connection's upstream; a partially-reattachable park is refused whole rather than half-spliced.
- [ ] **Step 2: Run them to verify they fail.**
- [ ] **Step 3: Implement**, reusing Task 9's discriminator and the established splice patterns.
- [ ] **Step 4: Decide sub-connection scope explicitly.** Task 6 kept mux sub-connections on `Direct` with a test pinning it. Either migrate them and replace that test, or state in the module doc why they stay direct — do not leave it implicit.
- [ ] **Step 5: Run the full gate and commit** (`fmt` → `clippy` → `test`; `resumption::cluster` must not drop).

---

### Task 11: Retire v4 on the home

Every edge speaks v5 after Tasks 4–6, so the v4 branch is now dead weight. This
is the contract half of the expand/contract: delete it, and let v5 become the
only shape the home understands.

**Files:**
- Modify: `bins/outline-ss-rust/src/server/cluster/mesh/frame.rs`
- Modify: `bins/outline-ss-rust/src/server/transport/mesh_relay.rs`
- Test: `bins/outline-ss-rust/src/server/cluster/mesh/tests/frame.rs`

**Interfaces:**
- Consumes: v5 edges for all three carriers (Tasks 4–6).
- Produces: a home that parses only v5. `OpenHeader`, `CarrierKind`, `MAX_PATH_LEN`, `CloseReason::NoRoute`, `RelayedRoute`, `resolve_relayed_route`, `refuse_unroutable_relay` and the old `serve_relayed` are gone.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn a_v4_frame_is_refused_outright() {
    // v4 is retired: every edge in a cluster running this build speaks v5. A
    // straggler gets a clean refusal and serves its client locally, which is the
    // documented "skew costs continuity, not traffic" behaviour.
    let v5 = OpenHeaderV5 {
        framing: MeshFraming::Tcp,
        session_id: [1u8; 16],
        resume_capable: false,
        ack_prefix: false,
        symmetric_replay: false,
        client_down_acked: 0,
        peer_addr: None,
    };
    let mut encoded = v5.encode();
    encoded[0] = 4;
    let err = OpenHeaderV5::parse(&encoded).expect_err("a v4 frame must be refused");
    assert!(err.to_string().contains("version"), "got: {err}");
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p outline-ss-rust --lib cluster::mesh::frame::tests::a_v4_frame_is_refused_outright`
Expected: FAIL only if the parser still accepts v4; if it already passes, the
deletions below are still required — proceed and rely on the compiler.

- [ ] **Step 3: Delete the v4 frame types**

From `frame.rs` remove: `OPEN_VERSION`, `OpenHeader` and its `encode`/`parse`,
`CarrierKind` with `to_u8`/`from_u8`, `MAX_PATH_LEN`, and the
`CloseReason::NoRoute` variant together with its arms in `code()`/`from_code()`
(code `4` becomes unmapped and falls back to `Abort`, correct for a straggler
that still sends it). Rename `OPEN_VERSION_V5` to `OPEN_VERSION` now that it is
the only one, and fold the v5 doc-log into the main version comment.

Consider renaming `OpenHeaderV5`/`MeshFraming` to `OpenHeader`/`CarrierKind`
now the originals are gone — but only if it is a pure rename; do not reshape
anything while deleting.

- [ ] **Step 4: Delete the v4 home path**

From `mesh_relay.rs` remove `serve_relayed`, `RelayedRoute`,
`resolve_relayed_route`, `refuse_unroutable_relay` and the route-table imports
they needed, plus the version dispatch added in Task 3 (there is one version
now). `serve_relayed_v5` becomes the only entry point — rename it to
`serve_relayed`.

- [ ] **Step 5: Verify nothing depended on the deleted code**

Run: `cargo test -p outline-ss-rust --lib resumption::cluster`
Expected: PASS — all 24 end-to-end cluster tests, now exercising v5 end to end
on every carrier. This is the moment the migration is genuinely complete.

- [ ] **Step 6: Run the full gate and commit**

```bash
cargo fmt --check -p outline-ss-rust -p outline-ws-rust -p outline-metrics -p outline-net -p outline-routing -p outline-transport -p outline-tun -p outline-uplink -p outline-wire -p shadowsocks-crypto -p socks5-proto
```

```bash
cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
```

```bash
cargo test --workspace --exclude sockudo-ws
```

```bash
git add bins/outline-ss-rust/src/server/cluster/mesh/frame.rs bins/outline-ss-rust/src/server/cluster/mesh/tests/frame.rs bins/outline-ss-rust/src/server/transport/mesh_relay.rs
git commit -m "refactor(cluster): retire the v4 mesh relay path now every edge speaks v5"
```

---

### Task 12: Cross-node continuity — the proof of the goal

**Files:**
- Modify: `bins/outline-ss-rust/src/server/tests/resumption/cluster.rs`

**Interfaces:**
- Consumes: everything from Tasks 1–6. Adds no production code.

This task adds no behaviour. It exists because the spec names this test as the
direct proof of the goal, and because the production failure it guards against —
a relay that never worked — was invisible for months. Every earlier task tests
one layer; this one tests the property the user actually asked for: **two nodes
with different paths and different credentials keep a session continuous.**

- [ ] **Step 1: Write the failing tests**

```rust
#[tokio::test]
async fn session_survives_a_move_between_nodes_with_different_paths_and_credentials() {
    // The exact topology that was broken in production: every node has its own
    // path and its own per-user credentials. Only the user name is shared.
    let home = TestNode::builder()
        .shard(0)
        .path("/home-only-path/ss")
        .user("beerloga", "home-secret")
        .build()
        .await;
    let edge = TestNode::builder()
        .shard(1)
        .path("/edge-only-path/ss")
        .user("beerloga", "edge-secret")
        .peer(&home)
        .build()
        .await;

    // 1. The client establishes on the home, using the home's credentials.
    let mut client = home.connect_client("beerloga", "home-secret").await;
    let upstream = home.accept_upstream().await;
    upstream.send(b"chunk-one:").await;
    assert_eq!(client.recv_plaintext().await, b"chunk-one:");
    let session_id = client.session_id();

    // 2. The carrier drops; the home parks the upstream.
    client.drop_carrier().await;
    home.await_park(session_id).await;

    // 3. The client reconnects to the *edge*, with the *edge's* credentials and
    //    the edge's path. Under the old design this was a black hole.
    let mut client = edge.reconnect_client(session_id, "beerloga", "edge-secret").await;

    assert_eq!(
        client.echoed_session_id(),
        session_id,
        "continuity: the edge must echo the id the client already holds"
    );

    // 4. The same upstream keeps serving, through the edge.
    upstream.send(b"chunk-two").await;
    assert_eq!(
        client.recv_plaintext().await,
        b"chunk-two",
        "the parked upstream must keep streaming across the node move"
    );
}

#[tokio::test]
async fn downlink_replay_has_no_gap_and_no_duplicate_across_the_move() {
    let home = TestNode::builder()
        .shard(0)
        .path("/home-only-path/ss")
        .user("beerloga", "home-secret")
        .symmetric_replay(true)
        .build()
        .await;
    let edge = TestNode::builder()
        .shard(1)
        .path("/edge-only-path/ss")
        .user("beerloga", "edge-secret")
        .symmetric_replay(true)
        .peer(&home)
        .build()
        .await;

    let mut client = home.connect_client("beerloga", "home-secret").await;
    let upstream = home.accept_upstream().await;
    let session_id = client.session_id();

    // Send 12 bytes; the client acknowledges only the first 5 before dropping.
    upstream.send(b"HELLO-WORLD!").await;
    client.recv_exactly(5).await;
    let acked = client.down_acked_offset();
    assert_eq!(acked, 5);
    client.drop_carrier().await;
    home.await_park(session_id).await;

    let mut client = edge
        .reconnect_client_with_ack(session_id, "beerloga", "edge-secret", acked)
        .await;

    // Exactly the unacked suffix — the edge re-sealed plaintext under its own key.
    assert_eq!(
        client.recv_plaintext().await,
        b"-WORLD!",
        "replay must resume precisely at the acked offset"
    );
}

#[tokio::test]
async fn a_relayed_session_moves_real_bytes_downstream() {
    // `mesh_bytes_total{direction="down"} == 0` fleet-wide was the symptom that
    // a never-working relay hid behind. Assert the counter actually moves.
    let home = TestNode::builder().shard(0).path("/h/ss").user("beerloga", "home-secret").build().await;
    let edge = TestNode::builder().shard(1).path("/e/ss").user("beerloga", "edge-secret").peer(&home).build().await;

    let mut client = home.connect_client("beerloga", "home-secret").await;
    let upstream = home.accept_upstream().await;
    let session_id = client.session_id();
    client.drop_carrier().await;
    home.await_park(session_id).await;

    let mut client = edge.reconnect_client(session_id, "beerloga", "edge-secret").await;
    upstream.send(b"downstream payload").await;
    client.recv_plaintext().await;

    assert!(home.mesh_bytes_down() > 0, "the home must have pushed bytes onto the mesh");
    assert_eq!(home.relay_outcome_count("hit"), 1);
    assert_eq!(home.relay_rejected_count("no_session"), 0);
}

#[tokio::test]
async fn a_refusal_leaves_no_half_served_client() {
    // The black-hole invariant: if the home cannot serve the relay, the client
    // must end up with a working fresh session, never a silent one.
    let home = TestNode::builder().shard(0).path("/h/ss").user("beerloga", "home-secret").build().await;
    let edge = TestNode::builder().shard(1).path("/e/ss").user("beerloga", "edge-secret").peer(&home).build().await;

    // A resume id whose shard points at the home, but with no park behind it.
    let stale = home.mint_session_id_without_park();

    let mut client = edge.reconnect_client(stale, "beerloga", "edge-secret").await;

    assert_ne!(client.echoed_session_id(), stale, "a fresh session mints a new id");
    let upstream = edge.accept_upstream().await;
    upstream.send(b"served locally").await;
    assert_eq!(
        client.recv_plaintext().await,
        b"served locally",
        "the client must be genuinely served, not silently stalled"
    );
    assert_eq!(home.relay_rejected_count("no_session"), 1);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p outline-ss-rust --lib resumption::cluster`
Expected: FAIL — the `TestNode` builder does not yet support per-node paths and
per-node credentials (today's harness assumes a symmetric cluster).

- [ ] **Step 3: Extend the test harness for asymmetric nodes**

Give `TestNode::builder()` the `path(...)`, `user(name, secret)`,
`symmetric_replay(bool)` and `peer(&other)` methods used above, so two nodes can
be stood up with deliberately different paths and secrets. Add the accessors the
assertions need: `mesh_bytes_down()`, `relay_outcome_count(outcome)`,
`relay_rejected_count(reason)`, `await_park(id)`, `mint_session_id_without_park()`.

Keep the harness in the test module — it is test scaffolding, not production code.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p outline-ss-rust --lib resumption::cluster`
Expected: PASS — 4 tests. If `downlink_replay_has_no_gap_and_no_duplicate_across_the_move`
fails, the replay offset accounting is wrong; do not weaken the assertion.

- [ ] **Step 5: Run the full gate and commit**

```bash
cargo test --workspace --exclude sockudo-ws
```

```bash
git add bins/outline-ss-rust/src/server/tests/resumption/cluster.rs
git commit -m "test(cluster): session continuity across nodes with different paths and credentials"
```

---

### Task 13: Validation, metrics and documentation

**Files:**
- Modify: `bins/outline-ss-rust/src/server/config/` (cluster validation)
- Modify: `bins/outline-ss-rust/src/metrics/mod.rs` (`record_mesh_relay_rejected` at `:582`), `metrics/registry.rs` (`:243`), `metrics/tests/mod.rs`
- Modify: `docs/CLUSTER.md`, `docs/CLUSTER.ru.md`, `docs/CLUSTER-DEPLOY.md`, `docs/CLUSTER-DEPLOY.ru.md`
- Modify: `bins/outline-ss-rust/CHANGELOG.md`, `CHANGELOG.ru.md`

**Interfaces:**
- Consumes: everything above, including `Metrics::record_mesh_relay_outcome` (defined in Task 3, because `serve_relayed` calls it).
- Produces: validated shared-user-namespace config; both new metrics registered and covered by label tests.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn mesh_rejection_reasons_are_registered() {
    let metrics = test_metrics();
    metrics.record_mesh_relay_rejected("no_session");
    metrics.record_mesh_relay_rejected("unknown_user");
    metrics.record_mesh_relay_rejected("capacity");

    let rendered = metrics.render();
    assert!(rendered.contains(r#"reason="no_session""#));
    assert!(rendered.contains(r#"reason="unknown_user""#));
    // The removed reason must be gone — it described a route lookup the home
    // no longer performs.
    assert!(!rendered.contains(r#"reason="no_route""#));
}

#[test]
fn mesh_relay_outcome_is_observable() {
    // A never-working relay went unnoticed in production because success was
    // only inferrable from byte counters. Make it a first-class signal.
    let metrics = test_metrics();
    metrics.record_mesh_relay_outcome("hit");
    metrics.record_mesh_relay_outcome("miss");

    let rendered = metrics.render();
    assert!(rendered.contains("outline_ss_mesh_relay_outcome_total"));
    assert!(rendered.contains(r#"outcome="hit""#));
    assert!(rendered.contains(r#"outcome="miss""#));
}

#[test]
fn config_rejects_a_user_name_that_cannot_cross_the_mesh() {
    // Paths and credentials are per-node now, but user *names* must agree across
    // nodes: `take_for_resume` is keyed by (session id, user), and the name
    // travels in a `UserFrame` bounded at `MAX_USER_LEN`. A name that cannot fit
    // could never authenticate a relayed session, so it fails at load instead of
    // at the first relay.
    let err = load_config_str(&config_with_cluster_and_user(&"u".repeat(MAX_USER_LEN + 1)))
        .expect_err("a name that cannot fit a UserFrame must be refused");
    assert!(err.to_string().contains("user name"), "got: {err}");
}

#[test]
fn config_accepts_user_names_within_the_mesh_bound() {
    load_config_str(&config_with_cluster_and_user("beerloga")).expect("an ordinary name loads");
    load_config_str(&config_with_cluster_and_user(&"u".repeat(MAX_USER_LEN)))
        .expect("a name exactly at the ceiling loads");
}

#[test]
fn the_user_name_bound_applies_only_to_a_clustered_server() {
    // A standalone server never sends a UserFrame, so its names are its own
    // business — do not break existing single-node deployments.
    load_config_str(&config_without_cluster_and_user(&"u".repeat(MAX_USER_LEN + 1)))
        .expect("an unclustered server is unaffected by the mesh bound");
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p outline-ss-rust --lib metrics config::cluster`
Expected: FAIL — `outline_ss_mesh_relay_outcome_total` is not registered, so it does not render; `no_route` is still registered; the cluster config validator accepts an empty user name.

- [ ] **Step 3: Register the metrics**

The `record_mesh_relay_outcome` method already exists (added in Task 3, where
`serve_relayed` calls it). What is missing is registration and label coverage:

Register `outline_ss_mesh_relay_outcome_total` in `metrics/registry.rs` next to the existing mesh entry (`:243`), following the shape of the entries around it. Then update `metrics/tests/mod.rs`, which currently asserts the `capacity` and `no_route` labels — replace `no_route` with `no_session` and add `unknown_user`.

- [ ] **Step 4: Add the shared-user-namespace validation**

`ClusterConfig` (`config/resolved.rs`) holds only shard/psk/mesh_listen/budget/peers — there is no user list there, so validate the names the server already knows: the `[[users]]` entries.

When (and only when) `[cluster] enabled = true`, reject any user name that is empty or longer than `MAX_USER_LEN` (64) — the bound `UserFrame` enforces on the wire. Such a name could never authenticate a relayed session, so failing at load beats failing at the first relay. An unclustered server keeps accepting whatever it accepts today.

- [ ] **Step 5: Rewrite the cluster documentation (EN and RU together)**

In `docs/CLUSTER-DEPLOY.md` and `docs/CLUSTER-DEPLOY.ru.md`, replace §3a — currently "verify paths and credentials match on every node" — with the new invariant: **paths and per-user credentials are per-node; only user names are shared.** State plainly that the previous requirement is gone and why (the edge now terminates client crypto).

In `docs/CLUSTER.md` and `docs/CLUSTER.ru.md`, document the two-phase OPEN, the trust model (the home accepts the edge's user attestation, backed by the mesh PSK), and that the mesh carries plaintext inside its TLS 1.3 QUIC tunnel.

Add CHANGELOG entries in `bins/outline-ss-rust/CHANGELOG.md` and `CHANGELOG.ru.md` describing the behaviour change and the rollout note below.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test -p outline-ss-rust --lib metrics config`
Expected: PASS.

- [ ] **Step 7: Run the full gate and commit**

```bash
cargo fmt --check -p outline-ss-rust -p outline-ws-rust -p outline-metrics -p outline-net -p outline-routing -p outline-transport -p outline-tun -p outline-uplink -p outline-wire -p shadowsocks-crypto -p socks5-proto
```

```bash
cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
```

```bash
cargo test --workspace --exclude sockudo-ws
```

```bash
git add bins/outline-ss-rust/src/metrics/ bins/outline-ss-rust/src/server/config/ docs/CLUSTER.md docs/CLUSTER.ru.md docs/CLUSTER-DEPLOY.md docs/CLUSTER-DEPLOY.ru.md bins/outline-ss-rust/CHANGELOG.md bins/outline-ss-rust/CHANGELOG.ru.md
git commit -m "feat(cluster): validate the shared user namespace, report relay outcomes, document per-node config"
```

---

## Rollout

`[cluster] enabled = false` on all three servers as of 2026-07-28, so node order does not matter: deploy the binary everywhere with `ops/deploy/deploy-binary.sh`, then flip `enabled = true` and restart (the mesh listener is built in `build_services` at startup; `/control/apply` does not raise it).

Under version skew a v4 node refuses a v5 stream and the edge serves its client locally — **the worst case is a loss of continuity, not a loss of traffic.**

Verify after enabling:
- `outline_ss_mesh_relay_outcome_total{outcome="hit"}` is non-zero — the signal whose absence hid a never-working relay.
- `outline_ss_mesh_bytes_total{direction="down"}` is non-zero (it was 0 fleet-wide before).
- No `outline_ss_mesh_relay_rejected_total{reason="unknown_user"}` — that would mean the user namespaces disagree.

## Out of scope

- VLESS-mux sub-connections (`vless_mux/tcp_sub.rs:44`) keep opening their own upstreams.
- Cross-node migration of the park itself: the park stays on the home; the edge relays to it.
- Any client-side (`outline-ws-rust`) change.
