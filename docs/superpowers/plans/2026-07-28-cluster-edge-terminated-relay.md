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
| `server/cluster/mesh/frame.rs` | T1 adds the `UserFrame` codec + `NoSession`; T3 switches to v5 (drops `path`, narrows `CarrierKind`, retires `NoRoute`) | 1, 3 |
| `server/cluster/mesh/tests/frame.rs` | Codec roundtrips, bounds rejection (T1); v5 layout and version rejection (T3) | 1, 3 |
| `server/relay.rs` | New `UpstreamRead` trait; `relay_upstream_to_client` generified off `OwnedReadHalf` | 2 |
| `server/tests/relay.rs` | Trait behaviour against a fake upstream | 2 |
| `server/resumption/registry.rs` | Read-only `has_park(id)` probe for the phase-1 ACK | 3 |
| `server/transport/mesh_relay.rs` | Home: two-phase accept + plaintext splice. Deletes `RelayedRoute`, `resolve_relayed_route`, `refuse_unroutable_relay` | 3 |
| `server/transport/tests/mesh_relay.rs` | Home-side hit/miss/owner-mismatch | 3 |
| `server/transport/upstream_source.rs` | `UpstreamSource` enum (`Direct` / `Mesh`) shared by all three carriers | 4 |
| `server/transport/tcp.rs` | Edge SS-TCP: authenticate, send USER, relay over mesh upstream, never park | 4 |
| `server/transport/vless/mod.rs`, `vless/tcp.rs` | Same for VLESS | 5 |
| `server/transport/udp.rs` | Same for SS-UDP (datagram framing) | 6 |
| `server/tests/resumption/cluster.rs` | Cross-node continuity with asymmetric paths and credentials | 7 |
| `server/config/` (validator), `metrics/registry.rs` | Shared-user-namespace validation; `no_session`/`unknown_user` labels registered | 8 |
| `docs/CLUSTER.md` + `.ru.md`, `docs/CLUSTER-DEPLOY.md` + `.ru.md` | Per-node paths/creds documented; §3a symmetry requirement replaced | 8 |

**Milestone:** after Task 4 the feature works end-to-end for SS-TCP — the largest carrier on the fleet. Tasks 5–6 extend it to VLESS and SS-UDP. The branch is deployable (behind `[cluster] enabled`, currently `false` fleet-wide) only after Task 6.

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

### Task 3: Home side — two-phase accept and plaintext splice

**Files:**
- Modify: `bins/outline-ss-rust/src/server/resumption/registry.rs` (add probe next to `symmetric_replay_enabled` at `:150`)
- Modify: `bins/outline-ss-rust/src/server/transport/mesh_relay.rs` (`serve_relayed` at `:800`; delete `RelayedRoute` `:711`, `resolve_relayed_route` `:733`, `refuse_unroutable_relay` `:782`)
- Test: `bins/outline-ss-rust/src/server/transport/tests/mesh_relay.rs`

**Interfaces:**
- Consumes: `UserFrame`, `MAX_USER_LEN`, `CloseReason::NoSession` from Task 1.
- Produces:
  - `OrphanRegistry::has_park(&self, id: SessionId) -> bool`
  - `Metrics::record_mesh_relay_outcome(&self, outcome: &'static str)` — defined here because `serve_relayed` calls it; its registry entry and label tests come in Task 8
  - The **v5 switch**, contracting what Task 1 expanded: `OPEN_VERSION = 5`, `OpenHeader` without `path`, `enum CarrierKind { Tcp, Udp }` (`Tcp` = 0, `Udp` = 1), `MAX_PATH_LEN` and `CloseReason::NoRoute` deleted
  - Home-side `serve_relayed` that acks on park-existence, reads `UserFrame`, calls `take_for_resume(id, &user)`, and splices plaintext — **no crypto, no route table**

- [ ] **Step 1: Write the failing tests**

Add the v5 layout tests to
`bins/outline-ss-rust/src/server/cluster/mesh/tests/frame.rs` — the switch and
the home rewrite land in one commit, so they are tested together:

```rust
#[test]
fn open_header_v5_roundtrips_without_peer_addr() {
    let header = OpenHeader {
        carrier: CarrierKind::Tcp,
        session_id: [7u8; 16],
        resume_capable: true,
        ack_prefix: true,
        symmetric_replay: false,
        client_down_acked: 4096,
        peer_addr: None,
    };
    let parsed = OpenHeader::parse(&header.encode()).expect("v5 header parses");
    assert_eq!(parsed, header);
}

#[test]
fn open_header_v5_roundtrips_with_peer_addr() {
    let header = OpenHeader {
        carrier: CarrierKind::Udp,
        session_id: [9u8; 16],
        resume_capable: true,
        ack_prefix: false,
        symmetric_replay: true,
        client_down_acked: u64::MAX,
        peer_addr: Some("198.51.100.7:443".parse().unwrap()),
    };
    let parsed = OpenHeader::parse(&header.encode()).expect("v5 header parses");
    assert_eq!(parsed, header);
}

#[test]
fn open_header_rejects_the_previous_version() {
    let header = OpenHeader {
        carrier: CarrierKind::Tcp,
        session_id: [1u8; 16],
        resume_capable: false,
        ack_prefix: false,
        symmetric_replay: false,
        client_down_acked: 0,
        peer_addr: None,
    };
    let mut encoded = header.encode();
    encoded[0] = 4; // a v4 peer's frame
    let err = OpenHeader::parse(&encoded).expect_err("v4 must be refused");
    assert!(err.to_string().contains("unsupported mesh OPEN version"), "got: {err}");
}

#[test]
fn carrier_kind_is_narrowed_to_the_framing_distinction() {
    assert_eq!(CarrierKind::from_u8(0).unwrap(), CarrierKind::Tcp);
    assert_eq!(CarrierKind::from_u8(1).unwrap(), CarrierKind::Udp);
    // The v4 kinds (SsXhttp = 4, VlessXhttp = 5, SsUdpXhttp = 6) are gone:
    // crypto is the edge's business now, so the home only needs the framing.
    assert!(CarrierKind::from_u8(4).is_err());
    assert!(CarrierKind::from_u8(6).is_err());
}
```

Append to `bins/outline-ss-rust/src/server/transport/tests/mesh_relay.rs`:

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
async fn home_refuses_when_no_park_exists() {
    let harness = MeshHomeHarness::new().await;
    let header = open_header(SessionId::from_bytes([6u8; 16]), CarrierKind::Tcp);

    let outcome = harness.serve(header, "beerloga").await;

    assert_eq!(outcome.close_reason(), Some(CloseReason::NoSession));
    assert!(!outcome.acked(), "the refusal must arrive instead of the ack, before any 101");
}

#[tokio::test]
async fn home_refuses_when_the_user_does_not_own_the_park() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([7u8; 16]);
    park_test_session(harness.registry(), id, "beerloga").await;

    // Phase 1 acks (a park exists), phase 2 rejects (wrong owner).
    let outcome = harness.serve(open_header(id, CarrierKind::Tcp), "cloud").await;

    assert!(outcome.acked(), "phase 1 cannot know the user yet, so it acks");
    assert_eq!(outcome.close_reason(), Some(CloseReason::NoSession));
}

#[tokio::test]
async fn home_splices_plaintext_to_the_parked_upstream() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([8u8; 16]);
    park_test_session(harness.registry(), id, "beerloga").await;

    let mut session = harness.serve_ok(open_header(id, CarrierKind::Tcp), "beerloga").await;

    // Uplink: what the edge writes as plaintext reaches the parked upstream verbatim.
    session.edge_write(b"GET / HTTP/1.1\r\n\r\n").await;
    assert_eq!(session.upstream_read().await, b"GET / HTTP/1.1\r\n\r\n");

    // Downlink: what the upstream sends reaches the edge as plaintext — the home
    // performs no encryption; the edge seals it under its own client key.
    session.upstream_write(b"HTTP/1.1 200 OK\r\n\r\n").await;
    assert_eq!(session.edge_read().await, b"HTTP/1.1 200 OK\r\n\r\n");
}

#[tokio::test]
async fn home_replays_the_ring_suffix_before_new_downlink() {
    let harness = MeshHomeHarness::new().await;
    let id = SessionId::from_bytes([9u8; 16]);
    // 12 plaintext bytes already sent, client acked the first 5.
    park_test_session_with_ring(harness.registry(), id, "beerloga", b"HELLO-WORLD!", 5).await;

    let mut header = open_header(id, CarrierKind::Tcp);
    header.symmetric_replay = true;
    header.client_down_acked = 5;

    let mut session = harness.serve_ok(header, "beerloga").await;

    assert_eq!(
        session.edge_read().await,
        b"-WORLD!",
        "the home must replay exactly the unacked suffix, as plaintext"
    );
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p outline-ss-rust --lib cluster::mesh::frame transport::mesh_relay`
Expected: FAIL — `OpenHeader` still has a `path` field so the v5 tests do not compile; `no method named has_park`; the harness/`serve_ok` helpers do not exist.

- [ ] **Step 3: Switch the frame to v5**

Contract what Task 1 expanded, in `cluster/mesh/frame.rs`:

- `OPEN_VERSION` 4 → 5, extending the version doc-log with: *v5 removed the
  request path and narrowed `CarrierKind` to the framing distinction — the edge
  now terminates client crypto, so the home neither resolves a route nor
  decrypts.*
- Delete the `path: String` field from `OpenHeader`, its doc comment, the two
  path lines in `encode` (fixing the layout doc to
  `version(1) | carrier(1) | flags(1) | down_acked(8) | session_id(16) | [peer_addr]`
  and the capacity hint to `27 + 19`), and the three `path_len`/`path` lines in
  `parse`.
- Delete `MAX_PATH_LEN`.
- Replace the seven-variant `CarrierKind` with `{ Tcp, Udp }` (`to_u8`/`from_u8`
  mapping `0`/`1`), documenting that body framing is all the home needs.
- Delete `CloseReason::NoRoute` and its arms in `code()`/`from_code()`; code `4`
  becomes unmapped and falls back to `Abort`, which is correct for a peer that
  still sends it.

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

`serve_relayed` reports its verdict, so the method must exist before Step 5
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

- [ ] **Step 6: Rewrite the home side**

In `mesh_relay.rs` delete `RelayedRoute` (`:711`), `resolve_relayed_route` (`:733`) and `refuse_unroutable_relay` (`:782`) outright, together with their imports of the route tables. Replace the body of `serve_relayed` (`:800`) with the two-phase flow:

```rust
/// Dispatches one relayed carrier: phase-1 ack on park existence, phase-2 owner
/// check, then a plaintext splice onto the parked upstream.
///
/// The home performs **no crypto and no route lookup**. The edge terminated the
/// client's SS/VLESS layer, so what arrives here is application plaintext inside
/// the mesh's own TLS 1.3 QUIC tunnel; the home only owns the upstream socket,
/// the park and the replay ring.
async fn serve_relayed(
    header: OpenHeader,
    mut stream: MeshStream,
    cluster: &ClusterCtx,
    services: &Services,
) -> Result<()> {
    let session_id = SessionId::from_bytes(header.session_id);

    // Phase 1: the only question answerable before the edge has authenticated
    // its client. A miss here is ordinary (parks expire), so the edge just
    // serves a fresh local session.
    if !services.orphan_registry.has_park(session_id) {
        cluster.metrics.record_mesh_relay_rejected("no_session");
        refuse_relay(stream, CloseReason::NoSession);
        return Ok(());
    }
    write_open_ack(&mut stream.send).await?;

    // Phase 2: the edge has now upgraded its client and authenticated it.
    let user = read_user_frame(&mut stream.recv).await?;
    let parked = match services.orphan_registry.take_for_resume(session_id, &user.user).await {
        ResumeOutcome::Hit(parked) => parked,
        ResumeOutcome::Miss(miss) => {
            let reason = match miss {
                ResumeMiss::OwnerMismatch => "unknown_user",
                _ => "no_session",
            };
            cluster.metrics.record_mesh_relay_rejected(reason);
            refuse_relay(stream, CloseReason::NoSession);
            return Ok(());
        },
    };

    let _relay_active = cluster.metrics.open_mesh_relay();
    cluster.metrics.record_mesh_relay_outcome("hit");

    match (header.carrier, parked) {
        (CarrierKind::Tcp, Parked::Tcp(parked)) => {
            splice_plaintext_tcp(stream, parked, header.client_down_acked, cluster).await
        },
        (CarrierKind::Udp, parked) => {
            splice_plaintext_udp(stream, parked, services, cluster).await
        },
        (carrier, _) => {
            // The park kind and the relayed framing disagree — a forged or
            // mismatched-version peer. Defensive refusal rather than a panic.
            warn!(?carrier, "relayed carrier framing does not match the parked session kind");
            refuse_relay(stream, CloseReason::Abort);
            Ok(())
        },
    }
}
```

Add `read_user_frame` (bounded read: one length byte then at most `MAX_USER_LEN`) and `splice_plaintext_tcp`. The latter is a plain bidirectional byte pump between the mesh stream and `parked.upstream_reader`/`upstream_writer`, prefixed by the ring suffix:

```rust
/// Splices a relayed plaintext stream onto a parked TCP upstream.
///
/// Simpler than the pre-v5 path it replaces: there is no decryptor, no
/// encryptor and no route context — just the unacked replay suffix followed by a
/// bidirectional pump. The ring already holds **plaintext** keyed by plaintext
/// offsets, so the suffix goes out as-is and the edge seals it under its own
/// client key.
async fn splice_plaintext_tcp(
    mut stream: MeshStream,
    parked: ParkedTcp,
    client_down_acked: u64,
    cluster: &ClusterCtx,
) -> Result<()> {
    if let Some(ring) = parked.downlink_ring.as_ref() {
        let suffix = ring.lock().replay_from(client_down_acked);
        for chunk in suffix.chunks {
            stream.send.write_all(&chunk).await?;
        }
    }
    // Bidirectional pump under the existing progress budget.
    pump_plaintext(stream, parked.upstream_reader, parked.upstream_writer, cluster.relay_budget)
        .await
}
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cargo test -p outline-ss-rust --lib cluster::mesh::frame transport::mesh_relay resumption::registry`
Expected: PASS — 7 new tests.

- [ ] **Step 8: Run the full gate and commit**

```bash
cargo test --workspace --exclude sockudo-ws
```

```bash
git add bins/outline-ss-rust/src/server/cluster/mesh/frame.rs bins/outline-ss-rust/src/server/cluster/mesh/tests/frame.rs bins/outline-ss-rust/src/server/resumption/registry.rs bins/outline-ss-rust/src/metrics/mod.rs bins/outline-ss-rust/src/server/transport/mesh_relay.rs bins/outline-ss-rust/src/server/transport/tests/mesh_relay.rs
git commit -m "feat(cluster): switch mesh OPEN to v5 and accept relays in two phases"
```

---

### Task 4: Edge side — SS-TCP (milestone: end-to-end)

**Files:**
- Create: `bins/outline-ss-rust/src/server/transport/upstream_source.rs`
- Modify: `bins/outline-ss-rust/src/server/transport/tcp.rs` (auth at `:735`, connect at `:960`, park at `:567`/`:640`, `run_tcp_relay` at `:292`)
- Modify: `bins/outline-ss-rust/src/server/transport/mesh_relay.rs` (`try_relay_edge` at `:507`, `EdgeRelay` at `:479`)
- Test: `bins/outline-ss-rust/src/server/transport/tests/tcp.rs`

**Interfaces:**
- Consumes: `UpstreamRead` (Task 2), `UserFrame`/`OpenHeader` v5 (Task 1), home behaviour (Task 3).
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

### Task 5: Edge side — VLESS

**Files:**
- Modify: `bins/outline-ss-rust/src/server/transport/vless/mod.rs` (`run_vless_relay` at `:46`, auth at `:454`), `vless/tcp.rs` (connect at `:404`, resume at `:177`)
- Test: `bins/outline-ss-rust/src/server/transport/vless/tests/mod.rs`

**Interfaces:**
- Consumes: `UpstreamSource`, `MeshUpstream` (Task 4).
- Produces: `run_vless_relay<T: WsSocket>(socket, server, route, resume, injected_monitor, upstream: UpstreamSource)`.

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

### Task 6: Edge side — SS-UDP

**Files:**
- Modify: `bins/outline-ss-rust/src/server/transport/udp.rs` (`run_udp_relay` at `:489`, auth at `:328`, NAT scope at `:219`)
- Test: `bins/outline-ss-rust/src/server/transport/tests/udp.rs`

**Interfaces:**
- Consumes: `UpstreamSource` (Task 4).
- Produces: `run_udp_relay<T: WsSocket>(socket, server, route, resume, injected_monitor, upstream: UpstreamSource)`.

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

### Task 7: Cross-node continuity — the proof of the goal

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

### Task 8: Validation, metrics and documentation

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
