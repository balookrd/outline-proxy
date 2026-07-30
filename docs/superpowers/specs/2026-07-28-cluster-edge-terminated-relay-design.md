# Edge-terminated cluster relay (design)

Date: 2026-07-28
Status: approved by owner (chat)

## Goal

Make the cluster mesh relay work with **per-node paths and per-node
credentials** — the topology the fleet actually runs. Today the relay requires
the opposite (identical paths *and* identical per-user credentials on every
node), and under the fleet's asymmetric config every relayed session was a
black hole: `mesh_bytes_total{direction="down"} = 0` on all nodes against
~4.5 MB relayed out. The relay had never worked in production.

Achieved by moving where client crypto terminates: from the home to the edge.

## Background: why the current design requires symmetry

The edge is a byte pipe. It splices the still-encrypted client carrier onto the
home (`transport/mesh_relay.rs:203-206` — "the edge does not decode the
SS/VLESS layer — it moves the WS binary payload verbatim"), and the home feeds
it into its normal accept path: `serve_relayed` dispatches into the same
`run_tcp_relay` / `run_vless_relay` / `run_udp_relay` with `route.users`
resolved from the OPEN header's `path` (`transport/mesh_relay.rs:872-942`).

So the **home** decrypts the client carrier and authenticates the user from the
relayed stream itself (SS salt / VLESS UUID). For that to succeed the home must
hold the same path and the same credentials the client encrypted with on the
edge. That is a property of the protocol, not a config mistake.

Two independent asymmetries existed on the fleet — different paths
(`/qtciVjc…`, `/maiRfy1…`, `/wZQvS85…`) *and* different per-user credentials —
so even matching paths would not have helped: the AEAD/VLESS-UUID would not
agree.

## Enabling fact: the replay ring is already plaintext

The downlink replay buffer used for byte-continuity is **plaintext**, and it is
keyed by plaintext offsets:

- `server/relay.rs:187-190` — `ring.lock().push(&buffer)` happens **before**
  `encryptor.encrypt_chunk(...)`. The code says so: "v2 capture: push plaintext
  into the per-session ring BEFORE encryption".
- `server/resumption/downlink_ring.rs:32-35` — "the wire-level offset is the
  `total_sent_downlink` **plaintext** byte counter".
- On resume the home re-encrypts the plaintext with a **fresh**
  `AeadStreamEncryptor` bound to the new client stream's response context
  (`transport/tcp.rs:768-770`, `859-860`).

The ring therefore needs no changes: it can be handed to a peer as plaintext,
and whichever node owns the client stream can seal it under its own key. This
is what makes the design below cheap rather than invasive.

`ParkedTcp` / `OrphanRegistry` live on the **home**
(`resumption/parked.rs:97,124`, `resumption/registry.rs:81`). The edge holds no
ring, no crypto and no park today.

## Model

Edge terminates client crypto; the mesh carries application plaintext inside
the existing mutually-authenticated TLS 1.3 QUIC tunnel (ephemeral ECDHE +
AES-GCM, PSK-derived cert pinning — `cluster/mesh/tls.rs:1-19`). Nothing is
exposed on the wire.

```
client ──SS/VLESS(edge's key)──▶ edge ──plaintext──▶ home ──▶ upstream
client ◀──SS/VLESS(edge's key)── edge ◀──plaintext── home ◀── upstream
```

1. Client reconnects to the edge with its resume id; the shard encoded in the
   id names the home.
2. The edge upgrades the carrier and authenticates the client **itself**, with
   its own credentials, through the same accept code used for local sessions,
   yielding the user's name.
3. The edge opens a mesh stream: `OPEN(resume-id, user, caps,
   client_down_acked)`.
4. The home runs `take_for_resume(resume_id, user)`. On **hit** it splices the
   plaintext mesh stream onto the parked upstream and replays the ring suffix
   `[client_acked_offset, total_sent)` as plaintext.
5. The edge seals the downlink with its own client key. Padding is applied on
   the edge, under the edge's own path scheme.

Rejected alternative (**B**): a shared internal cluster identity, with the edge
re-encrypting under one common key for the home. It reaches the same goal and
changes the home accept path less, but the mesh is already an encrypted tunnel,
so the second AEAD is pure CPU overhead on the hot path — and it reintroduces a
shared secret.

### Relay narrows to one purpose

A **resume miss** on the home (park expired or evicted) is answered with a
refusal, and the edge then serves the client **locally** — a path that already
exists (`try_relay_edge` hands the `WebSocketUpgrade` back). Fresh sessions are
never created over the mesh any more. The target is not carried over the mesh
at all: on a hit it is already ignored today ("by spec the parked target is
authoritative", `transport/tcp.rs:737-739`), and there is no other case.

This is a simplification against today's behaviour, where a home serves a fresh
local session on a miss.

## Trust model

Two deliberate shifts, both documented:

- The home accepts the **user's identity on the edge's word**, without
  re-verifying client crypto: the edge authenticated the client, and the home
  trusts the mesh PSK. This adds no trust boundary — a node holding the PSK is
  already a full cluster member — but the invariant changes from "the home
  verifies the client itself" to "the home trusts the edge's attestation".
- A **shared user namespace** becomes required: `take_for_resume` is keyed by
  (resume id, user), so a user name (`cloud`, `beerloga`) must denote the same
  person on every node. Credentials and paths stay per-node. This is the only
  remaining cluster-wide invariant, and it is checkable by a config validator.

## Two problems found while planning

Both were under-estimated in the first draft of this design and are recorded
here because they shape the work.

### The upstream is not abstracted anywhere

`relay_upstream_to_client` takes a concrete `OwnedReadHalf`
(`server/relay.rs:74`), and the upstream is `tokio::net::TcpStream` throughout
(`transport/tcp.rs:960`, `transport/vless/tcp.rs:404`,
`transport/vless_udp.rs:38`). The only trait with a suggestive name,
`UpstreamSink` (`server/relay.rs:57`), is the sink **towards the client**, not a
connection. There is no `Upstream`/`OutboundStream` abstraction.

So the edge — where a mesh stream plays the role of the upstream — needs a new
upstream trait plus a generified `relay.rs`. That is a task of its own, not a
detail.

`resumption/` still needs no change: on the **home** `ParkedTcp` keeps holding a
real `TcpStream` exactly as today (`resumption/parked.rs:97`). The abstraction is
required on the edge only.

### Echo and authentication are circularly dependent

`X-Outline-Resume-Session` is echoed in the `101` response headers. Deciding
whether to echo continuity requires a hit from the home, but
`take_for_resume(id, authenticated_user)` (`resumption/registry.rs:274`) is keyed
by **(session id, user)** — so it needs authentication, which is only possible
*after* `101` (the SS salt arrives in the first binary frame). The echo cannot be
decided before authentication, and authentication cannot happen before the echo.

Resolved with a **two-phase OPEN**, which preserves today's open-before-`101`
shape:

```
edge: OPEN(resume-id, caps)      ──▶ home     // no user yet
home: ACK / NoSession            ◀──          // "is there a park under this id?"
edge: 101 to the client (echo now decided)
edge: authenticate the client → user
edge: USER(user name)            ──▶ home
home: take_for_resume(id, user) → owner check // exactly as today, one phase later
      then the plaintext stream
```

The owner check is preserved in full, just moved one phase later. On
`ResumeMiss::OwnerMismatch` — a rare security event — the session is torn down
after `101`, which is the acceptable cost.

## Wire protocol

`OPEN_VERSION` 4 → 5, and OPEN becomes two-phase (see above): a `USER` frame
follows the ACK.

| Field | Today | Becomes |
|---|---|---|
| `path` | home resolves users + padding scheme from it | **removed** — the path stays a local matter of the edge |
| `carrier` | selects which route table to resolve | **narrowed** to `Tcp` / `Udp`; the home no longer distinguishes SS/VLESS/xhttp — that is the edge's crypto |
| `user` | — | **added**, but in the second-phase `USER` frame (≤ 64 bytes), not in OPEN — it is not known when OPEN is sent |
| `session_id`, `ack_prefix`, `symmetric_replay`, `client_down_acked`, `peer_addr` | | unchanged |

`OPEN_ACK_ACCEPTED` (v4) stays and gains a sharper meaning: the home
acknowledges a **resume hit**, not "the path resolves".
`CloseReason::NoRoute` is replaced by `CloseReason::NoSession` — "no such
park", an ordinary expected outcome rather than a sign of broken config.

The refusal arriving **before** the client carrier is upgraded is what kills the
black hole.

## Module boundaries

- `cluster/mesh/frame.rs` — new OPEN layout, `NoSession`. Single point of format
  change.
- `transport/mesh_relay.rs` (952 lines today) — **split**. `RelayedRoute`,
  `resolve_relayed_route` and `refuse_unroutable_relay` are removed outright:
  there is no route resolution on the home any more. A home-side "splice
  plaintext to the parked upstream" replaces them. The file shrinks
  substantially, which is the answer to its current size.
- `server/relay.rs` — **new upstream abstraction.** `relay_upstream_to_client`
  is generified off `OwnedReadHalf` onto a trait implemented by both a real TCP
  upstream and a mesh stream. Prerequisite for the edge side.
- **Edge side, the substantive change.** `try_relay_edge` is called *before* the
  upgrade today, to decide relay-vs-local. That stays (the OPEN phase still
  precedes `101`), but the edge now also authenticates the client after `101`
  and sends the `USER` frame. The edge path becomes "accept as a local session,
  but take the upstream over the mesh": `transport/tcp.rs`,
  `transport/vless/`, `transport/udp.rs` gain an upstream variant "mesh stream
  to home" alongside "TCP connect out", and must **not** park on the edge —
  parking stays a home concern.
- `resumption/` — **no behavioural change.** `DownlinkRing`, `OrphanRegistry`
  and `take_for_resume` work as they are; the edge never parks, so `ParkedTcp`
  keeps holding a real `TcpStream` on the home. One addition only: a read-only
  existence probe `has_park(id) -> bool`, needed for the phase-1 ACK (which must
  answer "is there a park under this id?" before a user is known). It touches no
  state and does not consume the park.
- `outline-ws-rust` (client) — **untouched**, as designed. *Divergence, recorded
  after the fact:* commit `386baa76` did change it. XHTTP packet-up has no
  carrier-level close — the downlink GET and each uplink POST are independent
  requests — so a client that finished left the server's read alive and the
  session lingered to the idle sweep instead of parking. Without a park there is
  nothing for a later `X-Outline-Resume` to find, on the carrier the fleet uses
  most, so the client now signals the close explicitly. It is argued in full in
  that commit and in both CHANGELOGs.

### UDP

Symmetric to TCP: the edge decodes SS-UDP (strips padding + AEAD, yielding
SOCKS5-wrapped datagrams) and plaintext datagrams cross the mesh in the
existing datagram framing (`MeshUdpCarrier` already preserves boundaries). NAT
and parking stay on the home.

## What this removes

The path/credential symmetry requirement. `[padding] paths` no longer has to
match across nodes (padding is entirely an edge concern). `docs/CLUSTER-DEPLOY.md`
§3a — currently "verify paths and credentials match" — is replaced by "user
names are shared, everything else is per-node".

## Migration and rollout

OPEN v5 is incompatible with v4, but the parser already rejects a foreign
version (`frame.rs`: `if version != OPEN_VERSION`), so a mixed cluster degrades
safely: a v4 node refuses a v5 stream, the edge gets a refusal and serves the
client locally. **The worst case under version skew is a loss of continuity,
not a loss of traffic.**

Rollout is simpler than the XHTTP-records change: `[cluster]` is currently
`enabled = false` on all nodes, so node order does not matter — deploy the
binary everywhere, then flip `enabled = true`. No "servers first, then clients".

## Error handling

| Situation | Behaviour |
|---|---|
| No park for the resume id (expired, evicted, wrong user) | `CloseReason::NoSession` **before** the upgrade → edge serves locally. Expected outcome: metric, not a WARN |
| Home unreachable / mesh dial fails | As today: `open_edge_relay` → `None` → local service |
| Home does not know the OPEN's user name | `NoSession` + WARN — a genuine config divergence (shared-name invariant broken) |
| Peer sent v4 or a malformed OPEN | Refuse (already implemented) |
| Plaintext stops flowing (upstream died on the home) | Existing `relay_budget_ms` and teardown |

Invariant guarded by test: **the refusal must arrive before the client carrier
is upgraded** — otherwise the client holds a session nobody will serve, which is
the same black hole in a new shape.

## Testing

Tests live in `tests/` subdirectories next to their module, per repo
convention.

- `frame.rs`: OPEN v5 roundtrip; rejection of v4; `user` length bounds;
  rejection of an empty or over-long name.
- Home side: hit → plaintext splices onto the parked upstream; miss →
  `NoSession`; unknown user → `NoSession`.
- **Cross-node continuity — the test that does not exist today.** Two nodes with
  **different paths and different credentials**: a session parks on the home,
  the client reconnects to the edge using the edge's credentials, and downlink
  byte-continuity is asserted (the ring suffix from `client_down_acked`, no gaps
  and no duplicates). This is the direct proof of the goal.
- Black-hole regression: a refusal leaves no upgraded client; and
  `mesh_bytes{direction="down"}` is non-zero on a successful relay — zero was
  precisely the production symptom.
- UDP twin: datagram boundaries survive the mesh; NAT stays on the home.

## Observability

`mesh_relay_rejected{reason}`: `no_route` → `no_session`, plus `unknown_user`.
A relayed-session counter by outcome (hit/miss) is added, so "the relay works"
is directly visible instead of being inferred from byte counters — the absence
of that signal is why a never-working relay went unnoticed.

## Out of scope

- Changing the shape of `DownlinkRing` / `OrphanRegistry`.
- Cross-node migration of the park itself (the park stays on the home; the edge
  relays to it).
- Any client-side (`outline-ws-rust`) change. (Held, with the one exception
  recorded above: the XHTTP packet-up close signal, `386baa76`.)
