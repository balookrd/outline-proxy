# Cluster deployment runbook

Operational guide for turning two or more standalone `outline-ss-rust` servers
into a mesh cluster where a client session survives switching between edges.
For the design, see [`CLUSTER.md`](CLUSTER.md).

## 0. Prerequisites

- **Two or more server nodes.** A one-node cluster is pointless — there is no
  peer to relay to. Nodes are usually in different countries.
- **All nodes on the same build**, ideally. The mesh wire protocol has a single
  version (`OPEN_VERSION`), and a node that does not speak it is refused at relay
  setup — explicitly, before any data — so a mixed fleet costs *continuity*, not
  traffic: those sessions are served locally on the edge instead of resuming on
  their home. Upgrade order does not matter; just do not leave the fleet mixed
  for long. Roll out one binary everywhere.
- The mesh interconnect uses **QUIC over UDP**. Make sure UDP between the nodes
  is allowed (see §4).

## 1. Topology and shard plan

Every node is simultaneously an **edge** (accepts clients) and a **home** (owns
its own sessions and accepts relays from other edges). Give each a unique
`shard_id` in `0..15`:

| Node | shard_id | public ingress (WS/H3/XHTTP) | mesh address (node-to-node) |
| --- | --- | --- | --- |
| A (e.g. DE) | 0 | unchanged | `A_ip:9443` |
| B (e.g. NL) | 1 | unchanged | `B_ip:9443` |

## 2. Shared secret

One secret for the whole cluster, identical on every node:

```bash
openssl rand -base64 32
```

It is HKDF-split by domain (`shard-obfuscation` for the session id,
`mesh-auth` for the interconnect keypair) — **no CA, no certificates** to
distribute. Store it like any other secret (not in git). Leaking it breaks
future mesh auth, but past traffic stays protected by the ephemeral QUIC keys.

## 3. Server `[cluster]` config

`peers` is the full shard → mesh-address map of **all** nodes; a node's own
entry is ignored, so the same `peers` block can be copied to every node.

**Node A** (`shard_id = 0`):

```toml
[cluster]
enabled = true
shard_id = 0
cluster_psk = "<same base64 on every node>"
mesh_listen = "[::]:9443"          # QUIC (UDP) listener for inbound relays
mesh_relay_budget_ms = 4000        # a relay stalled longer than this is torn down
peers = [
  { shard = 0, addr = "A_ip:9443" },   # own shard — ignored
  { shard = 1, addr = "B_ip:9443" },
]
```

**Node B** — identical, but `shard_id = 1`.

Validation is fail-fast at startup: `shard_id` required and `< 16`;
`cluster_psk` valid non-empty base64; `mesh_listen` a valid `host:port`; a
duplicate `peers` shard is an error. `enabled = false` (or omitting the whole
section) means standalone — byte-for-byte the current behaviour.

### 3a. Paths and credentials are per-node; only user *names* are shared

The `[cluster]` block is very nearly the whole contract. The edge terminates the
client's crypto and relays plaintext, so **nothing about a relayed session is
resolved on the home**: no path lookup, no route table, no user key. Paths and
credentials are therefore deliberately **per-node** — node A can serve `/tcp`
where node B serves `/a1b2`, with different `password` / `method` / `vless_id`
per user, and relays between them work. Rotating a node's credentials or paths is
a node-local operation that needs no fleet-wide coordination.

What *must* agree across nodes is the **user name** — the identifier parks are
keyed to. The home checks the name the edge attests against the park's owner
before handing the session over, so if `beerloga` denotes different people on two
nodes, resumes between them are refused
(`outline_ss_mesh_relay_rejected_total{reason="unknown_user"}`). That refusal is
the desired behaviour, not something to configure around. The same holds across
proxy protocols: a park authenticated under SS is never handed to a VLESS carrier
or the reverse (`reason="protocol_mismatch"`).

> **This reverses an earlier requirement.** While the home did the decryption,
> paths *and* per-user credentials had to be byte-identical fleet-wide, and any
> asymmetry produced a silent black hole (a relay onto a route holding no key).
> Moving the crypto to the edge removed both the requirement and the failure
> mode; the `no_route` refusal that reported it is gone with the route lookup
> itself. Config-comparison rituals across nodes are no longer needed.

The one thing the server itself checks is that a name *could* cross the mesh at
all. It travels in a `USER` frame whose length is a single byte, capped at 64
bytes, so with `enabled = true` a name that is empty or longer than 64 bytes
**aborts startup** with an explicit error instead of failing at the first relay.

That covers every name that can reach the wire, which is more than the
`[[users]]` ids: the attested name is the *effective accounting label*, so a
`[users.aliases]` key becomes the name on the mesh whenever the client's source
IP falls inside that alias's subnet. Both are checked. Nothing else about
`[[users]]` is compared, and a server with `enabled = false` (or no `[cluster]`
section at all) keeps accepting whatever it accepts today.

After rollout, watch `outline_ss_mesh_relay_rejected_total{reason="unknown_user"}`
instead: a non-zero rate means the park's owner is a different name than the edge
attested — user names disagreeing across the cluster, a genuine security event,
or a user with `[users.aliases]` connecting from a matching subnet (SS-TCP parks
under the base id while the mesh attests the effective label, so that case
mismatches with nothing wrong in the config).

## 4. Network / firewall

- Open the **mesh port (9443/UDP)** between nodes. It is QUIC — **UDP**, not TCP.
- Defense in depth: restrict the mesh port to the peer IPs. The PSK-derived
  mutual pin already rejects outsiders, but an IP filter shrinks the surface.
- The public ingress (WS/H3/XHTTP) is unchanged.

## 5. Client: reaching the cluster

The client is **cluster-agnostic and needs no code changes**, but the way it
addresses the cluster matters. The client caches its resumption id per
**resume scope**; a session only survives an edge switch if the client presents
the *same* resume id to whichever edge it lands on. There are three ways to get
that, in order of preference:

### 5a. Anycast (ideal)

One IP announced by BGP from every node. The client always dials one address;
the network routes it to the nearest/live node. One scope, one resume id,
survival for free. Nothing special in the client config.

### 5b. Single DNS hostname

One hostname with several A/AAAA records. Works **if** the client is configured
with a single uplink URL on that hostname (the scope is the uplink, not the
resolved IP). Fragile if resolution is unreliable.

### 5c. Explicit uplinks with `shared_resume` (no anycast / no reliable DNS)

List every node as its own uplink and mark the group so all uplinks **share one
resume scope** (the group name). Then, whichever edge the client's load balancer
dials, it presents the same resume id, the edge relays the session to its home,
and it survives the switch.

Simple (implicit) group form:

```toml
[[uplinks]]
name = "edge-de"
transport = "ss"                   # or vless; see UPLINK-CONFIGURATIONS.md
# ...url / cipher / password / mode fields for node A...

[[uplinks]]
name = "edge-nl"
transport = "ss"
# ...same for node B...

[load_balancing]
shared_resume = true               # ← all uplinks above share one resume id
```

Named-group form (`[[uplink_group]]`) — set `shared_resume = true` on the group
whose uplinks are the cluster edges.

`shared_resume` defaults to `false`. **Only enable it for a group whose uplinks
are edges of one mesh cluster.** For a group of independent servers, sharing a
resume id across unrelated homes would only ever miss.

The shared scope covers **UDP as well as TCP**: with `shared_resume = true`,
SS-UDP and VLESS-UDP sessions present a group-shared, shard-carrying resume id
and migrate across an edge switch just like TCP (relayed to their home shard).
See the "UDP cross-node migration" note in
[`UPLINK-CONFIGURATIONS.md`](../bins/outline-ws-rust/docs/UPLINK-CONFIGURATIONS.md).

## 6. Rollout order

1. Generate the PSK; prepare the `[cluster]` blocks.
2. Open the mesh port between nodes.
3. Deploy the new binary + config to all nodes (rolling is fine — a node still
   on the old binary just runs standalone for its clients; safe degradation).
4. Point the client at the cluster (§5).
5. Run the checks below.

## 7. Verification

- **Startup:** each node's log shows the mesh listener came up and no config
  validation error. A node that refuses to start with a message about the mesh
  user name bound has a name that is empty or over 64 bytes — a `[[users]]` id or
  a `[users.aliases]` key, and the error names which (§3a) — fix the name, not
  the cluster config.
- **Mesh reachability:** from a test client, dial one node presenting a resume
  id that decodes to a *different* node's shard (this happens by itself when a
  client moves between edges); the session is served and the upstream is not
  reopened. On an unreachable home the edge degrades silently to a fresh session
  (the topology is not revealed).
- **Survival:** start a session (a download in flight), force the client onto a
  different node (§5c makes this deterministic — kill the active uplink), and the
  download continues.
- **Metrics:** on each node's `/metrics` (and the ss-rust Grafana dashboard's
  *Cluster Mesh* row):
  - `outline_ss_mesh_relay_opened_total{outcome="ok"}` rising ⇒ edges are
    relaying cross-shard sessions to their homes; `{outcome="fail"}` rising ⇒ the
    OPEN never reached a home at all (peer down, mesh UDP port blocked, PSK
    mismatch, or this edge at its own outbound relay-stream cap) and the edge is
    degrading to fresh local sessions. `{outcome="refused"}` means the OPEN did
    reach a home that answered nothing usable — normally "no park under that id",
    but also a home at its relay cap and a peer on a wire version the cluster has
    moved past, so expect a burst of it while a rolling upgrade is in flight.
  - **`outline_ss_mesh_relay_outcome_total{outcome,close}` on the home is the
    signal to check first** — it is the direct answer to "is cluster relaying
    working", which byte counters alone never gave (a never-working relay once
    went unnoticed in production for exactly that reason). `{outcome="hit"}`
    non-zero means parked sessions are actually being found and spliced;
    `hit`/`miss` is the useful ratio. An outcome is recorded when the splice
    *ends*, not when it is admitted, so relays in flight are on
    `outline_ss_mesh_relay_active` and the streams this home served reconcile as
    `sum(outcome_total) + outline_ss_mesh_relay_active`. The `close` label says
    how a hit ended: `client_done` (the edge's client was finished, so the
    upstream was half-closed) versus `carrier_ended` (the edge only switched
    carriers, so the session went back into the registry). A `close` stuck at
    `carrier_ended` with no `client_done` at all means edges are not emitting the
    close intent — parks then linger to their TTL instead of being released.
    `{outcome="unusable"}` is the one to treat as a fault: a park *was* found and
    consumed but could not be spliced at all, so it is destroyed and that client's
    session is over. Expect a flat zero; the matching
    `outline_ss_mesh_relay_rejected_total` reason (`park_identity` or
    `park_incomplete`) says which shape it was.
  - `outline_ss_mesh_relay_active` gauges how many relays a home node is serving
    right now (zero on an idle cluster is normal — mesh streams are opened on
    demand, not held). Also watch `outline_ss_orphan_resume_hit_total` on the
    home: it climbs whenever a home reattaches a parked upstream for a client
    that arrived via another edge.
  - `outline_ss_mesh_relay_rejected_total{reason="capacity"}` rising ⇒ a home hit
    its concurrent relayed-session cap and is refusing new relay streams (the
    edges degrade to fresh local sessions). Expect zero; anything sustained means
    the cluster is pushing more concurrent relayed sessions at one home than it
    is sized for.
  - `outline_ss_mesh_relay_rejected_total{reason="no_session"}` is the **ordinary**
    refusal: the home holds no park under the relayed resume id (it expired, or
    this home never minted it) — including a park that was there when the setup
    was acked and gone by the time the USER frame arrived, which is an expiry and
    is counted as one. Its peers count the same event as
    `outline_ss_mesh_relay_opened_total{outcome="refused"}`. A healthy cluster
    shows a steady low rate; only a ratio near 100% of opens means something is
    wrong upstream of it.
  - `outline_ss_mesh_relay_rejected_total{reason="unknown_user"}` rising ⇒ the
    park under that id is owned by a different name than the edge attested (§3a).
    Usually **user names disagree across the cluster**; it can also be a user with
    `[users.aliases]` connecting from a matching subnet, which mismatches on a
    correct config. Expect a flat zero. `reason="protocol_mismatch"` is the same
    class (one name used for an SS user on one node and a VLESS user on another).
  - `outline_ss_mesh_relay_rejected_total{reason="park_shape"}` is expected, not a
    fault: an SS-UDP park under a VLESS resume id (or the reverse) is a shape no
    relay can ask for, so the relay is refused *without consuming the park* and
    that client is served locally. A VLESS command that simply needs a different shape than the park
    holds does not appear here at all — the home names the shape in its ack and
    the edge releases the relay itself, before anything is consumed.
  - The remaining reasons should all sit at a flat zero, and each names a
    different fault: `bad_setup` = the setup itself was unusable (an OPEN whose
    framing and protocol name no park shape, or an acked peer whose `USER` frame
    was malformed or never arrived) — a straggler build or a forged peer;
    `framing_mismatch` = the park under that id turned out not to be the kind the
    acked shape needs, which only the narrow reservation window can still produce
    (the park is put back untouched, so the client keeps its continuity);
    `park_identity` = an SS-UDP park holds no NAT key belonging to the user the
    edge attested, so there is no identity to route its datagrams under.
  - **Cluster traffic** (how much data actually crosses the mesh, not just how
    many relays open): `outline_ss_mesh_bytes_total{role,direction,transport}`
    and `outline_ss_mesh_datagrams_total{role,direction}`. `role="edge"` is the
    traffic this node forwards into the cluster; `role="home"` is what it serves
    for foreign edges — the same relayed session counted from opposite ends. Zero
    on both means no traffic is crossing the mesh (all sessions are local). A
    sustained `direction="up"` with `direction="down"` pinned at zero means
    relayed uplink is reaching a home that answers nothing — check the upstream
    the home is dialling. Panels *Mesh Throughput — edge/home* and *Mesh Datagram
    Rate*.
  - **Gone:** `outline_ss_mesh_throttle_hints_received_total{outcome}`,
    `outline_ss_mesh_control_datagram_errors_total` and the *Mesh Throttle Hints
    & Control Errors* panel. Throttle detection is local to the edge and the mesh
    carries no control datagrams at all any more, in either direction. Drop the
    panel from any dashboard copy you forked.
  - On the **client** (ws-rust dashboard, *Cluster / Soft-switch* row):
    `outline_ws_soft_switch_total{outcome}` — operator soft-switch
    migrations, dominated by `migrated` on a healthy switch; and
    `outline_ws_resume_lookup_total{transport,scope,result}` —
    `scope="group",result="hit"` is a cross-node-capable resume presented to a
    new edge.
- **⚠️ Integrity on real traffic:** the e2e tests cover the data plane but not
  production traffic. Download a large file through the cluster and **verify its
  sha256** against the original (the risk is silent corruption / reordering, like
  the TUN pump). Keep `git revert` ready for the first days.

## 8. Rollback

- Instant: set `enabled = false` in `[cluster]` (or delete the section) and
  restart — the node is standalone again, session ids are plain random, the mesh
  does not listen. Clients keep working (they degrade to a fresh session). On the
  client, drop `shared_resume` (or point at a single node).
- Full: revert the cluster commits and rebuild. But for turning it off,
  `enabled = false` is enough — the code with no `[cluster]` is unchanged.

## 9. Caveats

- **Double-hop RTT:** the edge → home hop between countries adds latency on long
  bulk transfers. The health budget catches *hangs*, not slowness.
- **Throttle detection:** keep it **off** at first. It now runs on the edge,
  which does see the client last mile, but its floors are still heuristics (see
  `CLUSTER.md`).
- **Every session kind now migrates**, VLESS-UDP and VLESS-mux included. A
  command that needs a shape the home does not hold still falls back to a fresh
  local session on that node (safe, just no cross-edge resume for that carrier),
  and the home leaves the park intact for a carrier it can serve.
  `reason="park_incomplete"` is the mux-specific refusal: a parked bundle with no
  sub-connection left is refused whole rather than half-spliced. Expect a flat
  zero.
- **Rolling upgrades cost continuity, not traffic.** There is one mesh wire
  version, and a node on a build the cluster has moved past is refused outright
  at relay setup; that edge then serves its client a fresh local session. Upgrade
  order does not matter, but expect a burst of `{outcome="refused"}` on the edges
  while the fleet is mixed.
