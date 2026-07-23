# Cluster deployment runbook

Operational guide for turning two or more standalone `outline-ss-rust` servers
into a mesh cluster where a client session survives switching between edges.
For the design, see [`CLUSTER.md`](CLUSTER.md).

## 0. Prerequisites

- **Two or more server nodes.** A one-node cluster is pointless — there is no
  peer to relay to. Nodes are usually in different countries.
- **All nodes on the same build.** The mesh wire protocol has a version
  (`OPEN_VERSION`); mixing builds can break the mesh handshake or OPEN parsing.
  Roll out one binary everywhere.
- The mesh interconnect uses **QUIC over UDP**. Make sure UDP between the nodes
  is allowed (see §4).

## 1. Topology and shard plan

Every node is simultaneously an **edge** (accepts clients) and a **home** (owns
its own sessions and accepts relays from other edges). Give each a unique
`shard_id` in `0..16`:

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
  validation panic.
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
    relaying cross-shard sessions to their homes; `{outcome="fail"}` rising ⇒ a
    peer is unreachable (peer down, mesh UDP port blocked, or PSK mismatch) and
    the edge is degrading to fresh local sessions.
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
  - **Cluster traffic** (how much data actually crosses the mesh, not just how
    many relays open): `outline_ss_mesh_bytes_total{role,direction,transport}`
    and `outline_ss_mesh_datagrams_total{role,direction}`. `role="edge"` is the
    traffic this node forwards into the cluster; `role="home"` is what it serves
    for foreign edges — the same relayed session counted from opposite ends. Zero
    on both means no traffic is crossing the mesh (all sessions are local). Panels
    *Mesh Throughput — edge/home* and *Mesh Datagram Rate*.
  - `outline_ss_mesh_throttle_hints_sent_total` /
    `outline_ss_mesh_throttle_hints_received_total{outcome}` /
    `outline_ss_mesh_control_datagram_errors_total` track edge→home throttle
    signalling; a steady `received{outcome="dropped"}` or `control_datagram_errors`
    rate points at edge/home config/version skew. Panel *Mesh Throttle Hints &
    Control Errors*.
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
- **Throttle detection:** keep it **off** at first — the home-side detector
  cannot tell the mesh interconnect apart from the client last mile and can fire
  spuriously (see `CLUSTER.md`).
- **UDP carriers** are not relayed yet — those legs fall back to a
  fresh local session on a foreign shard (safe, just no cross-edge resume).
