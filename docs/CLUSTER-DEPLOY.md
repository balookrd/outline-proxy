# Cluster deployment runbook

*Русская версия: [CLUSTER-DEPLOY.ru.md](CLUSTER-DEPLOY.ru.md)*

How to turn two or more standalone `outline-ss-rust` servers into a mesh
cluster in which a client session survives a switch between edges. The design
is in [`CLUSTER.md`](CLUSTER.md).

## 0. Prerequisites

- Two or more server nodes. A one-node cluster has no peer to relay to. Nodes
  are usually in different countries.
- The same build on all nodes. The mesh wire protocol has one version
  (`OPEN_VERSION = 5` in `server/cluster/mesh/frame.rs`); a peer that does not
  speak it is refused at relay setup, before any data. A mixed fleet therefore
  loses session continuity, not traffic: those sessions are served locally on
  the edge instead of resuming on their home. Upgrade order does not matter, but
  do not leave the fleet mixed for long.
- UDP between the nodes. The mesh is QUIC over UDP (see §4).

## 1. Topology and shard plan

Every node is both an edge (accepts clients) and a home (owns its sessions and
accepts relays from other edges). Give each node a unique `shard_id` in
`0..15`:

| Node | shard_id | public ingress (WS/H3/XHTTP) | mesh address (node-to-node) |
| --- | --- | --- | --- |
| A (e.g. DE) | 0 | unchanged | `<A_ip>:9443` |
| B (e.g. NL) | 1 | unchanged | `<B_ip>:9443` |

`<A_ip>` and `<B_ip>` are the IP addresses the nodes reach each other on. Port
9443 is the value used throughout this runbook; there is no default.

## 2. Shared secret

Generate one secret for the whole cluster, identical on every node:

```bash
openssl rand -base64 32
```

Two independent keys are derived from it with BLAKE3 `derive_key`: the
session-id shard-obfuscation key and the mesh-auth keypair. There is no CA and
no certificate to distribute. Store it like any other secret, outside git. A
leaked PSK lets an attacker impersonate a mesh peer in future handshakes;
recorded past traffic stays protected by the ephemeral QUIC keys.

## 3. Server `[cluster]` config

`peers` is the full shard → mesh-address map of all nodes. A node skips its own
entry, so the same `peers` block can be copied to every node.

Node A (`shard_id = 0`):

```toml
[cluster]
enabled = true
shard_id = 0
cluster_psk = "<same base64 on every node>"
mesh_listen = "[::]:9443"          # QUIC (UDP) listener for inbound relays
mesh_relay_budget_ms = 4000        # a relay stalled longer than this is torn down
peers = [
  { shard = 0, addr = "<A_ip>:9443" },   # own shard, skipped
  { shard = 1, addr = "<B_ip>:9443" },
]
```

Node B: the same, with `shard_id = 1`.

Startup validation (`config/loader.rs`, `resolve_cluster`) aborts the start on:
missing `shard_id` or `shard_id >= 16`; `cluster_psk` missing, not valid base64
or empty; `mesh_listen` or a peer `addr` that is not a socket address
(`IP:port`; host names are rejected); a duplicate shard in `peers`. With
`enabled = false`, or without the section, the server is standalone: plain
random session ids, no mesh listener. The key reference table is in
[`CLUSTER.md` § Configuration](CLUSTER.md#configuration).

### 3a. Paths and credentials are per-node; only user names are shared

The edge terminates the client's crypto and relays plaintext, so nothing about
a relayed session is resolved on the home: no path lookup, no route table, no
user key. Paths and credentials are therefore per-node. Node A can serve `/tcp`
where node B serves `/a1b2`, with different `password` / `method` / `vless_id`
per user, and relays between them work. Changing a node's credentials or paths
needs no coordination with other nodes.

The user name must agree across nodes: parks are keyed to it. The home checks
the name the edge attests against the park's owner before handing the session
over. If `carol` denotes different people on two nodes, resumes between them
are refused (`outline_ss_mesh_relay_rejected_total{reason="unknown_user"}`), as
intended. Proxy protocols do not have to agree: a park made under SS is handed
to a VLESS carrier of the same account and the reverse. This keeps sessions alive
on an uplink that re-picks its active wire across a mixed SS/VLESS set
(`shuffle_wires`), and there the user name is the only identity carrier.

> Earlier versions (wire v4 and before, where the home decrypted) required
> paths and per-user credentials to be byte-identical on every node; any
> asymmetry produced a silent black hole, a relay onto a route holding no key.
> That requirement is gone, and so is the `no_route` refusal reason that
> reported it. Comparing configs across nodes is no longer needed.

The server checks one thing itself: that a name can cross the mesh. It travels
in a `USER` frame with a one-byte length, capped at 64 bytes (`MAX_USER_LEN`).
With `enabled = true`, a name that is empty or longer than 64 bytes aborts
startup with an error naming the key.

The check covers every name that can reach the wire: the attested name is the
effective accounting label, so a `[users.aliases]` key becomes the name on the
mesh when the client's source IP falls inside that alias's subnet. Both
`[[users]]` ids and alias names are checked. Nothing else in `[[users]]` is
compared, and a server without `enabled = true` is not checked.

After rollout, watch `outline_ss_mesh_relay_rejected_total{reason="unknown_user"}`.
A non-zero rate means the park's owner is a different name than the edge
attested. Causes: user names disagree across the cluster; a security event; or a
user with `[users.aliases]` connecting from a matching subnet (an SS-TCP park is
keyed on the base id while the mesh attests the effective label, so this case
mismatches with a correct config).

## 4. Network and firewall

- Open the mesh port (9443/udp in this runbook) between nodes. It is QUIC, so
  UDP, not TCP.
- Restrict the mesh port to the peer IPs. The PSK-derived mutual pin already
  rejects hosts without the PSK; the IP filter also keeps them from reaching the
  QUIC handshake.
- The public ingress (WS/H3/XHTTP) does not change.

## 5. Client: reaching the cluster

The client needs no code changes, but how it addresses the cluster decides
whether sessions survive. The client caches its resumption id per resume
scope; a session survives an edge switch only if the client presents the same
resume id to whichever edge it lands on. Three ways to get that, in order of
preference:

### 5a. Anycast

One IP announced over BGP from every node. The client always dials one address
and the network routes it to the nearest live node. One scope, one resume id,
nothing special in the client config.

### 5b. Single DNS hostname

One hostname with several A/AAAA records. Works if the client has a single
uplink URL on that hostname (the scope is the uplink, not the resolved IP).
Breaks when resolution is unreliable.

### 5c. Explicit uplinks with `shared_resume`

For when there is no anycast and no reliable DNS. List every node as its own
uplink and mark the group so all uplinks share one resume scope (the group
name). Whichever edge the client's load balancer dials, it presents the same
resume id, the edge relays the session to its home, and the session survives.

Form without named groups:

```toml
[[outline.uplinks]]
name = "edge-de"
transport = "ss"                   # or vless; see UPLINK-CONFIGURATIONS.md
# ...url / cipher / password / mode fields for node A...

[[outline.uplinks]]
name = "edge-nl"
transport = "ss"
# ...same for node B...

[outline.load_balancing]
shared_resume = true               # all uplinks above share one resume id
```

Top-level `[[uplinks]]` / `[load_balancing]` still load but log a deprecation
warning (`config/compat.rs`). With named groups (`[[uplink_group]]`), set
`shared_resume = true` on the group whose uplinks are the cluster edges.

`shared_resume` defaults to `false`. Enable it only for a group whose uplinks
are edges of one mesh cluster. In a group of independent servers a shared
resume id would always miss on the other homes.

The shared scope covers UDP as well as TCP: with `shared_resume = true`, SS-UDP
and VLESS-UDP sessions present a group-shared, shard-carrying resume id and
migrate across an edge switch like TCP (relayed to their home shard). See
"UDP cross-node migration" in
[`UPLINK-CONFIGURATIONS.md`](../bins/outline-ws-rust/docs/UPLINK-CONFIGURATIONS.md).

## 6. Rollout order

1. Generate the PSK and prepare the `[cluster]` blocks.
2. Open the mesh port between nodes.
3. Deploy the new binary and config to all nodes, one node at a time. A node
   still on an old binary serves its clients standalone; its relays are refused
   and the client gets a fresh local session.
4. Point the client at the cluster (§5).
5. Run the checks in §7.

## 7. Verification

- Startup: the service is `active` and the log has no config validation error.
  Check the mesh listener on each node:

  ```bash
  sudo ss -lunp | grep 9443
  ```

  A node that refuses to start with an error about the mesh user name limit has
  a name that is empty or longer than 64 bytes, either a `[[users]]` id or a
  `[users.aliases]` key; the error names which (§3a). Fix the name, not the
  cluster config.
- Mesh reachability: from a test client, dial one node with a resume id that
  decodes to a different node's shard (this happens on its own when a client
  moves between edges). The session is served and the upstream is not reopened.
  If the home is unreachable, the edge gives the client a fresh session without
  revealing the topology.
- Survival: start a session with a download in flight, force the client onto a
  different node (with §5c, disable or kill the active uplink), and check that
  the download continues.
- Metrics on each node's `/metrics` (and in the ss-rust Grafana dashboard, row
  Cluster Mesh):
  - `outline_ss_mesh_relay_opened_total{outcome="ok"}` rising: edges relay
    cross-shard sessions to their homes. `{outcome="fail"}` rising: the OPEN
    never reached a home (no peer for that shard, dial failed: peer down, mesh
    UDP port blocked or PSK mismatch, or this edge at its outbound relay-stream
    cap) and the edge falls back to fresh local sessions. `{outcome="refused"}`:
    the OPEN reached a home that answered nothing usable. Usually "no park under
    that id", but also a home at its relay cap or a peer on a retired wire
    version, so expect a burst during a rolling upgrade.
  - `outline_ss_mesh_relay_outcome_total{outcome,close}` on the home is the
    first signal to check: it answers "does cluster relaying work", which byte
    counters alone never did (a relay that never worked once went unnoticed in
    production for that reason). Non-zero `{outcome="hit"}` means parked
    sessions are found and spliced; `hit`/`miss` is the useful ratio. An
    outcome is recorded when the splice ends, not when it is admitted, so
    relays in flight are on `outline_ss_mesh_relay_active`, and the streams this
    home served reconcile as `sum(outcome_total) + outline_ss_mesh_relay_active`.
    The `close` label says how a hit ended: `client_done` (the edge's client
    finished, so the upstream was half-closed) or `carrier_ended` (the edge only
    switched carriers, so the session went back into the registry). `close`
    always `carrier_ended` with no `client_done` at all means edges do not send
    the close intent, and parks linger to their TTL. `{outcome="unusable"}` is a
    fault: a park was found and consumed but could not be spliced, so it is
    destroyed and that client's session is over. Expected value is zero; the
    matching `outline_ss_mesh_relay_rejected_total` reason (`park_identity` or
    `park_incomplete`) names the shape. `{outcome="error"}` means setup failed
    before any park was resolved.
  - `outline_ss_mesh_relay_active`: relays this home serves right now. Zero on
    an idle cluster is normal; mesh streams are opened on demand. Also watch
    `outline_ss_orphan_resume_hit_total` on the home: it grows whenever the home
    reattaches a parked upstream for a client that arrived through another edge.
  - `outline_ss_mesh_relay_rejected_total{reason="capacity"}` rising: a home hit
    its cap of 4096 concurrent relayed sessions and refuses new relay streams;
    the edges fall back to fresh local sessions. Expected value is zero; a
    sustained rate means more concurrent relayed sessions go to one home than
    the cap allows.
  - `outline_ss_mesh_relay_rejected_total{reason="no_session"}` is the ordinary
    refusal: the home holds no park under the relayed resume id (it expired, or
    this home never minted it), including a park that existed at the ack and
    expired before the `USER` frame arrived. Edges count the same event as
    `outline_ss_mesh_relay_opened_total{outcome="refused"}`. A healthy cluster
    shows a steady low rate; a ratio near 100% of opens means a problem upstream
    of the relay.
  - `outline_ss_mesh_relay_rejected_total{reason="unknown_user"}` rising: the
    park under that id is owned by a different name than the edge attested
    (§3a). Usually user names disagree across the cluster; it can also be a user
    with `[users.aliases]` connecting from a matching subnet, which mismatches
    with a correct config. Expected value is zero.
    `reason="protocol_mismatch"` should also stay at zero, but means something
    else: a byte-stream park crosses protocols freely, so what remains under this
    reason is a datagram or mux park claimed under the other protocol. The shape
    probe makes that unreachable, so a non-zero value means a forged peer or the
    narrow reservation window.
  - `outline_ss_orphan_resume_cross_protocol_total{parked,resumed}` counts the
    crossings that did happen, on the node owning the park. Non-zero is normal
    wherever an uplink rotates its active wire across a mixed SS/VLESS set; the
    series shows how much continuity depends on it.
  - `outline_ss_mesh_relay_rejected_total{reason="park_shape"}` is expected, not
    a fault: an SS-UDP park under a VLESS resume id (or the reverse) is a shape
    no relay can ask for, so the relay is refused without consuming the park and
    the client is served locally. A VLESS command that needs a different shape
    than the park holds does not appear here: the home names the shape in its ack
    and the edge releases the relay before anything is consumed.
  - The remaining reasons should stay at zero, each a different fault:
    `bad_setup`: the setup was unusable (an OPEN whose framing and protocol name
    no park shape, or an acked peer whose `USER` frame was malformed or did not
    arrive within 5 s), meaning an old build or a forged peer;
    `framing_mismatch`: the park under that id is not the kind the acked shape
    needs, which only the narrow reservation window can produce (the park is put
    back untouched and the client keeps its continuity); `park_identity`: an
    SS-UDP park holds no NAT key of the user the edge attested, so there is no
    identity to route its datagrams under.
  - Mesh traffic (how much data crosses the mesh, not how many relays open):
    `outline_ss_mesh_bytes_total{role,direction,transport}` and
    `outline_ss_mesh_datagrams_total{role,direction}`. `role="edge"` is the
    traffic this node sends into the cluster; `role="home"` is what it serves for
    foreign edges, the same relayed session counted from the other end. Zero on
    both means no traffic crosses the mesh (all sessions are local). Sustained
    `direction="up"` with `direction="down"` at zero means relayed uplink
    reaches a home that answers nothing; check the upstream the home dials.
    Panels: Mesh Throughput — edge (into cluster), Mesh Throughput — home (from
    cluster), Mesh Datagram Rate (SS-UDP).
  - Removed: `outline_ss_mesh_throttle_hints_received_total{outcome}`,
    `outline_ss_mesh_control_datagram_errors_total` and the Mesh Throttle Hints
    & Control Errors panel. Throttle detection is local to the edge, and the mesh
    carries no control datagrams. Remove the panel from any forked dashboard.
  - On the client (ws-rust dashboard, row Cluster / Soft-switch):
    `outline_ws_soft_switch_total{outcome}` counts operator soft-switch
    migrations, mostly `migrated` on a healthy switch;
    `outline_ws_resume_lookup_total{transport,scope,result}` with
    `scope="group",result="hit"` is a cross-node resume presented to a new edge.
- Integrity on production traffic: the tests cover the data plane, not
  production traffic. Download a large file through the cluster and compare its
  sha256 with the original; the risk is silent corruption or reordering, as in
  the TUN pump. Keep `git revert` ready for the first days.

## 8. Rollback

- Turn the cluster off: set `enabled = false` in `[cluster]` (or delete the
  section) and restart. The node is standalone again: plain random session ids,
  no mesh listener. Clients keep working and get fresh sessions. On the client,
  remove `shared_resume` or point it at a single node.
- Remove the code: revert the cluster commits and rebuild. Not needed to turn
  the cluster off; a server without `[cluster] enabled = true` does not run
  any mesh code path.

## 9. Known limitations

- Double-hop RTT: the edge → home hop between countries adds latency to long
  bulk transfers. The health budget catches hangs, not slowness.
- Throttle detection: keep `[padding] throttle_detect_enabled = false` at first.
  It runs on the edge, which sees the client last mile, but its thresholds are
  heuristics (see `CLUSTER.md`).
- Every session kind migrates, VLESS-UDP and VLESS-mux included. A command that
  needs a shape the home does not hold falls back to a fresh local session on
  that node (no cross-edge resume for that carrier), and the home leaves the
  park intact for a carrier that can use it. `reason="park_incomplete"` is the
  mux refusal: a parked bundle with no sub-connection left is refused whole
  rather than half-spliced. Expected value is zero.
- Rolling upgrades cost continuity, not traffic. There is one mesh wire
  version, and a node on an older build is refused at relay setup; that edge
  serves its client a fresh local session. Upgrade order does not matter, but
  expect a burst of `outline_ss_mesh_relay_opened_total{outcome="refused"}` on
  the edges while the fleet is mixed.
