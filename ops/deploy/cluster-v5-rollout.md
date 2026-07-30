# Rollout runbook — edge-terminated cluster relay (v5)

Target commit: `cce11c51`. Supersedes the fleet's current build `3e0d3c481fe1`
(x86_64) / `affa2a1f536b` (aarch64), deployed 2026-07-28.

## What is actually changing, and why the risk is not where it looks

Two independent things ship together:

1. **The mesh relay is rewritten.** Client crypto now terminates on the edge and
   the mesh carries plaintext. **This is dead code on the fleet today** —
   `[cluster] enabled = false` on all three servers, so nothing exercises it
   until step 4. Deploying it changes nothing on its own.
2. **The client's XHTTP carrier learned to signal session close** (`386baa76`).
   This *is* live from the moment a client binary lands: XHTTP packet-up
   sessions now tell the server when they end, so the server parks them instead
   of letting them linger to the idle sweep. XHTTP is the fleet's primary
   carrier, so this is the change that can actually move production behaviour.

This is the *only* way the client binary changes. `bins/outline-ws-rust` itself
has no code diff in this range — just its CHANGELOG. The change arrives through
the shared crate `crates/outline-transport/src/xhttp/{h1,h2,h3,mod}.rs`, which
is compiled into the client. Both binaries still need rebuilding, because the
server links that crate too.

**Neither skew is dangerous, so the ordering is a convenience, not a
constraint.** `x-xhttp-fin` is *not* new server surface: the currently deployed
build already reads it in both `handlers.rs` and `h3.rs`, and its handling is
byte-identical to the new build's (only line numbers moved). What `386baa76`
changed is that the client finally *sends* it — the server half was already
waiting. So:

- new client → old server: the old server parks on FIN exactly as intended.
- old client → new server: no FIN is sent, sessions linger to the idle sweep —
  i.e. today's behaviour.

Servers still go first, for a weaker but real reason: with the cluster off, the
server deploy is a **no-op**, so doing it first establishes that a plain binary
swap is clean. Then step 3 introduces the single live behaviour change in
isolation, and anything that moves afterwards is attributable to it.

**The relay has never once worked in production.** `mesh_bytes_total
{direction="down"}` was zero on every node against megabytes relayed out. There
is no "it used to work" baseline to compare against — step 5 has to prove it
works, and a quiet fleet is not evidence.

## Non-negotiable rules for touching this fleet

Learned the hard way on 2026-07-30, when a `for`-loop restart of all three
servers took the whole fleet down at once — including the operator's own
connectivity, because the Mac tunnels through Beelink whose uplinks *are* those
three servers. There was then nothing left to diagnose or roll back with.

1. **Drain the server before you touch it — from _all four_ clients, not just
   the one you happen to be working on.** A server is shared: `.102`, `.104`,
   cloud3 and cloud4 each pick their own active uplink independently, so moving
   one client off `senko` leaves the other three still on it.

   For every one of the four, move the active uplink away from the target:

   ```bash
   curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"group":"main"}' http://127.0.0.1:9191/control/reselect
   ```

   `reselect` picks a weighted-random *other* uplink, so re-check the result —
   it can land back on the target from a different client. `POST
   /control/activate` pins a specific one when you need determinism. Then
   confirm the server is genuinely idle before restarting it:

   ```bash
   curl -s http://127.0.0.1:9090/metrics | grep '^outline_ss_active_websocket_sessions'
   ```

   Do **not** wait for that gauge to hit zero — it will not. Warm standby keeps
   a couple of connections open to every uplink a client knows about, target
   included, so a fully drained server still shows a small non-zero count. The
   criterion that matters is that **no client has this node as its _active_
   uplink**; the gauge is only there to confirm the count dropped to that
   residual floor rather than staying at load, and that no fresh
   authentications are arriving. *Then* restart. A
   drained server's restart is invisible to users; a loaded one's is an outage,
   and if it is carrying the operator's own path it also removes the means to
   fix it.
2. **One node at a time, with verification between.** `systemctl is-active`,
   `/metrics` 200, `NRestarts` still 0, and WARN volume unchanged. Only then the
   next node.
3. **Never write users through the control API or the dashboard UI — until the
   fix is deployed.** It rewrites `config.toml` and **destroys the other
   users** — observed on nuxt, which went from 137 lines and 9 users to 88 lines
   and 1 user while the service stayed `active` from memory, i.e. a time bomb
   that only fires on the next restart. Edit the config by hand (append via
   `sudo tee -a` from stdin), and diff against a backup before restarting.

   Fixed in `b48525b5` (merged to main 2026-07-30): mutations now patch the one
   named `[[users]]` entry, the write happens before the change goes live, and
   `atomic_write` preserves owner as well as mode. **That build is not on the
   fleet yet** — the four client-side nodes carry `00f1160c34a4`/`d63b4a6dddcb`,
   which predate it, and the three exit servers are older still. Until each node
   runs a binary at or after `b48525b5`, the prohibition stands for that node.
4. **Back up before every config edit**, and check the diff is exactly what you
   intended before any restart. `deploy-binary.sh` auto-rolls back a bad
   *binary*; nothing protects you from a bad *config*.

## Ports, so they are not guessed

| Service | Metrics | Control |
|---|---|---|
| `outline-ss-rust` (servers) | `127.0.0.1:9090` | `127.0.0.1:9190` |
| `outline-ws-rust` (clients) | `127.0.0.1:9091` | `127.0.0.1:9191` |

Both control ports need `Authorization: Bearer <token>` from the config's
`[control] token`. Note the server's metrics port is **9090**, not 9092 — a
wrong port returns an empty body that reads like "no such metrics" rather than
an error.

## Pre-flight — verified 2026-07-30, re-check before starting

| Check | State | Why it matters |
|---|---|---|
| User names identical on senko/nuxt/aeza | ✅ `alice mmv-mac mmv-zflip miklyaev dankrd socks5 cloud beerloga` | The new validator **refuses to start** a clustered node whose user name is empty or >64 bytes. A mismatch here is a boot failure, not a relay failure. |
| UDP 9443 open peer-to-peer | ✅ three `-s <peer>/32 -p udp --dport 9443 -j ACCEPT` rules per server | QUIC is UDP. Without this the mesh silently never connects. |
| `shared_resume = true` on group `main` | ✅ on `.104` and cloud3 | This is what puts one resume id in front of all three uplinks, which is what makes a resume land on a foreign shard. **Without it the relay never fires and step 5 proves nothing.** |
| `[cluster] enabled` | `false` on all three servers | Deliberate. Step 4 flips it. |
| Backups present | 3 per node | `deploy-binary.sh` rotates by mtime and auto-rolls back if `/metrics` does not answer after restart. |

Re-run the first three before starting — they are cheap and each one turns a
silent failure into a loud one.

## Known limitation to accept before starting

User `cloud` carries aliases `cloud3` and `cloud4`, and those are exactly the
nodes that reach these servers. The SS-TCP park is keyed on the **base** id
(`cloud`) while the mesh attestation uses the **effective label**
(`cloud3`/`cloud4`), so **cross-node resume will not work for that user on the
SS path.** It predates this migration and is not fixed here.

Impact is bounded: the fleet's uplinks dial VLESS first (`vless_xhttp_url`) and
VLESS is self-consistent — it parks under the effective label. SS is the
fallback. So expect this to show up as occasional `rejected{reason="unknown_user"}`
on the SS path, not as broken sessions. Do not chase it as a config problem: the
log line was softened precisely because it used to send operators after a
mismatch that does not exist.

## Executed 2026-07-30 — the four client-side nodes

Deployed in the operator's order — `.104`, cloud4, cloud3, `.102` — one node at a
time, both binaries per node, verification between. Every node runs *both* units,
so this was eight binary swaps, not four.

| Node | Arch | ss-rust | ws-rust | Result |
|---|---|---|---|---|
| `.104` | aarch64 | `d63b4a6dddcb` | `f4cbc1b8ac43` | active, NRestarts 0, 6/6 uplinks healthy, tunnel 204 @ 0.198s |
| cloud4 | x86_64 | `00f1160c34a4` | `97975c660e54` | active, NRestarts 0, 10/10 healthy, 204 @ 0.559s |
| cloud3 | x86_64 | `00f1160c34a4` | `97975c660e54` | active, NRestarts 0, 10/10 healthy, 204 @ 0.392s |
| `.102` | x86_64 | `00f1160c34a4` | `97975c660e54` | active, NRestarts 0, 6/6 healthy, 204 @ 0.262s |

Superseded builds: ss `3e0d3c481fe1`/`affa2a1f536b`, ws `1d1d412b4449`/`50317acbfd6a`.

The three exit servers (senko, nuxt, aeza) were **not** touched and still run
`3e0d3c481fe1`. That skew is safe — see the FIN analysis above — but it means the
mesh rewrite is not yet deployed where step 4 would enable it.

### Topology this order exists to respect

The four nodes are mutually dependent, which the original step 2/3 split missed:

- `.104` and `.102` carry uplinks to cloud3/cloud4 (group `beerloga`).
- cloud3 and cloud4 carry uplinks to `ss.beerloga.su:5443` and `:6443`, which are
  the router's port-forwards to **`.104`** (`beerloga-1`) and **`.102`**
  (`beerloga-2`) — group `russia`, `active_passive`, no `shared_resume`, so a
  hard switch.

So restarting `.104` or `.102` breaks a *live* leg of cloud3/cloud4. Before each,
steer the group away with `POST /control/activate`:

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"group":"russia","uplink":"beerloga-2"}' http://127.0.0.1:9191/control/activate
```

Note a restart **resets** the pin to the config default, so re-pin after
restarting cloud3/cloud4 and before restarting `.102`. The `beerloga` group on
`.104`/`.102` needs no drain — it has never been selected (no
`uplink_selected_total` samples at all).

### What could not be drained

`.104` had 27 live sessions and cloud3 had 122 (104 of them UDP-shadowsocks) from
third-party clients (happ/outline) arriving through the port-forwards. Those
cannot be steered — there is no control plane on the client side of them. The
restart drops them and they reconnect on their own. Do not compare the recovered
session count against the pre-restart one: cloud3's 122 had accumulated over two
days of uptime as long-lived UDP NAT entries, so a ten-minute-old table is a
smaller number for reasons that have nothing to do with health.

### Two measurement traps hit during this run

1. **A bare `curl` from `.104`/`.102` does not use the tunnel.** The main-table
   default is `via 198.18.1.1 dev eth0` (the LAN gateway), so an egress probe
   times out with `http=000` while the tunnel is perfectly healthy. Test through
   the client's own SOCKS5 ingress instead — and note the port differs per node
   (`127.0.0.1:1080` on `.104`/`.102`, `[::1]:31080` on cloud3/cloud4, the latter
   with credentials).
2. **A restart makes WARN volume jump for reasons that are not regressions.**
   Every node showed a spike that decayed to zero within ~2 minutes. The sources
   are once-per-boot (`config::load::probe`, `bootstrap`, `TUNSETOFFLOAD rejected
   USO` on `.104`'s vendor 6.1 kernel) plus the teardown of the very sessions the
   restart killed (`failed to accept HTTP/3 request`). Judge the *settled* rate in
   a window that excludes boot, not the first reading.

   Related: cloud3's ss-rust logs `tls handshake failed … DecryptError` from a
   single peer at ~6/min. This is **pre-existing** — the hourly history runs back
   through the previous day at the same magnitude (29 at 14:00 *before* the
   deploy, 26 at 15:00 after). A 10-minute pre-deploy baseline read zero purely
   because the phenomenon is bursty. Do not attribute it to a deploy.

## Step 1 — build

```bash
cargo ss-release-musl-x86_64 && cargo ss-release-musl-aarch64 && cargo ws-release-musl-x86_64 && cargo ws-release-musl-aarch64
```

Record the four hashes; they are the rollback boundary.

## Step 2 — servers, cluster still off

senko is the weakest node (960 MB, one core) and the one that carried the
original incident. Take it first: if the new binary misbehaves under memory
pressure, it shows there first and the blast radius is one exit node.

```bash
ops/deploy/deploy-binary.sh sysadm@senko.beerloga.su outline-ss-rust target/x86_64-unknown-linux-musl/release/outline-ss-rust
```

Then nuxt, then aeza, then the four client-side nodes that also run
`outline-ss-rust` (`.102`, cloud3, cloud4 x86_64; `.104` aarch64).

After each: the script itself asserts `active` + `/metrics` 200 and rolls back
otherwise. Additionally confirm the node did not start rejecting its own users:

```bash
sudo journalctl -u outline-ss-rust --since -3min --no-pager | grep -cE ' (WARN|ERROR) '
```

Expect the same order of magnitude as before the deploy. A jump means stop.

**Do not proceed to step 3 until all seven are green.** Not because the skew is
unsafe — it is not, see above — but because step 2 is meant to be a provable
no-op. If anything is off here, it is not the carrier change, and finding that
out after step 3 costs you the attribution.

## Step 3 — clients

```bash
ops/deploy/deploy-binary.sh mmv@198.18.1.104 outline-ws-rust target/aarch64-unknown-linux-musl/release/outline-ws-rust
```

`.104` first, for the same reason as senko — it is the constrained node, and it
is where the original decrypt storm was measured. Then `.102`, cloud3, cloud4.

This is the step that changes live behaviour (XHTTP close signalling). Watch for
one cycle before continuing:

```bash
sudo journalctl -u outline-ws-rust --since -10min --no-pager | grep -E ' WARN ' | sed -E 's/.*WARN +//' | cut -c1-90 | sort | uniq -c | sort -rn | head
```

The expected shape is *fewer* warnings than before, not more. If
`decryption failed` or `UDP packet is too short` appear at any rate, stop — that
is the original incident's signature and it should be extinct.

## Step 4 — enable the cluster

Only after steps 2 and 3 are quiet. On each of senko, nuxt, aeza:

```bash
sudo cp -p /etc/outline-ss-rust/config.toml /etc/outline-ss-rust/config.toml.bak.pre-cluster-on
```

Then set `enabled = true` inside `[cluster]` only. Use an awk block guard — the
file has two other `^enabled = true` lines (`[session_resumption]`, `[padding]`)
and a blind `sed` hits them:

```bash
sudo sh -c 'awk "/^\[cluster\]/{inb=1} /^\[/ && !/^\[cluster\]/{inb=0} inb && /^enabled[ \t]*=/ && !done {sub(/false/,\"true\"); done=1} {print}" /etc/outline-ss-rust/config.toml.bak.pre-cluster-on > /etc/outline-ss-rust/config.toml'
```

Note `sudo tee < file` does **not** work here — the redirect reads the file
without sudo and the config is `640 outline-ss-rust:outline-ss-rust`.

Diff must show exactly one changed line. Then restart — `/control/apply` does
**not** raise the mesh listener, it is built in `build_services` at startup:

```bash
sudo systemctl restart outline-ss-rust
```

Confirm the listener is actually up, which it has not been since 2026-07-28:

```bash
sudo ss -lnup | grep 9443
```

## Step 5 — prove the relay works

This is the step that matters. Everything before it only proves nothing broke.

A relay fires when a client resumes a session whose shard points at another
node. Do not wait for a natural failover — force one. On a client with
`shared_resume` (`.104` or cloud3):

```bash
curl -s -X POST http://127.0.0.1:9091/control/reselect -d '{"group":"main"}'
```

That performs a soft switch, which migrates live sessions through cluster
resume — exactly the traffic path under test. Then, on the home that owned those
sessions:

```bash
curl -s http://127.0.0.1:9092/metrics | grep -E 'mesh_relay_outcome_total|mesh_bytes_total|mesh_relay_rejected_total'
```

**Success is all three of:**

- `outline_ss_mesh_relay_outcome_total{outcome="hit"}` is non-zero and rising.
- `outline_ss_mesh_bytes_total{direction="down"}` is **non-zero** — this is the
  counter whose fleet-wide zero hid a dead relay for months. If it stays at zero
  while `hit` climbs, stop and investigate; that combination is the original
  symptom.
- No `outline_ss_mesh_relay_rejected_total{reason="unknown_user"}` beyond the
  known `cloud`-alias case above.

Read `hit` as a *completion* counter, not an admission one — it is recorded when
a splice ends. On long-lived sessions it lags, so the served total reconciles as
`sum(outcome_total) + outline_ss_mesh_relay_active`. A zero `hit` with a
non-zero `active` means relays are running, not missing.

Repeat the reselect on a second client so at least two of the three shard pairs
are exercised.

## Step 6 — soak

The scheduled reselect fires nightly at 03:00 (`.104`), 03:05 (`.102`), 03:10
(cloud3), 03:15 (cloud4) and exercises the relay without help. Check the morning
after:

```bash
curl -s 'http://127.0.0.1:8428/api/v1/query?query=increase(outline_ss_mesh_relay_outcome_total[1d])' | jq -r '.data.result[] | "\(.metric.outcome) \(.value[1])"'
```

Watch for a week:

- `rejected{reason="no_session"}` is ordinary — parks expire. A *rising ratio*
  against `hit` is not.
- `rejected{reason="park_shape"}` or `{reason="park_incomplete"}` should be near
  zero; they mean a client is presenting one id across different session kinds.
- Memory on senko. It is the one node where a new long-lived structure would
  show up as pressure first, and it has livelocked on memory before.

## Rollback

Per node, at any step:

```bash
sudo systemctl stop outline-ss-rust && sudo cp -p /usr/local/bin/outline-ss-rust.bak.<newest> /usr/local/bin/outline-ss-rust && sudo systemctl start outline-ss-rust
```

To retreat only from clustering, without touching binaries, restore
`config.toml.bak.pre-cluster-on` and restart. That returns the fleet to exactly
today's state — relay off, everything else new — and is the right first move if
step 5 or 6 looks wrong, because it isolates the mesh from the carrier changes.

Rolling back a *client* below `386baa76` withdraws the XHTTP close signal. This
is safe and needs no matching server rollback: the server never requires the
FIN, it only acts on one when it arrives. The single cost is XHTTP sessions
going back to parking on the idle sweep instead of promptly — which is exactly
where the fleet is today.
