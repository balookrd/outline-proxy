# outline-ui

Russian version: [README.ru.md](README.ru.md).

Real fleet node names, domains and addresses in this document are replaced with stand-ins: `fleet.example` is the fleet domain; `relay-a`…`relay-d` are the cloud relay nodes; `198.51.100.0/24` is the home network (`.102`, `.104` etc. are the last octet). The mapping lives in the local, uncommitted `FLEET.local.md`.

Web UI for the fleet. Serves the client and server dashboards and nothing
else: no uplinks, no listeners for proxied traffic, no traffic.

Both dashboards are HTTP clients of the instances' control APIs: the browser
talks to `outline-ui`, and `outline-ui` forwards each API call to the
instance's `control_url` with that instance's token.

| Path | Dashboard | Source |
|---|---|---|
| `/ws` | uplinks, routing, groups, settings, topology, carrier loss | client control API (`:9191` on the fleet) |
| `/ss` | users, mesh cluster, server settings | server control API (`:9190` on the fleet) |
| `/` | index linking both | — |

The service keeps no state and writes nothing to disk. The only secrets it
holds are its own token and the instance tokens its config points at.

## Server dashboard (`/ss`)

The `/ss` dashboard shares a single target selector in the toolbar for switching
between configured/discovered clusters (`cluster:<name>`) and individual servers
(`instance:<name>`):

- Users (`/ss`): create, edit, block/unblock, clone and delete access keys
  (Shadowsocks AEAD / VLESS) for a single server or atomically across a cluster
  (with pre-flight `409` duplicate checks, rollback on partial `POST` failure,
  idempotent `DELETE` when absent with `404`, per-node sync badges
  `Synced` / `Partial` / `Drift`, and BLAKE3 secret fingerprints `password_fp` /
  `vless_id_fp`). Includes an **Access links & subscriptions** dialog (`<dialog>`)
  with locally rendered SVG QR codes (Outline `ssconf://`, Happ/Xray `.json`,
  App Config `.toml`, and Share Links) plus one-click subscription regeneration
  (`--prune`).
- Mesh cluster (`/ss/cluster`): manage the `[cluster]` section — local shard ID
  (0..15), mesh listen address, peer reachability address (`mesh_addr`), relay
  budget (ms), cluster PSK rotation (BLAKE3-derived mTLS identity and shard
  obfuscation key), and symmetric peer list. In cluster mode, inspects
  `mesh_health` (`all_reachable`, `psk_match`, `shards_unique`,
  `peers_symmetric`, `restart_pending_nodes`); servers with matching
  `psk_fingerprint` and `cluster.enabled = true` are also auto-discovered when
  no explicit `[[ss.clusters]]` entry covers them.
- Server settings (`/ss/settings`): organized into 5 horizontal tabs
  (`Carriers & Endpoints`, `Network & TLS`, `Resumption & Camouflage`,
  `Subscriptions`, `Tuning & System`) with post-interaction validation, sticky
  save-bar, cluster `drift` badges with per-node diff & align, and a
  post-save banner showing `restart_pending` / subscription regeneration:
  - `[[endpoint]]` CRUD (`path`, `kind`, `padded`), `[shadowsocks].method`,
    `[http_root]` (`auth`, `realm`);
  - per-node & shared TCP/TLS and HTTP/3 settings (`listen`, `cert_path`,
    `key_path`, `[[server.certs]]`, `max_connections_per_ip`, `h3_listen`,
    `h3_cert_path`, `h3_key_path`, `[[server.h3.certs]]`, `h3_alpn`,
    `h3_udp_datagrams`, `h3_initial_mtu`, `h3_mtu_first_probe`, `[outbound]`);
  - `[session_resumption]`, all 11 `[padding]` fields, `[http_fallback]`, and
    `[sni_fallback]` with dynamic backends;
  - `[access_keys]` (`public_host`, `public_scheme`, `url_base`,
    `file_extension`, `write_dir`, `nodes`), which apply immediately without a
    server restart;
  - `tuning_profile` (`small`, `medium`, `large`) plus all 23 `[tuning]`
    override fields and read-only `[metrics]` / `[control]` status.
- UI version: fetched from `GET /api/meta` and shown in the sidebar footer (and
  in the mobile topbar on viewports `<= 900px`).

## Client dashboard (`/ws`)

- Topology (`/ws`): active wires, RTT, carrier packet-loss ratio per leg, manual
  selection of the active uplink.
- Uplinks (`/ws/uplinks`): editor of `[[outline.uplinks]]` entries and their
  fallback wire chains: order, per-wire `ipv4_only` / `ipv6_first` (unset /
  true / false), `shuffle_wires`, `shuffle_timer`, per-uplink `padding`
  override.
- Routing (`/ws/routing`): `[[route]]` rules — create, edit, delete, reorder
  (first match wins); applied without a restart.
- Uplink groups (`/ws/groups`): editor of `[[uplink_group]]` (mode, routing
  scope, reselect, warm standby, cluster resume, scoring/failover/keepalive
  parameters).
- Client settings (`/ws/settings`):
  - `[probe]`: intervals, timeouts, min failures, attempts, max concurrent
    probes, endpoint pre-check, HTTP URLs, TLS targets, DNS/TCP tests.
  - Network: global `ipv4_only`, `ipv6_first`, `direct_ipv6_prefix_interface`,
    carrier UDP socket buffers (`udp_recv_buf_bytes`, `udp_send_buf_bytes`).
  - Ingress: `[socks5]` listen address and credentials (single user or
    `[[socks5.users]]`); `[tun]` device, MTU, max flows, SNI routing, QUIC
    sniffing, IPsec bypass, PMTUD, Linux GSO/GRO/USO offloads; `[tun.tcp]`
    (payload sniffing, direct re-resolve, carrier migration, downlink rate
    caps, buffers).
  - Dial and fingerprint: `[dial]` timeout, TLS fingerprint profile (`off`,
    `stable`, `random`), direct fwmark, prefer public IPv6 source, `[padding]`
    (min/max bytes, cover jitter, throttle reaction).
  - Transport: `[quic]` receive windows and keepalive, `[h2]` window sizes and
    ping keepalive, `[tcp_timeouts]`.
  - **Apply now** applies the changes in place; when a socket or TUN device
    parameter changed, the page reports that a restart is needed instead.

## Moving the UI out of the traffic binaries

The dashboards used to live inside `outline-client` and `outline-server`.
That caused three problems:

- Web surface on production nodes. Reaching a dashboard listener is equivalent
  to holding every instance token it is configured with: the tokens are
  injected server-side on every proxied request. That authority sat in the same
  process as the data plane.
- A UI change cost a restart. The dashboard HTML was `include_str!`-ed into the
  binaries, so a cosmetic fix meant rebuilding and redeploying the
  traffic-carrying binary and restarting it, which drops every flow on that
  node.
- The UI could not move to the k3s cluster, where Grafana and VictoriaMetrics
  run.

The dashboards are now removed from both binaries; they expose only their
metrics and control listeners. Since `0.2.0` the UI is a Svelte SPA instead of
server-rendered HTML.

Design and plan of the extraction:
[spec](../../docs/superpowers/specs/2026-08-12-outline-ui-dashboard-extraction-design.md),
[plan](../../docs/superpowers/plans/2026-08-12-outline-ui.md); the Svelte
rewrite:
[spec](../../docs/superpowers/specs/2026-08-12-outline-ui-svelte-rewrite-design.md),
[plan](../../docs/superpowers/plans/2026-08-12-outline-ui-svelte-rewrite.md).

## Two gates, both before routing

Both gates are middleware layers on the whole `Router` (`main.rs`), so they run
before route matching, and a route added later cannot bypass them. Neither
replaces the other.

Credentials (`auth.rs`) decide who may use the panel. `Bearer <token>` for
scripts, `Basic` for browsers (any username, the password is the token); the
comparison is constant-time. A rejected request gets `401` with
`WWW-Authenticate: Basic realm="outline-ui"`, so a browser shows a login prompt.

Origin policy (`origin.rs`) decides where a request may come from. Credentials
alone do not stop CSRF: a browser attaches cached Basic credentials to a
cross-site request on its own. Three checks:

1. `Host` is one of `allowed_hosts`; otherwise `403`.
2. `Origin`, when present, is this panel's own; otherwise `403`.
3. Any method with a body declares `Content-Type: application/json`; otherwise
   `415`.

An absent `Origin` is allowed on purpose: curl never sends one, and a page
cannot suppress it.

`[server].token` (or `token_file`) is mandatory: without it the binary refuses
to start. In a pod the listener is on `0.0.0.0`, and an unauthenticated one
would hand every configured instance token to whoever reached it.

## Configuration

The config path is `--config` or `OUTLINE_UI_CONFIG`; the default is
`/etc/outline-ui/config.toml`.

```toml
[server]
listen = "0.0.0.0:9000"
# token_file is preferred over an inline token: the secret arrives as a mounted
# file, so the ConfigMap stays free of secrets and rotation needs no config edit.
token_file = "/etc/outline-ui/secrets/ui-token"
# Behind an ingress the browser's Host is the public name, not the pod's listen
# address. Add the Service DNS too, or every check from inside the cluster is
# answered 403 by the origin policy.
allowed_hosts = ["ui.k3s.fleet.example", "outline-ui.monitoring"]
request_timeout_secs = 10   # optional, default 10
refresh_interval_secs = 5   # optional, default 5

[[ws.instances]]
name = "beelink102"
control_url = "http://198.51.100.102:9191"
token_file = "/etc/outline-ui/secrets/ws-beelink102"

[[ss.instances]]
name = "relay-a"
control_url = "https://relay-a.fleet.example/rust-ss-exporter"
token_file = "/etc/outline-ui/secrets/ss-relay-a"
public_host = "relay-a.fleet.example"     # optional, used when generating cluster/subscription hosts
mesh_addr = "198.51.100.11:9443"          # optional, explicit peer mesh address in cluster setup

[[ss.instances]]
name = "relay-b"
control_url = "https://relay-b.fleet.example/rust-ss-exporter"
token_file = "/etc/outline-ui/secrets/ss-relay-b"
public_host = "relay-b.fleet.example"
mesh_addr = "198.51.100.12:9443"

[[ss.clusters]]                           # optional; overrides/supplements psk_fingerprint auto-discovery
name = "cloud"
members = ["relay-a", "relay-b"]
subscription_nodes = ["relay-a.fleet.example", "relay-b.fleet.example"]
```

| Key | Default | What it does |
|---|---|---|
| `[server] listen` | — (required) | Listen address |
| `[server] token` / `token_file` | — (one of them required) | Panel token for `Bearer`/`Basic` |
| `[server] allowed_hosts` | `[]` | Values of `Host` the origin policy accepts |
| `[server] request_timeout_secs` | `10` | Timeout of a call to an instance's control API |
| `[server] refresh_interval_secs` | `5` | Polling interval of the dashboards |
| `[[ws.instances]]` / `[[ss.instances]]` `name`, `control_url` | — (required) | Instance name and base URL of its control API |
| `[[ws.instances]]` / `[[ss.instances]]` `token` / `token_file` | — (one of them required) | Instance control token |
| `[[ss.instances]]` `public_host` | none | Public host advertised for this SS server |
| `[[ss.instances]]` `mesh_addr` | none | Peer mesh `host:port` used by cluster management |
| `[[ss.clusters]]` `name`, `members` | `[]` | Explicit SS cluster name and member instance names (`>= 2` members) |
| `[[ss.clusters]]` `subscription_nodes` | `[]` | Balancer hosts passed to access-keys regeneration for this cluster |

Every token is given either inline as `token` or from disk as `token_file`,
never both. Trailing whitespace in a token file is stripped: secret mounts and
`echo` add a newline, and carrying it into an `Authorization` header turns
every request into a 401.

`control_url` keeps its base path, so an instance behind a reverse proxy
(`https://host/rust-ws-exporter`) is reached under that path.

## Running locally

```bash
mkdir -p /tmp/ui && printf '%s' 'devtoken' > /tmp/ui/token
cat > /tmp/ui/config.toml <<'EOF'
[server]
listen = "127.0.0.1:9500"
token_file = "/tmp/ui/token"
allowed_hosts = ["127.0.0.1:9500"]
EOF
cargo run -p outline-ui -- --config /tmp/ui/config.toml
```

Check it:

```bash
curl -H 'Authorization: Bearer devtoken' http://127.0.0.1:9500/
```

Without the header the answer is 401. With it, `/` serves the SPA shell: the
"assets not embedded" stub unless the binary was built with
`--features embed-assets` against a `pnpm build`-ed `frontend/dist` (see
"Frontend development"). The JSON APIs of both dashboards are reachable the same
way, e.g. `/ws/dashboard/api/instances`.

## Frontend development

The dashboard UI is a Svelte 5 + TypeScript SPA in [`frontend/`](frontend),
built with Vite and Tailwind and verified with `pnpm check` (`svelte-check` +
`tsc`), Vitest component/unit tests, and Playwright Chromium E2E tests against
the built `dist/` bundle under production CSP headers:

```bash
cd bins/outline-ui/frontend
pnpm check                     # svelte-check + tsc-node (including e2e/)
pnpm test                      # Vitest unit & component UI suite (happy-dom)
pnpm build && pnpm test:e2e    # Playwright Chromium E2E against dist/
```

Run two processes side by side:

```bash
# terminal 1: the JSON APIs, listening on :9500 (see "Running locally")
cargo run -p outline-ui -- --config /tmp/ui/config.toml

# terminal 2: the SPA with hot reload
cd bins/outline-ui/frontend
pnpm install
pnpm dev   # http://localhost:5173
```

`vite.config.ts` proxies `/api`, `/ss/dashboard/api`, and `/ws/dashboard/api` to
`127.0.0.1:9500`: the dev server serves the SPA from its own origin, and its API
calls reach the backend process and, through it, the `control_url`s in its
`config.toml`. The requests still need `Bearer`/`Basic` credentials; the dev
server does not bypass `auth.rs`/`origin.rs`.

`pnpm build` compiles the SPA to `frontend/dist/`: hashed file names
(`assetsInlineLimit: 0`, so fonts and images load via `'self'` under
`Content-Security-Policy` rather than `data:` URIs), and `index.html` references
them under the absolute prefix `/ui-assets/` (`base: '/ui-assets/'` in
`vite.config.ts`). The Rust build reads that directory only with the
`embed-assets` Cargo feature on, so plain `cargo build` and `cargo test` do not
need Node, and the Rust CI jobs run without it.

The `frontend` job in `.github/workflows/ci.yml` runs on every pull request and
push to `main`: `pnpm install --frozen-lockfile`, `pnpm check`,
`pnpm exec vitest run`, `pnpm build`, `playwright install --with-deps chromium`,
`pnpm test:e2e`, and then `cargo build -p outline-ui --features embed-assets`
against the fresh `dist`. It is the only CI job that builds the feature.

## Serving two UIs under one port

One `Router` (`main.rs`) answers three kinds of requests, all behind the same
two gates:

- `/ui-assets/*` — hashed JS/CSS/font files (`assets::asset`). Vite emits
  assets under this prefix so they cannot collide with either dashboard's API
  tree.
- `/api/meta` — panel metadata (`{ "version": "<CARGO_PKG_VERSION>" }`, `Cache-Control: no-store`).
- `/ws/dashboard/api/...` and `/ss/dashboard/api/...` — the two dashboards'
  JSON APIs (including `/ss/dashboard/api/clusters` and `/ss/dashboard/api/clusters/{cluster}/...`),
  each `.nest`-ed under `/ws`/`/ss` (`ws::router`/`ss::router`).
- Everything else — `/`, a deep link like `/ws/uplinks`, a typo — serves the
  same `index.html` shell (`assets::spa_index`), including the `.fallback`
  inside the nested `/ws` and `/ss` routers.

Once the shell has loaded,
[`router.svelte.ts`](frontend/src/lib/router.svelte.ts) reads
`location.pathname` and picks the `ws`, `ss` or `landing` view. There is no
server-side templating: the same `index.html` is served for every route.

## Deployment

Runs in k3s, namespace `monitoring`, behind `ui.k3s.fleet.example`. Manifests:
[`ops/nanopi-r5c-k3s/apps/monitoring/outline-ui.yaml`](../../ops/nanopi-r5c-k3s/apps/monitoring/outline-ui.yaml),
ingress entry in
[`apps/ingress/ingress-routes.yaml`](../../ops/nanopi-r5c-k3s/apps/ingress/ingress-routes.yaml).
Cluster nodes are aarch64 (NanoPi R5C), hence the target and `--platform`.

The release binary embeds the built SPA, so build the frontend first and ask the
Rust build for the result explicitly. `<version>` below is `[workspace.package].version`
from the root `Cargo.toml`; set the same tag in the `image:` field of
`outline-ui.yaml` before `kubectl apply`.

```bash
pnpm -C bins/outline-ui/frontend install
pnpm -C bins/outline-ui/frontend build                        # → frontend/dist/
cargo zigbuild --release -p outline-ui --features embed-assets \
  --target aarch64-unknown-linux-musl
# --provenance=false --sbom=false: without them buildx stores the image as an
# OCI image index (arch manifest + attestation manifest), and the weekly
# registry-gc --delete-untagged then sweeps the child manifests (they carry no
# tag) → the image stops pulling on nodes without a local cache.
docker build --provenance=false --sbom=false --platform linux/arm64 \
  -f bins/outline-ui/Dockerfile \
  -t registry.k3s.fleet.example/outline-ui:<version> .
docker push registry.k3s.fleet.example/outline-ui:<version>
export KUBECONFIG=~/.kube/kubeconfig.yaml
kubectl apply -f ops/nanopi-r5c-k3s/apps/monitoring/outline-ui.yaml
kubectl -n monitoring rollout restart deploy/outline-ui
```

Check the result: `kubectl -n monitoring rollout status deploy/outline-ui`,
then open `https://ui.k3s.fleet.example/` — a page with the "assets not embedded"
stub means the binary was built without the frontend.

`Dockerfile` is a single `COPY` of
`target/aarch64-unknown-linux-musl/release/outline-ui` into `scratch`, run as
`65534:65534`, not a multi-stage build: the binary is cross-compiled outside
Docker (`cargo zigbuild`, as for `outline-server`/`outline-client`). Nothing
checks at build time that `frontend/dist` is fresh or that
`--features embed-assets` was passed; skip either step and the image still
builds, but serves the stub at `/`.

The cargo alias `cargo ui-release-musl-aarch64` does not pass
`--features embed-assets`; use the full command above. The default `jemalloc`
feature (`tikv-jemallocator` with `background_thread:true` and
`calloc_madvise_threshold:0`) avoids retaining freed slabs in Zig's musl
`SmpAllocator` when cross-compiling with `cargo zigbuild`; `LG_PAGE=12` for
`aarch64-unknown-linux-musl` is pinned in the root `.cargo/config.toml`.

`ops/deploy/deploy-binary.sh` does not cover this binary: it replaces the binary
of a systemd unit on a fleet node and restarts it, while `outline-ui` ships as a
container image to k3s. The commands above are the whole release procedure.

The config is read once at startup, so a ConfigMap edit takes effect only after
a pod restart.

### Known problems

- The registry is behind basic auth. Without `imagePullSecrets` the pull fails
  with `no basic auth credentials` and the pod sits in `ImagePullBackOff`. The
  `registry-creds` secret has to exist in the `monitoring` namespace.
- `allowed_hosts` must include the Service DNS in addition to the public name.
  Otherwise a request from inside the cluster with a valid token gets 403,
  which looks like an auth failure but comes from the origin policy.
- There is no liveness probe on purpose. Every route is behind the credential
  gate, so an unauthenticated probe would get 401 and the kubelet would restart
  a healthy pod in a loop. A probe needs an unauthenticated health route added
  first.
- The `ui-release-musl-*` aliases in `.cargo/config.toml` do not enable
  `embed-assets`. A binary built with the bare alias serves the "assets not
  embedded" stub; pass `--features embed-assets` after `pnpm build`, as the
  release workflow (`.github/workflows/_ui-release-build.yml`) and the
  procedure above do.
