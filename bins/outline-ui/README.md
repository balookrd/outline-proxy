# outline-ui

Aggregating web UI for the fleet. Serves both dashboards and nothing else — no
uplinks, no listeners, no traffic.

Russian version: [README.ru.md](README.ru.md).

## What it is

The client and server dashboards were never really part of the data plane: both
are HTTP clients that fan out to each instance's control API and render the
answers. This binary is those two dashboards with the data plane unhooked.

| Path | Dashboard | Source |
|---|---|---|
| `/ws` | uplinks, routing, topology, carrier loss | client control API (`:9191`) |
| `/ss` | user CRUD | server control API (`:9190`) |
| `/` | index linking both | — |

It holds no state, keeps nothing on disk, and stores no credentials of its own
beyond what its config points at.

The `/ws` dashboard's Uplink groups tab (`/ws/groups`) — CRUD editor for `[[uplink_group]]` policy
(mode, routing scope, reselect, warm standby, cluster resume, and the advanced
scoring/failover/keepalive knobs). Staged → **Apply now**, hot-applied without
a node restart. A group is created empty; add its uplinks in the Uplinks tab.
Delete is only allowed for a group with no uplinks.

The `/ws` dashboard's Routing tab edits an instance's `[[route]]` policy
rules — create, update, delete, and reorder, since first-match-wins means the
order of rules is itself part of what they do — and hot-applies them through
the same "Apply now" button the Uplinks tab uses.

## Why it exists

Three problems, all of them consequences of the UI living inside the binaries
that carry traffic:

- **Web surface on production nodes.** Reaching a dashboard listener is
  equivalent to holding every instance token it is configured with — the tokens
  are injected server-side on every proxied request. That authority sat on the
  same process as the data plane.
- **UI changes cost a restart.** The dashboard HTML used to be `include_str!`-ed
  straight into `outline-ws-rust`/`outline-ss-rust`, so a cosmetic fix meant
  rebuilding and redeploying the traffic-carrying binary and restarting it —
  dropping every flow on that node.
- **The UI could not move to the cluster**, where Grafana and VictoriaMetrics
  already live.

## Two gates, both before routing

Neither subsumes the other, and both run ahead of route matching so a route
added later cannot sit outside a check by simply not asking for it.

**Credentials** (`auth.rs`) — *who* may drive the panel. `Bearer` for scripted
clients, `Basic` for browsers (any username, the password carries the token),
compared in constant time. `WWW-Authenticate` is sent so a browser shows a login
prompt instead of a bare 401.

**Origin policy** (`origin.rs`) — *from where* a request may come. Credentials
alone do not stop CSRF: a browser attaches cached Basic credentials to a
cross-site request on its own. Three checks — `Host` names this listener,
`Origin` (when present) is this panel's own, and any body-bearing method declares
`Content-Type: application/json`. An absent `Origin` is allowed on purpose: curl
never sends one, and a page cannot suppress it.

`[server].token` is **mandatory**. In a pod the listener is on `0.0.0.0`, and an
unauthenticated one would hand the whole fleet to whoever reached it.

## Configuration

```toml
[server]
listen = "0.0.0.0:9000"
# token_file is preferred over an inline token: the secret arrives as a mounted
# file, so the ConfigMap stays free of secrets and rotation needs no config edit.
token_file = "/etc/outline-ui/secrets/ui-token"
# Behind an ingress the browser's Host is the public name, not the pod's listen
# address. Add the Service DNS too, or every check from inside the cluster is
# answered 403 by the origin policy.
allowed_hosts = ["ui.k3s.beerloga.su", "outline-ui.monitoring"]
request_timeout_secs = 10   # optional, default 10
refresh_interval_secs = 5   # optional, default 5

[[ws.instances]]
name = "beelink102"
control_url = "http://198.18.1.102:9191"
token_file = "/etc/outline-ui/secrets/ws-beelink102"

[[ss.instances]]
name = "cloud1"
control_url = "https://cloud1.beerloga.su/rust-ss-exporter"
token_file = "/etc/outline-ui/secrets/ss-cloud1"
```

Every token may be given inline as `token` or from disk as `token_file`, never
both. A trailing newline in a token file is stripped — secret mounts and `echo`
add one, and carrying it into an `Authorization` header turns every request into
an unexplainable 401.

`control_url` keeps its base path, so an instance behind a reverse proxy
(`https://host/rust-ws-exporter`) is reached correctly.

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

Then `curl -H 'Authorization: Bearer devtoken' http://127.0.0.1:9500/`. Without
the header the answer is 401; with it, `/` serves the SPA shell — the "assets
not embedded" stub unless the binary was built with `--features embed-assets`
against a `pnpm build`-ed `frontend/dist` (see "Frontend development" below).
The JSON APIs both dashboards use are reachable the same way, e.g.
`/ws/dashboard/api/instances`.

For live-reloading UI development against this backend, see "Frontend
development" below.

## Frontend development

The dashboard UI is a Svelte 5 + TypeScript SPA in [`frontend/`](frontend),
built with Vite and Tailwind and tested with `svelte-check`/Vitest.
`frontend/README.md` is the generic Vite/Svelte template boilerplate;
everything below is specific to how it plugs into this binary.

Two processes, run side by side:

```bash
# terminal 1: the JSON APIs — "Running locally" above, listens on :9500
cargo run -p outline-ui -- --config /tmp/ui/config.toml

# terminal 2: the SPA with hot reload
cd bins/outline-ui/frontend
pnpm install
pnpm dev   # http://localhost:5173
```

`vite.config.ts` proxies `/ss/dashboard/api` and `/ws/dashboard/api` to
`127.0.0.1:9500`, so the dev server's own origin serves the SPA while its API
calls reach the real backend process and, through it, whatever
`control_url`s its `config.toml` points at. Requests still need the
`Bearer`/`Basic` credentials the two gates require — the dev server does not
exempt itself from `auth.rs`/`origin.rs`.

`pnpm build` compiles the SPA to `frontend/dist/`: hashed `/ui-assets/*`
filenames, `index.html` referencing them by absolute path
(`vite.config.ts`'s `base: '/ui-assets/'`). Nothing in the Rust build reads
that directory unless the `embed-assets` Cargo feature is on — plain
`cargo build`/`cargo test` never need Node installed, which is why the
default Rust CI jobs stay node-less. See "Deployment" below for the release
build that turns the feature on.

`.github/workflows/ci.yml`'s `frontend` job runs `svelte-check`, `vitest
run`, and `pnpm build` on every PR and push to `main` — the frontend's own
gate, independent of the Rust jobs.

## Deployment

Runs in k3s, namespace `monitoring`, behind `ui.k3s.beerloga.su`. Manifests:
[`ops/nanopi-r5c-k3s/apps/monitoring/outline-ui.yaml`](../../ops/nanopi-r5c-k3s/apps/monitoring/outline-ui.yaml),
ingress entry in
[`apps/ingress/ingress-routes.yaml`](../../ops/nanopi-r5c-k3s/apps/ingress/ingress-routes.yaml).

The release binary embeds the built SPA, so the frontend is built *first*,
and the Rust build has to ask for the result explicitly — plain `cargo
build` never embeds it:

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
  -t registry.k3s.beerloga.su/outline-ui:0.2.0 .
docker push registry.k3s.beerloga.su/outline-ui:0.2.0
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl apply -f ops/nanopi-r5c-k3s/apps/monitoring/outline-ui.yaml
kubectl -n monitoring rollout restart deploy/outline-ui
```

`Dockerfile` is a plain `COPY` into `scratch`, not a multi-stage build: the
binary is cross-compiled outside Docker (`cargo zigbuild`, same as
`outline-ss-rust`/`outline-ws-rust`), and Docker's only job is packaging the
binary that build already produced — assets and all. Nothing checks at build
time that `frontend/dist` is fresh or that `--features embed-assets` was
passed; skip either step and the image still builds, it just serves the
"assets not embedded" stub at `/` instead of the dashboard.

`ops/deploy/deploy-binary.sh` does not cover this binary — it pushes to a
systemd unit on a fleet node (`outline-ws-rust`/`outline-ss-rust` only) and
restarts it in place, which doesn't match how `outline-ui` ships: no systemd
unit, no fleet node, a container image rolled out to k3s instead. The five
commands above are the whole release procedure.

Cluster nodes are aarch64 (NanoPi R5C), hence the target and `--platform`.

The config is read once at startup, so a ConfigMap edit needs a pod restart to
take effect.

### Traps met while deploying

- **The registry is behind basic auth.** Without `imagePullSecrets` the pull
  fails with `no basic auth credentials` and the pod sits in `ImagePullBackOff`.
  The `registry-creds` secret has to exist in this namespace.
- **`allowed_hosts` must include the Service DNS**, not just the public name, or
  a request from inside the cluster is answered 403 with a valid token — which
  reads as an auth failure and is not one.
- **There is no liveness probe on purpose.** Every route is behind the credential
  gate, so an unauthenticated probe would get a 401 and the kubelet would restart
  a healthy pod in a loop. A probe needs an unauthenticated health route added
  deliberately first.

## Serving two UIs under one port

One binary answers three kinds of request, all through the same `Router`
(`main.rs`), gated identically before any of them is matched:

- `/ui-assets/*` — hashed JS/CSS/font files (`assets::asset`), the prefix
  Vite is configured to emit (`base: '/ui-assets/'` in `vite.config.ts`)
  precisely so it cannot collide with either dashboard's API tree.
- `/ws/dashboard/api/...` and `/ss/dashboard/api/...` — the two dashboards'
  JSON APIs, unchanged in shape, each `.nest`-ed under `/ws`/`/ss`
  (`ws::router`/`ss::router`).
- Everything else — `/`, a deep link like `/ws/uplinks`, a typo — serves the
  same `index.html` shell (`assets::spa_index`), including the `.fallback`
  inside the `/ws` and `/ss` nested routers themselves.

Once that shell has loaded,
[`router.svelte.ts`](frontend/src/lib/router.svelte.ts) reads
`location.pathname` client-side and picks the `ws`/`ss`/`landing` view — there
is no more server-side templating to keep in sync with it: the same
`index.html` is served for every route, and the two dashboards no longer have
pages of their own to collide over.

## Current state

The dashboards have been **removed from `outline-ws-rust` and `outline-ss-rust`**;
this service is the only place they run now, and — as of `0.2.0` — as a
Svelte SPA rather than server-rendered HTML. The binaries expose only their
metrics and control listeners.

Design and plan — extraction from the traffic binaries:
[spec](../../docs/superpowers/specs/2026-08-12-outline-ui-dashboard-extraction-design.md),
[plan](../../docs/superpowers/plans/2026-08-12-outline-ui.md); the Svelte
rewrite:
[spec](../../docs/superpowers/specs/2026-08-12-outline-ui-svelte-rewrite-design.md),
[plan](../../docs/superpowers/plans/2026-08-12-outline-ui-svelte-rewrite.md).
