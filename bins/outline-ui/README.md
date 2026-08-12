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
| `/ws` | uplinks, topology, carrier loss | client control API (`:9191`) |
| `/ss` | user CRUD | server control API (`:9190`) |
| `/` | index linking both | — |

It holds no state, keeps nothing on disk, and stores no credentials of its own
beyond what its config points at.

## Why it exists

Three problems, all of them consequences of the UI living inside the binaries
that carry traffic:

- **Web surface on production nodes.** Reaching a dashboard listener is
  equivalent to holding every instance token it is configured with — the tokens
  are injected server-side on every proxied request. That authority sat on the
  same process as the data plane.
- **UI changes cost a restart.** `dashboard.html` is `include_str!`-ed into the
  binary, so a cosmetic fix meant rebuilding and redeploying the traffic-carrying
  binary and restarting it — dropping every flow on that node.
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

Then `curl -H 'Authorization: Bearer devtoken' http://127.0.0.1:9500/ws/dashboard`.
Without the header the answer is 401.

## Deployment

Runs in k3s, namespace `monitoring`, behind `ui.k3s.beerloga.su`. Manifests:
[`ops/nanopi-r5c-k3s/apps/monitoring/outline-ui.yaml`](../../ops/nanopi-r5c-k3s/apps/monitoring/outline-ui.yaml),
ingress entry in
[`apps/ingress/ingress-routes.yaml`](../../ops/nanopi-r5c-k3s/apps/ingress/ingress-routes.yaml).

```bash
cargo zigbuild --release -p outline-ui --target aarch64-unknown-linux-musl
docker build --platform linux/arm64 -f bins/outline-ui/Dockerfile \
  -t registry.k3s.beerloga.su/outline-ui:0.1.0 .
docker push registry.k3s.beerloga.su/outline-ui:0.1.0
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl apply -f ops/nanopi-r5c-k3s/apps/monitoring/outline-ui.yaml
kubectl -n monitoring rollout restart deploy/outline-ui
```

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

Both dashboards address their APIs absolutely (`/dashboard/api/...`). Mounted
under `/ws` and `/ss` those URLs would miss, and the two would collide on the
same paths. Each page therefore declares

```js
const API_BASE = "__BASE__";
```

and the handler substitutes `/ws` or `/ss` at response time (`assets::render`,
the same mechanism the dashboards already used for the refresh interval). A test
asserts no placeholder survives into a response.

`<base href>` was rejected: it silently rewrites every relative URL and anchor on
the page, fixing the fetches by changing things nobody audited.

## Current state

The dashboards have been **removed from `outline-ws-rust` and `outline-ss-rust`**;
this service is the only place they run now. The binaries expose only their
metrics and control listeners.

Design and plan:
[spec](../../docs/superpowers/specs/2026-08-12-outline-ui-dashboard-extraction-design.md),
[plan](../../docs/superpowers/plans/2026-08-12-outline-ui.md).
