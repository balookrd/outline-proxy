# Extracting the dashboards into `outline-ui` (design)

Date: 2026-08-12
Status: design agreed in chat; awaiting owner review of this document

## Problem

Both binaries ship a web UI that has nothing to do with moving packets. The
client serves an uplink/topology dashboard, the server a user-CRUD dashboard,
and each is welded into the process that carries production traffic. Three
consequences:

- **Web surface on production nodes.** Reaching either dashboard listener is
  equivalent to holding every instance token it is configured with — the code
  says so itself (`auth.rs`: "reaching this listener is equivalent to holding
  all of those tokens"). That authority sits on the same process as the data
  plane.
- **UI changes cost a data-plane restart.** `dashboard.html` is `include_str!`-ed
  into the binary, so a cosmetic UI fix means rebuilding and redeploying the
  binary that carries traffic, and restarting it — which drops every flow on
  that node. This was paid on 2026-08-12 to ship a loss column.
- **The UI cannot move to the cluster** while it is a function of the binary,
  even though everything else observability-shaped (Grafana, VictoriaMetrics)
  already lives in k3s.

The goal is a separate binary that serves both dashboards and nothing else, so
the UI can be deployed in k3s and removed from the nodes.

## Why this is cheap: the dashboards are already aggregators

Neither dashboard reads local state. Both are HTTP clients that fan out to the
control API of each configured instance and render the answers:

- `backend_client.rs` (ws) opens `TcpStream::connect(host, port)` against each
  `control_url`; the local node is just another entry pointing at `127.0.0.1`.
- `spawn_dashboard_server(config, shutdown)` takes only a `DashboardConfig` and
  a shutdown channel. It never touches `UplinkRegistry`, listeners or TUN.

What actually welds them in is the startup path, not the dashboards. Verified
2026-08-12:

- `load_uplinks` refuses a config with no uplink (`bail!("no uplink
  configured")`, `"uplinks is present but empty"`), so a dashboard-only config
  cannot even load today.
- `bootstrap::run_with_config` builds `UplinkRegistry` and spawns the probe,
  warm-standby, cert-check, loss-sampler and reselect loops unconditionally,
  before the dashboard is spawned.

So the dashboards do not need to be *ported* — they need to be *unhooked*.

Coupling to their host binaries is small. The whole of the ws dashboard reaches
into the crate for exactly four things: `crate::config`, `http::constant_time_eq`,
`http::body::read_limited_body`, `http::serve`. The ss dashboard reaches for
`crate::config` and a little of `crate::server`.

## Decisions

**One binary, `bins/outline-ui`, serving both dashboards on one port**, with
`Router::nest("/ws", …)` and `Router::nest("/ss", …)`. One pod, one Service,
one Ingress; `/` is a small index page linking both, not a redirect, because
neither UI is more "default" than the other.

**axum for both.** The ss dashboard is already axum; the ws dashboard is hand-
rolled hyper with a `match` on the path (`mod.rs`, 182 lines). axum's `nest`
gives the prefix requirement for free, and rewriting a path `match` into routes
is mechanical. Going the other way would mean re-implementing axum's extractors
for the ss handlers.

**The dashboards leave the binaries entirely** — no feature flag, no dead code
kept "just in case". A flag would keep the web surface compiled into production
binaries and leave two copies of the UI to drift apart.

**Fresh connection per request, no pool.** The ws client already opens a fresh
TCP+TLS connection per call with `Connection: close`; the ss side keeps a
`control_pool.rs`. The aggregator issues a handful of requests per page view
against at most a dozen instances, so the pool is optimising something that is
not hot, and dropping it removes a stateful component from an otherwise
stateless service. The pool is not carried over.

## Structure

```
bins/outline-ui/
  Cargo.toml
  src/main.rs         config load, one axum listener, shutdown
  src/config.rs       [server] + [[ws.instances]] + [[ss.instances]]
  src/auth.rs         Basic/Bearer guard + WWW-Authenticate, one layer for both trees
  src/backend.rs      HTTP(S) client to instance control APIs (ws backend_client + ss proxy/tls merged)
  src/assets.rs       shared static: outline-logo.png, index page
  src/ws/mod.rs       routes under /ws
  src/ws/api.rs       topology / instances / activate / reselect / set_enabled / apply
  src/ws/dashboard.html
  src/ws/uplinks.html
  src/ws/tests/       api, auth, guard, backend_client — carried over
  src/ss/mod.rs       routes under /ss
  src/ss/api.rs       instances / users CRUD
  src/ss/dashboard.html
  src/ss/tests/       auth, guard, handlers, proxy — carried over
  src/index.html      links to /ws and /ss
```

Both source directories hold 15 files each, and that count matters in two ways.
`outline-logo.png` is a static asset both UIs load, so it moves too and is served
once from `assets.rs` rather than duplicated per prefix. And each directory
already carries a `tests/` subtree — ws covers api, auth, guard and
backend_client; ss covers auth, control_pool, guard, handlers and proxy. Those
tests move with the code they exercise, which is what keeps this a low-risk
change: the behaviour being relocated is already pinned by tests, and a break
during the move surfaces immediately.

The `control_pool` tests are the exception — they are dropped with the pool
itself (see Decisions).

Each unit has one job: `backend.rs` knows how to talk to a control API and
nothing about HTML; `auth.rs` knows credentials and nothing about instances;
`ws/` and `ss/` know their own routes and own their HTML.

## Serving the HTML under a prefix

The UIs address their APIs absolutely (`fetch("/dashboard/api/instances")`).
Under `nest("/ws", …)` those URLs would miss, and worse, the two UIs would
collide on the same `/dashboard/api/*` paths.

Counted 2026-08-12: **17 absolute URLs and 12 `fetch` calls across all three
HTML files** — a bounded edit, not a rewrite.

Mechanism: each HTML gains one line near the top,

```js
const API_BASE = "__BASE__";
```

and every call becomes `fetch(\`${API_BASE}/dashboard/api/…\`)`. The handler
that serves the page replaces `__BASE__` with `/ws` or `/ss` at response time.

`<base href>` was rejected: it silently rewrites every relative URL and anchor
on the page, so it fixes the fetches by changing things nobody audited.

## Configuration

One TOML, its own file — the UI has no reason to read a data-plane config:

```toml
[server]
listen = "0.0.0.0:9000"
# Mandatory here. In the pod the listener is on 0.0.0.0, and reaching it grants
# every instance token below. token_file is preferred so the secret arrives as
# a mounted file rather than a config line.
token_file = "/etc/outline-ui/secrets/ui-token"

[[ws.instances]]
name = "beelink102"
control_url = "http://198.18.1.102:9191"
token_file = "/etc/outline-ui/secrets/ws-beelink102"

[[ss.instances]]
name = "cloud1"
control_url = "https://cloud1.beerloga.su/rust-ss-exporter"
token_file = "/etc/outline-ui/secrets/ss-cloud1"
```

Instance tokens are per-node since the 2026-08-12 rotation, so the UI config
carries eight of them. Each is read from a file so the ConfigMap stays free of
secrets and the Secret can be rotated without editing config.

## What is removed from the binaries

- **ws-rust**: `src/http/dashboard/` (15 files including `tests/` and the logo),
  the `dashboard` feature and its `outline-uplink/cert-check` / `base64`
  dependencies, and `[dashboard]` from the config schema.
- **ss-rust**: `src/server/dashboard/` (15 files including `tests/` and the
  logo) and its wiring in `server/mod.rs`.

`constant_time_eq`, `read_limited_body` and `http::serve` **stay**: the control
plane and the metrics listener use them. Nothing moves to a shared crate —
after the dashboards leave, there is exactly one consumer on each side.

The binaries shrink and stop serving HTML; their control and metrics listeners
are untouched.

## Deployment

Deployment + Service + Ingress in the `monitoring` namespace, alongside Grafana.
Config in a ConfigMap, the nine tokens (one UI + eight instance) in a Secret
mounted at `/etc/outline-ui/secrets/`.

Reachability is already proven — from a pod in the cluster, every control API
answers (verified 2026-08-12: `401` from `198.18.1.102:9191`,
`198.18.1.104:9191` and `https://cloud1.beerloga.su/rust-ws-exporter/…`, which
means the network path is open and only the token is missing). k3s nodes are
`10.10.10.51-53`, the fleet is `198.18.1.x`, and the route between them works.

`[server].token` is mandatory, and a traefik basic-auth middleware can be layered
on top of the Ingress — that pattern already exists in the cluster
(`registry-auth`).

## Testing

The existing `tests/` subtrees move with their code and must stay green — they
already cover auth, guard, the ws api layer, the ws backend client and the ss
proxy and handlers. New tests cover only what the move introduces:

- `auth.rs`: no credentials → 401 with `WWW-Authenticate`; correct Bearer → pass;
  wrong token → 401; comparison is constant-time.
- Prefix serving: a request to `/ws/` returns HTML whose `API_BASE` is `/ws`,
  `/ss/` returns `/ss`, and no `__BASE__` placeholder survives in either
  response.
- Routing: `/ws/dashboard/api/instances` and `/ss/dashboard/api/instances` reach
  different handlers and do not collide.
- `backend.rs`: a control API returning 401 surfaces as an instance-level error
  in the aggregated response rather than failing the whole page.
- After removal, `cargo check -p outline-ws-rust` and `-p outline-ss-rust` pass
  with `--no-default-features` and with defaults, and the full gate from
  `AGENTS.md` (fmt, clippy `-D warnings`, tests) is green.

## Risks and known limits

- **The UI becomes a single point for fleet control.** Today two listeners on
  two nodes each hold their own tokens; afterwards one pod holds all eight. That
  is the point (one place to guard) but it raises the value of that pod — hence
  the mandatory token and the optional ingress auth.
- **Control APIs are exposed on `0.0.0.0` over plain HTTP.** `.102` and `.104`
  listen on `0.0.0.0:9191` / `0.0.0.0:9190` with no firewall, so the UI's bearer
  tokens cross the LAN in clear text. This predates the change and is tracked
  separately; the extraction neither improves nor worsens it.
- **No local UI on a node.** After removal there is no way to open a dashboard
  on a node itself. Diagnosing a node whose network to the cluster is broken
  falls back to `curl` against its control API.
- **Cluster availability becomes UI availability.** If k3s is down, there is no
  dashboard at all. Acceptable: the dashboard is an operator convenience, not a
  data-plane dependency, and Grafana already has the same property.

## Out of scope

Metrics for the UI process itself, TLS inside the pod (the ingress terminates
it), and any change to what the dashboards display. This is a move, not a
redesign: the HTML changes only where the API base prefix requires it.
