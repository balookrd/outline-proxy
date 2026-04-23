# Grafana dashboard for `/control/*` uplink UI

This folder now includes:

- `dashboard/outline-ws-uplinks.json` — dashboard focused on control-plane topology/summary/activation.

## Recommended plugin stack

### Required

1. **Infinity datasource** (`yesoreyeram-infinity-datasource`)
   - used for `GET /control/topology` and `GET /control/summary`.

### Recommended for click-to-activate UX

2. **Volkov Labs Business Forms** (or another action/form panel with HTTP POST support)
   - used to send `POST /control/activate` directly from dashboard UI.

### Optional

3. **Prometheus datasource**
   - keep existing metrics dashboard panels from `outline-ws-rust-dashboard.json`.
   - useful if you want to combine probe/session metrics with control-plane state.

---

## Datasource and auth configuration

All control endpoints require bearer auth:

```http
Authorization: Bearer <token>
```

### Infinity datasource setup

- Base URL: your control listener (for example `http://127.0.0.1:9091`)
- For each query in dashboard JSON, request headers include:
  - `Authorization: Bearer ${control_token}`
- Dashboard variable `control_token` is hidden (`hide=2`) but still a dashboard variable.

> Practical recommendation: in production, prefer configuring the bearer token in datasource secure headers instead of dashboard variable when possible.

---

## JSON mapping assumptions

The dashboard assumes backend JSON contracts:

- `GET /control/summary` returns numeric counters (e.g. `groups_total`, `uplinks_total`, `active_tcp`, `active_udp`, ...).
- `GET /control/topology` returns nested object under `instance.groups[].uplinks[]` with fields:
  - `group`, `name`
  - `active_global`, `active_tcp`, `active_udp`
  - health/error fields (`tcp_healthy`, `udp_healthy`, `last_error`, etc.)

### Panel mapping used

- **Top stat cards**:
  - Instances
  - Uplink Groups
  - Uplinks
  - Active Uplinks
  - Inactive Uplinks
- **Main table** (`Uplinks topology table`): flattened rows from `$.instance.groups[*].uplinks[*]`.
- `active_any` is calculated in Grafana transform and mapped with green/red states.

---

## Activation flow (`POST /control/activate`)

Target request:

```http
POST /control/activate
Content-Type: application/json
Authorization: Bearer <token>

{
  "group": "core",
  "uplink": "uplink-02",
  "transport": "tcp"
}
```

### Why plugin is needed

Grafana built-in table links are URL-oriented and are not a reliable generic replacement for authenticated JSON POST actions with request body templating.

So for the expected UX (“click inactive uplink -> activate”), use a dedicated action/form panel plugin:

- Volkov Labs Business Forms (recommended)
- Alternative panels that support HTTP POST with headers + JSON payload

The included dashboard has a side instruction panel (`Activation action`) showing exact URL/body/headers.

---

## Expand/collapse and nested layout notes

Pure built-in Grafana does not provide perfect nested card-tree interaction like a custom web UI.

### What works now (importable baseline)

- Row sections (`Control summary`, `Instance / Group / Uplink topology`)
- Stat cards for counters
- Topology table with active highlighting

### Rich-card layout (optional enhancement)

If you need true card/tree expandable blocks per instance/group/uplink with inline buttons:

- use a custom panel plugin that can render HTML/cards and trigger HTTP actions,
- or use a small external UI embedded via iframe panel (internal-only).

---

## Minimal fallback dashboard (no extra action plugin)

If you cannot install action plugins:

1. Keep stat cards + topology table from this dashboard.
2. Keep `/switch` for manual ops via curl/API client.
3. Optionally add dashboard links that open runbook/API docs.

This still provides observability + operator guidance, but without one-click activation from the panel itself.

---

## Security notes (important)

- `/control` must **not** be public internet-facing.
- Keep control listener on loopback/management network/VPN only.
- Use strict firewall ACLs so only Grafana (or automation host) can reach it.
- Treat bearer token as secret:
  - do not hardcode in git,
  - rotate regularly,
  - prefer Grafana secure datasource secrets where possible.
- Keep metrics and control planes separate (as backend already does).

