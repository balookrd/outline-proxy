# Grafana dashboards

Dashboards for the `outline-ws-rust` Prometheus metrics (`/metrics` on `[metrics] listen`). Import the JSON files into Grafana and select the Prometheus data source in the `DS_PROMETHEUS` variable. Both dashboards filter by the `instance`, `job` and `group` variables.

| File | Title | Contents |
|---|---|---|
| `outline-ws-rust-dashboard.json` | `outline-ws-rust` | main operational dashboard. Rows: traffic, latency, health and routing, routing policy (including `bypass_when_down`), mid-session retries, inactive-uplink leak, cluster / soft switch, probes and standby, TUN (offload, downlink congestion), memory and allocator, FDs / threads / transport pressure, carrier writer terminations, carrier loss, RTT freshness, UDP over HTTP/3 datagrams |
| `outline-ws-rust-hang-diagnostics.json` | `outline-ws-rust hang diagnostics` | hang diagnostics: standby pool freshness, H3/QUIC transport stalls, mode-downgrade caps, TUN TCP stall signals, payload-integrity errors, probe vs user-flow correlation; active-uplink switches and failovers are overlaid as annotations |

The multi-instance uplink view with activation controls is not a Grafana dashboard: it is served by the `outline-ui` service, see [`bins/outline-ui/README.md`](../../outline-ui/README.md).
