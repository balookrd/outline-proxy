# Grafana dashboards

Packaged dashboards:

- `outline-ws-rust-dashboard.json` - main operational dashboard
- `outline-ws-rust-hang-diagnostics.json` - situational hang diagnostics: standby pool freshness, H3/QUIC transport stalls, mode-downgrade lockups, TUN TCP stall signals; uplink-switch and failover events overlaid as annotations

The experimental uplinks/control-plane dashboard was removed. Use the built-in `/dashboard` UI for multi-instance uplink activation.
