import type { GroupConfig } from './types';

export const MODES = ['active_active', 'active_passive'] as const;
export const SCOPES = ['per_flow', 'per_uplink', 'per_client', 'global'] as const;

export type ReselectMode = 'none' | 'at' | 'interval';
export type FieldKind = 'int' | 'float' | 'bool' | 'enum';

// Every `[[uplink_group]]` policy field NOT given a dedicated key control above
// (mode/routing_scope/shared_resume/warm_standby/reselect_*). `kind` drives
// both the input widget (Task 9) and the parse in buildGroupPayload/
// fieldsFromConfig — one list is the single source. `section` groups them into
// collapsible <details> blocks. Field names/kinds mirror
// bins/outline-ws-rust/src/config/schema.rs UplinkGroupSection.
export interface AdvancedField {
  key: string;
  label: string;
  kind: FieldKind;
  section: string;
  /// For kind==='enum'.
  options?: readonly string[];
}
export const ADVANCED_FIELDS: readonly AdvancedField[] = [
  // Failover / stickiness
  { key: 'sticky_ttl_secs', label: 'Sticky TTL (s)', kind: 'int', section: 'Failover' },
  { key: 'hysteresis_ms', label: 'Hysteresis (ms)', kind: 'int', section: 'Failover' },
  { key: 'failure_cooldown_secs', label: 'Failure cooldown (s)', kind: 'int', section: 'Failover' },
  { key: 'tcp_chunk0_failover_timeout_secs', label: 'TCP chunk-0 failover timeout (s)', kind: 'int', section: 'Failover' },
  { key: 'mode_downgrade_secs', label: 'Mode downgrade cooldown (s)', kind: 'int', section: 'Failover' },
  { key: 'carrier_degraded_failover_secs', label: 'Carrier-degraded failover (s)', kind: 'int', section: 'Failover' },
  { key: 'loss_failover_ratio', label: 'Loss failover ratio [0,1]', kind: 'float', section: 'Failover' },
  { key: 'loss_failover_secs', label: 'Loss failover hold (s)', kind: 'int', section: 'Failover' },
  { key: 'runtime_failure_window_secs', label: 'Runtime failure window (s)', kind: 'int', section: 'Failover' },
  { key: 'chunk0_failure_window_secs', label: 'Chunk-0 failure window (s)', kind: 'int', section: 'Failover' },
  { key: 'global_udp_strict_health', label: 'Global UDP strict health', kind: 'bool', section: 'Failover' },
  { key: 'auto_failback', label: 'Auto failback', kind: 'bool', section: 'Failover' },
  { key: 'health_weighted_selection', label: 'Health-weighted selection', kind: 'bool', section: 'Failover' },
  { key: 'health_weight_floor', label: 'Health weight floor [0,1]', kind: 'float', section: 'Failover' },
  { key: 'tun_wire_dial', label: 'TUN walks fallback wires', kind: 'bool', section: 'Failover' },
  // Scoring (RTT / loss)
  { key: 'rtt_ewma_alpha', label: 'RTT EWMA alpha', kind: 'float', section: 'Scoring' },
  { key: 'rtt_ewma_halflife_secs', label: 'RTT EWMA half-life (s)', kind: 'int', section: 'Scoring' },
  { key: 'loss_latency_penalty_k', label: 'Loss latency penalty k', kind: 'float', section: 'Scoring' },
  { key: 'loss_latency_inflation_max', label: 'Loss latency inflation max', kind: 'float', section: 'Scoring' },
  { key: 'loss_sample_interval_secs', label: 'Loss sample interval (s)', kind: 'int', section: 'Scoring' },
  { key: 'loss_sample_min_packets', label: 'Loss sample min packets', kind: 'int', section: 'Scoring' },
  { key: 'loss_ewma_alpha', label: 'Loss EWMA alpha', kind: 'float', section: 'Scoring' },
  { key: 'failure_penalty_ms', label: 'Failure penalty (ms)', kind: 'int', section: 'Scoring' },
  { key: 'failure_penalty_max_ms', label: 'Failure penalty max (ms)', kind: 'int', section: 'Scoring' },
  { key: 'failure_penalty_halflife_secs', label: 'Failure penalty half-life (s)', kind: 'int', section: 'Scoring' },
  // Keepalive
  { key: 'udp_ws_keepalive_secs', label: 'UDP WS keepalive (s)', kind: 'int', section: 'Keepalive' },
  { key: 'tcp_ws_keepalive_secs', label: 'TCP WS keepalive (s)', kind: 'int', section: 'Keepalive' },
  { key: 'tcp_ws_standby_keepalive_secs', label: 'TCP WS standby keepalive (s)', kind: 'int', section: 'Keepalive' },
  { key: 'tcp_active_keepalive_secs', label: 'TCP active keepalive (s)', kind: 'int', section: 'Keepalive' },
  { key: 'warm_probe_keepalive_secs', label: 'Warm probe keepalive (s)', kind: 'int', section: 'Keepalive' },
  // VLESS UDP mux
  { key: 'vless_udp_max_sessions', label: 'VLESS UDP max sessions', kind: 'int', section: 'VLESS UDP' },
  { key: 'vless_udp_session_idle_secs', label: 'VLESS UDP session idle (s)', kind: 'int', section: 'VLESS UDP' },
  { key: 'vless_udp_janitor_interval_secs', label: 'VLESS UDP janitor interval (s)', kind: 'int', section: 'VLESS UDP' },
  // TCP mid-session retry
  { key: 'tcp_mid_session_retry_buffer_bytes', label: 'Mid-session retry buffer (bytes)', kind: 'int', section: 'TCP retry' },
  { key: 'tcp_mid_session_retry_budget', label: 'Mid-session retry budget', kind: 'int', section: 'TCP retry' },
  { key: 'tcp_mid_session_retry_overflow_policy', label: 'Overflow policy', kind: 'enum', options: ['soft', 'hard'], section: 'TCP retry' },
  { key: 'tcp_mid_session_retry_consume_timeout_secs', label: 'Retry consume timeout (s)', kind: 'int', section: 'TCP retry' },
  { key: 'tcp_symmetric_replay_enabled', label: 'Symmetric replay enabled', kind: 'bool', section: 'TCP retry' },
  { key: 'tcp_symmetric_replay_max_bytes', label: 'Symmetric replay max (bytes)', kind: 'int', section: 'TCP retry' },
  // TUN when group is down
  { key: 'tun_suppress_icmp_reply_when_down', label: 'Suppress ICMP reply when down', kind: 'bool', section: 'TUN when down' },
  { key: 'tun_icmp_liveness_window_secs', label: 'ICMP liveness window (s)', kind: 'int', section: 'TUN when down' },
  { key: 'bypass_when_down', label: 'Bypass (direct) when down', kind: 'bool', section: 'TUN when down' },
];

export interface GroupFormFields {
  name: string;
  mode: string;
  routingScope: string;
  sharedResume: boolean;
  warmStandbyTcp: number | null;
  warmStandbyUdp: number | null;
  reselectMode: ReselectMode;
  reselectAt: string; // one HH:MM per line
  reselectInterval: string;
  reselectSync: boolean;
  // Raw string state for every ADVANCED_FIELDS key. bool → '' | 'true' | 'false'.
  advanced: Record<string, string>;
}

export function emptyGroupFields(): GroupFormFields {
  const advanced: Record<string, string> = {};
  for (const f of ADVANCED_FIELDS) advanced[f.key] = '';
  return {
    name: '',
    mode: 'active_active',
    routingScope: 'per_flow',
    sharedResume: false,
    warmStandbyTcp: null,
    warmStandbyUdp: null,
    reselectMode: 'none',
    reselectAt: '',
    reselectInterval: '',
    reselectSync: false,
    advanced,
  };
}

const lines = (s: string): string[] =>
  s.split('\n').map((l) => l.trim()).filter((l) => l.length > 0);

export function fieldsFromConfig(config: GroupConfig | null | undefined): GroupFormFields {
  const c = (config ?? {}) as Record<string, unknown>;
  const f = emptyGroupFields();
  if (typeof c.name === 'string') f.name = c.name;
  if (typeof c.mode === 'string') f.mode = c.mode;
  if (typeof c.routing_scope === 'string') f.routingScope = c.routing_scope;
  if (typeof c.shared_resume === 'boolean') f.sharedResume = c.shared_resume;
  if (typeof c.warm_standby_tcp === 'number') f.warmStandbyTcp = c.warm_standby_tcp;
  if (typeof c.warm_standby_udp === 'number') f.warmStandbyUdp = c.warm_standby_udp;
  if (Array.isArray(c.reselect_at)) {
    f.reselectMode = 'at';
    f.reselectAt = (c.reselect_at as string[]).join('\n');
  } else if (typeof c.reselect_interval === 'string') {
    f.reselectMode = 'interval';
    f.reselectInterval = c.reselect_interval;
  }
  if (typeof c.reselect_sync === 'boolean') f.reselectSync = c.reselect_sync;
  for (const field of ADVANCED_FIELDS) {
    const v = c[field.key];
    if (v == null) continue;
    f.advanced[field.key] = String(v);
  }
  return f;
}

export function validateGroupForm(f: GroupFormFields, editing: boolean): string | null {
  if (!editing && !f.name.trim()) return 'name is required';
  if (f.name.trim().toLowerCase() === 'direct' || f.name.trim().toLowerCase() === 'drop') {
    return 'name "direct"/"drop" is reserved';
  }
  if (f.reselectMode !== 'none') {
    if (f.mode !== 'active_passive') return 'reselect requires mode = active_passive';
    if (f.routingScope !== 'global' && f.routingScope !== 'per_uplink') {
      return 'reselect requires routing_scope = global or per_uplink';
    }
    if (f.reselectMode === 'at' && lines(f.reselectAt).length === 0) return 'reselect times are required';
    if (f.reselectMode === 'interval' && !f.reselectInterval.trim()) return 'reselect interval is required';
    if (f.reselectSync && f.reselectMode !== 'at') return 'reselect sync requires the at-schedule mode';
  } else if (f.reselectSync) {
    return 'reselect sync requires the at-schedule mode';
  }
  return null;
}

export function buildGroupPayload(f: GroupFormFields, editing: boolean): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  // name is identity — sent only on create (server ignores it on PATCH anyway).
  if (!editing && f.name.trim()) out.name = f.name.trim();
  if (f.mode) out.mode = f.mode;
  // routing_scope: emit only if non-default
  if (f.routingScope && f.routingScope !== 'per_flow') out.routing_scope = f.routingScope;
  if (f.sharedResume) out.shared_resume = true;
  if (f.warmStandbyTcp !== null) out.warm_standby_tcp = Math.trunc(f.warmStandbyTcp);
  if (f.warmStandbyUdp !== null) out.warm_standby_udp = Math.trunc(f.warmStandbyUdp);
  if (f.reselectMode === 'at') {
    const at = lines(f.reselectAt);
    if (at.length) out.reselect_at = at;
    if (f.reselectSync) out.reselect_sync = true;
  } else if (f.reselectMode === 'interval' && f.reselectInterval.trim()) {
    out.reselect_interval = f.reselectInterval.trim();
  }
  for (const field of ADVANCED_FIELDS) {
    const raw = (f.advanced[field.key] ?? '').trim();
    if (!raw) continue;
    if (field.kind === 'int') out[field.key] = Math.trunc(Number(raw));
    else if (field.kind === 'float') out[field.key] = Number(raw);
    else if (field.kind === 'bool') out[field.key] = raw === 'true';
    else out[field.key] = raw; // enum
  }
  return out;
}
