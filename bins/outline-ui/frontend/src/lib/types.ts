export interface Instance { name: string; }
export interface InstancesResponse { instances: Instance[]; refresh_interval_secs: number; }

// SS — fields mirror ss/dashboard.html payload(); server may add more (index signature keeps them).
export interface User {
  id: string; enabled: boolean;
  password?: string | null; vless_id?: string | null; method?: string | null;
  fwmark?: number | null; ws_path_tcp?: string | null; ws_path_udp?: string | null;
  ws_path_vless?: string | null; aliases?: Record<string, string | string[]> | null;
  // Always present on UserView (server/control/manager.rs) — never the raw
  // secret, just whether one is set. Drives the drawer's edit-mode
  // placeholder ("keep current password" vs "add Shadowsocks password").
  has_password?: boolean; has_vless_id?: boolean;
  created?: string; access_url?: string;
  [k: string]: unknown;
}
export type NewUser = Partial<User> & { id: string; enabled: boolean };
export type PatchUser = Partial<User>;

// WS — topology envelope from ws/api.rs InstanceView.
export interface TopologyResponse {
  name: string; ok: boolean; error?: string | null;
  topology?: { instance?: { groups?: Group[] } } | null;
}
// Mirrors ControlGroupTopology (bins/outline-ws-rust/src/http/control/topology.rs).
// The four `bypass_*`/`cluster_resume_enabled` fields are `skip_serializing_if`
// on the wire (absent, not `false`, when off) — hence `?: boolean` rather than
// a required field defaulting to false.
export interface Group {
  name: string;
  uplinks?: Uplink[];
  load_balancing_mode?: string;
  routing_scope?: string;
  auto_failback?: boolean;
  cluster_resume_enabled?: boolean;
  bypass_when_down?: boolean;
  bypass_active_tcp?: boolean;
  bypass_active_udp?: boolean;
  global_active_uplink?: string | null;
  tcp_active_uplink?: string | null;
  udp_active_uplink?: string | null;
  [k: string]: unknown;
}
// One wire (primary at index 0, then each `[[outline.uplinks.fallbacks]]`) in
// an uplink's `configured_wire_chain[]` — mirrors `WireChainEntry`
// (bins/outline-ws-rust/src/http/control/topology.rs:13-39). Every
// `*_mode`/`*_mode_effective` field is individually `skip_serializing_if`
// absent (only `transport` is unconditional), and Shadowsocks wires carry
// neither — their TCP/UDP shape is fixed by the address fields, not a mode
// enum.
export interface WireChainEntry {
  transport: string;
  tcp_mode?: string | null;
  tcp_mode_effective?: string | null;
  udp_mode?: string | null;
  udp_mode_effective?: string | null;
  [k: string]: unknown;
}
// Mirrors ControlUplinkTopology (bins/outline-ws-rust/src/http/control/topology.rs,
// built by build_uplink_topology() from outline-metrics's UplinkSnapshot) — the
// per-uplink entry inside `Group.uplinks[]`. Only the fields Task 9's topology
// read-view actually consumes are modeled here (the index signature covers the
// rest — submode/downgrade/cert/throttle/fingerprint/pin-timer/shuffle detail
// dashboard.html also renders but this simplified read-view does not).
//
// Fields marked `?:` without `| null` are genuinely `skip_serializing_if`
// absent-able (never present-but-null); every other `Option<T>` Rust field on
// this struct has NO `skip_serializing_if` — it is always present as a JSON
// key and simply reads `null` for `None` — hence `field: T | null` (present,
// required key) rather than `field?: T | null` for those.
export interface Uplink {
  name: string;
  index?: number;
  transport: string;
  tcp_mode: string | null;
  udp_mode: string | null;
  tcp_mode_effective: string | null;
  udp_mode_effective: string | null;
  weight: number;
  tcp_healthy: boolean | null;
  udp_healthy: boolean | null;
  tcp_health_effective: boolean | null;
  udp_health_effective: boolean | null;
  tcp_rtt_ewma_ms: number | null;
  udp_rtt_ewma_ms: number | null;
  // skip_serializing_if Option::is_none — absent, not null, until a wire flip
  // has produced its own measurement.
  tcp_active_wire_rtt_ewma_ms?: number | null;
  udp_active_wire_rtt_ewma_ms?: number | null;
  tcp_carrier_loss_ratio: number | null;
  udp_carrier_loss_ratio: number | null;
  last_error: string | null;
  active_global: boolean;
  active_global_reason: string | null;
  active_tcp: boolean;
  active_tcp_reason: string | null;
  active_udp: boolean;
  active_udp_reason: string | null;
  // Always present (`[]` when no fallbacks) — unlike configured_wire_chain
  // just below, `ControlUplinkTopology.configured_fallbacks` carries no
  // `skip_serializing_if`.
  configured_fallbacks: string[];
  // skip_serializing_if Vec::is_empty — absent (not `[]`) for a single-wire
  // uplink.
  configured_wire_chain?: WireChainEntry[];
  tcp_active_wire: number;
  udp_active_wire: number;
  admin_disabled: boolean;
  [k: string]: unknown; // submode/downgrade/cert/throttle/fingerprint/etc. — see ws/dashboard.html renderer
}
export interface ActivateTarget { instance: string; group: string; uplink: string; }
export interface ActivateBody { targets: ActivateTarget[]; transport?: 'tcp'|'udp'|'both'; soft?: boolean; }
// POST /ws/dashboard/api/activate response (ws/api.rs `activate()`/`ActivateResult`)
// — one entry per requested target, in request order. `status`/`body` are the
// proxied instance's own HTTP status/JSON body (null when the instance was
// unreachable, in which case `error` carries the transport failure instead).
export interface ActivateResult {
  target: ActivateTarget;
  ok: boolean;
  status: number | null;
  body: unknown | null;
  error: string | null;
}
export interface ActivateResponse { results: ActivateResult[]; }

// POST /ws/dashboard/api/reselect and /set_enabled share this envelope
// (ws/api.rs `proxy_json()`): `body` is the proxied instance's JSON reply on
// success. In practice `ok:false` never reaches a resolved promise today —
// proxy_json() mirrors the instance's own HTTP status onto its response, so a
// semantic failure surfaces as a thrown Error via lib/api.ts's json() helper
// instead — but the field is typed here so callers can handle it defensively
// if that proxying behaviour ever changes.
export interface ProxyOpResult { ok: boolean; body?: unknown; error?: string; }

// WS uplinks CRUD — GET /control/uplinks entries, proxied verbatim through
// /ws/dashboard/api/uplinks (see ws/api.rs `uplinks_proxy` and
// uplinks_crud/list.rs `UplinkListEntry`/`UplinkListResponse`). `config`
// mirrors the on-disk TOML table for one [[outline.uplinks]] entry
// (uplinks_crud/payload.rs `table_to_json`), rendered as literally-whatever
// fields the create/PATCH payload wrote (e.g. an uplink created via `link`
// has *only* `link` on disk — the share-link expansion into transport/
// carrier fields happens at config-load time, not at rest), and is absent
// when the config file couldn't be read.
//
// `WireConfig` is the field set shared by the top-level config AND one
// `[[outline.uplinks.fallbacks]]` entry's own config — every field
// `FallbackPayload` accepts (uplinks_crud/payload.rs), which is
// `UplinkPayload`'s full field set minus `name`/`weight`/`fallbacks` (those
// are parent-uplink-only, see `FallbackPayload`'s doc comment). `UplinkConfig`
// adds those three back; `FallbackConfig` needs nothing on top, so it's a
// plain alias.
export interface WireConfig {
  transport?: string;
  /// Share-link URI (`vless://…` / `ss://…`). Mutually exclusive on the wire
  /// with `transport` and every explicit carrier/credential field below —
  /// see `expand_share_link` in
  /// bins/outline-ws-rust/src/config/load/uplinks/wire_shape.rs (shared by
  /// both the primary wire and the fallback pre-pass — see `apply_link` in
  /// config/load/uplinks/fallback_resolution.rs).
  link?: string;
  tcp_ws_url?: string;
  tcp_xhttp_url?: string;
  tcp_mode?: string;
  udp_ws_url?: string;
  udp_xhttp_url?: string;
  udp_mode?: string;
  vless_ws_url?: string;
  vless_xhttp_url?: string;
  vless_mode?: string;
  vless_id?: string;
  ss_ws_url?: string;
  ss_xhttp_url?: string;
  ss_mode?: string;
  method?: string;
  password?: string;
  fwmark?: number;
  ipv6_first?: boolean;
  [k: string]: unknown;
}
export type FallbackConfig = WireConfig;
export interface UplinkConfig extends WireConfig {
  name?: string;
  weight?: number;
  /// `[[outline.uplinks.fallbacks]]`, in on-disk/priority order. Absent on
  /// an uplink with no fallbacks configured (not present in the TOML table
  /// at all — `table_to_json` only emits keys that exist on disk).
  fallbacks?: FallbackConfig[];
}
export interface UplinkEntry {
  group: string;
  name: string;
  index: number;
  config?: UplinkConfig | null;
}
export interface UplinksListResponse { uplinks: UplinkEntry[]; }
// POST /control/apply response (bins/outline-ws-rust/src/http/control/apply.rs
// `ApplyResponse`), proxied verbatim by /ws/dashboard/api/apply.
export interface ApplyResult {
  applied?: boolean;
  groups?: number;
  total_uplinks?: number;
  default_group?: string;
  error?: string;
}
