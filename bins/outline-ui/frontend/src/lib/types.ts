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
export interface Group { name: string; uplinks?: Uplink[]; [k: string]: unknown; }
export interface Uplink {
  name: string; admin_disabled?: boolean; last_error?: string | null;
  [k: string]: unknown; // wire chains / rtt / loss / weight / role — see ws/dashboard.html renderer
}
export interface ActivateTarget { instance: string; group: string; uplink: string; }
export interface ActivateBody { targets: ActivateTarget[]; transport?: 'tcp'|'udp'|'both'; soft?: boolean; }

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
