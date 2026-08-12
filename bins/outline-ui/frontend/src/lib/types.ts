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
// (uplinks_crud/payload.rs `table_to_json`) and is absent when the config
// file couldn't be read. Field set here matches ws/uplinks.html's FIELDS —
// the backend's UplinkPayload additionally accepts newer fields
// (tcp_xhttp_url/udp_xhttp_url/ss_*/link/fallbacks, see
// uplinks_crud/payload.rs) that this legacy-parity form doesn't expose; see
// task-8-report.md "Concerns". The index signature keeps those (and any
// other server-side additions) from breaking the type.
export interface UplinkConfig {
  name?: string;
  transport?: string;
  method?: string;
  password?: string;
  vless_id?: string;
  tcp_ws_url?: string;
  tcp_mode?: string;
  udp_ws_url?: string;
  udp_mode?: string;
  vless_ws_url?: string;
  vless_xhttp_url?: string;
  vless_mode?: string;
  weight?: number;
  fwmark?: number;
  ipv6_first?: boolean;
  [k: string]: unknown;
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
