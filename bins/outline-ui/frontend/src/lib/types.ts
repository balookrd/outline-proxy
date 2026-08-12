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
