export interface MetaResponse {
  name: string;
  version: string;
}

export interface Instance {
  name: string;
  public_host?: string;
  mesh_addr?: string;
  cluster?: string;
}

export interface ClusterSummary {
  name: string;
  source: 'config' | 'discovered';
  members: string[];
  subscription_nodes: string[];
}

export interface InstancesResponse {
  instances: Instance[];
  clusters?: ClusterSummary[];
  refresh_interval_secs: number;
}

export interface SsTarget {
  kind: 'cluster' | 'instance';
  name: string;
}

// SS — a user is pure credentials since the endpoint-model refactor: it works
// on every registered endpoint of its kind, so it no longer carries any
// per-user carrier paths (the server rejects them with deny_unknown_fields).
// The index signature keeps any extra fields the server may add.
export interface User {
  id: string;
  enabled: boolean;
  password?: string | null;
  vless_id?: string | null;
  method?: string | null;
  fwmark?: number | null;
  aliases?: Record<string, string | string[]> | null;
  // Always present on UserView (server/control/manager.rs) — never the raw
  // secret, just whether one is set. Drives the drawer's edit-mode
  // placeholder ("keep current password" vs "add Shadowsocks password").
  has_password?: boolean;
  has_vless_id?: boolean;
  password_fp?: string | null;
  vless_id_fp?: string | null;
  created?: string;
  access_url?: string;
  [k: string]: unknown;
}
export type NewUser = Partial<User> & {
  id: string;
  enabled: boolean;
  rollback_on_error?: boolean;
};
export type PatchUser = Partial<User>;

// SS — Server & Cluster Configuration
export interface ClusterPeer {
  shard: number;
  addr: string;
}

export interface ClusterConfig {
  enabled: boolean;
  shard_id: number | null;
  cluster_psk?: string | null;
  has_cluster_psk?: boolean;
  psk_fingerprint?: string | null;
  mesh_listen: string | null;
  mesh_relay_budget_ms: number | null;
  peers: ClusterPeer[];
}

export interface TlsCertDto {
  cert_path: string;
  key_path: string;
  sni?: string[] | null;
}

export interface ServerListenersConfig {
  listen: string | null;
  cert_path: string | null;
  key_path: string | null;
  max_connections_per_ip?: number | null;
  certs?: TlsCertDto[] | null;
  h3_listen: string | null;
  h3_cert_path: string | null;
  h3_key_path: string | null;
  h3_certs?: TlsCertDto[] | null;
  h3_alpn?: string[] | null;
  h3_initial_mtu?: number | null;
  h3_mtu_first_probe?: number | null;
  h3_udp_datagrams?: boolean | null;
}

export interface ShadowsocksConfigView {
  method?: string | null;
}

export interface HttpRootConfigView {
  auth?: boolean | null;
  realm?: string | null;
}

export interface AccessKeysConfigView {
  public_host?: string | null;
  public_scheme?: string | null;
  url_base?: string | null;
  file_extension?: string | null;
  write_dir?: string | null;
  nodes?: string[] | null;
}

export interface SessionResumptionConfig {
  enabled: boolean;
  orphan_ttl_tcp_secs: number | null;
  orphan_ttl_udp_secs: number | null;
  orphan_per_user_cap: number | null;
  orphan_global_cap: number | null;
  downlink_buffer_bytes: number | null;
}

export interface OutboundConfig {
  prefer_ipv4: boolean | null;
  ipv6_prefix: string | null;
  ipv6_interface: string | null;
  ipv6_prefix_interface?: string | null;
  ipv6_refresh_secs?: number | null;
  ipv6_sticky: boolean | null;
  ipv6_sticky_ttl_secs: number | null;
  block_private_ips?: boolean | null;
  allowed_subnets?: string[] | null;
}

export interface ServerPaddingConfig {
  min_bytes?: number | null;
  max_bytes?: number | null;
  cover?: boolean | null;
  cover_jitter_min_ms?: number | null;
  cover_jitter_max_ms?: number | null;
  throttle_detect_enabled?: boolean | null;
  throttle_ratio_percent?: number | null;
  throttle_window_secs?: number | null;
  throttle_sustain_windows?: number | null;
  throttle_min_bytes_per_sec?: number | null;
  throttle_signal_cooldown_secs?: number | null;
}

export interface ServerHttpFallbackConfig {
  backend?: string | null;
  request_timeout_secs?: number | null;
  add_x_forwarded_for?: boolean | null;
  add_x_forwarded_proto?: boolean | null;
  add_x_forwarded_host?: boolean | null;
  proxy_protocol?: string | null;
  backend_proto?: string | null;
  apply_to_h1?: boolean | null;
  apply_to_h3?: boolean | null;
}

export interface SniBackendConfig {
  backend: string;
  proxy_protocol?: string | null;
  match_sni?: string[] | null;
}

export interface ServerSniFallbackConfig {
  match_sni?: string[] | null;
  allow_no_sni?: boolean | null;
  max_client_hello_bytes?: number | null;
  backends?: SniBackendConfig[] | null;
}

export interface TuningOverridesConfig {
  h2_stream_window_bytes?: number | null;
  h2_connection_window_bytes?: number | null;
  h2_max_send_buf_size?: number | null;
  h3_stream_window_bytes?: number | null;
  h3_connection_window_bytes?: number | null;
  h3_max_concurrent_bidi_streams?: number | null;
  h3_max_concurrent_uni_streams?: number | null;
  h3_write_buffer_bytes?: number | null;
  h3_max_backpressure_bytes?: number | null;
  h3_udp_socket_buffer_bytes?: number | null;
  client_active_ttl_secs?: number | null;
  udp_nat_idle_timeout_secs?: number | null;
  udp_nat_max_entries?: number | null;
  udp_nat_max_entries_per_user?: number | null;
  udp_max_concurrent_relay_tasks?: number | null;
  udp_replay_max_sessions?: number | null;
  udp_replay_max_sessions_per_user?: number | null;
  tcp_handshake_replay_max_salts?: number | null;
  xhttp_max_sessions?: number | null;
  xhttp_max_sessions_per_ip?: number | null;
  xhttp_max_concurrent_relay_tasks?: number | null;
  dns_cache_max_entries?: number | null;
  ws_data_channel_capacity?: number | null;
}

export interface MetricsConfigView {
  listen?: string | null;
  path?: string | null;
}

export interface ControlReadOnlyView {
  listen?: string | null;
  access_keys_enabled: boolean;
}

export type EndpointKind =
  | 'ws_ss'
  | 'ws_ss_tcp'
  | 'ws_ss_udp'
  | 'ws_vless'
  | 'xhttp_ss'
  | 'xhttp_ss_tcp'
  | 'xhttp_ss_udp'
  | 'xhttp_vless';

export interface EndpointConfigItem {
  path: string;
  kind?: EndpointKind;
  protocol: string;
  transport: string;
  padded: boolean;
}

export interface ServerConfigResponse {
  config_path: string | null;
  restart_pending?: boolean;
  cluster: ClusterConfig | null;
  server: ServerListenersConfig | null;
  shadowsocks?: ShadowsocksConfigView | null;
  http_root?: HttpRootConfigView | null;
  access_keys?: AccessKeysConfigView | null;
  session_resumption: SessionResumptionConfig | null;
  outbound: OutboundConfig | null;
  padding?: ServerPaddingConfig | null;
  http_fallback?: ServerHttpFallbackConfig | null;
  sni_fallback?: ServerSniFallbackConfig | null;
  tuning_profile: string | null;
  tuning?: TuningOverridesConfig | null;
  metrics?: MetricsConfigView | null;
  control?: ControlReadOnlyView | null;
  endpoints: EndpointConfigItem[];
}

export interface EndpointPatch {
  path: string;
  kind?: EndpointKind;
  padded: boolean;
}

export interface ServerConfigPatch {
  cluster?: Partial<ClusterConfig> | null;
  server?: Partial<ServerListenersConfig> | null;
  shadowsocks?: Partial<ShadowsocksConfigView> | null;
  http_root?: Partial<HttpRootConfigView> | null;
  access_keys?: Partial<AccessKeysConfigView> | null;
  session_resumption?: Partial<SessionResumptionConfig> | null;
  outbound?: Partial<OutboundConfig> | null;
  padding?: Partial<ServerPaddingConfig> | null;
  http_fallback?: Partial<ServerHttpFallbackConfig> | null;
  sni_fallback?: Partial<ServerSniFallbackConfig> | null;
  tuning_profile?: string | null;
  tuning?: Partial<TuningOverridesConfig> | null;
  endpoints?: EndpointPatch[] | null;
}

export interface NodeActionResult {
  instance: string;
  ok: boolean;
  status: number;
  requires_restart?: boolean;
  already_absent?: boolean;
  rolled_back?: boolean;
  error?: string;
  data?: unknown;
}

export interface ClusterMutationResponse {
  ok: boolean;
  cluster?: string;
  id?: string;
  rolled_back?: boolean;
  error?: string;
  results: NodeActionResult[];
}

export interface ClusterConfigNode {
  instance: string;
  ok: boolean;
  status: number;
  config?: ServerConfigResponse;
  error?: string;
}

export interface ClusterMeshHealth {
  all_reachable: boolean;
  psk_match: boolean;
  shards_unique: boolean;
  peers_symmetric: boolean;
  restart_pending_nodes: string[];
}

export interface ClusterConfigResponse {
  cluster: string;
  source: 'config' | 'discovered';
  members: string[];
  subscription_nodes: string[];
  nodes: ClusterConfigNode[];
  drift: string[];
  mesh_health: ClusterMeshHealth;
}

export interface ClusterUser extends User {
  sync_status: 'synced' | 'partial' | 'drift' | 'unknown';
  present_on: string[];
  missing_on: string[];
  diff_fields: string[];
  per_node: Record<string, User>;
}

export interface ClusterUsersResponse {
  cluster: string;
  source: string;
  members: string[];
  total_nodes: number;
  reachable_nodes: number;
  node_errors: Array<{ instance: string; status: number; error: string }>;
  users: ClusterUser[];
}

export interface RegenerateReport {
  nodes?: string[];
  written?: Array<{ user: string; files: string[] }>;
  pruned?: string[];
  warnings?: string[];
}

export interface ClusterRegenerateResponse {
  ok: boolean;
  cluster: string;
  nodes?: string[] | null;
  results: NodeActionResult[];
}

export interface UserAccessKeysBundle {
  mode?: 'cluster' | 'per_node';
  source_node?: string;
  user: string;
  enabled: boolean;
  outline_url?: string | null;
  happ_url?: string | null;
  ws_url?: string | null;
  txt_url?: string | null;
  share_links?: string[];
  artifacts?: {
    conf?: string;
    json?: string;
    toml?: string;
    txt?: string;
  };
  warnings?: string[];
  nodes?: Array<{
    instance: string;
    ok: boolean;
    status: number;
    links?: UserAccessKeysBundle;
    error?: string;
  }>;
}

// WS — topology envelope from ws/api.rs InstanceView.
export interface TopologyResponse {
  name: string; ok: boolean; error?: string | null;
  topology?: { instance?: { groups?: Group[] } } | null;
}
// Mirrors ControlGroupTopology (bins/outline-client/src/http/control/topology.rs).
// The four `bypass_*`/`cluster_resume_enabled` fields are `skip_serializing_if`
// on the wire (absent, not `false`, when off) — hence `?: boolean` rather than
// a required field defaulting to false. `load_balancing_mode`/`routing_scope`
// (topology.rs:63-64) and `auto_failback` (topology.rs:65) carry no such
// attribute — always a present, concrete value — hence required (no `?`)
// rather than optional, unlike the bypass/cluster group.
//
// `*_active_reason` is the group-level switch reason ("why is this uplink the
// active one") — named `global_active_reason`/`tcp_active_reason`/
// `udp_active_reason` on the wire (topology.rs:89,91,93 on
// `ControlGroupTopology`), NOT `active_global_reason`/etc. Those latter names
// belong to a *different*, per-uplink field on `Uplink` below
// (`ControlUplinkTopology`, topology.rs:188,190,192) — same reason string,
// but only populated on the one uplink row that is actually active for that
// leg.
export interface Group {
  name: string;
  uplinks?: Uplink[];
  load_balancing_mode: string;
  routing_scope: string;
  auto_failback: boolean;
  cluster_resume_enabled?: boolean;
  bypass_when_down?: boolean;
  bypass_active_tcp?: boolean;
  bypass_active_udp?: boolean;
  global_active_uplink?: string | null;
  global_active_reason?: string | null;
  tcp_active_uplink?: string | null;
  tcp_active_reason?: string | null;
  udp_active_uplink?: string | null;
  udp_active_reason?: string | null;
  [k: string]: unknown;
}
// One wire (primary at index 0, then each `[[outline.uplinks.fallbacks]]`) in
// an uplink's `configured_wire_chain[]` — mirrors `WireChainEntry`
// (bins/outline-client/src/http/control/topology.rs:13-39). Every
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
// Mirrors ControlUplinkTopology (bins/outline-client/src/http/control/topology.rs,
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
  // Age (ms) of the reading behind *_active_wire_rtt_ewma_ms — also
  // skip_serializing_if Option::is_none, absent until that wire has been
  // measured. Drives the RTT cell's tooltip age suffix (rttTooltip() in
  // wsTopology.ts), not the visible cell text.
  tcp_active_wire_rtt_age_ms?: number | null;
  udp_active_wire_rtt_age_ms?: number | null;
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
  // Browser-fingerprint diversification identity for this uplink's primary
  // dial URL (topology.rs:230-247 on ControlUplinkTopology). `_name` is
  // skip_serializing_if Option::is_none (absent for `none` strategy or an
  // uplink with no URL-based dial path — never present-but-null);
  // `_strategy` is a plain String skipped when it equals the literal
  // "none" (is_none_strategy), so its absence also means "none" rather than
  // an unknown state. Drives the group-header/per-uplink fingerprint chip —
  // see wsTopology.ts's groupFingerprintChip()/uplinkFingerprintChip().
  fingerprint_profile_name?: string | null;
  fingerprint_profile_strategy?: string;
  [k: string]: unknown; // submode/downgrade/cert/throttle/etc. — see ws/dashboard.html renderer
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
  /// bins/outline-client/src/config/load/uplinks/wire_shape.rs (shared by
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
  ipv4_only?: boolean;
  [k: string]: unknown;
}
export type FallbackConfig = WireConfig;
export interface UplinkConfig extends WireConfig {
  name?: string;
  weight?: number;
  shuffle_wires?: boolean | null;
  shuffle_timer?: string | null;
  padding?: boolean | null;
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
// POST /control/apply response (bins/outline-client/src/http/control/apply.rs
// `ApplyResponse`), proxied verbatim by /ws/dashboard/api/apply.
export interface ApplyResult {
  applied?: boolean;
  groups?: number;
  total_uplinks?: number;
  default_group?: string;
  // Non-default rule count of the newly-applied routing table; absent
  // (not 0) when routing was NOT hot-applied — not configured at startup
  // (`shared_routing: None` on the node's `ApplyHandle`), or the reloaded
  // config has no `[[route]]`. Callers must branch on presence, not truthiness,
  // to tell "0 rules hot-applied" apart from "hot-apply skipped".
  routes_applied?: number;
  error?: string;
}

// WS routing — GET /control/routes entries, proxied verbatim through
// /ws/dashboard/api/routes (routes_crud/list.rs RouteListEntry/RoutesListResponse).
// `config` mirrors the on-disk `[[route]]` table (table_to_json), absent
// when the config couldn't be read.
export interface RouteConfig {
  prefixes?: string[];
  file?: string;
  files?: string[];
  domains?: string[];
  domain_file?: string;
  domain_files?: string[];
  file_poll_secs?: number;
  default?: boolean;
  via?: string;
  fallback_via?: string;
  fallback_direct?: boolean;
  fallback_drop?: boolean;
  invert?: boolean;
  [k: string]: unknown;
}
export interface RouteEntry {
  index: number;
  is_default: boolean;
  config?: RouteConfig | null;
}
export interface RoutesListResponse {
  routes: RouteEntry[];
  groups: string[];
  revision: string;
}
// POST/PATCH/DELETE /control/routes response (routes_crud MutationResponse).
export interface RouteMutationResponse {
  action: string;
  index: number;
  apply_required?: boolean;
  restart_required?: boolean;
  revision: string;
}

// WS uplink groups — GET /control/uplink_groups entries, proxied verbatim
// through /ws/dashboard/api/groups (groups_crud/list.rs GroupListEntry/
// GroupsListResponse). `config` mirrors the on-disk `[[uplink_group]]` table
// (table_to_json), absent when the config couldn't be read. Only the fields
// the form treats specially are named; the index signature carries the ~40
// Advanced policy fields (all optional, primitive-typed).
export interface GroupProbeConfig {
  interval_secs?: number;
  timeout_secs?: number;
  tls?: {
    target?: string;
    targets?: string[];
  };
  http?: {
    url?: string;
    urls?: string[];
  };
  [k: string]: unknown;
}

export interface GroupConfig {
  name?: string;
  mode?: string;
  routing_scope?: string;
  shared_resume?: boolean;
  warm_standby_tcp?: number;
  warm_standby_udp?: number;
  reselect_at?: string[];
  reselect_interval?: string;
  reselect_sync?: boolean;
  probe?: GroupProbeConfig | null;
  [k: string]: unknown;
}
export interface GroupEntry {
  name: string;
  // Number of [[outline.uplinks]] assigned to this group. Drives the strict
  // delete gate (disabled while > 0) and the empty-group apply hint.
  uplink_count: number;
  config?: GroupConfig | null;
}
export interface GroupsListResponse {
  groups: GroupEntry[];
}
// POST/PATCH/DELETE /control/uplink_groups response (groups_crud MutationResponse).
export interface GroupMutationResponse {
  name: string;
  action: string;
  apply_required?: boolean;
  restart_required?: boolean;
}

// Server-wide default a user inherits when it carries none of its own —
// mirrors ServerDefaults in outline-server's control API
// (server/control/manager.rs), which since the endpoint-model refactor
// carries only the default cipher. The clone form needs it so a
// default-method template can still generate a password (the UI must not
// guess a cipher it does not know).
export interface ServerDefaults {
  method: string;
}

// WS — Client & Subsystems Configuration (/control/config)
export interface WsProbeConfig {
  interval_secs?: number | null;
  timeout_secs?: number | null;
  max_concurrent?: number | null;
  max_dials?: number | null;
  min_failures?: number | null;
  attempts?: number | null;
  skip_when_active?: boolean | null;
  liveness_interval_secs?: number | null;
  endpoint_check?: boolean | null;
  endpoint_check_timeout_ms?: number | null;
  http_urls?: string[] | null;
  tls_targets?: string[] | null;
  dns_server?: string | null;
  dns_port?: number | null;
  dns_name?: string | null;
  tcp_host?: string | null;
  tcp_port?: number | null;
  ws_enabled?: boolean | null;
}

export interface WsSocks5User {
  username: string;
  has_password?: boolean;
  password?: string | null;
}

export interface WsSocks5Config {
  listen?: string | null;
  username?: string | null;
  has_password?: boolean;
  users?: WsSocks5User[];
  users_count?: number;
}

export interface WsTunTcpConfig {
  sniffing?: boolean | null;
  sniff_timeout_ms?: number | null;
  sniff_direct_reresolve?: boolean | null;
  carrier_migration?: boolean | null;
  downlink_max_mbit?: number | null;
  pending_server_budget_bytes?: number | null;
  initial_receive_window_bytes?: number | null;
  connect_timeout_secs?: number | null;
  handshake_timeout_secs?: number | null;
}

export interface WsTunConfig {
  name?: string | null;
  mtu?: number | null;
  max_flows?: number | null;
  max_carrier_flows?: number | null;
  idle_timeout_secs?: number | null;
  max_concurrent_upstream_dials?: number | null;
  ipsec_bypass?: boolean | null;
  pmtud_emit_below_quic_initial?: boolean | null;
  sniff_quic?: boolean | null;
  route_by_sni?: boolean | null;
  gso?: boolean | null;
  gro?: boolean | null;
  uso?: boolean | null;
  tcp?: WsTunTcpConfig | null;
}

export interface WsDialConfig {
  timeout_secs?: number | null;
}

export interface WsPaddingConfig {
  enabled?: boolean | null;
  min_bytes?: number | null;
  max_bytes?: number | null;
  cover?: boolean | null;
  cover_jitter_min_ms?: number | null;
  cover_jitter_max_ms?: number | null;
  react_to_throttle?: boolean | null;
}

export interface WsQuicConfig {
  stream_receive_window?: number | null;
  receive_window?: number | null;
  keepalive_secs?: number | null;
  idle_timeout_secs?: number | null;
  udp_datagrams?: boolean | null;
}

export interface WsH2Config {
  initial_stream_window_size?: number | null;
  initial_connection_window_size?: number | null;
  keepalive_interval_secs?: number | null;
  keepalive_timeout_secs?: number | null;
}

export interface WsTcpTimeoutsConfig {
  post_client_eof_downstream_secs?: number | null;
  upstream_response_secs?: number | null;
  socks_upstream_idle_secs?: number | null;
  direct_idle_secs?: number | null;
}

export interface WsConfigResponse {
  config_path?: string | null;
  probe?: WsProbeConfig | null;
  socks5?: WsSocks5Config | null;
  tun?: WsTunConfig | null;
  dial?: WsDialConfig | null;
  padding?: WsPaddingConfig | null;
  quic?: WsQuicConfig | null;
  h2?: WsH2Config | null;
  tcp_timeouts?: WsTcpTimeoutsConfig | null;
  fingerprint_profile?: string | null;
  prefer_public_ipv6_src?: boolean | null;
  direct_fwmark?: number | null;
  direct_ipv6_prefix_interface?: string | null;
  ipv4_only?: boolean | null;
  ipv6_first?: boolean | null;
  udp_recv_buf_bytes?: number | null;
  udp_send_buf_bytes?: number | null;
}

export interface WsConfigPatch {
  probe?: WsProbeConfig | null;
  socks5?: {
    listen?: string | null;
    username?: string | null;
    password?: string | null;
    users?: Array<{ username: string; password?: string | null }> | null;
  } | null;
  tun?: WsTunConfig | null;
  dial?: WsDialConfig | null;
  padding?: WsPaddingConfig | null;
  quic?: WsQuicConfig | null;
  h2?: WsH2Config | null;
  tcp_timeouts?: WsTcpTimeoutsConfig | null;
  fingerprint_profile?: string | null;
  prefer_public_ipv6_src?: boolean | null;
  direct_fwmark?: number | null;
  direct_ipv6_prefix_interface?: string | null;
  ipv4_only?: boolean | null;
  ipv6_first?: boolean | null;
  udp_recv_buf_bytes?: number | null;
  udp_send_buf_bytes?: number | null;
}

export interface WsConfigMutationResponse {
  status: string;
  apply_required: boolean;
  restart_required: boolean;
}
