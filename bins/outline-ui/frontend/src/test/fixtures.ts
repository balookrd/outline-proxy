import type {
  ApplyResult,
  ClusterConfigResponse,
  ClusterMutationResponse,
  ClusterRegenerateResponse,
  ClusterUser,
  ClusterUsersResponse,
  GroupConfig,
  GroupsListResponse,
  InstancesResponse,
  MetaResponse,
  RegenerateReport,
  RouteConfig,
  RoutesListResponse,
  ServerConfigResponse,
  ServerDefaults,
  TopologyResponse,
  Uplink,
  UplinksListResponse,
  User,
  UserAccessKeysBundle,
  WsConfigMutationResponse,
  WsConfigResponse,
} from '../lib/types';

function clone<T>(value: T): T {
  return structuredClone(value);
}

export function makeMeta(version = '26.11.3'): MetaResponse {
  return { name: 'outline-ui', version };
}

export function makeSsInstances(): InstancesResponse {
  return clone({
    instances: [
      { name: 'cloud1', public_host: 'cloud1.fleet.example', mesh_addr: '10.0.0.1:9443', cluster: 'cloud' },
      { name: 'cloud2', public_host: 'cloud2.fleet.example', mesh_addr: '10.0.0.2:9443', cluster: 'cloud' },
      { name: 'nuxt', public_host: 'nuxt.fleet.example', mesh_addr: '10.0.0.3:9443', cluster: 'nuxt+nuxt2' },
      { name: 'nuxt2', public_host: 'nuxt2.fleet.example', mesh_addr: '10.0.0.4:9443', cluster: 'nuxt+nuxt2' },
    ],
    clusters: [
      {
        name: 'cloud',
        source: 'config',
        members: ['cloud1', 'cloud2'],
        subscription_nodes: ['cloud1.fleet.example', 'cloud2.fleet.example'],
      },
      {
        name: 'nuxt+nuxt2',
        source: 'discovered',
        members: ['nuxt', 'nuxt2'],
        subscription_nodes: ['nuxt.fleet.example', 'nuxt2.fleet.example'],
      },
    ],
    refresh_interval_secs: 5,
  });
}

export function makeWsInstances(): InstancesResponse {
  return clone({
    instances: [
      { name: 'beelink102' },
      { name: 'router104' },
    ],
    refresh_interval_secs: 5,
  });
}

export function makeDefaults(method = '2022-blake3-aes-256-gcm'): ServerDefaults {
  return { method };
}

export function makeSingleUsers(): User[] {
  return clone([
    {
      id: 'alice',
      enabled: true,
      method: '2022-blake3-aes-256-gcm',
      has_password: true,
      has_vless_id: true,
      password_fp: 'aa11bb22cc33',
      vless_id_fp: 'dd44ee55ff66',
    },
    {
      id: 'bob',
      enabled: false,
      method: 'chacha20-ietf-poly1305',
      has_password: true,
      has_vless_id: false,
      password_fp: '998877665544',
    },
  ]);
}

export function makeClusterUsersResponse(cluster = 'cloud'): ClusterUsersResponse {
  const members = cluster === 'nuxt+nuxt2' ? ['nuxt', 'nuxt2'] : ['cloud1', 'cloud2'];
  const alice: ClusterUser = {
    id: 'alice',
    enabled: true,
    method: '2022-blake3-aes-256-gcm',
    has_password: true,
    has_vless_id: true,
    password_fp: 'aa11bb22cc33',
    vless_id_fp: 'dd44ee55ff66',
    sync_status: 'synced',
    present_on: [...members],
    missing_on: [],
    diff_fields: [],
    per_node: Object.fromEntries(
      members.map((m) => [
        m,
        {
          id: 'alice',
          enabled: true,
          method: '2022-blake3-aes-256-gcm',
          has_password: true,
          has_vless_id: true,
          password_fp: 'aa11bb22cc33',
          vless_id_fp: 'dd44ee55ff66',
        },
      ]),
    ),
  };
  const bob: ClusterUser = {
    id: 'bob',
    enabled: true,
    method: 'aes-256-gcm',
    has_password: true,
    has_vless_id: false,
    password_fp: '112233445566',
    sync_status: 'partial',
    present_on: [members[0]],
    missing_on: [members[1]],
    diff_fields: [],
    per_node: {
      [members[0]]: {
        id: 'bob',
        enabled: true,
        method: 'aes-256-gcm',
        has_password: true,
        has_vless_id: false,
      },
    },
  };
  const charlie: ClusterUser = {
    id: 'charlie',
    enabled: false,
    method: 'chacha20-ietf-poly1305',
    has_password: true,
    has_vless_id: false,
    password_fp: 'ff00ee11dd22',
    sync_status: 'drift',
    present_on: [...members],
    missing_on: [],
    diff_fields: ['password'],
    per_node: Object.fromEntries(
      members.map((m, idx) => [
        m,
        {
          id: 'charlie',
          enabled: false,
          method: 'chacha20-ietf-poly1305',
          has_password: true,
          has_vless_id: false,
          password_fp: idx === 0 ? 'ff00ee11dd22' : '00ff11ee22dd',
        },
      ]),
    ),
  };
  return clone({
    cluster,
    source: cluster === 'nuxt+nuxt2' ? 'discovered' : 'config',
    members,
    total_nodes: members.length,
    reachable_nodes: members.length,
    node_errors: [],
    users: [alice, bob, charlie],
  });
}

export function makeAccessKeysBundle(
  mode: 'cluster' | 'per_node' = 'cluster',
  user = 'alice',
): UserAccessKeysBundle {
  if (mode === 'per_node') {
    return clone({
      mode: 'per_node',
      user,
      enabled: true,
      nodes: [
        {
          instance: 'cloud1',
          ok: true,
          status: 200,
          links: {
            user,
            enabled: true,
            outline_url: `ssconf://cloud1.fleet.example/keys/${user}.conf`,
            happ_url: `https://cloud1.fleet.example/keys/${user}.json`,
            ws_url: `https://cloud1.fleet.example/keys/${user}.toml`,
            txt_url: `https://cloud1.fleet.example/keys/${user}.txt`,
            share_links: [`ss://abc@${encodeURIComponent('cloud1.fleet.example')}:443#cloud1-${user}`],
            artifacts: {
              conf: '{"server":"cloud1.fleet.example"}',
              json: '{"outbounds":[]}',
              toml: '[[outline.uplinks]]\nname="cloud1"\n',
              txt: `ss://abc@cloud1.fleet.example:443#cloud1-${user}\n`,
            },
          },
        },
        {
          instance: 'cloud2',
          ok: true,
          status: 200,
          links: {
            user,
            enabled: true,
            outline_url: `ssconf://cloud2.fleet.example/keys/${user}.conf`,
            happ_url: `https://cloud2.fleet.example/keys/${user}.json`,
            ws_url: `https://cloud2.fleet.example/keys/${user}.toml`,
            txt_url: `https://cloud2.fleet.example/keys/${user}.txt`,
            share_links: [`ss://def@${encodeURIComponent('cloud2.fleet.example')}:443#cloud2-${user}`],
            artifacts: {
              conf: '{"server":"cloud2.fleet.example"}',
              json: '{"outbounds":[{"tag":"cloud2"}]}',
              toml: '[[outline.uplinks]]\nname="cloud2"\n',
              txt: `ss://def@cloud2.fleet.example:443#cloud2-${user}\n`,
            },
          },
        },
      ],
    });
  }

  return clone({
    mode: 'cluster',
    source_node: 'cloud1',
    user,
    enabled: true,
    outline_url: `ssconf://cloud1.fleet.example/keys/${user}.conf`,
    happ_url: `https://cloud1.fleet.example/keys/${user}.json`,
    ws_url: `https://cloud1.fleet.example/keys/${user}.toml`,
    txt_url: `https://cloud1.fleet.example/keys/${user}.txt`,
    share_links: [
      `ss://abc@cloud1.fleet.example:443#cloud1-${user}`,
      `vless://11111111-1111-4111-8111-111111111111@cloud2.fleet.example:443#cloud2-${user}`,
    ],
    artifacts: {
      conf: `{"server":"cloud1.fleet.example","user":"${user}"}`,
      json: `{"remarks":"${user}"}`,
      toml: `[[outline.uplinks]]\nname = "${user}"\n`,
      txt: `ss://abc@cloud1.fleet.example:443#cloud1-${user}\n`,
    },
    warnings: [],
  });
}

export function makeServerConfig(overrides: Partial<ServerConfigResponse> = {}): ServerConfigResponse {
  const base: ServerConfigResponse = {
    config_path: '/etc/outline-server/config.toml',
    restart_pending: false,
    cluster: {
      enabled: true,
      shard_id: 1,
      has_cluster_psk: true,
      psk_fingerprint: 'deadbeef0102',
      mesh_listen: '[::]:9443',
      mesh_relay_budget_ms: 4000,
      peers: [{ shard: 2, addr: '10.0.0.2:9443' }],
    },
    server: {
      listen: '0.0.0.0:443',
      cert_path: '/etc/ssl/server.crt',
      key_path: '/etc/ssl/server.key',
      max_connections_per_ip: 64,
      certs: [],
      h3_listen: '0.0.0.0:443',
      h3_cert_path: null,
      h3_key_path: null,
      h3_certs: [],
      h3_alpn: ['h3'],
      h3_initial_mtu: 1350,
      h3_mtu_first_probe: 1400,
      h3_udp_datagrams: true,
    },
    shadowsocks: { method: '2022-blake3-aes-256-gcm' },
    http_root: { auth: false, realm: 'outline' },
    access_keys: {
      public_host: 'cloud1.fleet.example',
      public_scheme: 'https',
      url_base: 'https://cloud1.fleet.example/sub',
      file_extension: '.json',
      write_dir: '/var/lib/outline/keys',
      nodes: ['cloud1.fleet.example', 'cloud2.fleet.example'],
    },
    session_resumption: {
      enabled: true,
      orphan_ttl_tcp_secs: 60,
      orphan_ttl_udp_secs: 60,
      orphan_per_user_cap: 32,
      orphan_global_cap: 1024,
      downlink_buffer_bytes: 262144,
    },
    outbound: {
      prefer_ipv4: true,
      ipv6_prefix: null,
      ipv6_interface: null,
      ipv6_prefix_interface: null,
      ipv6_refresh_secs: 300,
      ipv6_sticky: true,
      ipv6_sticky_ttl_secs: 300,
      block_private_ips: true,
      allowed_subnets: [],
    },
    padding: {
      min_bytes: 64,
      max_bytes: 256,
      cover: false,
      cover_jitter_min_ms: 50,
      cover_jitter_max_ms: 150,
      throttle_detect_enabled: false,
      throttle_ratio_percent: 50,
      throttle_window_secs: 10,
      throttle_sustain_windows: 3,
      throttle_min_bytes_per_sec: 16384,
      throttle_signal_cooldown_secs: 30,
    },
    http_fallback: {
      backend: 'http://127.0.0.1:8080',
      request_timeout_secs: 15,
      add_x_forwarded_for: true,
      add_x_forwarded_proto: true,
      add_x_forwarded_host: true,
      proxy_protocol: 'off',
      backend_proto: 'http1',
      apply_to_h1: true,
      apply_to_h3: true,
    },
    sni_fallback: {
      match_sni: [],
      allow_no_sni: false,
      max_client_hello_bytes: 16384,
      backends: [],
    },
    tuning_profile: 'large',
    tuning: {},
    metrics: { listen: '127.0.0.1:9100', path: '/metrics' },
    control: { listen: '127.0.0.1:9190', access_keys_enabled: true },
    endpoints: [
      { path: '/ws-ss', kind: 'ws_ss', protocol: 'shadowsocks', transport: 'websocket', padded: true },
      { path: '/xhttp-vl', kind: 'xhttp_vless', protocol: 'vless', transport: 'xhttp', padded: false },
    ],
  };
  return clone({ ...base, ...overrides });
}

export function makeClusterConfigResponse(
  cluster = 'cloud',
  overrides: Partial<ClusterConfigResponse> = {},
): ClusterConfigResponse {
  const members = cluster === 'nuxt+nuxt2' ? ['nuxt', 'nuxt2'] : ['cloud1', 'cloud2'];
  const c1 = makeServerConfig({
    cluster: {
      enabled: true,
      shard_id: 1,
      has_cluster_psk: true,
      psk_fingerprint: 'deadbeef0102',
      mesh_listen: '[::]:9443',
      mesh_relay_budget_ms: 4000,
      peers: [{ shard: 2, addr: '10.0.0.2:9443' }],
    },
  });
  const c2 = makeServerConfig({
    cluster: {
      enabled: true,
      shard_id: 2,
      has_cluster_psk: true,
      psk_fingerprint: 'deadbeef0102',
      mesh_listen: '[::]:9443',
      mesh_relay_budget_ms: 4000,
      peers: [{ shard: 1, addr: '10.0.0.1:9443' }],
    },
    access_keys: {
      public_host: `${members[1]}.fleet.example`,
      public_scheme: 'https',
      url_base: `https://${members[1]}.fleet.example/sub`,
      file_extension: '.json',
      write_dir: '/var/lib/outline/keys',
      nodes: [`${members[0]}.fleet.example`, `${members[1]}.fleet.example`],
    },
  });

  const base: ClusterConfigResponse = {
    cluster,
    source: cluster === 'nuxt+nuxt2' ? 'discovered' : 'config',
    members,
    subscription_nodes: members.map((m) => `${m}.fleet.example`),
    nodes: [
      { instance: members[0], ok: true, status: 200, config: c1 },
      { instance: members[1], ok: true, status: 200, config: c2 },
    ],
    drift: [],
    mesh_health: {
      all_reachable: true,
      psk_match: true,
      shards_unique: true,
      peers_symmetric: true,
      restart_pending_nodes: [],
    },
  };
  return clone({ ...base, ...overrides });
}

export function makeClusterMutationResponse(
  members = ['cloud1', 'cloud2'],
  overrides: Partial<ClusterMutationResponse> = {},
): ClusterMutationResponse {
  return clone({
    ok: true,
    results: members.map((instance) => ({ instance, ok: true, status: 200 })),
    ...overrides,
  });
}

export function makeRegenerateReport(): RegenerateReport {
  return clone({
    nodes: ['cloud1.fleet.example', 'cloud2.fleet.example'],
    written: [{ user: 'alice', files: ['alice.conf', 'alice.json', 'alice.toml', 'alice.txt'] }],
    pruned: [],
    warnings: [],
  });
}

export function makeClusterRegenerateResponse(cluster = 'cloud'): ClusterRegenerateResponse {
  const members = cluster === 'nuxt+nuxt2' ? ['nuxt', 'nuxt2'] : ['cloud1', 'cloud2'];
  return clone({
    ok: true,
    cluster,
    nodes: members,
    results: members.map((instance) => ({ instance, ok: true, status: 200 })),
  });
}

export function makeUplink(overrides: Partial<Uplink> = {}): Uplink {
  return clone({
    name: 'cloud1-edge',
    index: 0,
    transport: 'websocket',
    tcp_mode: 'h2',
    udp_mode: 'h3',
    tcp_mode_effective: 'h2',
    udp_mode_effective: 'h3',
    weight: 10,
    tcp_healthy: true,
    udp_healthy: true,
    tcp_health_effective: true,
    udp_health_effective: true,
    tcp_rtt_ewma_ms: 24.4,
    udp_rtt_ewma_ms: 28.1,
    tcp_carrier_loss_ratio: 0,
    udp_carrier_loss_ratio: 0.005,
    last_error: null,
    active_global: true,
    active_global_reason: 'best_score',
    active_tcp: true,
    active_tcp_reason: 'best_score',
    active_udp: true,
    active_udp_reason: 'best_score',
    configured_fallbacks: ['fallback-h3'],
    configured_wire_chain: [
      { transport: 'websocket', tcp_mode: 'h2', tcp_mode_effective: 'h2', udp_mode: 'h3', udp_mode_effective: 'h3' },
      { transport: 'xhttp', tcp_mode: 'h3', tcp_mode_effective: 'h3', udp_mode: 'h3', udp_mode_effective: 'h3' },
    ],
    tcp_active_wire: 0,
    udp_active_wire: 0,
    admin_disabled: false,
    fingerprint_profile_name: 'chrome-132',
    fingerprint_profile_strategy: 'process_stable',
    ...overrides,
  });
}

export function makeTopologyResponse(name = 'beelink102', ok = true): TopologyResponse {
  if (!ok) {
    return clone({ name, ok: false, error: 'connection refused' });
  }
  const primary = makeUplink({ name: `${name}-primary` });
  const standby = makeUplink({
    name: `${name}-backup`,
    index: 1,
    weight: 5,
    tcp_rtt_ewma_ms: 48.2,
    udp_rtt_ewma_ms: 52.0,
    active_global: false,
    active_global_reason: null,
    active_tcp: false,
    active_tcp_reason: null,
    active_udp: false,
    active_udp_reason: null,
    configured_fallbacks: [],
    configured_wire_chain: undefined,
  });
  return clone({
    name,
    ok: true,
    topology: {
      instance: {
        groups: [
          {
            name: 'main',
            load_balancing_mode: 'active_passive',
            routing_scope: 'global',
            auto_failback: true,
            cluster_resume_enabled: true,
            global_active_uplink: primary.name,
            global_active_reason: 'best_score',
            uplinks: [primary, standby],
          },
        ],
      },
    },
  });
}

export function makeUplinksResponse(): UplinksListResponse {
  return clone({
    uplinks: [
      {
        group: 'main',
        name: 'cloud1-edge',
        index: 0,
        config: {
          name: 'cloud1-edge',
          transport: 'ss',
          tcp_ws_url: 'wss://cloud1.fleet.example/tcp',
          tcp_mode: 'ws_h2',
          udp_ws_url: 'wss://cloud1.fleet.example/udp',
          udp_mode: 'ws_h3',
          method: '2022-blake3-aes-256-gcm',
          password: 'secret-password',
          weight: 10,
        },
      },
      {
        group: 'main',
        name: 'cloud2-edge',
        index: 1,
        config: {
          name: 'cloud2-edge',
          transport: 'vless',
          vless_xhttp_url: 'https://cloud2.fleet.example/vl',
          vless_mode: 'xhttp_h3',
          vless_id: '11111111-1111-4111-8111-111111111111',
          weight: 5,
        },
      },
    ],
  });
}

export function makeGroupsResponse(): GroupsListResponse {
  const mainConfig: GroupConfig = {
    name: 'main',
    mode: 'active_passive',
    routing_scope: 'global',
    shared_resume: true,
  };
  const backupConfig: GroupConfig = {
    name: 'empty-backup',
    mode: 'active_active',
    routing_scope: 'per_flow',
  };
  return clone({
    groups: [
      { name: 'main', uplink_count: 2, config: mainConfig },
      { name: 'empty-backup', uplink_count: 0, config: backupConfig },
    ],
  });
}

export function makeRoutesResponse(revision = 'rev-1'): RoutesListResponse {
  const bypassCfg: RouteConfig = {
    prefixes: ['10.0.0.0/8', '192.168.0.0/16'],
    domains: ['local.internal'],
    via: 'direct',
  };
  const streamingCfg: RouteConfig = {
    domains: ['youtube.com'],
    via: 'main',
    fallback_direct: true,
  };
  const defaultCfg: RouteConfig = {
    default: true,
    via: 'main',
  };
  return clone({
    routes: [
      { index: 0, is_default: false, config: bypassCfg },
      { index: 1, is_default: false, config: streamingCfg },
      { index: 2, is_default: true, config: defaultCfg },
    ],
    groups: ['main', 'empty-backup'],
    revision,
  });
}

export function makeApplyResult(overrides: Partial<ApplyResult> = {}): ApplyResult {
  return clone({
    applied: true,
    groups: 2,
    total_uplinks: 2,
    default_group: 'main',
    routes_applied: 2,
    ...overrides,
  });
}

export function makeWsConfigResponse(overrides: Partial<WsConfigResponse> = {}): WsConfigResponse {
  const base: WsConfigResponse = {
    config_path: '/etc/outline-client/config.toml',
    probe: {
      interval_secs: 30,
      timeout_secs: 5,
      max_concurrent: 4,
      max_dials: null,
      min_failures: 2,
      attempts: 1,
      skip_when_active: true,
      liveness_interval_secs: 10,
      endpoint_check: true,
      endpoint_check_timeout_ms: 1500,
      http_urls: ['http://cp.cloudflare.com/generate_204'],
      tls_targets: ['www.youtube.com'],
      dns_server: '1.1.1.1',
      dns_port: 53,
      dns_name: 'example.com',
      tcp_host: '1.1.1.1',
      tcp_port: 443,
      ws_enabled: true,
    },
    socks5: {
      listen: '127.0.0.1:1080',
      users: [{ username: 'alice', has_password: true }],
    },
    tun: {
      name: 'tun0',
      mtu: 1500,
      max_flows: 8192,
      max_carrier_flows: 1024,
      idle_timeout_secs: 120,
      max_concurrent_upstream_dials: 128,
      ipsec_bypass: false,
      pmtud_emit_below_quic_initial: false,
      sniff_quic: true,
      route_by_sni: false,
      gso: true,
      gro: true,
      uso: true,
      tcp: {
        sniffing: true,
        sniff_timeout_ms: 500,
        sniff_direct_reresolve: true,
        carrier_migration: true,
        downlink_max_mbit: null,
        pending_server_budget_bytes: 2097152,
        initial_receive_window_bytes: 1048576,
        connect_timeout_secs: 10,
        handshake_timeout_secs: 10,
      },
    },
    dial: { timeout_secs: 10 },
    padding: {
      enabled: false,
      min_bytes: 64,
      max_bytes: 256,
      cover: false,
      cover_jitter_min_ms: 50,
      cover_jitter_max_ms: 150,
      react_to_throttle: true,
    },
    quic: {
      stream_receive_window: 4194304,
      receive_window: 16777216,
      keepalive_secs: 15,
      idle_timeout_secs: 60,
      udp_datagrams: true,
    },
    h2: {
      initial_stream_window_size: 4194304,
      initial_connection_window_size: 16777216,
      keepalive_interval_secs: 20,
      keepalive_timeout_secs: 10,
    },
    tcp_timeouts: {
      post_client_eof_downstream_secs: 10,
      upstream_response_secs: 30,
      socks_upstream_idle_secs: 300,
      direct_idle_secs: 300,
    },
    fingerprint_profile: 'stable',
    prefer_public_ipv6_src: false,
    direct_fwmark: null,
    direct_ipv6_prefix_interface: null,
    ipv4_only: false,
    ipv6_first: false,
    udp_recv_buf_bytes: 4194304,
    udp_send_buf_bytes: 4194304,
  };
  return clone({ ...base, ...overrides });
}

export function makeWsConfigMutationResponse(
  overrides: Partial<WsConfigMutationResponse> = {},
): WsConfigMutationResponse {
  return clone({
    status: 'ok',
    apply_required: false,
    restart_required: false,
    ...overrides,
  });
}
