import type {
  ClusterPeer,
  EndpointConfigItem,
  EndpointKind,
  EndpointPatch,
  ServerConfigPatch,
  ServerConfigResponse,
  SniBackendConfig,
  TlsCertDto,
  TuningOverridesConfig,
} from './types';

export const CIPHER_KINDS = [
  'aes-128-gcm',
  'aes-256-gcm',
  'chacha20-ietf-poly1305',
  '2022-blake3-aes-128-gcm',
  '2022-blake3-aes-256-gcm',
  '2022-blake3-chacha20-poly1305',
] as const;

export const ENDPOINT_KIND_OPTIONS: ReadonlyArray<{
  kind: EndpointKind;
  label: string;
  transport: string;
  protocol: string;
}> = [
  { kind: 'ws_ss', label: 'ws_ss (WS + Shadowsocks combined)', transport: 'websocket', protocol: 'shadowsocks' },
  { kind: 'ws_ss_tcp', label: 'ws_ss_tcp (WS + SS TCP leg)', transport: 'websocket', protocol: 'shadowsocks' },
  { kind: 'ws_ss_udp', label: 'ws_ss_udp (WS + SS UDP leg)', transport: 'websocket', protocol: 'shadowsocks' },
  { kind: 'ws_vless', label: 'ws_vless (WS + VLESS)', transport: 'websocket', protocol: 'vless' },
  { kind: 'xhttp_ss', label: 'xhttp_ss (XHTTP + Shadowsocks combined)', transport: 'xhttp', protocol: 'shadowsocks' },
  { kind: 'xhttp_ss_tcp', label: 'xhttp_ss_tcp (XHTTP + SS TCP leg)', transport: 'xhttp', protocol: 'shadowsocks' },
  { kind: 'xhttp_ss_udp', label: 'xhttp_ss_udp (XHTTP + SS UDP leg)', transport: 'xhttp', protocol: 'shadowsocks' },
  { kind: 'xhttp_vless', label: 'xhttp_vless (XHTTP + VLESS)', transport: 'xhttp', protocol: 'vless' },
];

export type TuningPresetName = 'small' | 'medium' | 'large';
export type TuningFieldKey = keyof TuningOverridesConfig;

export const TUNING_PRESETS: Record<TuningPresetName, Record<TuningFieldKey, number>> = {
  small: {
    h2_stream_window_bytes: 1024 * 1024,
    h2_connection_window_bytes: 4 * 1024 * 1024,
    h2_max_send_buf_size: 1024 * 1024,
    h3_stream_window_bytes: 1024 * 1024,
    h3_connection_window_bytes: 4 * 1024 * 1024,
    h3_max_concurrent_bidi_streams: 256,
    h3_max_concurrent_uni_streams: 128,
    h3_write_buffer_bytes: 128 * 1024,
    h3_max_backpressure_bytes: 1024 * 1024,
    h3_udp_socket_buffer_bytes: 4 * 1024 * 1024,
    client_active_ttl_secs: 180,
    udp_nat_idle_timeout_secs: 120,
    udp_nat_max_entries: 4096,
    udp_nat_max_entries_per_user: 1024,
    udp_max_concurrent_relay_tasks: 1024,
    udp_replay_max_sessions: 16384,
    udp_replay_max_sessions_per_user: 4096,
    tcp_handshake_replay_max_salts: 16384,
    xhttp_max_sessions: 16384,
    xhttp_max_sessions_per_ip: 0,
    xhttp_max_concurrent_relay_tasks: 1024,
    dns_cache_max_entries: 16384,
    ws_data_channel_capacity: 16,
  },
  medium: {
    h2_stream_window_bytes: 4 * 1024 * 1024,
    h2_connection_window_bytes: 16 * 1024 * 1024,
    h2_max_send_buf_size: 4 * 1024 * 1024,
    h3_stream_window_bytes: 4 * 1024 * 1024,
    h3_connection_window_bytes: 16 * 1024 * 1024,
    h3_max_concurrent_bidi_streams: 1024,
    h3_max_concurrent_uni_streams: 512,
    h3_write_buffer_bytes: 256 * 1024,
    h3_max_backpressure_bytes: 4 * 1024 * 1024,
    h3_udp_socket_buffer_bytes: 8 * 1024 * 1024,
    client_active_ttl_secs: 300,
    udp_nat_idle_timeout_secs: 240,
    udp_nat_max_entries: 16384,
    udp_nat_max_entries_per_user: 2048,
    udp_max_concurrent_relay_tasks: 2048,
    udp_replay_max_sessions: 65536,
    udp_replay_max_sessions_per_user: 8192,
    tcp_handshake_replay_max_salts: 65536,
    xhttp_max_sessions: 65536,
    xhttp_max_sessions_per_ip: 0,
    xhttp_max_concurrent_relay_tasks: 2048,
    dns_cache_max_entries: 65536,
    ws_data_channel_capacity: 64,
  },
  large: {
    h2_stream_window_bytes: 16 * 1024 * 1024,
    h2_connection_window_bytes: 64 * 1024 * 1024,
    h2_max_send_buf_size: 16 * 1024 * 1024,
    h3_stream_window_bytes: 16 * 1024 * 1024,
    h3_connection_window_bytes: 64 * 1024 * 1024,
    h3_max_concurrent_bidi_streams: 4096,
    h3_max_concurrent_uni_streams: 1024,
    h3_write_buffer_bytes: 512 * 1024,
    h3_max_backpressure_bytes: 16 * 1024 * 1024,
    h3_udp_socket_buffer_bytes: 32 * 1024 * 1024,
    client_active_ttl_secs: 300,
    udp_nat_idle_timeout_secs: 300,
    udp_nat_max_entries: 65536,
    udp_nat_max_entries_per_user: 4096,
    udp_max_concurrent_relay_tasks: 4096,
    udp_replay_max_sessions: 262144,
    udp_replay_max_sessions_per_user: 16384,
    tcp_handshake_replay_max_salts: 262144,
    xhttp_max_sessions: 262144,
    xhttp_max_sessions_per_ip: 0,
    xhttp_max_concurrent_relay_tasks: 4096,
    dns_cache_max_entries: 262144,
    ws_data_channel_capacity: 128,
  },
};

export const TUNING_FIELD_SPECS: ReadonlyArray<{
  key: TuningFieldKey;
  label: string;
  zeroOptOut?: boolean;
}> = [
  { key: 'h2_stream_window_bytes', label: 'H2 stream window (bytes)' },
  { key: 'h2_connection_window_bytes', label: 'H2 connection window (bytes)' },
  { key: 'h2_max_send_buf_size', label: 'H2 max send buffer (bytes)' },
  { key: 'h3_stream_window_bytes', label: 'H3 stream window (bytes)' },
  { key: 'h3_connection_window_bytes', label: 'H3 connection window (bytes)' },
  { key: 'h3_max_concurrent_bidi_streams', label: 'H3 max concurrent bidi streams' },
  { key: 'h3_max_concurrent_uni_streams', label: 'H3 max concurrent uni streams' },
  { key: 'h3_write_buffer_bytes', label: 'H3 write buffer (bytes)' },
  { key: 'h3_max_backpressure_bytes', label: 'H3 max backpressure (bytes)' },
  { key: 'h3_udp_socket_buffer_bytes', label: 'H3 UDP socket buffer (bytes)' },
  { key: 'client_active_ttl_secs', label: 'Client active TTL (s)' },
  { key: 'udp_nat_idle_timeout_secs', label: 'UDP NAT idle timeout (s)' },
  { key: 'udp_nat_max_entries', label: 'UDP NAT max entries', zeroOptOut: true },
  { key: 'udp_nat_max_entries_per_user', label: 'UDP NAT max entries/user', zeroOptOut: true },
  { key: 'udp_max_concurrent_relay_tasks', label: 'UDP max concurrent relay tasks', zeroOptOut: true },
  { key: 'udp_replay_max_sessions', label: 'UDP replay max sessions', zeroOptOut: true },
  { key: 'udp_replay_max_sessions_per_user', label: 'UDP replay max sessions/user', zeroOptOut: true },
  { key: 'tcp_handshake_replay_max_salts', label: 'TCP handshake replay max salts', zeroOptOut: true },
  { key: 'xhttp_max_sessions', label: 'XHTTP max sessions', zeroOptOut: true },
  { key: 'xhttp_max_sessions_per_ip', label: 'XHTTP max sessions/IP', zeroOptOut: true },
  { key: 'xhttp_max_concurrent_relay_tasks', label: 'XHTTP max concurrent relay tasks', zeroOptOut: true },
  { key: 'dns_cache_max_entries', label: 'DNS cache max entries', zeroOptOut: true },
  { key: 'ws_data_channel_capacity', label: 'WS data channel capacity (chunks)' },
];

export interface EditableEndpoint {
  path: string;
  kind: EndpointKind;
  padded: boolean;
}

export interface EditableTlsCert {
  cert_path: string;
  key_path: string;
  sniText: string;
}

export interface EditableSniBackend {
  backend: string;
  proxy_protocol: '' | 'v1' | 'v2';
  matchSniText: string;
}

export interface SharedSettingsModel {
  endpoints: EditableEndpoint[];
  shadowsocksMethod: string;
  httpRootAuth: boolean;
  httpRootRealm: string;
  maxConnectionsPerIp: number | null;
  h3Alpn: string[];
  h3UdpDatagrams: boolean;
  h3InitialMtu: number | null;
  h3MtuFirstProbe: number | null;
  sessionResumption: {
    enabled: boolean;
    orphan_ttl_tcp_secs: number | null;
    orphan_ttl_udp_secs: number | null;
    orphan_per_user_cap: number | null;
    orphan_global_cap: number | null;
    downlink_buffer_bytes: number | null;
  };
  outboundShared: {
    prefer_ipv4: boolean;
    ipv6_sticky: boolean;
    ipv6_sticky_ttl_secs: number | null;
    ipv6_refresh_secs: number | null;
    block_private_ips: boolean;
    allowedSubnetsText: string;
  };
  padding: {
    cover: boolean;
    min_bytes: number | null;
    max_bytes: number | null;
    cover_jitter_min_ms: number | null;
    cover_jitter_max_ms: number | null;
    throttle_detect_enabled: boolean;
    throttle_ratio_percent: number | null;
    throttle_window_secs: number | null;
    throttle_sustain_windows: number | null;
    throttle_min_bytes_per_sec: number | null;
    throttle_signal_cooldown_secs: number | null;
  };
  httpFallback: {
    backend: string;
    backend_proto: '' | 'h1' | 'h2';
    proxy_protocol: '' | 'v1' | 'v2';
    request_timeout_secs: number | null;
    apply_to_h1: boolean;
    apply_to_h3: boolean;
    add_x_forwarded_for: boolean;
    add_x_forwarded_proto: boolean;
    add_x_forwarded_host: boolean;
  };
  sniFallback: {
    matchSniText: string;
    allow_no_sni: boolean;
    max_client_hello_bytes: number | null;
    backends: EditableSniBackend[];
  };
  accessKeys: {
    public_host: string;
    public_scheme: '' | 'ws' | 'wss';
    url_base: string;
    file_extension: string;
    write_dir: string;
    nodesText: string;
  };
  tuningProfile: TuningPresetName;
  tuningOverrides: Record<TuningFieldKey, number | null>;
}

export interface PerNodeSettingsModel {
  listen: string;
  cert_path: string;
  key_path: string;
  certs: EditableTlsCert[];
  h3_listen: string;
  h3_cert_path: string;
  h3_key_path: string;
  h3CertsCustom: boolean;
  h3_certs: EditableTlsCert[];
  ipv6_prefix: string;
  ipv6_interface: string;
  ipv6_prefix_interface: string;
}

export function inferEndpointKind(ep: EndpointConfigItem): EndpointKind {
  if (ep.kind) return ep.kind;
  if (ep.transport === 'xhttp') {
    return ep.protocol === 'vless' ? 'xhttp_vless' : 'xhttp_ss';
  }
  return ep.protocol === 'vless' ? 'ws_vless' : 'ws_ss';
}

export function splitListText(raw: string): string[] {
  return raw
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function emptyTuningOverrides(): Record<TuningFieldKey, number | null> {
  const out = {} as Record<TuningFieldKey, number | null>;
  for (const spec of TUNING_FIELD_SPECS) out[spec.key] = null;
  return out;
}

export function sharedFromConfig(cfg: ServerConfigResponse): SharedSettingsModel {
  const tuningOverrides = emptyTuningOverrides();
  if (cfg.tuning) {
    for (const spec of TUNING_FIELD_SPECS) {
      tuningOverrides[spec.key] = cfg.tuning[spec.key] ?? null;
    }
  }
  const tp = cfg.tuning_profile;
  const tuningProfile: TuningPresetName =
    tp === 'small' || tp === 'medium' || tp === 'large' ? tp : 'large';

  const scheme = cfg.access_keys?.public_scheme;
  const public_scheme: '' | 'ws' | 'wss' = scheme === 'ws' || scheme === 'wss' ? scheme : '';

  const hfProto = cfg.http_fallback?.backend_proto;
  const hfProxy = cfg.http_fallback?.proxy_protocol;

  return {
    endpoints: (cfg.endpoints ?? []).map((ep) => ({
      path: ep.path,
      kind: inferEndpointKind(ep),
      padded: Boolean(ep.padded),
    })),
    shadowsocksMethod: cfg.shadowsocks?.method ?? '',
    httpRootAuth: Boolean(cfg.http_root?.auth),
    httpRootRealm: cfg.http_root?.realm ?? '',
    maxConnectionsPerIp: cfg.server?.max_connections_per_ip ?? null,
    h3Alpn: cfg.server?.h3_alpn?.length ? [...cfg.server.h3_alpn] : ['h3'],
    h3UdpDatagrams: cfg.server?.h3_udp_datagrams ?? true,
    h3InitialMtu: cfg.server?.h3_initial_mtu ?? null,
    h3MtuFirstProbe: cfg.server?.h3_mtu_first_probe ?? null,
    sessionResumption: {
      enabled: Boolean(cfg.session_resumption?.enabled),
      orphan_ttl_tcp_secs: cfg.session_resumption?.orphan_ttl_tcp_secs ?? null,
      orphan_ttl_udp_secs: cfg.session_resumption?.orphan_ttl_udp_secs ?? null,
      orphan_per_user_cap: cfg.session_resumption?.orphan_per_user_cap ?? null,
      orphan_global_cap: cfg.session_resumption?.orphan_global_cap ?? null,
      downlink_buffer_bytes: cfg.session_resumption?.downlink_buffer_bytes ?? null,
    },
    outboundShared: {
      prefer_ipv4: Boolean(cfg.outbound?.prefer_ipv4),
      ipv6_sticky: cfg.outbound?.ipv6_sticky ?? true,
      ipv6_sticky_ttl_secs: cfg.outbound?.ipv6_sticky_ttl_secs ?? null,
      ipv6_refresh_secs: cfg.outbound?.ipv6_refresh_secs ?? null,
      block_private_ips: Boolean(cfg.outbound?.block_private_ips),
      allowedSubnetsText: (cfg.outbound?.allowed_subnets ?? []).join(', '),
    },
    padding: {
      cover: Boolean(cfg.padding?.cover),
      min_bytes: cfg.padding?.min_bytes ?? null,
      max_bytes: cfg.padding?.max_bytes ?? null,
      cover_jitter_min_ms: cfg.padding?.cover_jitter_min_ms ?? null,
      cover_jitter_max_ms: cfg.padding?.cover_jitter_max_ms ?? null,
      throttle_detect_enabled: Boolean(cfg.padding?.throttle_detect_enabled),
      throttle_ratio_percent: cfg.padding?.throttle_ratio_percent ?? null,
      throttle_window_secs: cfg.padding?.throttle_window_secs ?? null,
      throttle_sustain_windows: cfg.padding?.throttle_sustain_windows ?? null,
      throttle_min_bytes_per_sec: cfg.padding?.throttle_min_bytes_per_sec ?? null,
      throttle_signal_cooldown_secs: cfg.padding?.throttle_signal_cooldown_secs ?? null,
    },
    httpFallback: {
      backend: cfg.http_fallback?.backend ?? '',
      backend_proto: hfProto === 'h1' || hfProto === 'h2' ? hfProto : '',
      proxy_protocol: hfProxy === 'v1' || hfProxy === 'v2' ? hfProxy : '',
      request_timeout_secs: cfg.http_fallback?.request_timeout_secs ?? null,
      apply_to_h1: cfg.http_fallback?.apply_to_h1 ?? true,
      apply_to_h3: cfg.http_fallback?.apply_to_h3 ?? false,
      add_x_forwarded_for: cfg.http_fallback?.add_x_forwarded_for ?? true,
      add_x_forwarded_proto: cfg.http_fallback?.add_x_forwarded_proto ?? true,
      add_x_forwarded_host: cfg.http_fallback?.add_x_forwarded_host ?? true,
    },
    sniFallback: {
      matchSniText: (cfg.sni_fallback?.match_sni ?? []).join(', '),
      allow_no_sni: Boolean(cfg.sni_fallback?.allow_no_sni),
      max_client_hello_bytes: cfg.sni_fallback?.max_client_hello_bytes ?? null,
      backends: (cfg.sni_fallback?.backends ?? []).map((b) => ({
        backend: b.backend,
        proxy_protocol: b.proxy_protocol === 'v1' || b.proxy_protocol === 'v2' ? b.proxy_protocol : '',
        matchSniText: (b.match_sni ?? []).join(', '),
      })),
    },
    accessKeys: {
      public_host: cfg.access_keys?.public_host ?? '',
      public_scheme,
      url_base: cfg.access_keys?.url_base ?? '',
      file_extension: cfg.access_keys?.file_extension ?? '',
      write_dir: cfg.access_keys?.write_dir ?? '',
      nodesText: (cfg.access_keys?.nodes ?? []).join(', '),
    },
    tuningProfile,
    tuningOverrides,
  };
}

function certsToEditable(certs: TlsCertDto[] | null | undefined): EditableTlsCert[] {
  return (certs ?? []).map((c) => ({
    cert_path: c.cert_path,
    key_path: c.key_path,
    sniText: (c.sni ?? []).join(', '),
  }));
}

function certsFromEditable(certs: EditableTlsCert[]): TlsCertDto[] {
  return certs.map((c) => {
    const snis = splitListText(c.sniText);
    return {
      cert_path: c.cert_path.trim(),
      key_path: c.key_path.trim(),
      ...(snis.length ? { sni: snis } : {}),
    };
  });
}

export function perNodeFromConfig(cfg: ServerConfigResponse): PerNodeSettingsModel {
  return {
    listen: cfg.server?.listen ?? '',
    cert_path: cfg.server?.cert_path ?? '',
    key_path: cfg.server?.key_path ?? '',
    certs: certsToEditable(cfg.server?.certs),
    h3_listen: cfg.server?.h3_listen ?? '',
    h3_cert_path: cfg.server?.h3_cert_path ?? '',
    h3_key_path: cfg.server?.h3_key_path ?? '',
    h3CertsCustom: cfg.server?.h3_certs != null,
    h3_certs: certsToEditable(cfg.server?.h3_certs),
    ipv6_prefix: cfg.outbound?.ipv6_prefix ?? '',
    ipv6_interface: cfg.outbound?.ipv6_interface ?? '',
    ipv6_prefix_interface: cfg.outbound?.ipv6_prefix_interface ?? '',
  };
}

function jsonEq(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

function nullableStrPatch(curr: string, init: string): string | null | undefined {
  const c = curr.trim();
  const i = init.trim();
  if (c === i) return undefined;
  return c === '' ? null : c;
}

export function buildSharedPatch(
  curr: SharedSettingsModel,
  init: SharedSettingsModel,
): { patch: ServerConfigPatch; dirtySections: string[] } {
  const patch: ServerConfigPatch = {};
  const dirtySections: string[] = [];

  if (!jsonEq(curr.endpoints, init.endpoints)) {
    const eps: EndpointPatch[] = curr.endpoints.map((ep) => ({
      path: ep.path.trim(),
      kind: ep.kind,
      padded: ep.padded,
    }));
    patch.endpoints = eps;
    dirtySections.push('endpoints');
  }

  const ssMethod = nullableStrPatch(curr.shadowsocksMethod, init.shadowsocksMethod);
  if (ssMethod !== undefined) {
    patch.shadowsocks = { method: ssMethod };
    dirtySections.push('shadowsocks');
  }

  const hrPatch: NonNullable<ServerConfigPatch['http_root']> = {};
  if (curr.httpRootAuth !== init.httpRootAuth) hrPatch.auth = curr.httpRootAuth;
  const realm = nullableStrPatch(curr.httpRootRealm, init.httpRootRealm);
  if (realm !== undefined) hrPatch.realm = realm;
  if (Object.keys(hrPatch).length) {
    patch.http_root = hrPatch;
    dirtySections.push('http_root');
  }

  const srvPatch: NonNullable<ServerConfigPatch['server']> = {};
  if (curr.maxConnectionsPerIp !== init.maxConnectionsPerIp) {
    srvPatch.max_connections_per_ip = curr.maxConnectionsPerIp;
  }
  if (!jsonEq(curr.h3Alpn, init.h3Alpn)) srvPatch.h3_alpn = curr.h3Alpn;
  if (curr.h3UdpDatagrams !== init.h3UdpDatagrams) srvPatch.h3_udp_datagrams = curr.h3UdpDatagrams;
  if (curr.h3InitialMtu !== init.h3InitialMtu) srvPatch.h3_initial_mtu = curr.h3InitialMtu;
  if (curr.h3MtuFirstProbe !== init.h3MtuFirstProbe) srvPatch.h3_mtu_first_probe = curr.h3MtuFirstProbe;
  if (Object.keys(srvPatch).length) {
    patch.server = srvPatch;
    dirtySections.push('server');
  }

  const srPatch: NonNullable<ServerConfigPatch['session_resumption']> = {};
  if (curr.sessionResumption.enabled !== init.sessionResumption.enabled) {
    srPatch.enabled = curr.sessionResumption.enabled;
  }
  for (const key of [
    'orphan_ttl_tcp_secs',
    'orphan_ttl_udp_secs',
    'orphan_per_user_cap',
    'orphan_global_cap',
    'downlink_buffer_bytes',
  ] as const) {
    if (curr.sessionResumption[key] !== init.sessionResumption[key]) {
      srPatch[key] = curr.sessionResumption[key];
    }
  }
  if (Object.keys(srPatch).length) {
    patch.session_resumption = srPatch;
    dirtySections.push('session_resumption');
  }

  const outPatch: NonNullable<ServerConfigPatch['outbound']> = {};
  if (curr.outboundShared.prefer_ipv4 !== init.outboundShared.prefer_ipv4) {
    outPatch.prefer_ipv4 = curr.outboundShared.prefer_ipv4;
  }
  if (curr.outboundShared.ipv6_sticky !== init.outboundShared.ipv6_sticky) {
    outPatch.ipv6_sticky = curr.outboundShared.ipv6_sticky;
  }
  if (curr.outboundShared.ipv6_sticky_ttl_secs !== init.outboundShared.ipv6_sticky_ttl_secs) {
    outPatch.ipv6_sticky_ttl_secs = curr.outboundShared.ipv6_sticky_ttl_secs;
  }
  if (curr.outboundShared.ipv6_refresh_secs !== init.outboundShared.ipv6_refresh_secs) {
    outPatch.ipv6_refresh_secs = curr.outboundShared.ipv6_refresh_secs;
  }
  if (curr.outboundShared.block_private_ips !== init.outboundShared.block_private_ips) {
    outPatch.block_private_ips = curr.outboundShared.block_private_ips;
  }
  const currSubnets = splitListText(curr.outboundShared.allowedSubnetsText);
  const initSubnets = splitListText(init.outboundShared.allowedSubnetsText);
  if (!jsonEq(currSubnets, initSubnets)) {
    outPatch.allowed_subnets = currSubnets.length ? currSubnets : null;
  }
  if (Object.keys(outPatch).length) {
    patch.outbound = outPatch;
    dirtySections.push('outbound');
  }

  const padPatch: NonNullable<ServerConfigPatch['padding']> = {};
  if (curr.padding.cover !== init.padding.cover) padPatch.cover = curr.padding.cover;
  if (curr.padding.throttle_detect_enabled !== init.padding.throttle_detect_enabled) {
    padPatch.throttle_detect_enabled = curr.padding.throttle_detect_enabled;
  }
  for (const key of [
    'min_bytes',
    'max_bytes',
    'cover_jitter_min_ms',
    'cover_jitter_max_ms',
    'throttle_ratio_percent',
    'throttle_window_secs',
    'throttle_sustain_windows',
    'throttle_min_bytes_per_sec',
    'throttle_signal_cooldown_secs',
  ] as const) {
    if (curr.padding[key] !== init.padding[key]) {
      padPatch[key] = curr.padding[key];
    }
  }
  if (Object.keys(padPatch).length) {
    patch.padding = padPatch;
    dirtySections.push('padding');
  }

  if (!jsonEq(curr.httpFallback, init.httpFallback)) {
    if (curr.httpFallback.backend.trim() === '') {
      patch.http_fallback = init.httpFallback.backend.trim() !== '' ? null : {};
      if (patch.http_fallback === null) dirtySections.push('http_fallback');
      else delete patch.http_fallback;
    } else {
      patch.http_fallback = {
        backend: curr.httpFallback.backend.trim(),
        backend_proto: curr.httpFallback.backend_proto || null,
        proxy_protocol: curr.httpFallback.proxy_protocol || null,
        request_timeout_secs: curr.httpFallback.request_timeout_secs,
        apply_to_h1: curr.httpFallback.apply_to_h1,
        apply_to_h3: curr.httpFallback.apply_to_h3,
        add_x_forwarded_for: curr.httpFallback.add_x_forwarded_for,
        add_x_forwarded_proto: curr.httpFallback.add_x_forwarded_proto,
        add_x_forwarded_host: curr.httpFallback.add_x_forwarded_host,
      };
      dirtySections.push('http_fallback');
    }
  }

  if (!jsonEq(curr.sniFallback, init.sniFallback)) {
    const matchSni = splitListText(curr.sniFallback.matchSniText);
    const backends: SniBackendConfig[] = curr.sniFallback.backends.map((b) => {
      const m = splitListText(b.matchSniText);
      return {
        backend: b.backend.trim(),
        proxy_protocol: b.proxy_protocol || null,
        match_sni: m.length ? m : null,
      };
    });
    if (matchSni.length === 0 && backends.length === 0) {
      patch.sni_fallback = null;
    } else {
      patch.sni_fallback = {
        match_sni: matchSni,
        allow_no_sni: curr.sniFallback.allow_no_sni,
        max_client_hello_bytes: curr.sniFallback.max_client_hello_bytes,
        backends,
      };
    }
    dirtySections.push('sni_fallback');
  }

  const akPatch: NonNullable<ServerConfigPatch['access_keys']> = {};
  for (const key of ['public_host', 'public_scheme', 'url_base', 'file_extension', 'write_dir'] as const) {
    const val = nullableStrPatch(curr.accessKeys[key], init.accessKeys[key]);
    if (val !== undefined) akPatch[key] = val;
  }
  const currNodes = splitListText(curr.accessKeys.nodesText);
  const initNodes = splitListText(init.accessKeys.nodesText);
  if (!jsonEq(currNodes, initNodes)) {
    akPatch.nodes = currNodes.length ? currNodes : null;
  }
  if (Object.keys(akPatch).length) {
    patch.access_keys = akPatch;
    dirtySections.push('access_keys');
  }

  if (curr.tuningProfile !== init.tuningProfile) {
    patch.tuning_profile = curr.tuningProfile;
    dirtySections.push('tuning_profile');
  }

  if (!jsonEq(curr.tuningOverrides, init.tuningOverrides)) {
    const anySet = TUNING_FIELD_SPECS.some((s) => curr.tuningOverrides[s.key] !== null);
    if (!anySet) {
      patch.tuning = null;
    } else {
      const tPatch: Partial<TuningOverridesConfig> = {};
      for (const spec of TUNING_FIELD_SPECS) {
        if (curr.tuningOverrides[spec.key] !== init.tuningOverrides[spec.key]) {
          tPatch[spec.key] = curr.tuningOverrides[spec.key];
        }
      }
      patch.tuning = tPatch;
    }
    dirtySections.push('tuning');
  }

  return { patch, dirtySections };
}

export function buildPerNodePatch(
  curr: PerNodeSettingsModel,
  init: PerNodeSettingsModel,
): { patch: ServerConfigPatch; dirtySections: string[] } {
  const patch: ServerConfigPatch = {};
  const dirtySections: string[] = [];

  const srvPatch: NonNullable<ServerConfigPatch['server']> = {};
  for (const key of ['listen', 'cert_path', 'key_path', 'h3_listen', 'h3_cert_path', 'h3_key_path'] as const) {
    const val = nullableStrPatch(curr[key], init[key]);
    if (val !== undefined) srvPatch[key] = val;
  }
  if (!jsonEq(curr.certs, init.certs)) {
    srvPatch.certs = curr.certs.length ? certsFromEditable(curr.certs) : null;
  }
  if (curr.h3CertsCustom !== init.h3CertsCustom || (curr.h3CertsCustom && !jsonEq(curr.h3_certs, init.h3_certs))) {
    srvPatch.h3_certs = curr.h3CertsCustom ? certsFromEditable(curr.h3_certs) : null;
  }
  if (Object.keys(srvPatch).length) {
    patch.server = srvPatch;
    dirtySections.push('node_server');
  }

  const outPatch: NonNullable<ServerConfigPatch['outbound']> = {};
  for (const key of ['ipv6_prefix', 'ipv6_interface', 'ipv6_prefix_interface'] as const) {
    const val = nullableStrPatch(curr[key], init[key]);
    if (val !== undefined) outPatch[key] = val;
  }
  if (Object.keys(outPatch).length) {
    patch.outbound = outPatch;
    dirtySections.push('node_outbound');
  }

  return { patch, dirtySections };
}

export function validateSocketAddr(raw: string): string | null {
  const s = raw.trim();
  if (!s) return null;
  const match = s.match(/^(?:\[([^\]]+)\]|([^:]+)):(\d{1,5})$/);
  if (!match) return 'Expected IP:port (e.g. 0.0.0.0:443 or [::]:443).';
  const port = Number(match[3]);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return 'Port must be between 1 and 65535.';
  }
  return null;
}

export function validateMtu(val: number | null): string | null {
  if (val === null || val === undefined || String(val) === '') return null;
  if (!Number.isInteger(val) || val < 1200 || val > 1452) {
    return 'MTU must be an integer between 1200 and 1452 bytes.';
  }
  return null;
}

export function validatePublicScheme(raw: string): string | null {
  const s = raw.trim();
  if (!s) return null;
  if (s !== 'ws' && s !== 'wss') return 'public_scheme must be "ws" or "wss".';
  return null;
}

export function validateNodeHostEntry(raw: string): string | null {
  const s = raw.trim();
  if (!s) return 'Node host cannot be empty.';
  if (s.length > 253) return 'Node host exceeds 253 characters.';
  if (s.startsWith('-')) return 'Node host cannot start with "-".';
  if (!/^[A-Za-z0-9.\-:\[\]]+$/.test(s)) return `Invalid node host: ${s}`;
  return null;
}

export function validateEndpoints(eps: EditableEndpoint[]): string | null {
  const seen = new Set<string>();
  for (let i = 0; i < eps.length; i++) {
    const p = eps[i].path.trim();
    if (!p) return `Endpoint #${i + 1}: path cannot be empty.`;
    if (!p.startsWith('/')) return `Endpoint #${i + 1}: path "${p}" must start with '/'.`;
    if (/\s/.test(p)) return `Endpoint #${i + 1}: path "${p}" cannot contain spaces.`;
    if (seen.has(p)) return `Duplicate endpoint path "${p}".`;
    seen.add(p);
  }
  return null;
}

export function validateSharedSettings(m: SharedSettingsModel): string | null {
  const epErr = validateEndpoints(m.endpoints);
  if (epErr) return epErr;

  const mtuErr = validateMtu(m.h3InitialMtu);
  if (mtuErr) return `H3 initial MTU: ${mtuErr}`;
  const probeErr = validateMtu(m.h3MtuFirstProbe);
  if (probeErr) return `H3 first probe: ${probeErr}`;

  if (m.padding.min_bytes != null && m.padding.max_bytes != null && m.padding.min_bytes > m.padding.max_bytes) {
    return 'Padding min_bytes cannot exceed max_bytes.';
  }
  if (
    m.padding.cover_jitter_min_ms != null &&
    m.padding.cover_jitter_max_ms != null &&
    m.padding.cover_jitter_min_ms > m.padding.cover_jitter_max_ms
  ) {
    return 'Padding cover_jitter_min_ms cannot exceed cover_jitter_max_ms.';
  }

  if (m.httpFallback.backend.trim() && !m.httpFallback.backend.trim().startsWith('http://')) {
    return 'http_fallback.backend must start with http://.';
  }

  const schemeErr = validatePublicScheme(m.accessKeys.public_scheme);
  if (schemeErr) return schemeErr;

  for (const node of splitListText(m.accessKeys.nodesText)) {
    const err = validateNodeHostEntry(node);
    if (err) return err;
  }

  if (m.sniFallback.max_client_hello_bytes != null && m.sniFallback.max_client_hello_bytes < 256) {
    return 'sni_fallback.max_client_hello_bytes must be >= 256.';
  }
  const hasSniConfig =
    splitListText(m.sniFallback.matchSniText).length > 0 || m.sniFallback.backends.length > 0;
  if (hasSniConfig) {
    if (splitListText(m.sniFallback.matchSniText).length === 0) {
      return 'sni_fallback.match_sni must contain at least one SNI pattern.';
    }
    if (m.sniFallback.backends.length === 0) {
      return 'sni_fallback requires at least one backend.';
    }
    for (let i = 0; i < m.sniFallback.backends.length; i++) {
      const b = m.sniFallback.backends[i];
      if (!b.backend.trim()) return `SNI backend #${i + 1}: host:port is required.`;
      const match = splitListText(b.matchSniText);
      if (match.length === 0 && i !== m.sniFallback.backends.length - 1) {
        return `SNI backend #${i + 1} has empty match_sni (catch-all) and must be last.`;
      }
    }
  }

  return null;
}

export function validatePerNodeSettings(m: PerNodeSettingsModel): string | null {
  const lErr = validateSocketAddr(m.listen);
  if (lErr) return `server.listen: ${lErr}`;
  const h3Err = validateSocketAddr(m.h3_listen);
  if (h3Err) return `server.h3.listen: ${h3Err}`;

  for (const [label, list] of [
    ['server.certs', m.certs],
    ['server.h3.certs', m.h3CertsCustom ? m.h3_certs : []],
  ] as const) {
    for (let i = 0; i < list.length; i++) {
      if (!list[i].cert_path.trim() || !list[i].key_path.trim()) {
        return `${label}[${i}]: cert_path and key_path are required.`;
      }
      for (const s of splitListText(list[i].sniText)) {
        if (s.includes('*')) {
          return `${label}[${i}]: explicit SNI resolver does not support wildcards ("${s}").`;
        }
      }
    }
  }
  return null;
}

export function buildSymmetricPeers(
  members: Array<{ name: string; shard_id: number; mesh_addr: string }>,
): { peersByNode: Record<string, ClusterPeer[]>; error: string | null } {
  const usedShards = new Set<number>();
  for (const m of members) {
    if (!Number.isInteger(m.shard_id) || m.shard_id < 0 || m.shard_id > 15) {
      return { peersByNode: {}, error: `${m.name}: shard_id must be in 0..15.` };
    }
    if (usedShards.has(m.shard_id)) {
      return { peersByNode: {}, error: `Duplicate shard_id ${m.shard_id}.` };
    }
    usedShards.add(m.shard_id);
    if (!m.mesh_addr.trim()) {
      return { peersByNode: {}, error: `${m.name}: mesh address is required.` };
    }
  }

  const peersByNode: Record<string, ClusterPeer[]> = {};
  for (const m of members) {
    peersByNode[m.name] = members
      .filter((other) => other.name !== m.name)
      .map((other) => ({ shard: other.shard_id, addr: other.mesh_addr.trim() }));
  }
  return { peersByNode, error: null };
}
