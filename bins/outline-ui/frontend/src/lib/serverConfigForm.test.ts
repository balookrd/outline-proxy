import { describe, it, expect } from 'vitest';
import type { ServerConfigResponse } from './types';
import {
  sharedFromConfig,
  perNodeFromConfig,
  buildSharedPatch,
  buildPerNodePatch,
  validateSharedSettings,
  buildSymmetricPeers,
} from './serverConfigForm';

const sampleConfig: ServerConfigResponse = {
  config_path: '/etc/outline-server/config.toml',
  restart_pending: false,
  cluster: null,
  server: {
    listen: '0.0.0.0:443',
    cert_path: '/etc/ssl/cert.pem',
    key_path: '/etc/ssl/key.pem',
    max_connections_per_ip: 64,
    certs: [],
    h3_listen: '0.0.0.0:443',
    h3_cert_path: null,
    h3_key_path: null,
    h3_certs: null,
    h3_alpn: ['h3'],
    h3_initial_mtu: 1400,
    h3_mtu_first_probe: null,
    h3_udp_datagrams: true,
  },
  shadowsocks: { method: '2022-blake3-aes-256-gcm' },
  http_root: { auth: true, realm: 'Fleet' },
  access_keys: {
    public_host: 'edge.fleet.example',
    public_scheme: 'wss',
    url_base: null,
    file_extension: '.conf',
    write_dir: '/var/lib/keys',
    nodes: ['relay-a.fleet.example', 'relay-b.fleet.example'],
  },
  session_resumption: {
    enabled: true,
    orphan_ttl_tcp_secs: 60,
    orphan_ttl_udp_secs: 60,
    orphan_per_user_cap: 4,
    orphan_global_cap: 1000,
    downlink_buffer_bytes: 0,
  },
  outbound: {
    prefer_ipv4: false,
    ipv6_prefix: '2001:db8::/64',
    ipv6_interface: null,
    ipv6_prefix_interface: null,
    ipv6_refresh_secs: 300,
    ipv6_sticky: true,
    ipv6_sticky_ttl_secs: 1800,
    block_private_ips: true,
    allowed_subnets: ['198.51.100.0/24'],
  },
  padding: { min_bytes: 0, max_bytes: 128, cover: false },
  http_fallback: { backend: 'http://127.0.0.1:8080', apply_to_h1: true, apply_to_h3: false },
  sni_fallback: null,
  tuning_profile: 'medium',
  tuning: { ws_data_channel_capacity: 64 },
  metrics: { listen: '127.0.0.1:9100', path: '/metrics' },
  control: { listen: '127.0.0.1:9191', access_keys_enabled: true },
  endpoints: [{ path: '/ws', kind: 'ws_ss', protocol: 'shadowsocks', transport: 'websocket', padded: false }],
};

describe('serverConfigForm', () => {
  it('produces minimal patch and emits explicit null when optional fields are cleared', () => {
    const init = sharedFromConfig(sampleConfig);
    const curr = structuredClone(init);
    curr.accessKeys.nodesText = '';
    curr.httpFallback.backend = '';
    curr.tuningOverrides.ws_data_channel_capacity = null;
    curr.endpoints = [...curr.endpoints, { path: '/vless', kind: 'xhttp_vless', padded: true }];

    const { patch, dirtySections } = buildSharedPatch(curr, init);
    expect(dirtySections).toEqual(['endpoints', 'http_fallback', 'access_keys', 'tuning']);
    expect(patch.access_keys).toEqual({ nodes: null });
    expect(patch.http_fallback).toBeNull();
    expect(patch.tuning).toBeNull();
    expect(patch.endpoints).toEqual([
      { path: '/ws', kind: 'ws_ss', padded: false },
      { path: '/vless', kind: 'xhttp_vless', padded: true },
    ]);
  });

  it('tracks per-node field clears and custom h3_certs toggle', () => {
    const init = perNodeFromConfig(sampleConfig);
    const curr = structuredClone(init);
    curr.ipv6_prefix = '';
    curr.h3CertsCustom = true;
    curr.h3_certs = [];

    const { patch, dirtySections } = buildPerNodePatch(curr, init);
    expect(dirtySections).toEqual(['node_server', 'node_outbound']);
    expect(patch.server).toEqual({ h3_certs: [] });
    expect(patch.outbound).toEqual({ ipv6_prefix: null });
  });

  it('validates endpoint paths, public_scheme, and padding bounds', () => {
    const model = sharedFromConfig(sampleConfig);
    model.endpoints = [
      { path: 'no-slash', kind: 'ws_ss', padded: false },
    ];
    expect(validateSharedSettings(model)).toContain("must start with '/'");

    model.endpoints = [
      { path: '/dup', kind: 'ws_ss', padded: false },
      { path: '/dup', kind: 'xhttp_ss', padded: false },
    ];
    expect(validateSharedSettings(model)).toContain('Duplicate endpoint path');

    model.endpoints = [{ path: '/ok', kind: 'ws_ss', padded: false }];
    model.accessKeys.public_scheme = 'https' as any;
    expect(validateSharedSettings(model)).toContain('ws');
  });

  it('builds symmetric peer tables and rejects duplicate shards', () => {
    const res = buildSymmetricPeers([
      { name: 'relay-a', shard_id: 0, mesh_addr: '198.51.100.10:9443' },
      { name: 'relay-b', shard_id: 1, mesh_addr: '198.51.100.11:9443' },
    ]);
    expect(res.error).toBeNull();
    expect(res.peersByNode['relay-a']).toEqual([{ shard: 1, addr: '198.51.100.11:9443' }]);
    expect(res.peersByNode['relay-b']).toEqual([{ shard: 0, addr: '198.51.100.10:9443' }]);

    const dup = buildSymmetricPeers([
      { name: 'relay-a', shard_id: 0, mesh_addr: '198.51.100.10:9443' },
      { name: 'relay-b', shard_id: 0, mesh_addr: '198.51.100.11:9443' },
    ]);
    expect(dup.error).toContain('Duplicate shard_id');
  });
});
