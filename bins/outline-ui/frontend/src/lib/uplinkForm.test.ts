import { describe, it, expect } from 'vitest';
import { buildUplinkPayload, validateUplinkForm, fieldsFromConfig, emptyUplinkFields } from './uplinkForm';
import type { UplinkConfig } from './types';

// Mirrors ws/uplinks.html's FIELDS / collectForm() / submitForm() exactly —
// see that file for the behavior these tests pin down.

describe('validateUplinkForm', () => {
  it('create requires a name', () => {
    expect(validateUplinkForm(emptyUplinkFields(), false)).toBe('name is required');
  });
  it('create passes once name is set', () => {
    expect(validateUplinkForm({ ...emptyUplinkFields(), name: 'cloud1' }, false)).toBeNull();
  });
  it('create fails when name is whitespace-only', () => {
    expect(validateUplinkForm({ ...emptyUplinkFields(), name: '   ' }, false)).toBe('name is required');
  });
  it('edit never requires a name', () => {
    expect(validateUplinkForm(emptyUplinkFields(), true)).toBeNull();
  });
});

describe('buildUplinkPayload — create', () => {
  it('minimal create sends name + default transport only', () => {
    const fields = { ...emptyUplinkFields(), name: 'cloud1' };
    expect(buildUplinkPayload(fields, false)).toEqual({ name: 'cloud1', transport: 'ss' });
  });

  it('empty optional fields are omitted, not sent as empty strings', () => {
    const fields = { ...emptyUplinkFields(), name: 'cloud1' };
    const out = buildUplinkPayload(fields, false);
    expect(out).not.toHaveProperty('method');
    expect(out).not.toHaveProperty('password');
    expect(out).not.toHaveProperty('vless_id');
    expect(out).not.toHaveProperty('tcp_ws_url');
    expect(out).not.toHaveProperty('weight');
    expect(out).not.toHaveProperty('fwmark');
    expect(out).not.toHaveProperty('ipv6_first');
  });

  it('weight 0 is sent (numeric zero is a provided value, not empty)', () => {
    const fields = { ...emptyUplinkFields(), name: 'x', weight: 0 };
    expect(buildUplinkPayload(fields, false)).toMatchObject({ weight: 0 });
  });

  it('fwmark is truncated to an integer (parseInt(raw, 10) parity)', () => {
    const fields = { ...emptyUplinkFields(), name: 'x', fwmark: 3.9 };
    expect(buildUplinkPayload(fields, false)).toMatchObject({ fwmark: 3 });
  });

  it('ipv6First "true"/"false" map to booleans; "" is omitted', () => {
    expect(buildUplinkPayload({ ...emptyUplinkFields(), name: 'x', ipv6First: 'true' }, false)).toMatchObject({
      ipv6_first: true,
    });
    expect(buildUplinkPayload({ ...emptyUplinkFields(), name: 'x', ipv6First: 'false' }, false)).toMatchObject({
      ipv6_first: false,
    });
    expect(buildUplinkPayload({ ...emptyUplinkFields(), name: 'x' }, false)).not.toHaveProperty('ipv6_first');
  });

  it('all fields filled round-trip onto the payload with snake_case keys', () => {
    const fields = {
      name: 'cloud1',
      transport: 'vless',
      method: 'chacha20-ietf-poly1305',
      password: 'secret',
      vlessId: 'uuid-1',
      tcpWsUrl: 'wss://cloud1/tcp',
      tcpMode: 'ws_h2',
      udpWsUrl: 'wss://cloud1/udp',
      udpMode: 'ws_h3',
      vlessWsUrl: 'wss://cloud1/vless',
      vlessXhttpUrl: 'https://cloud1/xhttp',
      vlessMode: 'xhttp_h3',
      weight: 12.5,
      fwmark: 7,
      ipv6First: 'true' as const,
    };
    expect(buildUplinkPayload(fields, false)).toEqual({
      name: 'cloud1',
      transport: 'vless',
      method: 'chacha20-ietf-poly1305',
      password: 'secret',
      vless_id: 'uuid-1',
      tcp_ws_url: 'wss://cloud1/tcp',
      tcp_mode: 'ws_h2',
      udp_ws_url: 'wss://cloud1/udp',
      udp_mode: 'ws_h3',
      vless_ws_url: 'wss://cloud1/vless',
      vless_xhttp_url: 'https://cloud1/xhttp',
      vless_mode: 'xhttp_h3',
      weight: 12.5,
      fwmark: 7,
      ipv6_first: true,
    });
  });
});

describe('buildUplinkPayload — edit', () => {
  it('name is never included, regardless of the name field value', () => {
    const fields = { ...emptyUplinkFields(), name: 'should-not-appear', method: 'x' };
    expect(buildUplinkPayload(fields, true)).not.toHaveProperty('name');
  });

  it('unchanged (pre-filled) values are resent as a normal PATCH, not diffed away', () => {
    const fields = fieldsFromConfig({ transport: 'ss', weight: 10 });
    expect(buildUplinkPayload(fields, true)).toEqual({ transport: 'ss', weight: 10 });
  });

  it('fields left blank stay omitted entirely (server keeps the existing value)', () => {
    const out = buildUplinkPayload(emptyUplinkFields(), true);
    expect(out).toEqual({ transport: 'ss' });
  });
});

describe('fieldsFromConfig', () => {
  it('populates every field from an existing config', () => {
    const cfg: UplinkConfig = {
      transport: 'vless',
      method: 'aes-256-gcm',
      password: 'p',
      vless_id: 'uuid',
      tcp_ws_url: '/tcp',
      tcp_mode: 'ws_h2',
      udp_ws_url: '/udp',
      udp_mode: 'ws_h3',
      vless_ws_url: '/vless',
      vless_xhttp_url: '/xhttp',
      vless_mode: 'xhttp_h2',
      weight: 12,
      fwmark: 5,
      ipv6_first: false,
    };
    expect(fieldsFromConfig(cfg)).toEqual({
      name: '',
      transport: 'vless',
      method: 'aes-256-gcm',
      password: 'p',
      vlessId: 'uuid',
      tcpWsUrl: '/tcp',
      tcpMode: 'ws_h2',
      udpWsUrl: '/udp',
      udpMode: 'ws_h3',
      vlessWsUrl: '/vless',
      vlessXhttpUrl: '/xhttp',
      vlessMode: 'xhttp_h2',
      weight: 12,
      fwmark: 5,
      ipv6First: 'false',
    });
  });

  it('null/missing config (no on-disk entry) becomes blank fields, transport defaults to ss', () => {
    expect(fieldsFromConfig(null)).toEqual(emptyUplinkFields());
    expect(fieldsFromConfig(undefined)).toEqual(emptyUplinkFields());
    expect(fieldsFromConfig({})).toEqual(emptyUplinkFields());
  });

  it('ipv6_first unset (not present in config) stays the blank tri-state, not "false"', () => {
    expect(fieldsFromConfig({ transport: 'ss' }).ipv6First).toBe('');
  });
});

describe('emptyUplinkFields', () => {
  it('is the create-mode default: blank strings, null weight/fwmark, transport ss', () => {
    expect(emptyUplinkFields()).toEqual({
      name: '',
      transport: 'ss',
      method: '',
      password: '',
      vlessId: '',
      tcpWsUrl: '',
      tcpMode: '',
      udpWsUrl: '',
      udpMode: '',
      vlessWsUrl: '',
      vlessXhttpUrl: '',
      vlessMode: '',
      weight: null,
      fwmark: null,
      ipv6First: '',
    });
  });
});
