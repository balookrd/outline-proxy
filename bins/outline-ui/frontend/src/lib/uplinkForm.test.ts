import { describe, it, expect } from 'vitest';
import { buildUplinkPayload, validateUplinkForm, fieldsFromConfig, emptyUplinkFields } from './uplinkForm';
import type { UplinkConfig } from './types';
import type { UplinkFormFields } from './uplinkForm';

// Mirrors ws/uplinks.html's FIELDS / collectForm() / submitForm() for the
// legacy-parity subset, extended to the full top-level `UplinkPayload`
// (bins/outline-ws-rust/src/http/control/uplinks_crud/payload.rs) and to the
// share-link-vs-explicit mode split fixed in Task 8b (see
// `expand_share_link` in
// bins/outline-ws-rust/src/config/load/uplinks/wire_shape.rs for why the two
// are mutually exclusive on the wire).

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

  it('create in share-link mode requires a link', () => {
    const fields = { ...emptyUplinkFields(), name: 'cloud1', useShareLink: true };
    expect(validateUplinkForm(fields, false)).toBe('link is required in share-link mode');
  });
  it('create in share-link mode passes once link is set', () => {
    const fields = { ...emptyUplinkFields(), name: 'cloud1', useShareLink: true, link: 'vless://uuid@host:443' };
    expect(validateUplinkForm(fields, false)).toBeNull();
  });
  it('edit in share-link mode does not require a link (blank means "leave untouched")', () => {
    const fields = { ...emptyUplinkFields(), useShareLink: true };
    expect(validateUplinkForm(fields, true)).toBeNull();
  });
});

describe('buildUplinkPayload — create, explicit mode', () => {
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
    expect(out).not.toHaveProperty('tcp_xhttp_url');
    expect(out).not.toHaveProperty('udp_ws_url');
    expect(out).not.toHaveProperty('udp_xhttp_url');
    expect(out).not.toHaveProperty('vless_ws_url');
    expect(out).not.toHaveProperty('vless_xhttp_url');
    expect(out).not.toHaveProperty('ss_ws_url');
    expect(out).not.toHaveProperty('ss_xhttp_url');
    expect(out).not.toHaveProperty('ss_mode');
    expect(out).not.toHaveProperty('link');
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

  it('all explicit fields filled round-trip onto the payload with snake_case keys', () => {
    const fields: UplinkFormFields = {
      name: 'cloud1',
      useShareLink: false,
      link: '',
      transport: 'vless',
      tcpWsUrl: 'wss://cloud1/tcp',
      tcpXhttpUrl: 'https://cloud1/tcp-xhttp',
      tcpMode: 'ws_h2',
      udpWsUrl: 'wss://cloud1/udp',
      udpXhttpUrl: 'https://cloud1/udp-xhttp',
      udpMode: 'ws_h3',
      vlessWsUrl: 'wss://cloud1/vless',
      vlessXhttpUrl: 'https://cloud1/xhttp',
      vlessMode: 'xhttp_h3',
      vlessId: 'uuid-1',
      ssWsUrl: 'wss://cloud1/ss',
      ssXhttpUrl: 'https://cloud1/ss-xhttp',
      ssMode: 'xhttp_h1',
      method: 'chacha20-ietf-poly1305',
      password: 'secret',
      weight: 12.5,
      fwmark: 7,
      ipv6First: 'true',
    };
    expect(buildUplinkPayload(fields, false)).toEqual({
      name: 'cloud1',
      transport: 'vless',
      tcp_ws_url: 'wss://cloud1/tcp',
      tcp_xhttp_url: 'https://cloud1/tcp-xhttp',
      tcp_mode: 'ws_h2',
      udp_ws_url: 'wss://cloud1/udp',
      udp_xhttp_url: 'https://cloud1/udp-xhttp',
      udp_mode: 'ws_h3',
      vless_ws_url: 'wss://cloud1/vless',
      vless_xhttp_url: 'https://cloud1/xhttp',
      vless_mode: 'xhttp_h3',
      vless_id: 'uuid-1',
      ss_ws_url: 'wss://cloud1/ss',
      ss_xhttp_url: 'https://cloud1/ss-xhttp',
      ss_mode: 'xhttp_h1',
      method: 'chacha20-ietf-poly1305',
      password: 'secret',
      weight: 12.5,
      fwmark: 7,
      ipv6_first: true,
    });
  });
});

describe('buildUplinkPayload — edit, explicit mode', () => {
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

describe('buildUplinkPayload — share-link vs explicit emit rule (Task 8b core fix)', () => {
  it('share-link mode emits link + name/weight/fwmark/ipv6_first, never transport or any carrier/cred field', () => {
    const fields: UplinkFormFields = {
      ...emptyUplinkFields(),
      name: 'cloud1',
      useShareLink: true,
      link: 'vless://uuid@host:443?type=ws#cloud1',
      weight: 5,
      fwmark: 10,
      ipv6First: 'true',
      // Stale explicit values left over from before the toggle was flipped —
      // must never leak into the payload regardless.
      transport: 'vless',
      tcpWsUrl: 'wss://leftover/tcp',
      tcpXhttpUrl: 'https://leftover/tcp',
      udpWsUrl: 'wss://leftover/udp',
      vlessWsUrl: 'wss://leftover/vless',
      vlessId: 'leftover-uuid',
      ssWsUrl: 'wss://leftover/ss',
      method: 'aes-256-gcm',
      password: 'leftover-secret',
    };
    const out = buildUplinkPayload(fields, false);
    expect(out).toEqual({
      name: 'cloud1',
      link: 'vless://uuid@host:443?type=ws#cloud1',
      weight: 5,
      fwmark: 10,
      ipv6_first: true,
    });
    expect(out).not.toHaveProperty('transport');
    expect(out).not.toHaveProperty('tcp_ws_url');
    expect(out).not.toHaveProperty('tcp_xhttp_url');
    expect(out).not.toHaveProperty('udp_ws_url');
    expect(out).not.toHaveProperty('vless_ws_url');
    expect(out).not.toHaveProperty('vless_id');
    expect(out).not.toHaveProperty('ss_ws_url');
    expect(out).not.toHaveProperty('method');
    expect(out).not.toHaveProperty('password');
  });

  it('explicit mode emits transport + carrier fields, never link', () => {
    const fields: UplinkFormFields = {
      ...emptyUplinkFields(),
      name: 'cloud1',
      useShareLink: false,
      transport: 'ss',
      ssXhttpUrl: 'https://cloud1/ss',
      ssMode: 'xhttp_h2',
      method: 'chacha20-ietf-poly1305',
      password: 'secret',
      // Leftover link value from a mode toggle — must never leak either.
      link: 'ss://leftover',
    };
    const out = buildUplinkPayload(fields, false);
    expect(out).toMatchObject({
      transport: 'ss',
      ss_xhttp_url: 'https://cloud1/ss',
      ss_mode: 'xhttp_h2',
      method: 'chacha20-ietf-poly1305',
      password: 'secret',
    });
    expect(out).not.toHaveProperty('link');
  });

  it('share-link edit sends only link + common fields, omitting even a present name/other explicit values', () => {
    const fields: UplinkFormFields = {
      ...fieldsFromConfig({ link: 'ss://old-link' }),
      link: 'ss://new-link',
      weight: 3,
    };
    expect(buildUplinkPayload(fields, true)).toEqual({ link: 'ss://new-link', weight: 3 });
  });

  it('share-link edit with a blank link omits link entirely (PATCH leaves it untouched, not cleared)', () => {
    const fields = fieldsFromConfig({ link: 'ss://existing' });
    fields.link = '';
    const out = buildUplinkPayload(fields, true);
    expect(out).not.toHaveProperty('link');
    expect(out).not.toHaveProperty('transport');
  });
});

describe('fieldsFromConfig', () => {
  it('populates every explicit field from an existing config', () => {
    const cfg: UplinkConfig = {
      transport: 'vless',
      tcp_ws_url: '/tcp',
      tcp_xhttp_url: '/tcp-xhttp',
      tcp_mode: 'ws_h2',
      udp_ws_url: '/udp',
      udp_xhttp_url: '/udp-xhttp',
      udp_mode: 'ws_h3',
      vless_ws_url: '/vless',
      vless_xhttp_url: '/xhttp',
      vless_mode: 'xhttp_h2',
      vless_id: 'uuid',
      ss_ws_url: '/ss',
      ss_xhttp_url: '/ss-xhttp',
      ss_mode: 'xhttp_h1',
      method: 'aes-256-gcm',
      password: 'p',
      weight: 12,
      fwmark: 5,
      ipv6_first: false,
    };
    expect(fieldsFromConfig(cfg)).toEqual({
      name: '',
      useShareLink: false,
      link: '',
      transport: 'vless',
      tcpWsUrl: '/tcp',
      tcpXhttpUrl: '/tcp-xhttp',
      tcpMode: 'ws_h2',
      udpWsUrl: '/udp',
      udpXhttpUrl: '/udp-xhttp',
      udpMode: 'ws_h3',
      vlessWsUrl: '/vless',
      vlessXhttpUrl: '/xhttp',
      vlessMode: 'xhttp_h2',
      vlessId: 'uuid',
      ssWsUrl: '/ss',
      ssXhttpUrl: '/ss-xhttp',
      ssMode: 'xhttp_h1',
      method: 'aes-256-gcm',
      password: 'p',
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

  it('link present ⇒ share-link mode, prefilled from config (Task 8b edit-mode detection)', () => {
    const out = fieldsFromConfig({ link: 'vless://uuid@host:443', weight: 4 });
    expect(out.useShareLink).toBe(true);
    expect(out.link).toBe('vless://uuid@host:443');
    expect(out.weight).toBe(4);
  });

  it('link absent ⇒ explicit mode', () => {
    expect(fieldsFromConfig({ transport: 'ss', tcp_ws_url: '/tcp' }).useShareLink).toBe(false);
  });

  it('link present but blank/whitespace-only ⇒ explicit mode (not a real link)', () => {
    expect(fieldsFromConfig({ link: '' }).useShareLink).toBe(false);
    expect(fieldsFromConfig({ link: '   ' }).useShareLink).toBe(false);
  });
});

describe('emptyUplinkFields', () => {
  it('is the create-mode default: blank strings, null weight/fwmark, transport ss, explicit mode', () => {
    expect(emptyUplinkFields()).toEqual({
      name: '',
      useShareLink: false,
      link: '',
      transport: 'ss',
      tcpWsUrl: '',
      tcpXhttpUrl: '',
      tcpMode: '',
      udpWsUrl: '',
      udpXhttpUrl: '',
      udpMode: '',
      vlessWsUrl: '',
      vlessXhttpUrl: '',
      vlessMode: '',
      vlessId: '',
      ssWsUrl: '',
      ssXhttpUrl: '',
      ssMode: '',
      method: '',
      password: '',
      weight: null,
      fwmark: null,
      ipv6First: '',
    });
  });
});
