import { describe, it, expect } from 'vitest';
import { buildUserPayload, validateUserForm, fieldsFromUser, emptyUserFields } from './userForm';
import type { User } from './types';

// Mirrors ss/dashboard.html's payload(form, editing) / saveUser() exactly —
// see that file's lines ~1105-1152 for the behavior these tests pin down.
// The eight per-transport path fields (ws_path_{tcp,udp,ss,vless} +
// xhttp_path_{tcp,udp,ss,vless}) all share the "resettable" semantics of
// ws_path_tcp: a non-empty value is sent as-is, an empty one is omitted on
// create and sent as explicit null (reset to default) on edit.

describe('validateUserForm', () => {
  it('create requires password or vless_id', () => {
    expect(validateUserForm(emptyUserFields(), false)).toBe('password or vless_id is required.');
  });
  it('create passes with password only', () => {
    expect(validateUserForm({ ...emptyUserFields(), password: 'x' }, false)).toBeNull();
  });
  it('create passes with vless_id only', () => {
    expect(validateUserForm({ ...emptyUserFields(), vlessId: 'x' }, false)).toBeNull();
  });
  it('create fails when both are whitespace-only', () => {
    expect(validateUserForm({ ...emptyUserFields(), password: '   ' }, false)).toBe(
      'password or vless_id is required.',
    );
  });
  it('edit never requires password/vless_id', () => {
    expect(validateUserForm(emptyUserFields(), true)).toBeNull();
  });
});

describe('buildUserPayload — create', () => {
  it('minimal create sends only id/password/enabled', () => {
    const fields = { ...emptyUserFields(), id: 'team-madrid', password: 'secret' };
    expect(buildUserPayload(fields, false)).toEqual({ id: 'team-madrid', password: 'secret', enabled: true });
  });

  it('empty optional fields are omitted on create, not nulled', () => {
    const fields = { ...emptyUserFields(), id: 'x', vlessId: 'uuid' };
    const out = buildUserPayload(fields, false);
    expect(out).toEqual({ id: 'x', vless_id: 'uuid', enabled: true });
    expect(out).not.toHaveProperty('method');
    expect(out).not.toHaveProperty('fwmark');
    expect(out).not.toHaveProperty('ws_path_tcp');
    expect(out).not.toHaveProperty('ws_path_ss');
    expect(out).not.toHaveProperty('xhttp_path_tcp');
    expect(out).not.toHaveProperty('xhttp_path_vless');
    expect(out).not.toHaveProperty('aliases');
  });

  it('fwmark 0 is sent (numeric zero is a provided value, not empty)', () => {
    const fields = { ...emptyUserFields(), id: 'x', password: 'p', fwmark: 0 };
    expect(buildUserPayload(fields, false)).toMatchObject({ fwmark: 0 });
  });

  it('all fields filled round-trip onto the payload with snake_case keys', () => {
    const fields = {
      id: 'x',
      password: 'p',
      vlessId: 'v',
      method: 'aes-256-gcm',
      fwmark: 7,
      wsPathTcp: '/tcp',
      wsPathUdp: '/udp',
      wsPathSs: '/pss',
      wsPathVless: '/vless',
      xhttpPathTcp: '/pxtcp',
      xhttpPathUdp: '/pxudp',
      xhttpPathSs: '/pssx',
      xhttpPathVless: '/pxhttp',
      aliases: 'mobile = 10.0.0.0/8',
      enabled: false,
    };
    expect(buildUserPayload(fields, false)).toEqual({
      id: 'x',
      password: 'p',
      vless_id: 'v',
      method: 'aes-256-gcm',
      fwmark: 7,
      ws_path_tcp: '/tcp',
      ws_path_udp: '/udp',
      ws_path_ss: '/pss',
      ws_path_vless: '/vless',
      xhttp_path_tcp: '/pxtcp',
      xhttp_path_udp: '/pxudp',
      xhttp_path_ss: '/pssx',
      xhttp_path_vless: '/pxhttp',
      aliases: { mobile: ['10.0.0.0/8'] },
      enabled: false,
    });
  });
});

describe('buildUserPayload — edit', () => {
  it('id is never included, regardless of the id field value', () => {
    const fields = { ...emptyUserFields(), id: 'should-not-appear', password: 'x' };
    expect(buildUserPayload(fields, true)).not.toHaveProperty('id');
  });

  it('empty password/vless_id are omitted entirely (server keeps existing value)', () => {
    const out = buildUserPayload(emptyUserFields(), true);
    expect(out).not.toHaveProperty('password');
    expect(out).not.toHaveProperty('vless_id');
  });

  it('empty method/fwmark/ws_path_*/xhttp_path_*/aliases reset to explicit null', () => {
    const out = buildUserPayload(emptyUserFields(), true);
    expect(out).toEqual({
      method: null,
      fwmark: null,
      ws_path_tcp: null,
      ws_path_udp: null,
      ws_path_ss: null,
      ws_path_vless: null,
      xhttp_path_tcp: null,
      xhttp_path_udp: null,
      xhttp_path_ss: null,
      xhttp_path_vless: null,
      aliases: null,
      enabled: true,
    });
  });

  it('non-empty resettable values overwrite normally instead of nulling', () => {
    const fields = {
      ...emptyUserFields(),
      method: 'aes-128-gcm',
      fwmark: 3,
      wsPathSs: '/pss',
      xhttpPathVless: '/pxhttp',
      aliases: 'mobile = 10.0.0.0/8',
    };
    const out = buildUserPayload(fields, true);
    expect(out).toMatchObject({
      method: 'aes-128-gcm',
      fwmark: 3,
      ws_path_ss: '/pss',
      xhttp_path_vless: '/pxhttp',
      aliases: { mobile: ['10.0.0.0/8'] },
    });
  });

  it('provided password/vless_id are sent as a real change', () => {
    const fields = { ...emptyUserFields(), password: 'newpass' };
    const out = buildUserPayload(fields, true);
    expect(out).toMatchObject({ password: 'newpass' });
    expect(out).not.toHaveProperty('vless_id');
  });

  it('enabled is always included, both true and false', () => {
    expect(buildUserPayload({ ...emptyUserFields(), enabled: true }, true)).toMatchObject({ enabled: true });
    expect(buildUserPayload({ ...emptyUserFields(), enabled: false }, true)).toMatchObject({ enabled: false });
  });
});

describe('fieldsFromUser', () => {
  it('populates from a user, leaving secret fields blank (password/vless_id never round-trip)', () => {
    const user: User = {
      id: 'u1',
      enabled: true,
      method: 'aes-256-gcm',
      fwmark: 5,
      ws_path_tcp: '/tcp',
      ws_path_udp: null,
      ws_path_ss: '/pss',
      xhttp_path_ss: '/pssx',
      xhttp_path_vless: '/pxhttp',
      aliases: { mobile: '10.0.0.0/8', office: ['192.0.2.0/24', '203.0.113.5'] },
    };
    expect(fieldsFromUser(user)).toEqual({
      id: 'u1',
      password: '',
      vlessId: '',
      method: 'aes-256-gcm',
      fwmark: 5,
      wsPathTcp: '/tcp',
      wsPathUdp: '',
      wsPathSs: '/pss',
      wsPathVless: '',
      xhttpPathTcp: '',
      xhttpPathUdp: '',
      xhttpPathSs: '/pssx',
      xhttpPathVless: '/pxhttp',
      aliases: 'mobile = 10.0.0.0/8\noffice = 192.0.2.0/24, 203.0.113.5',
      enabled: true,
    });
  });

  it('null/missing optional fields become empty string, fwmark null, no aliases text', () => {
    const user: User = { id: 'u2', enabled: false };
    expect(fieldsFromUser(user)).toEqual({
      id: 'u2',
      password: '',
      vlessId: '',
      method: '',
      fwmark: null,
      wsPathTcp: '',
      wsPathUdp: '',
      wsPathSs: '',
      wsPathVless: '',
      xhttpPathTcp: '',
      xhttpPathUdp: '',
      xhttpPathSs: '',
      xhttpPathVless: '',
      aliases: '',
      enabled: false,
    });
  });
});

describe('emptyUserFields', () => {
  it('is the create-mode default: blank strings, null fwmark, enabled true', () => {
    expect(emptyUserFields()).toEqual({
      id: '',
      password: '',
      vlessId: '',
      method: '',
      fwmark: null,
      wsPathTcp: '',
      wsPathUdp: '',
      wsPathSs: '',
      wsPathVless: '',
      xhttpPathTcp: '',
      xhttpPathUdp: '',
      xhttpPathSs: '',
      xhttpPathVless: '',
      aliases: '',
      enabled: true,
    });
  });
});

import {
  generatePassword,
  generateVlessId,
  cloneUserFields,
} from './userForm';

// Deterministic byte source: n bytes all equal to 0x07. Lets us assert the
// decoded master-key length without depending on real randomness.
const fixedBytes = (n: number): Uint8Array => new Uint8Array(n).fill(7);

describe('generatePassword', () => {
  it('SS-2022 aes-128 → base64 of a 16-byte master key', () => {
    const pw = generatePassword('2022-blake3-aes-128-gcm', fixedBytes);
    expect(pw).not.toBeNull();
    expect(atob(pw as string).length).toBe(16);
  });
  it('SS-2022 aes-256 → base64 of a 32-byte master key', () => {
    const pw = generatePassword('2022-blake3-aes-256-gcm', fixedBytes);
    expect(atob(pw as string).length).toBe(32);
  });
  it('SS-2022 chacha20 → base64 of a 32-byte master key', () => {
    const pw = generatePassword('2022-blake3-chacha20-poly1305', fixedBytes);
    expect(atob(pw as string).length).toBe(32);
  });
  it('legacy AEAD method → non-empty base64url secret (no padding, url-safe)', () => {
    const pw = generatePassword('aes-256-gcm', fixedBytes) as string;
    expect(pw.length).toBeGreaterThan(0);
    expect(pw).toMatch(/^[A-Za-z0-9_-]+$/);
  });
  it('empty method (server default) → null (UI cannot know the cipher)', () => {
    expect(generatePassword('', fixedBytes)).toBeNull();
  });
});

describe('generateVlessId', () => {
  it('returns the injected uuid verbatim', () => {
    expect(generateVlessId(() => 'fixed-uuid-value')).toBe('fixed-uuid-value');
  });
  it('default source produces a v4 UUID', () => {
    expect(generateVlessId()).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
  });
});

const fixedUuid = () => 'uuid-fixed';

describe('cloneUserFields', () => {
  it('copies the carrier, generates a password, blanks id/aliases (SS-2022 template)', () => {
    const template: User = {
      id: 'team-madrid',
      enabled: true,
      method: '2022-blake3-aes-256-gcm',
      fwmark: 7,
      ws_path_tcp: '/tcp',
      ws_path_ss: '/pss',
      xhttp_path_vless: '/pxhttp',
      aliases: { mobile: '10.0.0.0/8' },
      has_password: true,
    };
    const out = cloneUserFields(template, null, fixedBytes, fixedUuid);
    expect(out.id).toBe('');
    expect(out.aliases).toBe('');
    expect(out.method).toBe('2022-blake3-aes-256-gcm');
    expect(out.fwmark).toBe(7);
    expect(out.wsPathTcp).toBe('/tcp');
    expect(out.wsPathSs).toBe('/pss');
    expect(out.xhttpPathVless).toBe('/pxhttp');
    expect(out.enabled).toBe(true);
    expect(atob(out.password).length).toBe(32);
    expect(out.vlessId).toBe(''); // no has_vless_id on the template
  });

  it('generates vless_id only when the template has one', () => {
    const template: User = {
      id: 'v-only', enabled: true, method: '2022-blake3-aes-256-gcm',
      ws_path_vless: '/vless', has_vless_id: true,
    };
    const out = cloneUserFields(template, null, fixedBytes, fixedUuid);
    expect(out.vlessId).toBe('uuid-fixed');
    expect(out.password).toBe(''); // no has_password
  });

  it('generates both secrets when the template has both identities', () => {
    const template: User = {
      id: 'both', enabled: false, method: '2022-blake3-aes-128-gcm',
      ws_path_ss: '/pss', ws_path_vless: '/vless',
      has_password: true, has_vless_id: true,
    };
    const out = cloneUserFields(template, null, fixedBytes, fixedUuid);
    expect(atob(out.password).length).toBe(16);
    expect(out.vlessId).toBe('uuid-fixed');
    expect(out.enabled).toBe(false); // enabled copied verbatim
  });

  it('default-method template: password stays blank (not guessed)', () => {
    const template: User = {
      id: 'def', enabled: true, ws_path_ss: '/pss', has_password: true,
    };
    const out = cloneUserFields(template, null, fixedBytes, fixedUuid);
    expect(out.method).toBe('');
    expect(out.password).toBe('');
  });
});

import type { ServerDefaults } from './types';

const srvDefaults: ServerDefaults = {
  method: '2022-blake3-aes-256-gcm',
  ws_path_tcp: '/dtcp',
  ws_path_udp: '/dudp',
  ws_path_vless: '/dvless',
  xhttp_path_vless: '/dxvless',
};

describe('cloneUserFields with server defaults', () => {
  it('fills the effective method so a default-method template still gets a password', () => {
    const template: User = { id: 'plain', enabled: true, has_password: true };
    const out = cloneUserFields(template, srvDefaults, fixedBytes, () => 'uuid-fixed');
    expect(out.method).toBe('2022-blake3-aes-256-gcm');
    expect(atob(out.password).length).toBe(32);
  });

  it('fills split ss paths from defaults when the template has none', () => {
    const template: User = { id: 'plain', enabled: true, has_password: true };
    const out = cloneUserFields(template, srvDefaults, fixedBytes, () => 'uuid-fixed');
    expect(out.wsPathTcp).toBe('/dtcp');
    expect(out.wsPathUdp).toBe('/dudp');
    expect(out.wsPathSs).toBe('');
  });

  it('prefers a combined ss path when the server default is combined', () => {
    const combined: ServerDefaults = { ...srvDefaults, ws_path_ss: '/dss' };
    const template: User = { id: 'plain', enabled: true, has_password: true };
    const out = cloneUserFields(template, combined, fixedBytes, () => 'uuid-fixed');
    expect(out.wsPathSs).toBe('/dss');
    expect(out.wsPathTcp).toBe('');
    expect(out.wsPathUdp).toBe('');
  });

  it("never overrides the template's own explicit values", () => {
    const template: User = {
      id: 'explicit', enabled: true, method: 'aes-256-gcm',
      ws_path_tcp: '/own-tcp', has_password: true,
    };
    const out = cloneUserFields(template, srvDefaults, fixedBytes, () => 'uuid-fixed');
    expect(out.method).toBe('aes-256-gcm');
    expect(out.wsPathTcp).toBe('/own-tcp');
    expect(out.wsPathUdp).toBe('/dudp'); // unset on the template -> default
  });

  it('fills vless paths only for a template that has a vless identity', () => {
    const vlessOnly: User = { id: 'v', enabled: true, has_vless_id: true };
    const out = cloneUserFields(vlessOnly, srvDefaults, fixedBytes, () => 'uuid-fixed');
    expect(out.wsPathVless).toBe('/dvless');
    expect(out.xhttpPathVless).toBe('/dxvless');
    expect(out.wsPathTcp).toBe(''); // no ss identity -> no ss paths
    expect(out.password).toBe('');
    expect(out.vlessId).toBe('uuid-fixed');
  });

  it('without defaults behaves exactly as before (no password for a default method)', () => {
    const template: User = { id: 'plain', enabled: true, has_password: true };
    const out = cloneUserFields(template, null, fixedBytes, () => 'uuid-fixed');
    expect(out.method).toBe('');
    expect(out.password).toBe('');
    expect(out.wsPathTcp).toBe('');
  });

  // Shape precedence must come from what the template itself already owns,
  // mirroring the server's specific-beats-general rule
  // (user_entry.rs::effective_ws_path_ss / effective_xhttp_path_ss): an
  // owned split path (tcp and/or udp) suppresses a combined path entirely.
  // Deciding purely from the default's shape — the previous bug — could
  // populate both shapes at once and silently change the user's effective
  // routing server-side.
  it("keeps a template-owned combined ss path when the default is split-only (doesn't also fill split)", () => {
    const template: User = {
      id: 'clone-combined', enabled: true, ws_path_ss: '/own-ss', has_password: true,
    };
    // srvDefaults is split-only: ws_path_tcp/ws_path_udp set, no ws_path_ss.
    const out = cloneUserFields(template, srvDefaults, fixedBytes, () => 'uuid-fixed');
    expect(out.wsPathSs).toBe('/own-ss');
    expect(out.wsPathTcp).toBe('');
    expect(out.wsPathUdp).toBe('');
  });

  it('keeps a template-owned split ss path when the default is combined, filling only the missing peer', () => {
    const combined: ServerDefaults = { ...srvDefaults, ws_path_ss: '/dss' };
    const template: User = {
      id: 'clone-split', enabled: true, ws_path_tcp: '/own-tcp', has_password: true,
    };
    const out = cloneUserFields(template, combined, fixedBytes, () => 'uuid-fixed');
    expect(out.wsPathTcp).toBe('/own-tcp');
    expect(out.wsPathUdp).toBe('/dudp'); // missing peer filled from the split default
    expect(out.wsPathSs).toBe(''); // owned split suppresses combined -> never filled
  });

  it('mirrors the same precedence for xhttp: template-owned combined path beats split xhttp defaults', () => {
    const splitXhttpDefaults: ServerDefaults = {
      ...srvDefaults,
      xhttp_path_tcp: '/dxtcp',
      xhttp_path_udp: '/dxudp',
    };
    const template: User = {
      id: 'clone-xhttp-combined', enabled: true, xhttp_path_ss: '/own-xss', has_password: true,
    };
    const out = cloneUserFields(template, splitXhttpDefaults, fixedBytes, () => 'uuid-fixed');
    expect(out.xhttpPathSs).toBe('/own-xss');
    expect(out.xhttpPathTcp).toBe('');
    expect(out.xhttpPathUdp).toBe('');
  });
});
