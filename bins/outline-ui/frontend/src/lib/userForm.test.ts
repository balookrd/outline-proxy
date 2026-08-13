import { describe, it, expect } from 'vitest';
import { buildUserPayload, validateUserForm, fieldsFromUser, emptyUserFields } from './userForm';
import type { User } from './types';

// Mirrors ss/dashboard.html's payload(form, editing) / saveUser() exactly —
// see that file's lines ~1105-1152 for the behavior these tests pin down.

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
      wsPathVless: '/vless',
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
      ws_path_vless: '/vless',
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

  it('empty method/fwmark/ws_path_*/aliases reset to explicit null', () => {
    const out = buildUserPayload(emptyUserFields(), true);
    expect(out).toEqual({
      method: null,
      fwmark: null,
      ws_path_tcp: null,
      ws_path_udp: null,
      ws_path_vless: null,
      aliases: null,
      enabled: true,
    });
  });

  it('non-empty resettable values overwrite normally instead of nulling', () => {
    const fields = { ...emptyUserFields(), method: 'aes-128-gcm', fwmark: 3, aliases: 'mobile = 10.0.0.0/8' };
    const out = buildUserPayload(fields, true);
    expect(out).toMatchObject({ method: 'aes-128-gcm', fwmark: 3, aliases: { mobile: ['10.0.0.0/8'] } });
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
      wsPathVless: '',
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
      wsPathVless: '',
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
      wsPathVless: '',
      aliases: '',
      enabled: true,
    });
  });
});
