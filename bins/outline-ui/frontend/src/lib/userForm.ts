import { parseAliases, aliasesToText } from './format';
import type { NewUser, PatchUser, ServerDefaults, User } from './types';

// Random-bytes source, injectable so unit tests stay deterministic. Default
// is WebCrypto (available in the browser and in Vitest's Node env via the
// global `crypto`).
export type RandomBytes = (n: number) => Uint8Array;
export const webCryptoBytes: RandomBytes = (n) => crypto.getRandomValues(new Uint8Array(n));

function bytesToBase64(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}
function bytesToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// SS-2022 master-key length per cipher (bins/outline-ss-rust crates/outline-wire
// cipher.rs::key_len). For these methods the Shadowsocks "password" IS the
// base64 of a raw key of exactly this length.
const SS2022_KEY_LEN: Record<string, number> = {
  '2022-blake3-aes-128-gcm': 16,
  '2022-blake3-aes-256-gcm': 32,
  '2022-blake3-chacha20-poly1305': 32,
};

// Generate a Shadowsocks password appropriate for `method`:
//   - SS-2022  → base64 of a fresh random master key of the exact length;
//   - legacy AEAD (aes-*-gcm, chacha20-ietf-poly1305) → an arbitrary random
//     secret (the server EVP-derives the key from it), url-safe base64;
//   - '' (server default) → null: the UI does not know the server's effective
//     cipher, so it must not guess a format. Caller prompts to pick a method.
export function generatePassword(method: string, rand: RandomBytes = webCryptoBytes): string | null {
  if (!method) return null;
  const keyLen = SS2022_KEY_LEN[method];
  if (keyLen) return bytesToBase64(rand(keyLen));
  return bytesToBase64Url(rand(24));
}

export function generateVlessId(uuid: () => string = () => crypto.randomUUID()): string {
  return uuid();
}

// Plain-string/number form state for UserDrawer.svelte, kept framework-free
// so the tricky part of Task 7 (edit-time null-reset semantics, create-time
// validation) is unit-testable without mounting a Svelte component. `fwmark`
// is `number | null` rather than a string because it's bound to
// `<input type="number">`, which Svelte's `bind:value` already coerces to
// `null` (empty) or a `number` at the DOM-binding layer (see
// node_modules/svelte/src/internal/client/dom/elements/bindings/input.js
// `to_number`) — mirroring that here avoids a second, redundant
// string->number parse step.
export interface UserFormFields {
  id: string;
  password: string;
  vlessId: string;
  method: string;
  fwmark: number | null;
  aliases: string;
  enabled: boolean;
}

// Create-mode default: matches dashboard.html's openDrawer() (blank form,
// enabled defaults to checked).
export function emptyUserFields(): UserFormFields {
  return {
    id: '',
    password: '',
    vlessId: '',
    method: '',
    fwmark: null,
    aliases: '',
    enabled: true,
  };
}

// Edit-mode population from an existing user — matches dashboard.html's
// openEditDrawer(id). Password/VLESS UUID are secrets the API never echoes
// back, so they always start blank; leaving them blank on submit means
// "keep unchanged" (see buildUserPayload below), not "clear it".
export function fieldsFromUser(user: User): UserFormFields {
  return {
    id: user.id,
    password: '',
    vlessId: '',
    method: user.method ?? '',
    fwmark: user.fwmark ?? null,
    aliases: aliasesToText(user.aliases),
    enabled: user.enabled,
  };
}

// Build create-form fields from an existing user as a template ("clone a
// similar account"): the carrier (method, fwmark, enabled) is copied verbatim
// via fieldsFromUser; `id` and `aliases` are blanked (id must be unique; alias
// names are globally unique server-side, so they cannot be duplicated); fresh
// secrets are generated only for the identities the template actually has.
//
// `defaults` is the server's effective default (GET /control/defaults) — only
// the cipher since the endpoint-model refactor. A user that carries no method
// of its own runs on it, so a clone that ignored it could not generate a
// password at all (the UI must not guess a cipher it does not know). It is
// applied only where the template is silent, and only when the template has a
// password identity.
export function cloneUserFields(
  template: User,
  defaults: ServerDefaults | null = null,
  rand: RandomBytes = webCryptoBytes,
  uuid: () => string = () => crypto.randomUUID(),
): UserFormFields {
  const base = fieldsFromUser(template);
  const out: UserFormFields = { ...base, id: '', aliases: '' };

  if (defaults && template.has_password) {
    out.method = base.method || defaults.method;
  }

  out.password = template.has_password ? (generatePassword(out.method, rand) ?? '') : '';
  out.vlessId = template.has_vless_id ? generateVlessId(uuid) : '';
  return out;
}

// Matches saveUser()'s pre-submit guard: creating a user needs a credential
// (password or vless_id) or the key is useless. Editing has no such
// requirement — a PATCH can touch just `enabled`, a path, etc. without
// resending credentials.
export function validateUserForm(fields: UserFormFields, editing: boolean): string | null {
  if (!editing && !fields.password.trim() && !fields.vlessId.trim()) {
    return 'password or vless_id is required.';
  }
  return null;
}

// Matches ss/dashboard.html's payload(form, editing) exactly:
//   - create: empty optional fields are simply omitted from the payload;
//     `id` is included (trimmed).
//   - edit: empty password/vless_id are omitted too — omission means "leave
//     unchanged" server-side, since blanking a credential to null makes no
//     sense. Empty method/fwmark are instead sent as an explicit
//     `null`, which the server treats as "reset to default". `id` is never
//     sent on edit (immutable once created).
//   - aliases: non-empty text parses to a name->CIDRs map (`{ name: [cidr,
//     ...] }`, see lib/format.ts's parseAliases); empty text resets to
//     `null` on edit, is omitted on create (same reset-vs-omit split as the
//     other optional fields).
//   - `enabled` is always included, both create and edit.
export function buildUserPayload(fields: UserFormFields, editing: boolean): NewUser | PatchUser {
  const out: Record<string, unknown> = {};

  const keepUnlessProvided = (key: string, raw: string) => {
    const text = raw.trim();
    if (text) out[key] = text;
    // empty: create -> omitted; edit -> omitted (server keeps the existing value)
  };
  const resettable = (key: string, raw: string) => {
    const text = raw.trim();
    if (text) out[key] = text;
    else if (editing) out[key] = null;
  };

  keepUnlessProvided('password', fields.password);
  keepUnlessProvided('vless_id', fields.vlessId);
  resettable('method', fields.method);

  if (fields.fwmark !== null) out.fwmark = fields.fwmark;
  else if (editing) out.fwmark = null;

  const parsedAliases = parseAliases(fields.aliases);
  if (parsedAliases) out.aliases = parsedAliases;
  else if (editing) out.aliases = null;

  out.enabled = fields.enabled;
  if (!editing) out.id = fields.id.trim();

  return out as NewUser | PatchUser;
}
