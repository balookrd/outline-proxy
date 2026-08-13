import { parseAliases, aliasesToText } from './format';
import type { NewUser, PatchUser, User } from './types';

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
  wsPathTcp: string;
  wsPathUdp: string;
  wsPathSs: string;
  wsPathVless: string;
  xhttpPathTcp: string;
  xhttpPathUdp: string;
  xhttpPathSs: string;
  xhttpPathVless: string;
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
    wsPathTcp: user.ws_path_tcp ?? '',
    wsPathUdp: user.ws_path_udp ?? '',
    wsPathSs: user.ws_path_ss ?? '',
    wsPathVless: user.ws_path_vless ?? '',
    xhttpPathTcp: user.xhttp_path_tcp ?? '',
    xhttpPathUdp: user.xhttp_path_udp ?? '',
    xhttpPathSs: user.xhttp_path_ss ?? '',
    xhttpPathVless: user.xhttp_path_vless ?? '',
    aliases: aliasesToText(user.aliases),
    enabled: user.enabled,
  };
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
//     sense. Empty method/fwmark/ws_path_* are instead sent as an explicit
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
  resettable('ws_path_tcp', fields.wsPathTcp);
  resettable('ws_path_udp', fields.wsPathUdp);
  resettable('ws_path_ss', fields.wsPathSs);
  resettable('ws_path_vless', fields.wsPathVless);
  resettable('xhttp_path_tcp', fields.xhttpPathTcp);
  resettable('xhttp_path_udp', fields.xhttpPathUdp);
  resettable('xhttp_path_ss', fields.xhttpPathSs);
  resettable('xhttp_path_vless', fields.xhttpPathVless);

  if (fields.fwmark !== null) out.fwmark = fields.fwmark;
  else if (editing) out.fwmark = null;

  const parsedAliases = parseAliases(fields.aliases);
  if (parsedAliases) out.aliases = parsedAliases;
  else if (editing) out.aliases = null;

  out.enabled = fields.enabled;
  if (!editing) out.id = fields.id.trim();

  return out as NewUser | PatchUser;
}
