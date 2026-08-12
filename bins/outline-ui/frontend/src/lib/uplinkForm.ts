import type { UplinkConfig } from './types';

// Plain-string/number form state for features/ws/Uplinks.svelte's add/edit
// drawer, kept framework-free like lib/userForm.ts so payload-building is
// unit-testable without mounting a Svelte component. Mirrors
// bins/outline-ui/src/ws/uplinks.html's FIELDS/collectForm()/renderForm()
// exactly — field set, required-ness, and the "send whatever is currently
// non-empty" submit semantics all come from that file (task-8-brief.md pins
// the field set to it, not to the backend's fuller UplinkPayload — see
// task-8-report.md "Concerns" for the fields this intentionally omits:
// tcp_xhttp_url/udp_xhttp_url/ss_*/link/fallbacks).
export const TRANSPORTS = ['ss', 'vless'] as const;
export const WS_MODES = ['', 'ws_h1', 'ws_h2', 'ws_h3'] as const;
export const VLESS_MODES = ['', 'ws_h1', 'ws_h2', 'ws_h3', 'xhttp_h2', 'xhttp_h3'] as const;

export interface UplinkFormFields {
  name: string;
  transport: string;
  method: string;
  password: string;
  vlessId: string;
  tcpWsUrl: string;
  tcpMode: string;
  udpWsUrl: string;
  udpMode: string;
  vlessWsUrl: string;
  vlessXhttpUrl: string;
  vlessMode: string;
  weight: number | null;
  fwmark: number | null;
  ipv6First: '' | 'true' | 'false';
}

// Create-mode default. `transport` starts on "ss" (the first TRANSPORTS
// entry): uplinks.html's <select> for this field has no blank option (unlike
// tcp_mode/udp_mode/vless_mode/ipv6_first, which all start with `""`), so
// with nothing explicitly chosen the browser silently pre-selects "ss" and
// that value is what actually gets submitted. Defaulting to "ss" here
// reproduces that effective behavior instead of inventing a blank state the
// legacy form never has.
export function emptyUplinkFields(): UplinkFormFields {
  return {
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
  };
}

// Edit-mode population from the `config` object /control/uplinks attaches to
// a list entry — or none, when the on-disk TOML couldn't be read
// (getUplinkConfig() in uplinks.html falls back to `{}` in that case, so the
// edit form still opens with every field blank rather than failing).
export function fieldsFromConfig(config: UplinkConfig | null | undefined): UplinkFormFields {
  const cfg = config ?? {};
  return {
    name: typeof cfg.name === 'string' ? cfg.name : '',
    transport: typeof cfg.transport === 'string' && cfg.transport ? cfg.transport : 'ss',
    method: typeof cfg.method === 'string' ? cfg.method : '',
    password: typeof cfg.password === 'string' ? cfg.password : '',
    vlessId: typeof cfg.vless_id === 'string' ? cfg.vless_id : '',
    tcpWsUrl: typeof cfg.tcp_ws_url === 'string' ? cfg.tcp_ws_url : '',
    tcpMode: typeof cfg.tcp_mode === 'string' ? cfg.tcp_mode : '',
    udpWsUrl: typeof cfg.udp_ws_url === 'string' ? cfg.udp_ws_url : '',
    udpMode: typeof cfg.udp_mode === 'string' ? cfg.udp_mode : '',
    vlessWsUrl: typeof cfg.vless_ws_url === 'string' ? cfg.vless_ws_url : '',
    vlessXhttpUrl: typeof cfg.vless_xhttp_url === 'string' ? cfg.vless_xhttp_url : '',
    vlessMode: typeof cfg.vless_mode === 'string' ? cfg.vless_mode : '',
    weight: typeof cfg.weight === 'number' ? cfg.weight : null,
    fwmark: typeof cfg.fwmark === 'number' ? cfg.fwmark : null,
    ipv6First: cfg.ipv6_first === true ? 'true' : cfg.ipv6_first === false ? 'false' : '',
  };
}

// Matches submitForm()'s pre-submit guard in uplinks.html: only `name` is
// required, and only on create (checked right before the POST). Edit has no
// required fields — a PATCH can touch just one key.
export function validateUplinkForm(fields: UplinkFormFields, editing: boolean): string | null {
  if (!editing && !fields.name.trim()) {
    return 'name is required';
  }
  return null;
}

// Matches collectForm() in uplinks.html: every field with a non-empty
// current value is sent, unconditionally — not a diff against the original
// config. An edit form pre-filled from the existing config therefore resends
// its unchanged values too; only fields that were (and remain) blank stay
// omitted. `name` is excluded whenever `editing` is true regardless of its
// value (the identity key is immutable — see merge_patch_into_table's own
// "name is deliberately not merged" comment in
// bins/outline-ws-rust/src/http/control/uplinks_crud/payload.rs). Numeric
// coercion mirrors collectForm's parseFloat(weight)/parseInt(fwmark, 10);
// ipv6_first maps the tri-state select to a boolean, omitted when blank.
export function buildUplinkPayload(fields: UplinkFormFields, editing: boolean): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (!editing && fields.name.trim()) out.name = fields.name.trim();
  if (fields.transport.trim()) out.transport = fields.transport.trim();
  if (fields.method.trim()) out.method = fields.method.trim();
  if (fields.password.trim()) out.password = fields.password.trim();
  if (fields.vlessId.trim()) out.vless_id = fields.vlessId.trim();
  if (fields.tcpWsUrl.trim()) out.tcp_ws_url = fields.tcpWsUrl.trim();
  if (fields.tcpMode.trim()) out.tcp_mode = fields.tcpMode.trim();
  if (fields.udpWsUrl.trim()) out.udp_ws_url = fields.udpWsUrl.trim();
  if (fields.udpMode.trim()) out.udp_mode = fields.udpMode.trim();
  if (fields.vlessWsUrl.trim()) out.vless_ws_url = fields.vlessWsUrl.trim();
  if (fields.vlessXhttpUrl.trim()) out.vless_xhttp_url = fields.vlessXhttpUrl.trim();
  if (fields.vlessMode.trim()) out.vless_mode = fields.vlessMode.trim();
  if (fields.weight !== null) out.weight = fields.weight;
  if (fields.fwmark !== null) out.fwmark = Math.trunc(fields.fwmark);
  if (fields.ipv6First !== '') out.ipv6_first = fields.ipv6First === 'true';
  return out;
}
